//! Port of `sarif.managers.DataTypesSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use serde_json::{Map, Value};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::{DEFAULT_HANDLER, REPLACE_HANDLER};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::listing::Program;
use crate::program::model::symbol::source_type::SourceType;
use crate::program::seam_stubs::share_data_type;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    ArrayDataType, BuiltInDataTypePlaceholder, CompositePacking, DtParser, EnumDataType,
    FunctionDefinitionDataType, MessageLog, PointerDataType, SarifDataTypeWriter, SarifMgr,
    SarifProgramOptions, SarifWriterTask, StructureDataType, TaskLauncher, TypedefDataType,
    UnionDataType,
};

/// `DataTypesSarifMgr.foreignTypedefs`: SARIF-only type names mapped onto the Ghidra built-in
/// each one stands for. Java holds these as the `dataType` singletons of `CharDataType`,
/// `PascalString255DataType`, `PascalStringDataType`, `PascalUnicodeDataType`,
/// `LongDoubleDataType` and `UnsignedInteger3DataType`; none of those classes is constructible in
/// the crate yet, so each is represented by its Ghidra name and length. The gaps in the sequence
/// (`string4`, `unicode4`, `oword`, packed real) are the ones Java leaves commented out.
static FOREIGN_TYPEDEFS: Lazy<HashMap<&'static str, Arc<dyn DataType>>> = Lazy::new(|| {
    let entries: [(&'static str, &'static str, i32); 6] = [
        ("ascii", "char", 1),
        ("string1", "PascalString255", -1),
        ("string2", "PascalString", -1),
        ("unicode2", "PascalUnicode", -1),
        // 10-byte float
        ("tbyte", "longdouble", 10),
        ("3byte", "uint3", 3),
    ];
    entries
        .into_iter()
        .map(|(sarif_name, ghidra_name, length)| {
            let dt: Arc<dyn DataType> = Arc::new(BuiltInDataTypePlaceholder::new(ghidra_name, length));
            (sarif_name, dt)
        })
        .collect()
});

/// Uniform field access over the top-level `HashMap` a SARIF result arrives as and the
/// `serde_json::Map`s nested inside it, so the `process*`/`findDataType` helpers can walk both
/// without copying either.
trait JsonFields {
    fn field(&self, name: &str) -> Option<&Value>;
}

impl JsonFields for HashMap<String, Value> {
    fn field(&self, name: &str) -> Option<&Value> {
        self.get(name)
    }
}

impl JsonFields for Map<String, Value> {
    fn field(&self, name: &str) -> Option<&Value> {
        self.get(name)
    }
}

fn text(fields: &dyn JsonFields, name: &str) -> Option<String> {
    fields.field(name).and_then(Value::as_str).map(str::to_string)
}

/// SARIF numbers arrive as JSON doubles; Java casts them with `(int) (double)`, which truncates.
fn number(fields: &dyn JsonFields, name: &str) -> Option<f64> {
    fields.field(name).and_then(Value::as_f64)
}

fn flag(fields: &dyn JsonFields, name: &str) -> Option<bool> {
    fields.field(name).and_then(Value::as_bool)
}

fn object<'a>(fields: &'a dyn JsonFields, name: &str) -> Option<&'a Map<String, Value>> {
    fields.field(name).and_then(Value::as_object)
}

/// Stands in for the `NullPointerException` Java raises when a `Program` hands back no
/// `DataTypeManager`: an empty manager that holds, resolves and remembers nothing.
struct NoDataTypeManager;

impl DataTypeManager for NoDataTypeManager {}

/// Reads and writes `DATATYPE` entries between a [`Program`]'s
/// [`DataTypeManager`] and SARIF.
///
/// Port of `sarif.managers.DataTypesSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have.
///
/// Java's `process*` methods each construct a concrete `ghidra.program.model.data` class
/// (`StructureDataType`, `EnumDataType`, ...). Those classes exist in the crate only as
/// constructor-less traits, so this port builds the placeholders in
/// [`crate::sarif::seam_stubs`] instead; every one of them implements the real [`DataType`]
/// trait, so the manager's own path, lookup and multi-pass logic is ported exactly.
pub struct DataTypesSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    data_manager: Box<dyn DataTypeManager>,
    dt_parser: Option<DtParser>,
    data_types: HashMap<String, Arc<dyn DataType>>,
    is_packed: HashMap<String, bool>,
    packing_value: HashMap<String, i32>,
}

impl DataTypesSarifMgr {
    /// `DataTypesSarifMgr.KEY`.
    pub const KEY: &'static str = "DATATYPE";
    /// `DataTypesSarifMgr.MAX_PASSES`.
    const MAX_PASSES: i32 = 10;
    /// `DataTypesSarifMgr.DEFAULT_SIZE`.
    const DEFAULT_SIZE: i32 = 1;

    /// `new DataTypesSarifMgr(Program program, MessageLog log)`.
    ///
    /// Java reaches the manager through `program.getListing().getDataTypeManager()`; the
    /// equivalent [`Program::get_data_type_manager`] is used here since it needs only a shared
    /// borrow and, as in Ghidra, hands back the same manager `writeAsSARIF` later asks the
    /// program for directly.
    pub fn new(program: Arc<dyn Program>, log: MessageLog) -> Self {
        let data_manager = program
            .get_data_type_manager()
            .unwrap_or_else(|| Box::new(NoDataTypeManager));
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            data_manager,
            dt_parser: None,
            data_types: HashMap::new(),
            is_packed: HashMap::new(),
            packing_value: HashMap::new(),
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `DataTypesSarifMgr.readResults`.
    ///
    /// Data types reference each other, and the SARIF results arrive in no particular order, so
    /// the whole list is replayed until either every entry resolved or `MAX_PASSES` passes have
    /// been spent.
    pub fn read_results(
        &mut self,
        list: Option<&[HashMap<String, Value>]>,
        options: Option<&SarifProgramOptions>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let key = self.get_key().to_string();
        let Some(list) = list else {
            monitor.set_message(&format!("Skipping over {key} ..."));
            return Ok(());
        };

        monitor.set_message(&format!("Processing {key}..."));
        let mut pass = 0;
        loop {
            monitor.set_maximum(list.len() as i64 * Self::MAX_PASSES as i64);
            monitor.check_cancelled()?;
            let mut processed_all = true;
            for result in list {
                if monitor.is_cancelled() {
                    break;
                }
                processed_all &= self.read(result, options, monitor);
                monitor.increment_progress(1);
            }
            pass += 1;
            if processed_all || pass >= Self::MAX_PASSES {
                return Ok(());
            }
        }
    }

    /// `DataTypesSarifMgr.read`: recreates the data type encoded in one SARIF result inside this
    /// manager's [`DataTypeManager`].
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        self.dt_parser = Some(DtParser::new());
        let processed = self.process(result);
        // Java's `finally` block.
        self.data_manager.close();
        self.dt_parser = None;
        processed
    }

    /// `DataTypesSarifMgr.process`: dispatches on the result's `Message` tag.
    fn process(&mut self, result: &HashMap<String, Value>) -> bool {
        let name = text(result, "Message").unwrap_or_default();
        let outcome = match name.as_str() {
            "DT.Struct" => Some(self.process_structure(result)),
            "DT.Union" => Some(self.process_union(result)),
            "DT.Enum" => Some(self.process_enum(result)),
            "DT.Typedef" => Some(self.process_type_def(result)),
            "DT.TypedObject" => Some(self.process_typed_object(result)),
            "DT.Builtin" => Some(self.process_builtin(result)),
            "DT.Function" => Some(self.process_function_def(result)),
            _ => None,
        };
        match outcome {
            Some(Ok(processed)) => processed,
            // Java catches every exception, logs it, and reports the result as processed so the
            // multi-pass loop does not retry it forever.
            Some(Err(message)) => {
                self.log.append_msg(message);
                true
            }
            None => {
                self.log.append_msg(format!("Unrecognized datatype tag: {name}"));
                true
            }
        }
    }

    /// `DataTypesSarifMgr.addDataType(String key, DataType dt)`.
    ///
    /// Java casts `dt` to `Composite` to apply the packing recorded for `key` while the struct or
    /// union was read. Rust cannot recover a `&mut dyn Composite` from a shared data type, so the
    /// concrete placeholder is taken by value and packing is applied through [`CompositePacking`]
    /// before the type is shared.
    pub fn add_data_type<D>(&mut self, key: &str, mut data_type: D)
    where
        D: DataType + CompositePacking + 'static,
    {
        if let Some(&packed) = self.is_packed.get(key) {
            data_type.set_packing_enabled(packed);
            if let Some(&pack_value) = self.packing_value.get(key) {
                data_type.set_explicit_packing_value(pack_value);
            }
        }
        self.add_shared_data_type(key, Arc::new(data_type));
    }

    /// The tail of [`add_data_type`](Self::add_data_type) for a data type this manager did not
    /// build itself -- Java's `processBuiltin` path, where the packing cast never applies because
    /// only `processStructure`/`processUnion` ever record packing, and only under their own keys.
    pub fn add_shared_data_type(&mut self, key: &str, data_type: Arc<dyn DataType>) {
        self.data_types.insert(key.to_string(), data_type.clone());
        self.data_manager
            .add_data_type(share_data_type(&data_type), &REPLACE_HANDLER);
    }

    /// `DataTypesSarifMgr.processFunctionDef`.
    fn process_function_def(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let mut processed_all = true;
        let name = text(result, "name").unwrap_or_default();
        let path = Self::get_category_path(result);
        let mut function = FunctionDefinitionDataType::new(path, &name);
        Self::process_settings(result, function.get_default_settings().as_mut());
        function.set_var_args(flag(result, "hasVarArgs").unwrap_or(false));
        function.set_no_return(flag(result, "hasNoReturn").unwrap_or(false));
        function.set_calling_convention(text(result, "callingConventionName"));

        let function_path = Self::path_of(&function);
        // Java parks the still-empty definition in `dataTypes` so a parameter can refer back to
        // it; a snapshot has to stand in for Java's live reference, and the finished definition
        // replaces it below.
        self.data_types
            .insert(function_path.clone(), Arc::new(function.clone()));

        if let Some(ret_type) = object(result, "retType") {
            if let Some(return_type) = self.find_data_type(ret_type) {
                function.set_return_type(return_type);
            }
        }

        if let Some(params) = result.get("params").and_then(Value::as_array) {
            for param in params {
                let Some(param) = param.as_object() else {
                    continue;
                };
                processed_all &= self.process_function_members(param, &mut function);
            }
        }

        self.add_data_type(&function_path, function);
        Ok(processed_all)
    }

    /// `DataTypesSarifMgr.processEnum`.
    fn process_enum(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let name = text(result, "name").unwrap_or_default();
        let enum_comment = text(result, "comment");
        let category_path = Self::get_category_path(result);
        let size = number(result, "size").unwrap_or(0.0) as i32;

        let mut enumeration = EnumDataType::new(category_path, &name, size);
        Self::process_settings(result, enumeration.get_default_settings().as_mut());

        let _ = enumeration.set_description(enum_comment.as_deref().unwrap_or_default());
        if let Some(constants) = object(result, "constants") {
            for (constant_name, constant_value) in constants {
                Self::process_enum_members(constant_name, constant_value, &mut enumeration);
            }
        }

        let path = Self::path_of(&enumeration);
        self.add_data_type(&path, enumeration);
        Ok(true)
    }

    /// `DataTypesSarifMgr.processTypeDef`.
    fn process_type_def(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let name = text(result, "name").unwrap_or_default();
        let is_auto_named = flag(result, "autoNamed");

        let Some(data_type) = self.find_data_type(result) else {
            self.log.append_msg(format!("{name} NOT FOUND"));
            return Ok(false);
        };

        let dt_size = data_type.get_length();
        let size = number(result, "size").unwrap_or(0.0) as i32;
        if size != -1 && size != dt_size {
            let raw_size = result.get("size").map(Value::to_string).unwrap_or_default();
            self.log.append_msg(format!(
                "SIZE={raw_size} specified on type-def {name} does not agree with length of datatype {} ({dt_size})",
                data_type.get_path_name()
            ));
        }

        let category_path = Self::get_category_path(result);

        // Java re-points `td` at the existing data type when the type-def merely re-declares
        // itself, then moves it into `cp`. A data type already shared out of `dataTypes` cannot
        // be re-categorized here, so it is registered under its existing path unchanged.
        if name == data_type.get_path_name() && data_type.is_typedef() {
            let existing_path = Self::path_of(data_type.as_ref());
            self.add_shared_data_type(&existing_path, data_type);
            return Ok(true);
        }

        let mut type_def = TypedefDataType::new(category_path.clone(), &name, data_type);
        Self::process_settings(result, type_def.get_default_settings().as_mut());
        if is_auto_named == Some(true) {
            type_def.enable_auto_naming();
        }

        if type_def.set_category_path(category_path.clone()).is_err() {
            self.log.append_msg(format!(
                "Unable to place typedef '{name}' in category '{}'",
                category_path.get_path()
            ));
        }

        let path = Self::path_of(&type_def);
        self.add_data_type(&path, type_def);
        Ok(true)
    }

    /// `DataTypesSarifMgr.processStructure`.
    fn process_structure(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let name = text(result, "name").unwrap_or_default();
        let path = Self::get_category_path(result);
        let size = number(result, "size").map(|s| s as i32).unwrap_or(Self::DEFAULT_SIZE);
        let mut structure = StructureDataType::new(path, &name, size);
        Self::process_settings(result, structure.get_default_settings().as_mut());

        if let Some(comment) = Self::get_regular_comment(result) {
            let _ = structure.set_description(&comment);
        }
        if let Some(alignment_min) = number(result, "explicitMinimumAlignment") {
            structure.set_explicit_minimum_alignment(alignment_min as i32);
        }

        let structure_path = Self::path_of(&structure);
        if let Some(packing) = text(result, "packed") {
            // NB: not `structure.set_packing_enabled(..)` here -- Java defers packing to
            // `addDataType` so that it lands after every member has been added.
            self.is_packed
                .insert(structure_path.clone(), packing.eq_ignore_ascii_case("true"));
            if let Some(explicit_packing_value) = number(result, "explicitPackingValue") {
                self.packing_value
                    .insert(structure_path.clone(), explicit_packing_value as i32);
            }
        }

        // Java parks the still-empty structure in `dataTypes` so a member can refer back to it; a
        // snapshot has to stand in for Java's live reference.
        self.data_types
            .insert(structure_path.clone(), Arc::new(structure.clone()));

        let mut processed_all = true;
        if let Some(fields) = object(result, "fields") {
            for (field_name, field) in fields {
                processed_all &= self.process_struct_members(field_name, field, &mut structure);
            }
        }
        if processed_all {
            self.add_data_type(&structure_path, structure);
        } else {
            self.data_types.insert(structure_path, Arc::new(structure));
        }
        Ok(processed_all)
    }

    /// `DataTypesSarifMgr.processUnion`.
    fn process_union(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let name = text(result, "name").unwrap_or_default();
        let path = Self::get_category_path(result);
        let comment = Self::get_regular_comment(result);
        let mut union = UnionDataType::new(path, &name);
        Self::process_settings(result, union.get_default_settings().as_mut());

        if let Some(comment) = comment {
            let _ = union.set_description(&comment);
        }
        if let Some(alignment_min) = number(result, "explicitMinimumAlignment") {
            union.set_explicit_minimum_alignment(alignment_min as i32);
        }

        let union_path = Self::path_of(&union);
        if let Some(packing) = text(result, "packed") {
            self.is_packed
                .insert(union_path.clone(), packing.eq_ignore_ascii_case("true"));
            if let Some(explicit_packing_value) = number(result, "explicitPackingValue") {
                self.packing_value
                    .insert(union_path.clone(), explicit_packing_value as i32);
            }
        }

        self.data_types.insert(union_path.clone(), Arc::new(union.clone()));

        let mut processed_all = true;
        if let Some(fields) = object(result, "fields") {
            for (field_name, field) in fields {
                processed_all &= self.process_union_members(field_name, field, &mut union);
            }
        }
        if processed_all {
            self.add_data_type(&union_path, union);
        } else {
            self.data_types.insert(union_path, Arc::new(union));
        }
        Ok(processed_all)
    }

    /// `DataTypesSarifMgr.processTypedObject`.
    fn process_typed_object(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let category_path = Self::category_path(text(result, "typeLocation").as_deref());
        let kind = text(result, "kind").unwrap_or_default();
        let size = number(result, "size").unwrap_or(0.0) as i32;

        let Some(base) = object(result, "type") else {
            return Ok(false);
        };
        let Some(base_type) = self.find_data_type_in(base, &category_path) else {
            return Ok(false);
        };
        if kind != "pointer" {
            return Err(format!("Unexpected baseType kind={kind}"));
        }
        let pointer = PointerDataType::with_size(base_type, size);
        let path = Self::path_of(&pointer);
        self.add_data_type(&path, pointer);
        Ok(true)
    }

    /// `DataTypesSarifMgr.processBuiltin`.
    fn process_builtin(&mut self, result: &HashMap<String, Value>) -> Result<bool, String> {
        let name = text(result, "name").unwrap_or_default();
        let category_path = Self::get_category_path(result);
        let Some(data_type) = self.find_data_type_in(result, &category_path) else {
            return Ok(false);
        };
        let path = Self::get_path(&category_path, &name);
        self.add_shared_data_type(&path, data_type);
        Ok(true)
    }

    /// `DataTypesSarifMgr.getRegularComment`.
    fn get_regular_comment(result: &dyn JsonFields) -> Option<String> {
        text(result, "comment")
    }

    /// `DataTypesSarifMgr.processFunctionMembers`.
    fn process_function_members(
        &mut self,
        param: &Map<String, Value>,
        function: &mut FunctionDefinitionDataType,
    ) -> bool {
        let Some(data_type) = self.find_data_type(param) else {
            return false;
        };
        let ordinal = number(param, "ordinal").unwrap_or(0.0) as i32;
        let name = text(param, "name");
        let comment = text(param, "comment");
        // Java computes a `size` here (the data type's length, falling back to the SARIF `size`)
        // and never uses it.
        function.replace_argument(ordinal, name, data_type, comment, SourceType::UserDefined);
        true
    }

    /// `DataTypesSarifMgr.processEnumMembers`.
    fn process_enum_members(name: &str, value: &Value, enumeration: &mut EnumDataType) {
        let entry_value = value.as_f64().unwrap_or(0.0) as i64;
        enumeration.add(name, entry_value);
    }

    /// `DataTypesSarifMgr.processStructMembers`.
    fn process_struct_members(
        &mut self,
        member_name: &str,
        field: &Value,
        structure: &mut StructureDataType,
    ) -> bool {
        let Some(field) = field.as_object() else {
            return true;
        };
        let offset = number(field, "offset").unwrap_or(0.0) as i32;
        let Some(field_type) = object(field, "type") else {
            return true;
        };

        let Some(member_dt) = self.find_data_type(field_type) else {
            return text(field_type, "kind").as_deref() == Some("pointer");
        };

        Self::process_settings(field_type, member_dt.get_default_settings().as_mut());
        match member_dt.as_dynamic() {
            Some(dynamic) if !dynamic.can_specify_length() => return false,
            None if member_dt.get_length() <= 0 => return false,
            _ => {}
        }

        let mut name = Some(member_name.to_string());
        if flag(field, "hasNoFieldName") == Some(true) {
            name = None;
        }
        let comment = text(field, "comment");
        let comp_size = number(field, "length").unwrap_or(0.0) as i32;

        // NOTE: Size consistency checking was removed since some types are filled-out lazily and
        // may not have their ultimate size at this point.

        if let Some(bit_offset) = number(field, "bitOffset") {
            let bit_size = number(field, "bitSize").unwrap_or(0.0) as i32;
            // NB: we're using "insert" and the team has suggested "add" is a better choice, but,
            // because of the multi-pass approach, an in-order load cannot be guaranteed.
            let component = structure.insert_bit_field_at(
                offset,
                member_dt.get_length(),
                bit_offset as i32,
                member_dt,
                bit_size,
                name,
                comment,
            );
            Self::process_settings(field, component.get_default_settings().as_mut());
            return true;
        }

        let component = if offset == structure.get_length() {
            structure.add(member_dt, comp_size, name, comment)
        } else {
            structure.replace_at_offset(offset, member_dt, comp_size, name, comment)
        };
        Self::process_settings(field, component.get_default_settings().as_mut());
        true
    }

    /// `DataTypesSarifMgr.processUnionMembers`.
    fn process_union_members(
        &mut self,
        member_name: &str,
        member: &Value,
        union: &mut UnionDataType,
    ) -> bool {
        let Some(member) = member.as_object() else {
            return true;
        };
        let mut name = Some(member_name.to_string());
        if flag(member, "hasNoFieldName") == Some(true) {
            name = None;
        }

        let Some(member_type) = object(member, "type") else {
            return true;
        };
        let Some(member_dt) = self.find_data_type(member_type) else {
            return true;
        };

        Self::process_settings(member_type, member_dt.get_default_settings().as_mut());
        let comment = text(member, "comment");
        let dt_size = member_dt.get_length();
        if let Some(bit_size) = number(member, "bitSize") {
            union.add_bit_field(member_dt, bit_size as i32, name, comment);
            return true;
        }
        let component = union.add(member_dt, dt_size, name, comment);
        Self::process_settings(member, component.get_default_settings().as_mut());
        true
    }

    /// `DataTypesSarifMgr.getCategoryPath`.
    fn get_category_path(result: &dyn JsonFields) -> CategoryPath {
        Self::category_path(text(result, "location").as_deref())
    }

    /// `namespace == null ? CategoryPath.ROOT : new CategoryPath(namespace)`.
    fn category_path(path: Option<&str>) -> CategoryPath {
        match path {
            Some(path) => CategoryPath::parse(path).unwrap_or_else(|_| ROOT.clone()),
            None => ROOT.clone(),
        }
    }

    /// `DataTypesSarifMgr.processSettings`.
    fn process_settings(result: &dyn JsonFields, default_settings: &mut dyn Settings) {
        let Some(settings) = result.field("settings").and_then(Value::as_array) else {
            return;
        };
        for setting in settings {
            let Some(setting) = setting.as_object() else {
                continue;
            };
            let setting_name = text(setting, "name").unwrap_or_default();
            let setting_value = text(setting, "value").unwrap_or_default();
            if text(setting, "kind").as_deref() == Some("long") {
                let value = match setting_value.parse::<i64>() {
                    Ok(value) => value,
                    Err(error) => {
                        Msg::error(
                            "DataTypesSarifMgr",
                            &format!("For input string: \"{setting_value}\" ({error})"),
                        );
                        0
                    }
                };
                if setting_name != "ptr_type" {
                    default_settings.set_long(&setting_name, value);
                }
            } else {
                default_settings.set_string(&setting_name, &setting_value);
            }
        }
    }

    /// `DataTypesSarifMgr.findDataType(Map)`: derives the category path from the type itself (or
    /// its subtype) before deferring to [`find_data_type_in`](Self::find_data_type_in).
    fn find_data_type(&mut self, data_type: &dyn JsonFields) -> Option<Arc<dyn DataType>> {
        let mut location = text(data_type, "location");
        if location.is_none() {
            if let Some(subtype) = object(data_type, "subtype") {
                location = text(subtype, "location");
            }
        }
        let category_path = Self::category_path(location.as_deref());
        self.find_data_type_in(data_type, &category_path)
    }

    /// `DataTypesSarifMgr.findDataType(Map, CategoryPath)`.
    fn find_data_type_in(
        &mut self,
        data_type: &dyn JsonFields,
        category_path: &CategoryPath,
    ) -> Option<Arc<dyn DataType>> {
        let kind = text(data_type, "kind")?;
        let mut category_path = category_path.clone();
        let mut name = text(data_type, "name");

        if kind == "pointer" || kind == "array" {
            let by_name = self.find_existing_data_type(
                &category_path,
                &kind,
                name.as_deref().unwrap_or_default(),
            );
            if let Some(by_name) = by_name {
                if by_name.is_function_definition_type() {
                    return Some(Arc::new(PointerDataType::new(by_name)));
                }
                return Some(by_name);
            }
            if let Some(subtype) = object(data_type, "subtype") {
                let base = self.find_data_type_in(subtype, &category_path)?;
                if kind == "pointer" {
                    return Some(Arc::new(PointerDataType::new(base)));
                }
                let count = number(data_type, "count").unwrap_or(0.0) as i32;
                let element_length = base.get_length();
                return Some(Arc::new(ArrayDataType::new(base, count, element_length)));
            }
        }

        let mut name = name.take()?;

        if kind == "typedef" || kind == "bitfield" {
            if let Some(type_name) = text(data_type, "typeName") {
                category_path = Self::category_path(text(data_type, "typeLocation").as_deref());
                name = type_name;
            } else if let Some(subtype) = object(data_type, "type") {
                return self.find_data_type(subtype);
            }
        }

        self.find_existing_data_type(&category_path, &kind, &name)
    }

    /// `DataTypesSarifMgr.findExistingDataType`.
    fn find_existing_data_type(
        &mut self,
        category_path: &CategoryPath,
        kind: &str,
        name: &str,
    ) -> Option<Arc<dyn DataType>> {
        let parsed = self
            .dt_parser
            .as_ref()
            .and_then(|parser| parser.parse_data_type(name, category_path, -1));
        let parsed = match parsed {
            Some(parsed) => Some(parsed),
            None if self.add_foreign_typedef_if_needed(name) => self
                .dt_parser
                .as_ref()
                .and_then(|parser| parser.parse_data_type(name, category_path, -1)),
            None => None,
        };
        if parsed.is_some() {
            return parsed;
        }

        let by_path = self.data_types.get(&Self::get_path(category_path, name));
        if let Some(by_path) = by_path {
            return Some(by_path.clone());
        }
        if kind == "typedef" {
            let function_key = format!("{}/functions/{name}", category_path.get_path());
            if let Some(by_function_path) = self.data_types.get(&function_key) {
                return Some(by_function_path.clone());
            }
        }
        self.data_types.get(&format!("/{name}")).cloned()
    }

    /// `DataTypesSarifMgr.addForeignTypedefIfNeeded`: teaches the data type manager about a
    /// SARIF-only alias (`ascii`, `3byte`, ...) the first time one is referenced.
    fn add_foreign_typedef_if_needed(&mut self, dt_name: &str) -> bool {
        let ptr_index = dt_name.find('*').map_or(-1, |i| i as isize);
        let mut index = dt_name.find('[').map_or(-1, |i| i as isize);
        let mut base_name = dt_name.trim().to_string();
        if index < 0 || index > ptr_index {
            index = ptr_index;
        }
        if index > 0 {
            base_name = dt_name[..index as usize].trim().to_string();
        }

        let Some(our_type) = FOREIGN_TYPEDEFS.get(base_name.as_str()) else {
            return false;
        };
        if self.data_manager.get_data_type(&format!("/{base_name}")).is_some() {
            return false;
        }
        let new_typedef = TypedefDataType::new(ROOT.clone(), &base_name, our_type.clone());
        // Java passes a `null` conflict handler, which `DataTypeManager.resolve` reads as its
        // default policy.
        self.data_manager.resolve(Box::new(new_typedef), &DEFAULT_HANDLER);
        true
    }

    /// `DataTypesSarifMgr.getPath(DataType)`.
    ///
    /// Note that Ghidra's `DataType.getPathName()` already includes the category path, so -- as
    /// in Java -- the category prefix appears twice in the key this produces. That is why the key
    /// differs from [`get_path`](Self::get_path)'s for the same type.
    fn path_of(data_type: &dyn DataType) -> String {
        Self::join(data_type.get_category_path().get_path(), &data_type.get_path_name())
    }

    /// `DataTypesSarifMgr.getPath(CategoryPath, String)`.
    fn get_path(category_path: &CategoryPath, display_name: &str) -> String {
        Self::join(category_path.get_path(), display_name)
    }

    fn join(mut path: String, display_name: &str) -> String {
        if path != "/" {
            path.push('/');
        }
        path.push_str(display_name);
        path
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `DataTypesSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing DATA TYPES ...");

        let mut data_type_list = Vec::new();
        self.data_manager.get_all_data_types_into(&mut data_type_list);

        Self::write_as_sarif(&self.program, data_type_list, results, monitor);
        Ok(())
    }

    /// `DataTypesSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(
        program: &Arc<dyn Program>,
        data_type_list: Vec<Box<dyn DataType>>,
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        // Java hands the writer `program.getDataTypeManager()`; the placeholder writer does not
        // consult it yet.
        let _ = program;
        let writer = SarifDataTypeWriter::new(data_type_list);
        let task = SarifWriterTask::new("DataTypes", writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::sarif::seam_stubs::SettingValue;
    use crate::util::task::DummyMonitor;
    use serde_json::json;

    struct MockProgram;

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    fn mgr() -> DataTypesSarifMgr {
        DataTypesSarifMgr::new(Arc::new(MockProgram), MessageLog::new())
    }

    fn result(value: Value) -> HashMap<String, Value> {
        value
            .as_object()
            .expect("test results are JSON objects")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    #[test]
    fn key_matches_java() {
        assert_eq!(DataTypesSarifMgr::KEY, "DATATYPE");
        assert_eq!(mgr().get_key(), "DATATYPE");
    }

    #[test]
    fn get_path_joins_category_and_name_the_way_java_does() {
        // Java: path = cp.getPath(); if (!path.equals("/")) path += "/"; return path + name;
        assert_eq!(
            DataTypesSarifMgr::get_path(&ROOT, "Foo"),
            "/Foo",
            "ROOT already ends in the delimiter, so Java does not add a second one"
        );
        let demo = CategoryPath::parse("/demo").unwrap();
        assert_eq!(DataTypesSarifMgr::get_path(&demo, "Foo"), "/demo/Foo");
        let nested = CategoryPath::parse("/demo/inner").unwrap();
        assert_eq!(DataTypesSarifMgr::get_path(&nested, "Foo"), "/demo/inner/Foo");
    }

    #[test]
    fn path_of_data_type_repeats_the_category_like_java() {
        // Java's getPath(DataType) concatenates the category path with getPathName(), which
        // already contains it -- so "/demo" + "/" + "/demo/Foo".
        let structure = StructureDataType::new(CategoryPath::parse("/demo").unwrap(), "Foo", 4);
        assert_eq!(structure.get_path_name(), "/demo/Foo");
        assert_eq!(DataTypesSarifMgr::path_of(&structure), "/demo//demo/Foo");

        let at_root = StructureDataType::new(ROOT.clone(), "Bar", 4);
        assert_eq!(DataTypesSarifMgr::path_of(&at_root), "//Bar");
    }

    #[test]
    fn get_category_path_defaults_to_root() {
        assert!(DataTypesSarifMgr::get_category_path(&result(json!({}))).is_root());
        assert_eq!(
            DataTypesSarifMgr::get_category_path(&result(json!({ "location": "/demo" }))).get_path(),
            "/demo"
        );
    }

    #[test]
    fn process_settings_skips_ptr_type_and_defaults_bad_longs_to_zero() {
        let mut settings = crate::sarif::seam_stubs::SharedSettings::new();
        DataTypesSarifMgr::process_settings(
            &result(json!({
                "settings": [
                    { "name": "endian", "value": "big", "kind": "string" },
                    { "name": "mutability", "value": "2", "kind": "long" },
                    { "name": "ptr_type", "value": "1", "kind": "long" },
                    { "name": "broken", "value": "not-a-number", "kind": "long" },
                ]
            })),
            &mut settings,
        );

        let entries = settings.entries();
        assert_eq!(entries.get("endian"), Some(&SettingValue::String("big".into())));
        assert_eq!(entries.get("mutability"), Some(&SettingValue::Long(2)));
        assert_eq!(entries.get("broken"), Some(&SettingValue::Long(0)));
        assert_eq!(entries.get("ptr_type"), None, "Java never writes ptr_type");
    }

    #[test]
    fn unrecognized_message_tag_is_logged_and_counts_as_processed() {
        let mut mgr = mgr();
        assert!(mgr.read(&result(json!({ "Message": "DT.Nope" })), None, &DummyMonitor));
        assert_eq!(mgr.log.messages(), vec!["Unrecognized datatype tag: DT.Nope"]);
    }

    #[test]
    fn process_structure_records_members_packing_and_description() {
        let mut mgr = mgr();
        // A struct whose one member is a pointer with no resolvable subtype: Java treats an
        // unresolved *pointer* member as processed, so the struct still lands in `dataTypes`.
        let processed = mgr.read(
            &result(json!({
                "Message": "DT.Struct",
                "name": "Point",
                "location": "/demo",
                "size": 8.0,
                "comment": "a point",
                "explicitMinimumAlignment": 4.0,
                "packed": "true",
                "explicitPackingValue": 2.0,
                "fields": {
                    "x": { "offset": 0.0, "length": 4.0, "type": { "kind": "pointer" } },
                }
            })),
            None,
            &DummyMonitor,
        );
        assert!(processed);

        let key = "/demo//demo/Point";
        assert_eq!(mgr.is_packed.get(key), Some(&true));
        assert_eq!(mgr.packing_value.get(key), Some(&2));
        let stored = mgr.data_types.get(key).expect("struct registered under its path");
        assert_eq!(stored.get_name(), "Point");
        assert_eq!(stored.get_length(), 8);
        assert_eq!(stored.get_description(), "a point");
        assert_eq!(stored.get_category_path().get_path(), "/demo");
    }

    #[test]
    fn process_enum_records_constants_and_description() {
        let mut mgr = mgr();
        assert!(mgr.read(
            &result(json!({
                "Message": "DT.Enum",
                "name": "Color",
                "location": "/demo",
                "size": 4.0,
                "comment": "colors",
                "constants": { "RED": 0.0, "GREEN": 1.0, "BLUE": 2.0 }
            })),
            None,
            &DummyMonitor,
        ));
        assert!(mgr.log.messages().is_empty());

        let stored = mgr
            .data_types
            .get("/demo//demo/Color")
            .expect("enum registered under its path");
        assert_eq!(stored.get_name(), "Color");
        assert_eq!(stored.get_length(), 4);
        assert_eq!(stored.get_description(), "colors");
    }

    #[test]
    fn find_data_type_resolves_a_previously_read_type_by_name() {
        let mut mgr = mgr();
        // A ROOT-level enum is registered under "//Color" by getPath(DataType), but
        // findExistingDataType's last resort looks it up as "/Color".
        mgr.read(
            &result(json!({
                "Message": "DT.Enum",
                "name": "Color",
                "size": 4.0,
                "constants": { "RED": 0.0 }
            })),
            None,
            &DummyMonitor,
        );
        mgr.dt_parser = Some(DtParser::new());

        let found = mgr.find_data_type(&result(json!({ "kind": "enum", "name": "Color" })));
        assert!(found.is_none(), "getPath(DataType) keys it as //Color, not /Color");

        // The same enum registered through the CategoryPath-keyed path *is* findable.
        let color: Arc<dyn DataType> = Arc::new(EnumDataType::new(ROOT.clone(), "Color", 4));
        mgr.add_shared_data_type("/Color", color);
        let found = mgr
            .find_data_type(&result(json!({ "kind": "enum", "name": "Color" })))
            .expect("resolved from dataTypes");
        assert_eq!(found.get_name(), "Color");
        assert_eq!(found.get_length(), 4);
    }

    #[test]
    fn find_data_type_wraps_a_missing_pointer_subtype_result() {
        let mut mgr = mgr();
        mgr.dt_parser = Some(DtParser::new());
        let base: Arc<dyn DataType> = Arc::new(EnumDataType::new(ROOT.clone(), "Color", 4));
        mgr.add_shared_data_type("/Color", base);

        let pointer = mgr
            .find_data_type(&result(json!({
                "kind": "pointer",
                "subtype": { "kind": "enum", "name": "Color" }
            })))
            .expect("pointer built from its subtype");
        assert_eq!(pointer.get_name(), "Color *");
        assert!(pointer.is_pointer());

        let array = mgr
            .find_data_type(&result(json!({
                "kind": "array",
                "count": 3.0,
                "subtype": { "kind": "enum", "name": "Color" }
            })))
            .expect("array built from its subtype");
        assert_eq!(array.get_name(), "Color[3]");
        assert_eq!(array.get_length(), 12);
    }

    #[test]
    fn foreign_typedef_base_name_strips_pointer_and_array_suffixes() {
        let mut mgr = mgr();
        assert!(mgr.add_foreign_typedef_if_needed("ascii"));
        assert!(mgr.add_foreign_typedef_if_needed("ascii *"));
        assert!(mgr.add_foreign_typedef_if_needed("ascii[16] *"));
        assert!(mgr.add_foreign_typedef_if_needed("3byte"));
        assert!(!mgr.add_foreign_typedef_if_needed("int"));
        assert!(
            !mgr.add_foreign_typedef_if_needed("notatype *"),
            "only the six names in Java's foreignTypedefs map are known"
        );
        // Java resets the '[' index back to the (absent) '*' index whenever the array bracket
        // comes first, so a plain array name is never trimmed down to its base.
        assert!(!mgr.add_foreign_typedef_if_needed("ascii[16]"));
    }

    #[test]
    fn type_def_for_a_missing_target_is_logged_and_retried() {
        let mut mgr = mgr();
        let processed = mgr.read(
            &result(json!({
                "Message": "DT.Typedef",
                "name": "Handle",
                "kind": "typedef",
                "size": 4.0
            })),
            None,
            &DummyMonitor,
        );
        assert!(!processed, "Java returns false so the next pass can retry");
        assert_eq!(mgr.log.messages(), vec!["Handle NOT FOUND"]);
    }

    #[test]
    fn read_results_gives_up_after_max_passes() {
        let mut mgr = mgr();
        let list = vec![result(json!({
            "Message": "DT.Typedef",
            "name": "Handle",
            "kind": "typedef",
            "size": 4.0
        }))];
        assert!(mgr.read_results(Some(&list), None, &DummyMonitor).is_ok());
        // One "NOT FOUND" per pass, and Java stops at MAX_PASSES.
        assert_eq!(mgr.log.messages().len(), DataTypesSarifMgr::MAX_PASSES as usize);
    }

    #[test]
    fn read_results_with_no_list_logs_nothing() {
        let mut mgr = mgr();
        assert!(mgr.read_results(None, None, &DummyMonitor).is_ok());
        assert!(mgr.log.messages().is_empty());
    }

    #[test]
    fn process_typed_object_rejects_a_non_pointer_kind() {
        let mut mgr = mgr();
        let base: Arc<dyn DataType> = Arc::new(EnumDataType::new(ROOT.clone(), "Color", 4));
        mgr.add_shared_data_type("/Color", base);
        assert!(mgr.read(
            &result(json!({
                "Message": "DT.TypedObject",
                "kind": "reference",
                "size": 8.0,
                "typeLocation": "/",
                "type": { "kind": "enum", "name": "Color" }
            })),
            None,
            &DummyMonitor,
        ));
        assert_eq!(
            mgr.log.messages(),
            vec!["Unexpected baseType kind=reference"],
            "Java's RuntimeException is caught by process() and logged"
        );
    }

    #[test]
    fn process_typed_object_builds_a_sized_pointer() {
        let mut mgr = mgr();
        let base: Arc<dyn DataType> = Arc::new(EnumDataType::new(ROOT.clone(), "Color", 4));
        mgr.add_shared_data_type("/Color", base);
        assert!(mgr.read(
            &result(json!({
                "Message": "DT.TypedObject",
                "kind": "pointer",
                "size": 8.0,
                "typeLocation": "/",
                "type": { "kind": "enum", "name": "Color" }
            })),
            None,
            &DummyMonitor,
        ));

        let stored = mgr
            .data_types
            .get("//Color *")
            .expect("pointer registered under getPath(DataType)");
        assert_eq!(stored.get_name(), "Color *");
        assert_eq!(stored.get_length(), 8);
    }

    #[test]
    fn write_with_an_empty_manager_produces_no_results() {
        let mut mgr = mgr();
        let mut results = Vec::new();
        assert!(mgr.write(&mut results, &DummyMonitor).is_ok());
        assert!(results.is_empty());
    }
}
