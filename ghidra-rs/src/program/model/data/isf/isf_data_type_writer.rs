//! Port of `ghidra.program.model.data.ISF.IsfDataTypeWriter`.
//!
//! Exports data types and symbols as ISF JSON, the format Volatility consumes.
//!
//! Two shape decisions differ from the Java original and are worth stating up front, because
//! every method below follows from them:
//!
//! - **ISF objects are [`serde_json::Value`], not `IsfObject`.** Java's writer builds a graph of
//!   `IsfObject` subclasses and hands each to gson, which reflects over the fields. The ported
//!   `IsfObject` is a marker trait, and the ported ISF object types hold `Box<dyn IsfObject>`
//!   children, so a `dyn IsfObject` cannot be serialized -- there is nothing on the trait to
//!   serialize through. The writer therefore produces the JSON tree directly. Where a ported ISF
//!   object *is* serializable it is constructed and serialized as-is ([`IsfEnum`],
//!   [`IsfProducer`], [`IsfWinOS`], [`IsfLinuxOS`], [`IsfDataTypeNull`]); where it is not, or
//!   where the Java class is not ported yet, a `new_*`/`*_json` helper here builds the same field
//!   set and names the Java class it mirrors.
//! - **The program is held directly, not downcast out of the data-type manager.** Java branches on
//!   `dtm instanceof ProgramDataTypeManager` and calls `getProgram()`. `dyn DataTypeManager`
//!   cannot be downcast, so [`IsfDataTypeWriter::with_program`] supplies the program instead:
//!   having one is exactly the condition Java's `instanceof` tests, and metadata and symbol
//!   generation are skipped without it.
//!
//! Field-set fidelity is per Java class: fields inherited from `AbstractIsfObject` carry gson's
//! `@Exclude`, so they never appear in the output and are not emitted here either.

use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{json, Map, Value as JsonValue};

use crate::program::model::address::Address;
use crate::program::model::data::abstract_data_type::default_data_organization;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::{
    DataTypeComponent, DEFAULT_FIELD_NAME_PREFIX,
};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Symbol, SymbolTable};
use crate::program::seam_stubs::{DataTypeUtilities, IsfBaseDataType, IsfUtilities};
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use super::{
    AbstractIsfWriterState, IsfDataTypeNull, IsfEnum, IsfLinuxOS, IsfProducer, IsfWinOS,
    IsfWriterImpl,
};

/// Originator string for this writer's [`Msg`] output, standing in for Java's `this`.
const ORIGINATOR: &str = "IsfDataTypeWriter";

/// `DataOrganizationImpl.pointerSize`'s field initializer, used when no data organization is
/// available; see [`IsfDataTypeWriter::data_organization`].
const DEFAULT_POINTER_SIZE: i32 = 4;

/// `DataOrganizationImpl.bigEndian`'s field initializer, used when no data organization is
/// available; see [`IsfDataTypeWriter::data_organization`].
const DEFAULT_BIG_ENDIAN: bool = false;

/// Writes data types and symbols as ISF JSON.
///
/// Port of `IsfDataTypeWriter`, which extends `AbstractIsfWriter`; here that base is embedded as
/// [`AbstractIsfWriterState`] and reached through [`IsfWriterImpl`].
pub struct IsfDataTypeWriter {
    state: AbstractIsfWriterState,

    /// Java `Map<DataType, IsfObject> resolved`, keyed by path name rather than by data-type
    /// identity: `dyn DataType` is neither `Hash` nor `Eq`. Two data types sharing a path name
    /// are exactly the case Java's `resolvedTypeMap` already reports as a conflict, so collapsing
    /// them here costs nothing that survives to the output.
    resolved: HashMap<String, JsonValue>,
    resolved_type_map: HashMap<String, Box<dyn DataType>>,
    /// Path names of `.conflict` types held back for a second pass; public, as in Java.
    pub deferred_keys: Vec<String>,

    dtm: Option<Box<dyn DataTypeManager>>,
    /// Stands in for Java's `((ProgramDataTypeManager) dtm).getProgram()`; see the module docs.
    program: Option<Box<dyn Program>>,
    /// The data organization to size pointers against. Java falls back to
    /// `DataOrganizationImpl.getDefaultOrganization()` when there is no data-type manager; that
    /// static is not ported, so this stays `None` there and [`DEFAULT_POINTER_SIZE`] /
    /// [`DEFAULT_BIG_ENDIAN`] -- `DataOrganizationImpl`'s own field initializers -- stand in.
    data_organization: Option<Box<dyn DataOrganization>>,

    /// The root ISF document, assembled by [`gen_root`](IsfWriterImpl::gen_root).
    pub data: JsonValue,
    pub metadata: JsonValue,
    pub base_types: JsonValue,
    pub user_types: JsonValue,
    pub enums: JsonValue,
    pub functions: JsonValue,
    pub symbols: JsonValue,

    requested_addresses: Vec<Address>,
    requested_symbols: Vec<String>,
    requested_data_types: Vec<Box<dyn DataType>>,
    skip_symbols: bool,
    skip_types: bool,
}

impl IsfDataTypeWriter {
    /// Constructs a writer over `base_writer`.
    ///
    /// `dtm` is the data-type manager for the target program, or `None` for the default data
    /// organization. `target` is the set of data types to export; `None` (Java's `null`) means
    /// "every type the manager knows", resolved later in `gen_types`. Sets `STRICT`, so the
    /// output is valid for Volatility.
    pub fn new(
        dtm: Option<Box<dyn DataTypeManager>>,
        target: Option<Vec<Box<dyn DataType>>>,
        base_writer: Option<Box<dyn Write>>,
    ) -> Self {
        let data_organization = dtm.as_deref().map(|dtm| default_data_organization(Some(dtm)));
        let mut state = AbstractIsfWriterState::new(base_writer);
        state.strict = true;

        Self {
            state,
            resolved: HashMap::new(),
            resolved_type_map: HashMap::new(),
            deferred_keys: Vec::new(),
            dtm,
            program: None,
            data_organization,
            data: json!({}),
            metadata: json!({}),
            base_types: json!({}),
            user_types: json!({}),
            enums: json!({}),
            functions: json!({}),
            symbols: json!({}),
            requested_addresses: Vec::new(),
            requested_symbols: Vec::new(),
            requested_data_types: target.unwrap_or_default(),
            skip_symbols: false,
            skip_types: false,
        }
    }

    /// Supplies the program the exported types belong to, enabling metadata and symbol output.
    ///
    /// Stands in for Java's `dtm instanceof ProgramDataTypeManager` test: with no program, this
    /// writer emits types only, exactly as Java does for a non-program data-type manager.
    pub fn with_program(mut self, program: Box<dyn Program>) -> Self {
        self.program = Some(program);
        self
    }

    /// Adds `child` to `parent` under `opt_key`, or appends it when `parent` is an array.
    ///
    /// Port of `add(JsonElement, String, JsonElement)`. An associated function rather than a
    /// method because every caller passes one of this writer's own JSON fields as `parent`.
    pub fn add(parent: &mut JsonValue, opt_key: &str, child: JsonValue) {
        // Java writes the two cases as independent `if`s, but a JsonElement is never both.
        if let Some(object) = parent.as_object_mut() {
            object.insert(opt_key.to_string(), child);
        } else if let Some(array) = parent.as_array_mut() {
            array.push(child);
        }
    }

    /// Whether symbol generation is skipped.
    pub fn set_skip_symbols(&mut self, val: bool) {
        self.skip_symbols = val;
    }

    /// Whether type generation is skipped.
    pub fn set_skip_types(&mut self, val: bool) {
        self.skip_types = val;
    }

    /// Records an address whose symbols should be exported, parsed from `key`.
    ///
    /// Port of `requestAddress(String)`. Java distinguishes an unparseable address (an
    /// `AddressFormatException`, rethrown as an `IOException`) from one that parses to `null`
    /// (logged and dropped); [`AddressFactory::get_address`] collapses both into `None`, so both
    /// surface here as the error, which is the more informative of the two.
    ///
    /// [`AddressFactory::get_address`]: crate::program::model::address::factory::AddressFactory::get_address
    pub fn request_address(&mut self, key: &str) -> Result<(), std::io::Error> {
        let address = match self.program.as_ref() {
            None => return Ok(()),
            Some(program) => match program.get_address_factory() {
                None => return Ok(()),
                Some(factory) => factory.get_address(key),
            },
        };
        match address {
            Some(address) => {
                self.requested_addresses.push(address);
                Ok(())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Bad address format: {key}"),
            )),
        }
    }

    /// Records a symbol name to export.
    ///
    /// Port of `requestSymbol(String)`, whose null check is vacuous for a `&str`.
    pub fn request_symbol(&mut self, symbol: &str) {
        self.requested_symbols.push(symbol.to_string());
    }

    /// Port of `genMetadata()`.
    fn gen_metadata(&mut self) {
        let Some(program) = self.program.as_ref() else {
            return;
        };
        let meta_data = program.get_metadata();
        let creation_time =
            UNIX_EPOCH + Duration::from_millis(program.get_creation_date().max(0) as u64);

        let producer = serde_json::to_value(IsfProducer::new(&meta_data, creation_time))
            .unwrap_or(JsonValue::Null);

        let mut oskey = meta_data
            .get("Compiler ID")
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let mut os = json!({});
        if meta_data.contains_key("PDB Loaded") {
            os = serde_json::to_value(IsfWinOS::new(&meta_data)).unwrap_or(json!({}));
        } else if let Some(format) = meta_data.get("Executable Format") {
            if format.contains("ELF") {
                oskey = "linux".to_string();
                os = serde_json::to_value(IsfLinuxOS::new(&meta_data)).unwrap_or(json!({}));
            }
        }

        if let Some(object) = self.metadata.as_object_mut() {
            object.insert("format".to_string(), json!("6.2.0"));
        }
        Self::add(&mut self.metadata, "producer", producer);
        Self::add(&mut self.metadata, &oskey, os);
    }

    /// Port of `genSymbols(TaskMonitor)`.
    fn gen_symbols(&mut self, _monitor: &dyn TaskMonitor) {
        if self.skip_symbols {
            return;
        }
        let requested_addresses = std::mem::take(&mut self.requested_addresses);
        let requested_symbols = std::mem::take(&mut self.requested_symbols);

        let map = {
            let Some(program) = self.program.as_mut() else {
                self.requested_addresses = requested_addresses;
                self.requested_symbols = requested_symbols;
                return;
            };
            let image_base = program.get_image_base();

            // Collected up front: the reference manager and the symbol table are each reached
            // through a `&mut` borrow of the program, so they cannot be held at the same time.
            let xrefs: Vec<(Address, Address)> = match program.get_reference_manager() {
                Some(manager) => manager
                    .get_external_references()
                    .map(|reference| (reference.from_address(), reference.to_address()))
                    .collect(),
                None => Vec::new(),
            };

            let Some(symbol_table) = program.get_symbol_table() else {
                self.requested_addresses = requested_addresses;
                self.requested_symbols = requested_symbols;
                return;
            };

            let mut linkages: HashMap<String, std::sync::Arc<dyn Symbol>> = HashMap::new();
            for (from_address, to_address) in xrefs {
                let from_symbol = symbol_table.get_primary_symbol(&from_address).ok().flatten();
                let to_symbol = symbol_table.get_primary_symbol(&to_address).ok().flatten();
                if let (Some(from_symbol), Some(to_symbol)) = (from_symbol, to_symbol) {
                    linkages.insert(to_symbol.get_name().to_string(), from_symbol);
                }
            }

            let mut map: HashMap<String, JsonValue> = HashMap::new();
            if requested_symbols.is_empty() {
                if requested_addresses.is_empty() {
                    // `getSymbolIterator()` over every symbol; `*` is this port's match-all.
                    let mut iterator = symbol_table.get_symbol_iterator("*", true);
                    while let Some(symbol) = iterator.next_symbol() {
                        symbol_to_json(
                            image_base.as_ref(),
                            symbol_table,
                            &linkages,
                            &mut map,
                            &*symbol,
                        );
                    }
                } else {
                    for addr in &requested_addresses {
                        let offset = image_base.as_ref().map(|base| base.offset()).unwrap_or(0);
                        let Ok(rebased) = addr.add(offset) else {
                            continue;
                        };
                        let Ok(symbols) = symbol_table.get_symbols(&rebased) else {
                            continue;
                        };
                        for symbol in symbols {
                            symbol_to_json(
                                image_base.as_ref(),
                                symbol_table,
                                &linkages,
                                &mut map,
                                &*symbol,
                            );
                        }
                    }
                }
            } else {
                for key in &requested_symbols {
                    let mut iterator = symbol_table.get_symbol_iterator(key, true);
                    while let Some(symbol) = iterator.next_symbol() {
                        symbol_to_json(
                            image_base.as_ref(),
                            symbol_table,
                            &linkages,
                            &mut map,
                            &*symbol,
                        );
                    }
                }
            }
            map
        };

        self.requested_addresses = requested_addresses;
        self.requested_symbols = requested_symbols;

        for (key, value) in &map {
            Self::add(&mut self.symbols, key, value.clone());
        }
        // A second pass republishing every leading-underscore name without it, as in Java.
        for (key, value) in &map {
            if let Some(stripped) = key.strip_prefix('_') {
                Self::add(&mut self.symbols, stripped, value.clone());
            }
        }
    }

    /// Port of `genTypes(TaskMonitor)`.
    fn gen_types(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        if self.skip_types {
            return Ok(());
        }
        if self.requested_data_types.is_empty() {
            if let Some(dtm) = self.dtm.as_ref() {
                let mut all = Vec::new();
                dtm.get_all_data_types_into(&mut all);
                self.requested_data_types = all;
            }
            self.add_singletons();
        }
        monitor.initialize(self.requested_data_types.len() as i64);

        // Moved out so the per-type loop below can take `&mut self`; put back before returning.
        let types = std::mem::take(&mut self.requested_data_types);
        let mut map: HashMap<String, usize> = HashMap::new();
        for (index, data_type) in types.iter().enumerate() {
            map.insert(data_type.get_path_name(), index);
        }

        let mut keylist: Vec<String> = map.keys().cloned().collect();
        keylist.sort();
        let result = self.process_map(&types, &map, &keylist, monitor);

        let result = result.and_then(|()| {
            if self.deferred_keys.is_empty() {
                return Ok(());
            }
            Msg::warn(ORIGINATOR, &"Processing .conflict objects");
            let deferred = self.deferred_keys.clone();
            self.process_map(&types, &map, &deferred, monitor)
        });

        self.requested_data_types = types;
        result
    }

    /// Port of `processMap(Map, List, TaskMonitor)`.
    fn process_map(
        &mut self,
        types: &[Box<dyn DataType>],
        index: &HashMap<String, usize>,
        keylist: &[String],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_maximum(keylist.len() as i64);
        for key in keylist {
            let Some(data_type) = index.get(key).map(|i| &*types[*i]) else {
                continue;
            };
            if DataTypeUtilities::is_conflict_data_type(data_type) {
                continue;
            }
            let Some(object) = self.get_object_for_data_type(data_type, monitor)? else {
                continue;
            };
            let path_name = data_type.get_path_name();
            if data_type.is_function_definition_type() {
                // Volatility does not consume these; kept out of the root document below.
                Self::add(&mut self.functions, &path_name, object);
            } else if IsfUtilities::is_base_data_type(data_type) {
                Self::add(&mut self.base_types, &path_name, object);
            } else if let Some(typedef) = data_type.as_typedef() {
                let base_data_type = typedef.get_base_data_type();
                if IsfUtilities::is_base_data_type(&*base_data_type) {
                    Self::add(&mut self.base_types, &path_name, object);
                } else if base_data_type.as_enum().is_some() {
                    Self::add(&mut self.enums, &path_name, object);
                } else {
                    Self::add(&mut self.user_types, &path_name, object);
                }
            } else if data_type.as_enum().is_some() {
                Self::add(&mut self.enums, &path_name, object);
            } else if data_type.as_composite().is_some() {
                Self::add(&mut self.user_types, &path_name, object);
            }
            monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Port of `addSingletons()`.
    fn add_singletons(&mut self) {
        let pointer = self.new_typedef_pointer(None);
        Self::add(&mut self.base_types, "pointer", pointer);
        let undefined = self.new_typedef_pointer(None);
        Self::add(&mut self.base_types, "undefined", undefined);
    }

    /// Port of `getObjectForDataType(DataType, TaskMonitor)`.
    pub fn get_object_for_data_type(
        &mut self,
        dt: &dyn DataType,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<JsonValue>, CancelledException> {
        match self.get_isf_object(dt, monitor)? {
            Some(object) => {
                self.resolved.insert(dt.get_path_name(), object.clone());
                Ok(Some(object))
            }
            None => Ok(None),
        }
    }

    /// Renders `dt` as ISF JSON.
    ///
    /// Port of `getIsfObject(DataType, TaskMonitor)`. Top-level bit-fields and function
    /// definitions are unsupported by ISF and fall through to `None`.
    pub fn get_isf_object(
        &mut self,
        dt: &dyn DataType,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<JsonValue>, CancelledException> {
        if dt.is_factory_type() {
            Msg::error(
                ORIGINATOR,
                &format!("Factory data types may not be written - type: {}", dt.get_path_name()),
            );
        }
        if dt.is_bit_field_type() {
            Msg::error(
                ORIGINATOR,
                &format!("BitField data types may not be written - type: {}", dt.get_path_name()),
            );
        }
        if dt.is_pointer() || dt.is_array() {
            let type_object = self.get_base_object_data_type(dt);
            return Ok(Some(Self::new_typed_object(dt, type_object)));
        }

        // Force resize/repack for the target data organization.
        let cloned = self.dtm.as_ref().map(|dtm| dt.clone_data_type(&**dtm));
        let dt: &dyn DataType = cloned.as_deref().unwrap_or(dt);

        if let Some(resolved) = self.resolve(dt) {
            return Ok(Some(resolved));
        }

        if let Some(dynamic) = dt.as_dynamic() {
            let replacement = dynamic.get_replacement_base_type();
            return self.get_isf_object(&*replacement, monitor);
        }
        if let Some(typedef) = dt.as_typedef() {
            return Ok(self.get_object_type_def(typedef, monitor));
        }
        if dt.as_composite().is_some() {
            return Ok(Some(self.new_isf_composite(dt, monitor)));
        }
        if let Some(enumm) = dt.as_enum() {
            return Ok(Some(
                serde_json::to_value(IsfEnum::new(enumm)).unwrap_or(JsonValue::Null),
            ));
        }
        if IsfUtilities::is_built_in_data_type(dt) {
            return Ok(Some(Self::new_isf_built_in(dt)));
        }
        if dt.is_default_data_type() {
            return Ok(None);
        }
        Msg::warn(
            ORIGINATOR,
            &format!("Unable to write datatype. Type unrecognized: {}", dt.get_path_name()),
        );
        Ok(None)
    }

    /// Port of `resolve(DataType)`.
    ///
    /// Returns the ISF JSON already generated for `dt`'s path name, if any, and otherwise claims
    /// that path name for `dt` and returns `None` -- the signal to generate it.
    pub fn resolve(&mut self, dt: &dyn DataType) -> Option<JsonValue> {
        let path_name = dt.get_path_name();
        if let Some(object) = self.resolved.get(&path_name) {
            return Some(object.clone());
        }

        if let Some(resolved_type) = self.resolved_type_map.get(&path_name) {
            // Skip an equivalent type sharing a resolved type's name.
            if resolved_type.is_equivalent(dt) {
                return self.resolved.get(&path_name).cloned();
            }
            if let Some(typedef) = dt.as_typedef() {
                if resolved_type.as_composite().is_some() || resolved_type.as_enum().is_some() {
                    // An auto-typedef already generated for the composite or enum.
                    if typedef.get_base_data_type().is_equivalent(&**resolved_type) {
                        return self.resolved.get(&path_name).cloned();
                    }
                }
            }
            Msg::warn(
                ORIGINATOR,
                &format!(
                    "WARNING! conflicting data type names: {} - {}",
                    path_name,
                    resolved_type.get_path_name()
                ),
            );
            return self.resolved.get(&path_name).cloned();
        }

        // Claiming the name needs an owned copy, which only the data-type manager can make; with
        // no manager the claim is skipped and every type is generated on its own terms.
        let owned = self.dtm.as_ref().map(|dtm| dt.clone_data_type(&**dtm));
        if let Some(owned) = owned {
            self.resolved_type_map.insert(path_name, owned);
        }
        None
    }

    /// Port of `clearResolve(String, DataType)`.
    fn clear_resolve(&mut self, typedef_name: &str, base_type: &dyn DataType) {
        if base_type.as_composite().is_some() || base_type.as_enum().is_some() {
            // An auto-typedef is generated alongside every composite and enum.
            if typedef_name == base_type.get_path_name() {
                self.resolved_type_map.remove(typedef_name);
            }
            return;
        }
        // Inherited from DataTypeWriter (logic lost to time): a comment explaining the special
        // 'P' case would be helpful!! Smells like fish.
        let Some(pointer) = base_type.as_pointer() else {
            return;
        };
        let Some(stripped) = typedef_name.strip_prefix('P') else {
            return;
        };
        let Some(mut dt) = pointer.get_data_type() else {
            return;
        };
        if let Some(base) = dt.as_typedef().map(|typedef| typedef.get_base_data_type()) {
            dt = base;
        }
        if dt.as_composite().is_some() && dt.get_path_name() == stripped {
            // An auto-pointer-typedef is generated alongside every composite.
            self.resolved_type_map.remove(typedef_name);
        }
    }

    /// Port of `getObjectTypeDeclaration(DataTypeComponent)`.
    ///
    /// `None` is Java's `null` return: the component contributes no `type` to its ISF field.
    pub fn get_object_type_declaration(
        &mut self,
        component: &dyn DataTypeComponent,
    ) -> Option<JsonValue> {
        let data_type = component.get_data_type();
        if let Some(dynamic) = data_type.as_dynamic() {
            if !dynamic.can_specify_length() {
                return None;
            }
            let replacement = dynamic.get_replacement_base_type();
            let cloned = self
                .dtm
                .as_ref()
                .map(|dtm| replacement.clone_data_type(&**dtm));
            let replacement = cloned.unwrap_or(replacement);

            let type_object = self.get_object_data_type(Some(&*replacement), -1);
            let element_len = replacement.get_length();
            if element_len > 0 {
                let element_cnt = (component.get_length() + element_len - 1) / element_len;
                return Some(Self::new_isf_dynamic_component(type_object, element_cnt));
            }
            Msg::error(
                ORIGINATOR,
                &format!(
                    "{} returned bad replacementBaseType: {}",
                    data_type.get_name(),
                    replacement.get_name()
                ),
            );
            return None;
        }

        let is_function_pointer = match IsfUtilities::get_base_data_type(&*data_type) {
            IsfBaseDataType::Same(base) => base.is_function_definition_type(),
            IsfBaseDataType::Unwrapped(base) => base
                .as_deref()
                .is_some_and(|base| base.is_function_definition_type()),
        };
        if is_function_pointer {
            return Some(Self::new_isf_function_pointer());
        }
        Some(self.get_object_data_type(Some(&*data_type), component.get_offset()))
    }

    /// Port of `getObjectDataType(DataType)`, i.e. with no component offset.
    pub fn get_object_data_type_of(&mut self, data_type: Option<&dyn DataType>) -> JsonValue {
        self.get_object_data_type(data_type, -1)
    }

    /// Port of `getObjectDataType(DataType, int)`.
    pub fn get_object_data_type(
        &mut self,
        data_type: Option<&dyn DataType>,
        component_offset: i32,
    ) -> JsonValue {
        let Some(dt) = data_type else {
            return isf_data_type_null_json();
        };

        // Java compares `dataType` against its base type; a type that unwraps to something is by
        // construction not equal to it, and one that does not unwrap is.
        if let IsfBaseDataType::Unwrapped(base) = IsfUtilities::get_base_data_type(dt) {
            if let Some(array) = dt.as_array() {
                let element = array.get_data_type();
                let count = array.get_num_elements();
                let type_object = self.get_object_data_type(Some(&*element), -1);
                return Self::new_isf_data_type_array(dt, count, type_object);
            }
            if let Some(bit_field) = dt.as_bit_field() {
                let bit_length = bit_field.get_bit_size();
                let bit_offset = bit_field.get_bit_offset();
                let base_type = bit_field.get_base_data_type();
                let type_object = self.get_object_data_type(Some(&*base_type), -1);
                return Self::new_isf_data_type_bit_field(
                    dt,
                    bit_length,
                    bit_offset,
                    component_offset,
                    type_object,
                );
            }
            let base_object = self.get_object_data_type(base.as_deref(), -1);
            return Self::new_isf_data_type_typedef(dt, base_object);
        }

        if DataTypeUtilities::is_conflict_data_type(dt) {
            let path_name = dt.get_path_name();
            if !self.deferred_keys.contains(&path_name) {
                self.deferred_keys.push(path_name);
            }
        }
        Self::new_isf_data_type_default(dt)
    }

    /// Port of `getObjectTypeDef(TypeDef, TaskMonitor)`.
    ///
    /// Typedef format: `typedef <TYPE_DEF_NAME> <BASE_TYPE_NAME>`.
    fn get_object_type_def(
        &mut self,
        type_def: &dyn TypeDef,
        monitor: &dyn TaskMonitor,
    ) -> Option<JsonValue> {
        let data_type = TypeDef::get_data_type(type_def);
        let typedef_name = type_def.get_path_name();
        let base_type = TypeDef::get_data_type(type_def);

        if IsfUtilities::is_built_in_data_type(&*base_type) {
            return Some(self.new_typedef_base(type_def, &*base_type));
        }
        if !base_type.is_pointer() {
            // Java catches every exception here, logs it and falls through to `clearResolve`.
            match self.get_isf_object(&*data_type, monitor) {
                Ok(object) => return object.map(Self::new_typedef_user),
                Err(e) => Msg::error(ORIGINATOR, &format!("TypeDef error: {e:?}")),
            }
        } else {
            return Some(self.new_typedef_pointer(Some(type_def)));
        }

        self.clear_resolve(&typedef_name, &*base_type);
        None
    }

    /// The ISF object for `dt`'s base type, as `getIsfObject` builds for pointers and arrays.
    fn get_base_object_data_type(&mut self, dt: &dyn DataType) -> JsonValue {
        match IsfUtilities::get_base_data_type(dt) {
            IsfBaseDataType::Same(base) => self.get_object_data_type(Some(base), -1),
            IsfBaseDataType::Unwrapped(base) => self.get_object_data_type(base.as_deref(), -1),
        }
    }

    /// Port of `newTypedefBase(TypeDef)`, mirroring `IsfTypedefBase`'s fields.
    pub fn new_typedef_base(&self, type_def: &dyn TypeDef, base_type: &dyn DataType) -> JsonValue {
        json!({
            "size": type_def.get_length(),
            "kind": IsfUtilities::get_built_in_kind(base_type),
            "endian": IsfUtilities::get_endianness(type_def),
        })
    }

    /// Port of `newTypedefPointer(TypeDef)`, mirroring `IsfTypedefPointer`'s fields.
    ///
    /// `None` is Java's `null` argument, which stands up a bare `PointerDataType`; that class is
    /// not ported, so the writer's data organization supplies the pointer's size and endianness.
    pub fn new_typedef_pointer(&self, type_def: Option<&dyn TypeDef>) -> JsonValue {
        let (size, endian) = match type_def {
            Some(type_def) => {
                let pointer = type_def.get_base_data_type();
                let size = if pointer.has_language_dependant_length() {
                    -1
                } else {
                    pointer.get_length()
                };
                (size, IsfUtilities::get_endianness(&*pointer))
            }
            None => {
                let (size, big_endian) = match self.data_organization.as_deref() {
                    Some(org) => (org.get_pointer_size(), org.is_big_endian()),
                    None => (DEFAULT_POINTER_SIZE, DEFAULT_BIG_ENDIAN),
                };
                (size, if big_endian { "big" } else { "little" }.to_string())
            }
        };
        json!({
            "size": size,
            "kind": "typedef",
            "endian": endian,
            // `IsfPointer`: same size and endianness as the pointer it was built from.
            "type": { "size": size, "kind": "pointer", "endian": endian },
        })
    }

    /// Port of `newTypedefUser(TypeDef, IsfObject)`, which discards the typedef and returns the
    /// object unchanged.
    pub fn new_typedef_user(object: JsonValue) -> JsonValue {
        object
    }

    /// Port of `newTypedObject(DataType, IsfObject)`, mirroring `IsfTypedObject`'s fields.
    pub fn new_typed_object(dt: &dyn DataType, type_object: JsonValue) -> JsonValue {
        json!({
            "kind": IsfUtilities::get_kind(dt),
            "size": if dt.has_language_dependant_length() { -1 } else { dt.get_length() },
            "type": type_object,
        })
    }

    /// Port of `newIsfDynamicComponent(Dynamic, IsfObject, int)`, mirroring
    /// [`IsfDynamicComponent`](super::IsfDynamicComponent)'s fields. That type holds its subtype
    /// as `Box<dyn IsfObject>`, which cannot be serialized, so the JSON is built directly.
    pub fn new_isf_dynamic_component(type_object: JsonValue, element_cnt: i32) -> JsonValue {
        json!({ "kind": "array", "count": element_cnt, "subtype": type_object })
    }

    /// Mirrors `IsfBuiltIn`'s fields.
    fn new_isf_built_in(dt: &dyn DataType) -> JsonValue {
        json!({
            "size": IsfUtilities::get_length(dt),
            "kind": IsfUtilities::get_built_in_kind(dt),
            "endian": IsfUtilities::get_endianness(dt),
        })
    }

    /// Mirrors `IsfDataTypeDefault`'s fields.
    fn new_isf_data_type_default(dt: &dyn DataType) -> JsonValue {
        json!({ "kind": IsfUtilities::get_kind(dt), "size": dt.get_length() })
    }

    /// Mirrors `IsfDataTypeArray`'s fields.
    fn new_isf_data_type_array(dt: &dyn DataType, count: i32, subtype: JsonValue) -> JsonValue {
        json!({ "kind": IsfUtilities::get_kind(dt), "count": count, "subtype": subtype })
    }

    /// Mirrors `IsfDataTypeBitField`'s fields; its `bit_offset` and `storage_size` carry
    /// `@Exclude` and so are absorbed into `bit_position` rather than emitted.
    fn new_isf_data_type_bit_field(
        dt: &dyn DataType,
        bit_length: i32,
        bit_offset: i32,
        component_offset: i32,
        type_object: JsonValue,
    ) -> JsonValue {
        json!({
            "kind": IsfUtilities::get_kind(dt),
            "bit_length": bit_length,
            "bit_position": component_offset % 4 * 8 + bit_offset,
            "type": type_object,
        })
    }

    /// Mirrors `IsfDataTypeTypeDef`'s fields.
    fn new_isf_data_type_typedef(dt: &dyn DataType, subtype: JsonValue) -> JsonValue {
        json!({ "kind": IsfUtilities::get_kind(dt), "subtype": subtype })
    }

    /// Mirrors `IsfFunctionPointer`'s fields.
    ///
    /// Java also nests an `IsfFunction` built from the `FunctionDefinition` it downcast the base
    /// type to; [`DataType`] exposes no such downcast yet (only
    /// [`is_function_definition_type`](DataType::is_function_definition_type)), so the `subtype`
    /// is omitted until it does. `subtype` being absent is already how gson renders a null one.
    fn new_isf_function_pointer() -> JsonValue {
        json!({ "kind": "pointer" })
    }

    /// Mirrors `IsfComposite`'s fields, including the per-component `IsfComponent` map.
    fn new_isf_composite(&mut self, dt: &dyn DataType, monitor: &dyn TaskMonitor) -> JsonValue {
        let size = if dt.is_zero_length() { 0 } else { dt.get_length() };
        let kind = if dt.is_structure() { "struct" } else { "union" };
        let components = match dt.as_composite() {
            Some(composite) => composite.get_defined_components(),
            None => Vec::new(),
        };

        let mut fields = Map::new();
        for component in components {
            if monitor.is_cancelled() {
                break;
            }
            let type_object = self.get_object_type_declaration(&*component);
            let key = component.get_field_name().unwrap_or_else(|| {
                let mut key = format!("{}{}", DEFAULT_FIELD_NAME_PREFIX, component.get_ordinal());
                if component.get_parent().is_structure() {
                    key.push_str(&format!("_0x{:x}", component.get_offset()));
                }
                key
            });
            let mut field = json!({ "offset": component.get_offset() });
            if let (Some(object), Some(field)) = (type_object, field.as_object_mut()) {
                field.insert("type".to_string(), object);
            }
            fields.insert(key, field);
        }

        json!({ "kind": kind, "size": size, "fields": JsonValue::Object(fields) })
    }
}

/// Mirrors [`IsfDataTypeNull`]'s fields, reusing the ported type for the values themselves.
fn isf_data_type_null_json() -> JsonValue {
    let void = IsfDataTypeNull::new();
    json!({ "kind": void.kind(), "name": void.name() })
}

/// Port of `symbolToJson(...)`.
///
/// A free function rather than a method: it needs a `&dyn SymbolTable` borrowed out of the
/// writer's program, which rules out taking `&mut self` alongside it, and it touches no other
/// writer state.
fn symbol_to_json(
    image_base: Option<&Address>,
    symbol_table: &dyn SymbolTable,
    linkages: &HashMap<String, std::sync::Arc<dyn Symbol>>,
    map: &mut HashMap<String, JsonValue>,
    symbol: &dyn Symbol,
) {
    let key = symbol.get_name().to_string();
    let address = symbol.get_address();
    let mut sym = map.get(&key).cloned().unwrap_or_else(|| json!({}));

    if let Some(object) = sym.as_object_mut() {
        if address.is_external_address() {
            object.insert("address".to_string(), json!(address.offset()));
            if let Some(linkage) = linkages.get(&key) {
                object.insert("linkage_name".to_string(), json!(linkage.get_name()));
                object.insert("address".to_string(), json!(linkage.get_address().offset()));
            }
        } else {
            match image_base {
                Some(base) if address.same_address_space(base) => {
                    object.insert("address".to_string(), json!(address.subtract(base)));
                }
                _ => {
                    object.insert("address".to_string(), json!(address.offset()));
                }
            }
        }
    }
    map.insert(key.clone(), sym.clone());

    if !symbol.is_primary() {
        let Ok(Some(primary_symbol)) = symbol_table.get_primary_symbol(&address) else {
            return;
        };
        let primary_name = primary_symbol.get_name().to_string();
        if key.contains(&primary_name) {
            if let Some(object) = sym.as_object_mut() {
                object.insert("linkage_name".to_string(), json!(key));
            }
            map.insert(key, sym.clone());
            map.insert(primary_name, sym);
        }
    }
}

impl IsfWriterImpl for IsfDataTypeWriter {
    /// Port of `genRoot(TaskMonitor)`.
    ///
    /// `functions` is assembled but deliberately left out of the document: Volatility does not
    /// consume it.
    fn gen_root(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        self.gen_metadata();
        self.gen_types(monitor)?;
        self.gen_symbols(monitor);

        let metadata = self.metadata.clone();
        Self::add(&mut self.data, "metadata", metadata);
        let base_types = self.base_types.clone();
        Self::add(&mut self.data, "base_types", base_types);
        let user_types = self.user_types.clone();
        Self::add(&mut self.data, "user_types", user_types);
        let enums = self.enums.clone();
        Self::add(&mut self.data, "enums", enums);
        let symbols = self.symbols.clone();
        Self::add(&mut self.data, "symbols", symbols);

        // Java overrides `getRootObject` to return `data`; the ported trait reads `state.root`.
        self.state.root = self.data.clone();
        Ok(())
    }

    fn state_mut(&mut self) -> &mut AbstractIsfWriterState {
        &mut self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::util::task::DummyMonitor;

    /// A minimal built-in integer type, standing in for e.g. `IntegerDataType`.
    struct MockInt {
        name: String,
        length: i32,
    }

    impl MockInt {
        fn new(name: &str, length: i32) -> Self {
            Self { name: name.to_string(), length }
        }
    }

    impl DataType for MockInt {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse("/").unwrap()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_integer_type(&self) -> bool {
            true
        }

        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }

    /// Only the two members `IsfUtilities.getEndianness` and `newTypedefPointer` reach for are
    /// answered; the rest are not exercised by these tests.
    struct MockDataOrganization;

    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn is_signed_char(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_char_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_wide_char_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_short_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_integer_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_long_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_long_long_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_float_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_double_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_long_double_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_machine_alignment(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_alignment(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_bit_field_packing(
            &self,
        ) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            unimplemented!("not exercised by these tests")
        }
        fn get_size_alignment_count(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_sizes(&self) -> Vec<i32> {
            unimplemented!("not exercised by these tests")
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            unimplemented!("not exercised by these tests")
        }
    }

    fn writer() -> IsfDataTypeWriter {
        IsfDataTypeWriter::new(None, None, None)
    }

    #[test]
    fn add_inserts_into_objects_and_appends_to_arrays() {
        let mut object = json!({});
        IsfDataTypeWriter::add(&mut object, "key", json!(1));
        assert_eq!(object, json!({ "key": 1 }));

        let mut array = json!([]);
        // Java's `add` ignores the key for arrays.
        IsfDataTypeWriter::add(&mut array, "ignored", json!(1));
        IsfDataTypeWriter::add(&mut array, "ignored", json!(2));
        assert_eq!(array, json!([1, 2]));
    }

    #[test]
    fn null_data_type_renders_as_isf_void() {
        // Java: `getObjectDataType(null)` -> `new IsfDataTypeNull()`.
        let mut writer = writer();
        assert_eq!(
            writer.get_object_data_type_of(None),
            json!({ "kind": "base", "name": "void" })
        );
    }

    #[test]
    fn plain_data_type_renders_kind_and_size() {
        // Java: `IsfDataTypeDefault` carries `kind` from `IsfUtilities.getKind` -- "base" for a
        // built-in integer -- and `size` from `getLength`.
        let mut writer = writer();
        let dt = MockInt::new("int", 4);
        assert_eq!(
            writer.get_object_data_type_of(Some(&dt)),
            json!({ "kind": "base", "size": 4 })
        );
    }

    #[test]
    fn built_in_isf_object_carries_size_kind_and_endian() {
        // Java: `IsfBuiltIn(builtin)` -> size/kind/endian, with `getBuiltInKind` returning an
        // integer type's own name.
        let mut writer = writer();
        let dt = MockInt::new("long", 8);
        let object = writer.get_isf_object(&dt, &DummyMonitor).unwrap().unwrap();
        assert_eq!(object, json!({ "size": 8, "kind": "long", "endian": "little" }));
    }

    #[test]
    fn add_singletons_registers_pointer_and_undefined_typedefs() {
        let mut writer = writer();
        writer.add_singletons();

        let base_types = writer.base_types.as_object().unwrap();
        assert!(base_types.contains_key("pointer"));
        assert!(base_types.contains_key("undefined"));
        // Java: `IsfTypedefPointer` hardcodes `kind` and nests an `IsfPointer`.
        assert_eq!(base_types["pointer"]["kind"], json!("typedef"));
        assert_eq!(base_types["pointer"]["type"]["kind"], json!("pointer"));
    }

    #[test]
    fn gen_root_emits_the_volatility_sections() {
        let mut writer = writer();
        let root = writer.get_root_object(&DummyMonitor).unwrap();

        // `serde_json::Map` orders its keys, so compare as a set rather than in Java's
        // insertion order.
        let root = root.as_object().unwrap();
        let mut keys = root.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["base_types", "enums", "metadata", "symbols", "user_types"]);
        // Volatility does not consume `functions`, so Java leaves it out of the document.
        assert!(!root.contains_key("functions"));
    }

    #[test]
    fn resolve_claims_a_path_name_then_returns_the_generated_object() {
        // Without a data-type manager there is nothing to clone into `resolvedTypeMap`, so the
        // first call still reports "not yet resolved".
        let mut writer = writer();
        let dt = MockInt::new("int", 4);
        assert!(writer.resolve(&dt).is_none());

        let object = writer
            .get_object_for_data_type(&dt, &DummyMonitor)
            .unwrap()
            .unwrap();
        assert_eq!(writer.resolve(&dt), Some(object));
    }

    #[test]
    fn typed_object_wraps_a_pointers_base_type() {
        // Java: a pointer reaches `newTypedObject(dt, getObjectDataType(getBaseDataType(dt)))`.
        struct MockPointer;
        impl DataType for MockPointer {
            fn get_name(&self) -> String {
                "int *".to_string()
            }
            fn get_category_path(&self) -> CategoryPath {
                CategoryPath::parse("/").unwrap()
            }
            fn get_length(&self) -> i32 {
                8
            }
            fn is_pointer(&self) -> bool {
                true
            }
        }

        let mut writer = writer();
        let object = writer
            .get_isf_object(&MockPointer, &DummyMonitor)
            .unwrap()
            .unwrap();
        // `getKind` checks BuiltInDataType before Pointer, so a pointer reports "base".
        assert_eq!(object["kind"], json!("base"));
        assert_eq!(object["size"], json!(8));
        assert!(object["type"].is_object());
    }

    #[test]
    fn skip_types_suppresses_type_generation() {
        let mut writer = writer();
        writer.set_skip_types(true);
        writer.gen_types(&DummyMonitor).unwrap();
        // `addSingletons` runs only inside `genTypes`, so nothing was registered.
        assert_eq!(writer.base_types, json!({}));
    }
}
