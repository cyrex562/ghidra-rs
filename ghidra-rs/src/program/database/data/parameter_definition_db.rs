//! Port of `ghidra.program.database.data.ParameterDefinitionDB`.
//!
//! The Java class is a package-private, `final class ParameterDefinitionDB implements
//! ParameterDefinition`. Unlike [`FunctionDefinitionDb`](super::function_definition_db::FunctionDefinitionDb)
//! (a `DataTypeDB` subclass promoted to a trait for cycle-breaking reasons),
//! `ParameterDefinitionDB` needs no such promotion: it directly implements the already-ported
//! [`ParameterDefinition`] trait, so it is ported here as a concrete struct, per this session's
//! established "implements X" convention (see `data_type_component_db.rs`,
//! `data_type_proxy_component_db.rs`).
//!
//! # Fields: `dataMgr`/`adapter`/`parent`/`record`
//!
//! - `dataMgr`/`adapter` are stored the same way every other DB-backed datatype in this crate
//!   stores its owning manager/adapter (see e.g. [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB),
//!   [`UnionDb`](super::union_db::UnionDb)): `Arc<Mutex<dyn DataTypeManagerDb + Send>>` /
//!   `Arc<Mutex<dyn FunctionParameterAdapter + Send>>`, both singletons shared by every parameter
//!   of every function definition in the manager.
//! - `parent` (the owning `FunctionDefinitionDB`) is stored as `Arc<dyn FunctionDefinitionDb +
//!   Send + Sync>`. This is *not* a "no live back-reference" workaround like
//!   [`DataTypeComponentDB`]'s treatment of its owning composite (that case was genuinely
//!   unsound: an element of a `Vec` cannot also hold a live handle back to the `Vec`'s owner). A
//!   `ParameterDefinitionDB`'s `parent` is used only as an *argument* passed to other calls
//!   (`getDataType().removeParent(parent)`, `type.addParent(parent)`,
//!   `dataMgr.dataTypeChanged(parent, false)`) -- Java never mutates `parent` itself through this
//!   class -- so a shared, `&self`-only `Arc` handle is a faithful, sound representation with no
//!   gap. (No concrete [`FunctionDefinitionDb`](super::function_definition_db::FunctionDefinitionDb)
//!   implementor exists yet in this crate; once one does, it can hand each of its parameters a
//!   clone of its own `Arc<Self>`.)
//! - `record` is stored as a plain owned [`DBRecord`] (not wrapped in a `Mutex`, unlike e.g.
//!   [`TypedefDb`](super::typedef_db::TypedefDb)'s `Mutex<DBRecord>`): every [`ParameterDefinition`]
//!   method that mutates state (`set_data_type`/`set_name`/`set_comment`) already takes `&mut
//!   self` on the already-ported trait, so ordinary field mutation suffices -- no interior
//!   mutability is needed to satisfy a `&self`-only trait method, unlike `TypedefDb`'s situation
//!   under the (unrelated) `DataType` trait.
//!
//! # `getParent()` is not part of the `ParameterDefinition` trait
//!
//! The already-ported [`ParameterDefinition`] trait declares no `get_parent` method (Java's
//! `public FunctionDefinition getParent()` is not `@Override`-annotated -- it is not part of the
//! `ParameterDefinition` interface at all, just an extra public method on this concrete class).
//! It is exposed here as the inherent method [`ParameterDefinitionDb::parent`], returning a
//! cloned `Arc<dyn FunctionDefinitionDb + Send + Sync>` handle (from which every
//! `FunctionDefinition`/`FunctionSignature`/`DataType` supertrait method remains directly
//! callable) rather than attempting a `dyn FunctionDefinitionDb -> dyn FunctionDefinition`
//! trait-object upcast into a distinct `Box`/`Arc` type.
//!
//! # `isEquivalent(ParameterDefinition, DataTypeConflictHandler)`'s `DataTypeDB` downcast
//!
//! `ParameterDefinitionDB.isEquivalent(parm, handler)` falls back to `DataTypeDB.isEquivalent(dataType,
//! otherDataType, handler)`, a static helper that `instanceof`-checks whether the *existing*
//! `DataType` is itself a `DataTypeDB` to reach a handler-aware `isEquivalent` overload; when it
//! is not, it falls back to the ordinary `existingDataType.isEquivalent(otherDataType)`. A plain
//! `&dyn DataType` cannot be downcast to detect a `DataTypeDB` implementor generically in this
//! crate (no `Any`-based mechanism is wired up for it), so -- mirroring the identical, already
//! documented precedent in `data_type_proxy_component_db.rs`'s `is_equivalent` -- this port always
//! takes the ordinary-equivalence fallback path. `handler` is accepted (matching the Java
//! signature) but, given that fallback, never actually consulted.
//!
//! # `doSetDataType`/`setName`/`doSetComment`'s `IOException` handling
//!
//! Java catches `IOException` from `adapter.updateRecord(record)` and reports it via
//! `dataMgr.dbError(e)` (which typically surfaces the error to the user and/or aborts the
//! enclosing transaction -- it does not return a value the caller can inspect). This port calls
//! [`DataTypeManagerDb::db_error`] identically. For [`ParameterDefinition::set_data_type`] (whose
//! already-ported trait signature returns `Result<(), String>`, mirroring the
//! `IllegalArgumentException` `validateDataType` can throw), a persistence failure is also
//! surfaced as an `Err` after reporting it, so a caller relying on the `Result` sees the failure
//! rather than silently believing it succeeded. [`ParameterDefinition::set_name`]/
//! [`ParameterDefinition::set_comment`] have no `Result` in their already-ported trait signatures
//! (matching Java's `void` return), so for those two, `db_error` is the only observable signal --
//! identical to Java.

use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::data::function_definition_db::FunctionDefinitionDb;
use crate::program::database::data::function_parameter_adapter::{
    FunctionParameterAdapter, PARAMETER_COMMENT_COL, PARAMETER_DT_ID_COL, PARAMETER_DT_LENGTH_COL,
    PARAMETER_NAME_COL, PARAMETER_ORDINAL_COL,
};
use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_utilities::DataTypeUtilities as ModelDataTypeUtilities;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::{DataTypeConflictHandler, DefaultHandlerImpl};
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::data::parameter_definition_impl::validate_data_type;
use crate::program::model::listing::Variable;
use crate::program::model::symbol::symbol_utilities::SymbolUtilities;

/// A dummy zero-sized receiver used purely to invoke the model-layer [`ModelDataTypeUtilities`]'s
/// default methods, per the convention already established throughout `program/database/data`
/// (see e.g. `data_type_component_db.rs`, `data_type_proxy_component_db.rs`).
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl ModelDataTypeUtilities for Utils {}
impl SymbolUtilities for Utils {}

/// Stands in for `DataType.DEFAULT`, returned by [`ParameterDefinitionDb::get_data_type`] when
/// the parameter's referenced-type id no longer resolves to anything in the owning manager.
/// Mirrors the identical `DefaultDataTypeStandIn`/`MissingDataType` stand-ins in
/// `data_type_component_db.rs`/`typedef_db.rs`.
#[derive(Debug, Clone, Copy)]
struct DefaultDataTypeStandIn;
impl DataType for DefaultDataTypeStandIn {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
    fn is_default_data_type(&self) -> bool {
        true
    }
}

/// Database implementation for a Parameter.
///
/// Port of `ghidra.program.database.data.ParameterDefinitionDB`. See the module documentation for
/// how each field is represented and for the `isEquivalent`/`IOException`-handling notes.
pub struct ParameterDefinitionDb {
    data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
    adapter: Arc<Mutex<dyn FunctionParameterAdapter + Send>>,
    parent: Arc<dyn FunctionDefinitionDb + Send + Sync>,
    record: DBRecord,
}

impl ParameterDefinitionDb {
    /// Port of `ParameterDefinitionDB(DataTypeManagerDB, FunctionParameterAdapter,
    /// FunctionDefinitionDB, DBRecord)`.
    pub fn new(
        data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: Arc<Mutex<dyn FunctionParameterAdapter + Send>>,
        parent: Arc<dyn FunctionDefinitionDb + Send + Sync>,
        record: DBRecord,
    ) -> Self {
        ParameterDefinitionDb {
            data_mgr,
            adapter,
            parent,
            record,
        }
    }

    /// Port of the package-private `ParameterDefinitionDB.getRecord()`.
    pub fn get_record(&self) -> DBRecord {
        self.record.clone()
    }

    /// Port of the package-private `ParameterDefinitionDB.getKey()`.
    pub fn get_key(&self) -> i64 {
        self.record.get_key().get_long_value()
    }

    /// Port of `ParameterDefinitionDB.getParent()`. See the module documentation for why this is
    /// an inherent method rather than part of the [`ParameterDefinition`] trait.
    pub fn parent(&self) -> Arc<dyn FunctionDefinitionDb + Send + Sync> {
        Arc::clone(&self.parent)
    }

    /// Port of the package-private `ParameterDefinitionDB.doSetDataType(DataType, boolean)`.
    pub fn do_set_data_type(&mut self, data_type: Box<dyn DataType>, notify: bool) -> Result<(), String> {
        let validated = {
            let guard = self.data_mgr.lock().unwrap();
            let dt_mgr: &dyn crate::program::model::data::data_type_manager::DataTypeManager = &*guard;
            validate_data_type(Some(data_type), Some(dt_mgr), false)?
        };

        let mut current = self.get_data_type_impl();
        current.remove_parent(self.parent.as_ref());

        let resolved = {
            let mut guard = self.data_mgr.lock().unwrap();
            guard.resolve(validated, &DefaultHandlerImpl)
        };
        let mut resolved = resolved;
        resolved.add_parent(self.parent.as_ref());

        let resolved_id = {
            let mut guard = self.data_mgr.lock().unwrap();
            guard.get_resolved_id(resolved.as_ref())
        };

        self.record.set_long(PARAMETER_DT_ID_COL, resolved_id);
        self.record.set_int(PARAMETER_DT_LENGTH_COL, resolved.get_length());

        let update_result = {
            let mut guard = self.adapter.lock().unwrap();
            guard.update_record(&self.record)
        };

        match update_result {
            Ok(()) => {
                if notify {
                    self.data_mgr
                        .lock()
                        .unwrap()
                        .data_type_changed(self.parent.as_ref(), false);
                }
                Ok(())
            }
            Err(e) => {
                let message = e.to_string();
                self.data_mgr.lock().unwrap().db_error(e);
                Err(message)
            }
        }
    }

    /// Port of the package-private `ParameterDefinitionDB.doSetComment(String, boolean)`.
    pub fn do_set_comment(&mut self, comment: Option<String>, notify: bool) {
        self.record.set_string(PARAMETER_COMMENT_COL, comment);
        let update_result = {
            let mut guard = self.adapter.lock().unwrap();
            guard.update_record(&self.record)
        };
        match update_result {
            Ok(()) => {
                if notify {
                    self.data_mgr
                        .lock()
                        .unwrap()
                        .data_type_changed(self.parent.as_ref(), false);
                }
            }
            Err(e) => self.data_mgr.lock().unwrap().db_error(e),
        }
    }

    /// Port of the package-private `ParameterDefinitionDB.isEquivalent(ParameterDefinition,
    /// DataTypeConflictHandler)`. See the module documentation for why the `DataTypeDB`-downcast
    /// dispatch always takes the ordinary-equivalence fallback path in this port.
    pub fn is_equivalent_with_handler(
        &self,
        parm: Option<&dyn ParameterDefinition>,
        _handler: Option<&dyn DataTypeConflictHandler>,
    ) -> bool {
        let Some(parm) = parm else {
            return false;
        };
        if self.get_ordinal_impl() != parm.get_ordinal() {
            return false;
        }

        let data_type = self.get_data_type_impl();
        let other_data_type = parm.get_data_type();

        if Utils.is_same_data_type(data_type.as_ref(), other_data_type.as_ref()) {
            return true;
        }

        data_type.is_equivalent(other_data_type.as_ref())
    }

    fn get_ordinal_impl(&self) -> i32 {
        self.record.get_int(PARAMETER_ORDINAL_COL).unwrap_or(0)
    }

    fn get_data_type_impl(&self) -> Box<dyn DataType> {
        let id = self.record.get_long(PARAMETER_DT_ID_COL).unwrap_or(-1);
        let resolved = self.data_mgr.lock().unwrap().get_data_type_by_id(id);
        resolved.unwrap_or_else(|| Box::new(DefaultDataTypeStandIn))
    }
}

impl ParameterDefinition for ParameterDefinitionDb {
    /// Port of `ParameterDefinitionDB.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.get_data_type_impl()
    }

    /// Port of `ParameterDefinitionDB.setDataType(DataType)`.
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String> {
        self.do_set_data_type(data_type, true)
    }

    /// Port of `ParameterDefinitionDB.getName()`.
    fn get_name(&self) -> Option<String> {
        match self.record.get_string(PARAMETER_NAME_COL) {
            Some(name) => Some(name.to_string()),
            None => Some(Utils.get_default_param_name(self.get_ordinal_impl())),
        }
    }

    /// Port of `ParameterDefinitionDB.getLength()`.
    fn get_length(&self) -> i32 {
        let dt = self.get_data_type_impl();
        let dt_len = dt.get_length();
        if dt_len > -1 {
            dt_len
        } else {
            self.record.get_int(PARAMETER_DT_LENGTH_COL).unwrap_or(0)
        }
    }

    /// Port of `ParameterDefinitionDB.setName(String)`.
    fn set_name(&mut self, name: Option<String>) {
        let name = match &name {
            Some(n) if !Utils.is_default_parameter_name(Some(n)) => name,
            _ => None,
        };
        self.record.set_string(PARAMETER_NAME_COL, name);
        let update_result = {
            let mut guard = self.adapter.lock().unwrap();
            guard.update_record(&self.record)
        };
        match update_result {
            Ok(()) => {
                self.data_mgr
                    .lock()
                    .unwrap()
                    .data_type_changed(self.parent.as_ref(), false);
            }
            Err(e) => self.data_mgr.lock().unwrap().db_error(e),
        }
    }

    /// Port of `ParameterDefinitionDB.getComment()`.
    fn get_comment(&self) -> Option<String> {
        self.record.get_string(PARAMETER_COMMENT_COL).map(str::to_string)
    }

    /// Port of `ParameterDefinitionDB.setComment(String)`.
    fn set_comment(&mut self, comment: Option<String>) {
        self.do_set_comment(comment, true);
    }

    /// Port of `ParameterDefinitionDB.getOrdinal()`.
    fn get_ordinal(&self) -> i32 {
        self.get_ordinal_impl()
    }

    /// Port of `ParameterDefinitionDB.isEquivalent(Variable)`.
    fn is_equivalent_variable(&self, variable: &dyn Variable) -> bool {
        let Some(other_ordinal) = variable.parameter_ordinal() else {
            return false;
        };
        if self.get_ordinal_impl() != other_ordinal {
            return false;
        }
        crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type(
            self.get_data_type_impl().as_ref(),
            variable.get_data_type().as_ref(),
        )
    }

    /// Port of the public `ParameterDefinitionDB.isEquivalent(ParameterDefinition)`, which
    /// delegates to the package-private handler-aware overload with a `null` handler.
    fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool {
        self.is_equivalent_with_handler(Some(parm), None)
    }

    /// Port of `ParameterDefinitionDB.compareTo(ParameterDefinition)`.
    fn compare_to(&self, other: &dyn ParameterDefinition) -> Ordering {
        self.get_ordinal_impl().cmp(&other.get_ordinal())
    }
}

impl std::fmt::Display for ParameterDefinitionDb {
    /// Port of `ParameterDefinitionDB.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.get_data_type_impl().get_name(),
            ParameterDefinition::get_name(self).unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, Schema};
    use crate::program::database::data::function_parameter_adapter::schema as parameter_schema;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::listing::function::UNKNOWN_CALLING_CONVENTION_STRING;
    use crate::program::model::listing::function_signature::FunctionSignature;
    use crate::program::model::data::function_definition::FunctionDefinition;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use std::io;

    #[derive(Clone)]
    struct MockInt {
        name: String,
        length: i32,
    }
    impl DataType for MockInt {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
    }

    fn int_type(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockInt { name: name.to_string(), length })
    }

    struct MockManager {
        types: std::collections::HashMap<i64, Box<dyn DataType>>,
        next_id: i64,
        changed: Vec<String>,
    }
    impl MockManager {
        fn new() -> Self {
            let mut types: std::collections::HashMap<i64, Box<dyn DataType>> = std::collections::HashMap::new();
            types.insert(1, int_type("int", 4));
            types.insert(2, int_type("char", 1));
            MockManager { types, next_id: 3, changed: Vec::new() }
        }

        fn insert(&mut self, id: i64, dt: Box<dyn DataType>) {
            self.types.insert(id, dt);
        }
    }
    impl DataTypeManager for MockManager {
        fn resolve(
            &mut self,
            data_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            data_type
        }
        fn get_resolved_id(&mut self, dt: &dyn DataType) -> i64 {
            for (id, existing) in self.types.iter() {
                if existing.get_name() == dt.get_name() && existing.get_length() == dt.get_length() {
                    return *id;
                }
            }
            let id = self.next_id;
            self.next_id += 1;
            self.types.insert(id, dt.clone_data_type(self));
            id
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            self.types.get(&data_type_id).map(|dt| dt.clone_data_type(self))
        }
    }
    impl DataTypeManagerDb for MockManager {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
        fn data_type_changed(&mut self, dt: &dyn DataType, _is_auto_change: bool) {
            self.changed.push(dt.get_name());
        }
    }

    struct MockAdapter {
        updates: Vec<DBRecord>,
        fail_next: bool,
    }
    impl MockAdapter {
        fn new() -> Self {
            MockAdapter { updates: Vec::new(), fail_next: false }
        }
    }
    impl FunctionParameterAdapter for MockAdapter {
        fn get_records(&self) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!()
        }
        fn delete_table(&mut self, _handle: &mut crate::framework::db::DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn create_record(
            &mut self,
            _data_type_id: i64,
            _parent_id: i64,
            _ordinal: i32,
            _name: Option<&str>,
            _comment: Option<&str>,
            _dt_length: i32,
        ) -> io::Result<DBRecord> {
            unimplemented!()
        }
        fn get_record(&self, _parameter_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            if self.fail_next {
                return Err(io::Error::new(io::ErrorKind::Other, "boom"));
            }
            self.updates.push(record.clone());
            Ok(())
        }
        fn remove_record(&mut self, _parameter_id: i64) -> io::Result<bool> {
            Ok(true)
        }
        fn get_parameter_ids_in_function_def(&self, _function_def_id: i64) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
    }

    struct MockParent {
        name: String,
    }
    impl DataType for MockParent {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }
    impl FunctionSignature for MockParent {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_prototype_string_with_calling_convention(&self, _include: bool) -> String {
            String::new()
        }
        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            Vec::new()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            int_type("void", 0)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn has_no_return(&self) -> bool {
            false
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            UNKNOWN_CALLING_CONVENTION_STRING.to_string()
        }
        fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool {
            self.name == signature.get_name()
        }
    }
    impl FunctionDefinition for MockParent {
        fn set_arguments(&mut self, _args: Vec<Box<dyn ParameterDefinition>>) {}
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn crate::program::seam_stubs::GenericCallingConvention,
        ) {
        }
        fn set_calling_convention(
            &mut self,
            _convention_name: Option<String>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn replace_argument(
            &mut self,
            _ordinal: i32,
            _name: Option<String>,
            _dt: Box<dyn DataType>,
            _comment: Option<String>,
            _source: crate::program::model::symbol::source_type::SourceType,
        ) {
        }
    }
    impl FunctionDefinitionDb for MockParent {
        fn refresh(&mut self, _record: Option<DBRecord>) -> bool {
            true
        }
        fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
            unimplemented!()
        }
    }

    fn make_record(schema: Arc<Schema>, key: i64, dt_id: i64, ordinal: i32, name: Option<&str>, comment: Option<&str>) -> DBRecord {
        let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
        rec.set_long(PARAMETER_DT_ID_COL, dt_id);
        rec.set_string(PARAMETER_NAME_COL, name.map(str::to_string));
        rec.set_string(PARAMETER_COMMENT_COL, comment.map(str::to_string));
        rec.set_int(PARAMETER_ORDINAL_COL, ordinal);
        rec.set_int(PARAMETER_DT_LENGTH_COL, -1);
        rec
    }

    fn make_param(
        mgr: &Arc<Mutex<MockManager>>,
        adapter: &Arc<Mutex<MockAdapter>>,
        dt_id: i64,
        ordinal: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> ParameterDefinitionDb {
        let schema = parameter_schema();
        let record = make_record(schema, ordinal as i64, dt_id, ordinal, name, comment);
        let parent: Arc<dyn FunctionDefinitionDb + Send + Sync> =
            Arc::new(MockParent { name: "myFunc".to_string() });
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = mgr.clone();
        let adapter: Arc<Mutex<dyn FunctionParameterAdapter + Send>> = adapter.clone();
        ParameterDefinitionDb::new(mgr, adapter, parent, record)
    }

    fn setup() -> (Arc<Mutex<MockManager>>, Arc<Mutex<MockAdapter>>) {
        let mgr = Arc::new(Mutex::new(MockManager::new()));
        let adapter = Arc::new(Mutex::new(MockAdapter::new()));
        (mgr, adapter)
    }

    #[test]
    fn get_ordinal_reads_record_column() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 2, Some("count"), None);
        assert_eq!(ParameterDefinition::get_ordinal(&param), 2);
    }

    #[test]
    fn get_data_type_resolves_via_manager() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 0, None, None);
        assert_eq!(param.get_data_type().get_name(), "int");
    }

    #[test]
    fn get_data_type_falls_back_to_default_when_unresolved() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 999, 0, None, None);
        let dt = param.get_data_type();
        assert!(dt.is_default_data_type());
    }

    #[test]
    fn get_name_falls_back_to_default_param_name() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 3, None, None);
        assert_eq!(ParameterDefinition::get_name(&param), Some("param_4".to_string()));
    }

    #[test]
    fn get_name_returns_explicit_name() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 0, Some("length"), None);
        assert_eq!(ParameterDefinition::get_name(&param), Some("length".to_string()));
    }

    #[test]
    fn set_name_persists_and_notifies() {
        let (mgr, adapter) = setup();
        let mut param = make_param(&mgr, &adapter, 1, 0, None, None);
        param.set_name(Some("total".to_string()));
        assert_eq!(ParameterDefinition::get_name(&param), Some("total".to_string()));
        assert_eq!(adapter.lock().unwrap().updates.len(), 1);
    }

    #[test]
    fn set_name_normalizes_default_looking_name_to_none() {
        let (mgr, adapter) = setup();
        let mut param = make_param(&mgr, &adapter, 1, 1, Some("original"), None);
        param.set_name(Some("param_2".to_string()));
        // ordinal 1 => default name is "param_2", so the explicit name collapses to None and
        // get_name() falls back to the computed default again.
        assert_eq!(ParameterDefinition::get_name(&param), Some("param_2".to_string()));
        assert_eq!(param.record.get_string(PARAMETER_NAME_COL), None);
    }

    #[test]
    fn set_comment_round_trips() {
        let (mgr, adapter) = setup();
        let mut param = make_param(&mgr, &adapter, 1, 0, None, None);
        assert_eq!(param.get_comment(), None);
        param.set_comment(Some("a comment".to_string()));
        assert_eq!(param.get_comment(), Some("a comment".to_string()));
    }

    #[test]
    fn set_data_type_updates_record_and_length() {
        let (mgr, adapter) = setup();
        let mut param = make_param(&mgr, &adapter, 1, 0, None, None);
        assert_eq!(ParameterDefinition::get_data_type(&param).get_name(), "int");
        param.set_data_type(int_type("char", 1)).expect("valid data type");
        assert_eq!(ParameterDefinition::get_data_type(&param).get_name(), "char");
        assert_eq!(ParameterDefinition::get_length(&param), 1);
        assert_eq!(mgr.lock().unwrap().changed.len(), 1);
    }

    #[test]
    fn set_data_type_reports_io_failure() {
        let (mgr, adapter) = setup();
        adapter.lock().unwrap().fail_next = true;
        let mut param = make_param(&mgr, &adapter, 1, 0, None, None);
        let result = param.set_data_type(int_type("char", 1));
        assert!(result.is_err());
    }

    #[test]
    fn get_length_falls_back_to_stored_length_for_negative_length_type() {
        #[derive(Clone)]
        struct NegativeLengthType;
        impl DataType for NegativeLengthType {
            fn get_name(&self) -> String {
                "neg".to_string()
            }
            fn get_length(&self) -> i32 {
                -1
            }
            fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
                Box::new(self.clone())
            }
        }

        let mut mock_mgr = MockManager::new();
        mock_mgr.insert(3, Box::new(NegativeLengthType));
        let mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(mock_mgr));
        let adapter: Arc<Mutex<dyn FunctionParameterAdapter + Send>> = Arc::new(Mutex::new(MockAdapter::new()));

        let schema = parameter_schema();
        let mut record = make_record(schema, 5, 3, 0, None, None);
        record.set_int(PARAMETER_DT_LENGTH_COL, 7);
        let parent: Arc<dyn FunctionDefinitionDb + Send + Sync> = Arc::new(MockParent { name: "f".to_string() });
        let param = ParameterDefinitionDb::new(mgr, adapter, parent, record);

        // The referenced type reports a negative length (an unsized/incomplete type), so
        // `getLength()` falls back to the value stashed in `PARAMETER_DT_LENGTH_COL` at
        // set_data_type time, mirroring `ParameterDefinitionDB.getLength()`.
        assert_eq!(param.get_data_type().get_name(), "neg");
        assert_eq!(param.get_length(), 7);
    }

    #[test]
    fn is_equivalent_parameter_checks_ordinal_and_data_type() {
        let (mgr, adapter) = setup();
        let a = make_param(&mgr, &adapter, 1, 2, None, None);
        let b = make_param(&mgr, &adapter, 1, 2, Some("other name"), None);
        let c = make_param(&mgr, &adapter, 2, 2, None, None);
        let d = make_param(&mgr, &adapter, 1, 3, None, None);
        assert!(a.is_equivalent_parameter(&b)); // name doesn't matter
        assert!(!a.is_equivalent_parameter(&c)); // different data type
        assert!(!a.is_equivalent_parameter(&d)); // different ordinal
    }

    #[test]
    fn is_equivalent_variable_checks_parameter_ordinal() {
        struct MockVar {
            ordinal: Option<i32>,
            dt: Box<dyn DataType>,
        }
        impl Variable for MockVar {
            fn get_data_type(&self) -> Box<dyn DataType> {
                self.dt.clone_data_type(&MockManager::new())
            }
            fn set_data_type_with_storage(
                &mut self,
                _data_type: Box<dyn DataType>,
                _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
                _force: bool,
                _source: crate::program::model::symbol::SourceType,
            ) -> Result<(), crate::util::exception::InvalidInputException> {
                Ok(())
            }
            fn set_data_type(
                &mut self,
                _data_type: Box<dyn DataType>,
                _source: crate::program::model::symbol::SourceType,
            ) -> Result<(), crate::util::exception::InvalidInputException> {
                Ok(())
            }
            fn set_data_type_aligned(
                &mut self,
                _data_type: Box<dyn DataType>,
                _align_stack: bool,
                _force: bool,
                _source: crate::program::model::symbol::SourceType,
            ) -> Result<(), crate::util::exception::InvalidInputException> {
                Ok(())
            }
            fn get_name(&self) -> Option<String> {
                None
            }
            fn get_length(&self) -> i32 {
                0
            }
            fn is_valid(&self) -> bool {
                true
            }
            fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
                None
            }
            fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
                struct MockProgram;
                impl crate::framework::model::DomainObject for MockProgram {}
                impl crate::program::model::listing::Program for MockProgram {
                    fn get_name(&self) -> String {
                        "mock".to_string()
                    }
                    fn get_language_id(&self) -> String {
                        "mock:LE:32:default".to_string()
                    }
                }
                Arc::new(MockProgram)
            }
            fn get_source(&self) -> crate::program::model::symbol::SourceType {
                crate::program::model::symbol::SourceType::UserDefined
            }
            fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
                Ok(())
            }
            fn get_comment(&self) -> Option<String> {
                None
            }
            fn set_comment(&mut self, _comment: Option<String>) {}
            fn get_variable_storage(&self) -> Option<Box<dyn crate::program::model::listing::variable_storage::VariableStorage>> {
                None
            }
            fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
                None
            }
            fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
                None
            }
            fn is_stack_variable(&self) -> bool {
                false
            }
            fn has_stack_storage(&self) -> bool {
                false
            }
            fn is_register_variable(&self) -> bool {
                false
            }
            fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
                None
            }
            fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
                None
            }
            fn get_stack_offset(&self) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
                Err(crate::program::model::listing::variable::UnsupportedOperationError("no".to_string()))
            }
            fn is_memory_variable(&self) -> bool {
                false
            }
            fn is_unique_variable(&self) -> bool {
                false
            }
            fn is_compound_variable(&self) -> bool {
                false
            }
            fn has_assigned_storage(&self) -> bool {
                false
            }
            fn get_first_use_offset(&self) -> i32 {
                0
            }
            fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
                None
            }
            fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
                false
            }
            fn compare_to(&self, _other: &dyn Variable) -> Ordering {
                Ordering::Equal
            }
            fn parameter_ordinal(&self) -> Option<i32> {
                self.ordinal
            }
        }

        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 2, None, None);
        let matching = MockVar { ordinal: Some(2), dt: int_type("int", 4) };
        let wrong_ordinal = MockVar { ordinal: Some(3), dt: int_type("int", 4) };
        let not_a_parameter = MockVar { ordinal: None, dt: int_type("int", 4) };
        assert!(param.is_equivalent_variable(&matching));
        assert!(!param.is_equivalent_variable(&wrong_ordinal));
        assert!(!param.is_equivalent_variable(&not_a_parameter));
    }

    #[test]
    fn compare_to_orders_by_ordinal() {
        let (mgr, adapter) = setup();
        let a = make_param(&mgr, &adapter, 1, 0, None, None);
        let b = make_param(&mgr, &adapter, 1, 1, None, None);
        assert_eq!(ParameterDefinition::compare_to(&a, &b), Ordering::Less);
        assert_eq!(ParameterDefinition::compare_to(&b, &a), Ordering::Greater);
    }

    #[test]
    fn get_key_reads_record_key() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 7, None, None);
        assert_eq!(param.get_key(), 7);
    }

    #[test]
    fn parent_returns_shared_handle() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 0, None, None);
        let parent = param.parent();
        assert_eq!(FunctionSignature::get_name(parent.as_ref()), "myFunc");
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let (mgr, adapter) = setup();
        let param = make_param(&mgr, &adapter, 1, 0, Some("len"), None);
        assert_eq!(format!("{param}"), "int len");
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let (mgr, adapter) = setup();
        let param: Box<dyn ParameterDefinition> = Box::new(make_param(&mgr, &adapter, 1, 4, Some("x"), None));
        assert_eq!(param.get_ordinal(), 4);
        assert_eq!(param.get_data_type().get_name(), "int");
    }
}
