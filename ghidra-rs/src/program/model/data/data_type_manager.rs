use std::collections::HashSet;

use thiserror::Error;

use crate::program::model::data::archive_type::ArchiveType;
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
use crate::program::model::data::invalidated_listener::InvalidatedListener;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::function_definition::FunctionDefinition;
use crate::program::model::data::structure::Structure;
use crate::program::model::lang::ProgramArchitecture;
use crate::program::seam_stubs::{
    AddressMap, DataTypePath, PointerTypedefBuilder, PrototypeModel, Transaction,
};
use crate::util::exception::{CancelledException, InvalidNameException};
use crate::util::function::{ExceptionalCallback, ExceptionalSupplier};
use crate::util::task::TaskMonitor;
use crate::util::UniversalID;

/// ID for the default (undefined) data type.
pub const DEFAULT_DATATYPE_ID: i64 = 0;

/// ID if data type type is not known in this data type manager.
pub const NULL_DATATYPE_ID: i64 = -1;

/// ID if data type type is BAD.
pub const BAD_DATATYPE_ID: i64 = -2;

/// Name of the category for the build in data types.
pub const BUILT_IN_DATA_TYPES_NAME: &str = "BuiltInTypes";

/// Key of the archive representing types local to a program/archive.
pub const LOCAL_ARCHIVE_KEY: i64 = 0;

/// Key of the archive holding Ghidra's built-in data types.
pub const BUILT_IN_ARCHIVE_KEY: i64 = 1;

/// Returns the [`UniversalID`] for [`LOCAL_ARCHIVE_KEY`].
///
/// A function rather than a constant since [`UniversalID::new`] is not `const`.
pub fn local_archive_universal_id() -> UniversalID {
    UniversalID::new(LOCAL_ARCHIVE_KEY)
}

/// Returns the [`UniversalID`] for [`BUILT_IN_ARCHIVE_KEY`].
///
/// A function rather than a constant since [`UniversalID::new`] is not `const`.
pub fn built_in_archive_universal_id() -> UniversalID {
    UniversalID::new(BUILT_IN_ARCHIVE_KEY)
}

/// Error produced by [`DataTypeManager::replace_data_type`], standing in for the checked
/// `DataTypeDependencyException` and the unchecked `IllegalArgumentException` declared on the
/// Java method `DataTypeManager.replaceDataType`.
#[derive(Error, Debug)]
pub enum ReplaceDataTypeError {
    #[error(transparent)]
    Dependency(#[from] DataTypeDependencyException),
    #[error("IllegalArgumentException: {0}")]
    InvalidArgument(String),
}

/// Interface for Managing data types.
///
/// Port of `ghidra.program.model.data.DataTypeManager`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
///
/// Every method is given a default so that the many existing bare `impl DataTypeManager for
/// MockX {}` blocks scattered across this crate (in
/// [`FileBasedDataTypeManager`](super::file_based_data_type_manager::FileBasedDataTypeManager),
/// [`Category`], [`Structure`](super::structure::Structure),
/// [`Union`](super::union::Union), [`Enum`](super::enum_::Enum),
/// [`InvalidatedListener`], and others) keep compiling unmodified. Concrete implementations
/// (`DataTypeManagerDB`, `StandAloneDataTypeManager`, etc.) will override these with real
/// behavior once they are ported. Where a Java default method exists (`remove(DataType,
/// TaskMonitor)`, the two `withTransaction` overloads), the Rust default mirrors it exactly.
/// Where no Java default exists but a trivial, meaningful fallback is available (e.g. echoing
/// back an input `DataType`, treating an empty manager as containing nothing), that fallback is
/// used; where the referenced type (`Category`, `Pointer`'s pointee, `DataOrganization`) has no
/// concrete implementation ported yet and no meaningful empty value exists, the default panics
/// via `unimplemented!` (mirroring [`DataType::get_data_organization`](super::data_type::DataType::get_data_organization)).
pub trait DataTypeManager {
    /// Returns the universal ID for this dataType manager.
    fn get_universal_id(&self) -> UniversalID {
        UniversalID::new(0)
    }

    /// Get the optional program architecture details associated with this archive.
    fn get_program_architecture(&self) -> Option<Box<dyn ProgramArchitecture>> {
        None
    }

    /// Get the program architecture information which has been associated with this data type
    /// manager, if it has been set.
    fn get_program_architecture_summary(&self) -> Option<String> {
        None
    }

    /// Returns true if the given category path exists in this data type manager.
    fn contains_category(&self, path: &CategoryPath) -> bool {
        let _ = path;
        false
    }

    /// Returns a unique name not currently used by any other data type or category with the
    /// same base name.
    fn get_unique_name(&self, path: &CategoryPath, base_name: &str) -> String {
        let _ = path;
        base_name.to_string()
    }

    /// Returns a data type that is "in" this Manager, creating a new one if necessary.
    fn resolve(
        &mut self,
        data_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        let _ = handler;
        data_type
    }

    /// Returns a data type after adding it to this data manager.
    fn add_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        self.resolve(data_type, handler)
    }

    /// Sequentially adds a collection of datatypes to this data manager.
    ///
    /// # Errors
    /// Returns `Err` if the monitor is cancelled.
    fn add_data_types(
        &mut self,
        data_types: Vec<Box<dyn DataType>>,
        handler: &dyn DataTypeConflictHandler,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        for dt in data_types {
            monitor.check_cancelled()?;
            self.add_data_type(dt, handler);
        }
        Ok(())
    }

    /// Returns all the dataTypes in this manager.
    fn get_all_data_types(&self) -> Vec<Box<dyn DataType>> {
        Vec::new()
    }

    /// Adds all data types to the specified list.
    fn get_all_data_types_into(&self, list: &mut Vec<Box<dyn DataType>>) {
        list.extend(self.get_all_data_types());
    }

    /// Returns all structures in this manager.
    fn get_all_structures(&self) -> Vec<Box<dyn Structure>> {
        Vec::new()
    }

    /// Returns all composite data types (structures and unions) in this manager.
    fn get_all_composites(&self) -> Vec<Box<dyn Composite>> {
        Vec::new()
    }

    /// Returns all function definition data types in this manager.
    fn get_all_function_definitions(&self) -> Vec<Box<dyn FunctionDefinition>> {
        Vec::new()
    }

    /// Begin searching at the root category for all data types with the given name, placing
    /// matches into `list`. The presence of a `.conflict` extension is ignored.
    fn find_data_types(&self, name: &str, list: &mut Vec<Box<dyn DataType>>) {
        let _ = (name, list);
    }

    /// Begin searching at the root category for all data types with names that match the given
    /// (possibly wildcarded) name, placing matches into `list`.
    fn find_data_types_matching(
        &self,
        name: &str,
        list: &mut Vec<Box<dyn DataType>>,
        case_sensitive: bool,
        monitor: &dyn TaskMonitor,
    ) {
        let _ = (name, list, case_sensitive, monitor);
    }

    /// Replace an existing dataType with another. Both datatypes must be fixed-length
    /// datatypes.
    ///
    /// # Errors
    /// Returns `Err` if the replacement datatype depends on the existing dataType (mirrors
    /// `DataTypeDependencyException`), or an invalid replacement datatype is specified (mirrors
    /// `IllegalArgumentException`).
    fn replace_data_type(
        &mut self,
        existing_dt: &dyn DataType,
        replacement_dt: Box<dyn DataType>,
        update_category_path: bool,
    ) -> Result<Box<dyn DataType>, ReplaceDataTypeError> {
        let _ = (existing_dt, update_category_path);
        Ok(replacement_dt)
    }

    /// Retrieve the data type with the fully qualified path, e.g. `/foo/bar`.
    fn get_data_type(&self, data_type_path: &str) -> Option<Box<dyn DataType>> {
        let _ = data_type_path;
        None
    }

    /// Retrieve the data type with the fully qualified path.
    ///
    /// # Deprecated
    /// Use [`get_data_type`](Self::get_data_type) instead.
    fn find_data_type(&self, data_type_path: &str) -> Option<Box<dyn DataType>> {
        self.get_data_type(data_type_path)
    }

    /// Find the dataType for the given dataTypePath.
    fn get_data_type_at_path(&self, data_type_path: &DataTypePath) -> Option<Box<dyn DataType>> {
        let _ = data_type_path;
        None
    }

    /// Returns the dataTypeId for the given dataType, adding it to this manager if it is not
    /// currently present.
    fn get_resolved_id(&mut self, dt: &dyn DataType) -> i64 {
        let _ = dt;
        NULL_DATATYPE_ID
    }

    /// Returns the dataTypeId for the given dataType, or -1 if the dataType does not exist.
    fn get_id(&self, dt: &dyn DataType) -> i64 {
        let _ = dt;
        NULL_DATATYPE_ID
    }

    /// Returns the dataType associated with the given dataTypeId, or `None` if the id is not
    /// valid.
    fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
        let _ = data_type_id;
        None
    }

    /// Returns the Category with the given id.
    fn get_category(&self, category_id: i64) -> Option<Box<dyn Category>> {
        let _ = category_id;
        None
    }

    /// Get the category that has the given path, or `None` if not defined.
    fn get_category_at_path(&self, path: &CategoryPath) -> Option<Box<dyn Category>> {
        let _ = path;
        None
    }

    /// Add a listener that is notified when the dataTypeManger changes.
    fn add_data_type_manager_listener(&mut self, listener: Box<dyn DataTypeManagerChangeListener>) {
        let _ = listener;
    }

    /// Remove the DataTypeManger change listener.
    fn remove_data_type_manager_listener(&mut self, listener: &dyn DataTypeManagerChangeListener) {
        let _ = listener;
    }

    /// Adds a listener that will be notified when this manager's cache is invalidated.
    fn add_invalidated_listener(&mut self, listener: Box<dyn InvalidatedListener>) {
        let _ = listener;
    }

    /// Removes a previously added invalidated listener.
    fn remove_invalidated_listener(&mut self, listener: &dyn InvalidatedListener) {
        let _ = listener;
    }

    /// Remove the given data type from this manager, returning true if it existed and was
    /// removed.
    fn remove(&mut self, data_type: &dyn DataType) -> bool {
        let _ = data_type;
        false
    }

    /// Deprecated. Use [`remove`](Self::remove).
    fn remove_with_monitor(&mut self, data_type: &dyn DataType, monitor: &dyn TaskMonitor) -> bool {
        let _ = monitor;
        self.remove(data_type)
    }

    /// Remove the given data types from this manager.
    ///
    /// # Errors
    /// Returns `Err` if the user cancels via `monitor`.
    fn remove_all(
        &mut self,
        data_types: &[&dyn DataType],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        for dt in data_types {
            monitor.check_cancelled()?;
            self.remove(*dt);
        }
        Ok(())
    }

    /// Return true if the given data type exists in this data type manager.
    fn contains(&self, data_type: &dyn DataType) -> bool {
        let _ = data_type;
        false
    }

    /// Create a category for the given path; returns the current category if it already
    /// exists.
    ///
    /// No meaningful `Category` fallback is available yet since no concrete implementation has
    /// been ported; overriding implementations must supply their own.
    fn create_category(&mut self, path: &CategoryPath) -> Box<dyn Category> {
        let _ = path;
        unimplemented!("DataTypeManager::create_category has no default implementation yet")
    }

    /// Gets the data type with the indicated name in the indicated category.
    fn get_data_type_in_category(&self, path: &CategoryPath, name: &str) -> Option<Box<dyn DataType>> {
        let _ = (path, name);
        None
    }

    /// Returns this data type manager's name.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Sets this data type manager's name.
    ///
    /// # Errors
    /// Returns `Err` if the given name is invalid (such as when empty).
    fn set_name(&mut self, name: &str) -> Result<(), InvalidNameException> {
        let _ = name;
        Ok(())
    }

    /// Returns true if this DataTypeManager can be modified.
    fn is_updatable(&self) -> bool {
        false
    }

    /// Open a new transaction. Should generally be paired with a call to
    /// [`end_transaction`](Self::end_transaction).
    ///
    /// # Errors
    /// Returns `Err` if this manager has already been closed (mirrors `IllegalStateException`).
    fn open_transaction(&mut self, description: &str) -> Result<Box<dyn Transaction>, String> {
        let _ = description;
        Ok(Box::new(NoOpTransaction))
    }

    /// Starts a transaction for making changes in this data type manager, returning the
    /// transaction ID.
    fn start_transaction(&mut self, description: &str) -> i32 {
        let _ = description;
        0
    }

    /// Ends the current transaction. Returns true if this invocation was the final transaction
    /// and all changes were committed.
    fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
        let _ = transaction_id;
        commit
    }

    /// Performs the given callback inside of a transaction, always committing when finished.
    ///
    /// # Errors
    /// Propagates any error returned by `callback`.
    fn with_transaction(
        &mut self,
        description: &str,
        callback: ExceptionalCallback<String>,
    ) -> Result<(), String> {
        let id = self.start_transaction(description);
        let result = callback();
        self.end_transaction(id, true);
        result
    }

    /// Calls the given supplier inside of a transaction, committing only if it succeeds.
    ///
    /// # Errors
    /// Propagates any error returned by `supplier`.
    fn with_transaction_result<T>(
        &mut self,
        description: &str,
        supplier: ExceptionalSupplier<T, String>,
    ) -> Result<T, String>
    where
        Self: Sized,
    {
        let id = self.start_transaction(description);
        let result = supplier();
        let success = result.is_ok();
        self.end_transaction(id, success);
        result
    }

    /// Force all pending notification events to be flushed.
    fn flush_events(&mut self) {}

    /// Closes this dataType manager.
    fn close(&mut self) {}

    /// Returns a default sized pointer to the given datatype.
    fn get_pointer(&self, datatype: &dyn DataType) -> Box<dyn Pointer> {
        let _ = datatype;
        Box::new(EmptyPointer)
    }

    /// Returns a pointer of the given size to the given datatype (-1 for a default sized
    /// pointer).
    fn get_pointer_with_size(&self, datatype: &dyn DataType, size: i32) -> Box<dyn Pointer> {
        let _ = (datatype, size);
        Box::new(EmptyPointer)
    }

    /// Returns the root category Manager.
    ///
    /// No meaningful `Category` fallback is available yet since no concrete implementation has
    /// been ported; overriding implementations must supply their own.
    fn get_root_category(&self) -> Box<dyn Category> {
        unimplemented!("DataTypeManager::get_root_category has no default implementation yet")
    }

    /// Returns true if the given datatype has been designated as a favorite.
    fn is_favorite(&self, datatype: &dyn DataType) -> bool {
        let _ = datatype;
        false
    }

    /// Sets the given dataType to be either a favorite or not a favorite.
    fn set_favorite(&mut self, datatype: &dyn DataType, is_favorite: bool) {
        let _ = (datatype, is_favorite);
    }

    /// Returns a list of datatypes that have been designated as favorites.
    fn get_favorites(&self) -> Vec<Box<dyn DataType>> {
        Vec::new()
    }

    /// Returns the total number of data type categories.
    fn get_category_count(&self) -> i32 {
        0
    }

    /// Returns the total number of defined data types.
    fn get_data_type_count(&self, include_pointers_and_arrays: bool) -> i32 {
        let _ = include_pointers_and_arrays;
        0
    }

    /// Adds all enum value names that match the given value to the given set.
    fn find_enum_value_names(&self, value: i64, enum_value_names: &mut HashSet<String>) {
        let _ = (value, enum_value_names);
    }

    /// Finds the data type using the given source archive and id.
    fn get_data_type_from_source(
        &self,
        source_archive: Option<&dyn SourceArchive>,
        datatype_id: UniversalID,
    ) -> Option<Box<dyn DataType>> {
        let _ = (source_archive, datatype_id);
        None
    }

    /// Gets the data type with the matching universal data type id.
    fn find_data_type_for_id(&self, datatype_id: UniversalID) -> Option<Box<dyn DataType>> {
        let _ = datatype_id;
        None
    }

    /// Returns the timestamp of the last time this manager was changed.
    fn get_last_change_time_for_my_manager(&self) -> i64 {
        0
    }

    /// Returns the source archive for the given ID, or `None` if it does not exist.
    fn get_source_archive(&self, source_id: UniversalID) -> Option<Box<dyn SourceArchive>> {
        let _ = source_id;
        None
    }

    /// Returns this manager's archive type.
    fn get_type(&self) -> ArchiveType {
        ArchiveType::Temporary
    }

    /// Returns all data types within this manager that have the given source archive.
    fn get_data_types_from_archive(&self, source_archive: &dyn SourceArchive) -> Vec<Box<dyn DataType>> {
        let _ = source_archive;
        Vec::new()
    }

    /// Returns the source archive for this manager, or `None` if it does not exist.
    fn get_local_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        None
    }

    /// Change the given data type and its dependencies so their source archive is the given
    /// archive.
    fn associate_data_type_with_archive(&mut self, datatype: &dyn DataType, archive: &dyn SourceArchive) {
        let _ = (datatype, archive);
    }

    /// If the indicated data type is associated with a source archive, remove that association.
    fn disassociate(&mut self, datatype: &dyn DataType) {
        let _ = datatype;
    }

    /// Updates the name associated with a source archive identified by domain file ID. Returns
    /// true if the name was changed.
    fn update_source_archive_name_for_file(&mut self, archive_file_id: &str, name: &str) -> bool {
        let _ = (archive_file_id, name);
        false
    }

    /// Updates the name associated with a source archive identified by universal ID. Returns
    /// true if the name was changed.
    fn update_source_archive_name(&mut self, source_id: UniversalID, name: &str) -> bool {
        let _ = (source_id, name);
        false
    }

    /// Get the data organization associated with this data type manager (never `None`).
    ///
    /// No meaningful `DataOrganization` fallback is available yet since no concrete
    /// implementation has been ported; overriding implementations must supply their own.
    fn get_data_organization(&self) -> Box<dyn DataOrganization> {
        unimplemented!("DataTypeManager::get_data_organization has no default implementation yet")
    }

    /// Returns the associated AddressMap used by this datatype manager, or `None` if one has
    /// not been established.
    fn get_address_map(&self) -> Option<Box<dyn AddressMap>> {
        None
    }

    /// Returns a list of source archives not including the builtin or the program's archive.
    fn get_source_archives(&self) -> Vec<Box<dyn SourceArchive>> {
        Vec::new()
    }

    /// Removes the source archive from this manager, disassociating all data types from it.
    fn remove_source_archive(&mut self, source_archive: &dyn SourceArchive) {
        let _ = source_archive;
    }

    /// Returns or creates a persisted version of the given source archive.
    fn resolve_source_archive(&mut self, source_archive: Box<dyn SourceArchive>) -> Box<dyn SourceArchive> {
        source_archive
    }

    /// Returns the data types within this data type manager that contain the specified data
    /// type.
    ///
    /// # Deprecated
    /// Use `DataType::get_parents` instead.
    fn get_data_types_containing(&self, data_type: &dyn DataType) -> Vec<Box<dyn DataType>> {
        let _ = data_type;
        Vec::new()
    }

    /// Determine if settings are supported for BuiltIn datatypes within this datatype manager.
    fn allows_default_built_in_settings(&self) -> bool {
        false
    }

    /// Determine if settings are supported for datatype components (structure/union
    /// components) within this datatype manager.
    fn allows_default_component_settings(&self) -> bool {
        false
    }

    /// Get the ordered list of known calling convention names.
    fn get_known_calling_convention_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get the ordered list of defined calling convention names.
    fn get_defined_calling_convention_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get the default calling convention's prototype model in this data type manager, if
    /// known.
    fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
        None
    }

    /// Get the prototype model of the calling convention with the specified name.
    fn get_calling_convention(&self, name: &str) -> Option<Box<dyn PrototypeModel>> {
        let _ = name;
        None
    }
}

/// No-op [`Transaction`] handle returned by [`DataTypeManager::open_transaction`]'s default
/// implementation.
struct NoOpTransaction;
impl Transaction for NoOpTransaction {}

/// Trivial fallback used by [`DataTypeManager::get_pointer`] and
/// [`DataTypeManager::get_pointer_with_size`]'s default implementations: a pointer to nothing.
struct EmptyPointer;
impl DataType for EmptyPointer {}
impl Pointer for EmptyPointer {
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
        Box::new(EmptyPointer)
    }

    fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
        Box::new(EmptyPointerTypedefBuilder)
    }
}

/// Trivial fallback used by [`EmptyPointer::typedef_builder`].
struct EmptyPointerTypedefBuilder;
impl PointerTypedefBuilder for EmptyPointerTypedefBuilder {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeConflictHandler;
    impl DataTypeConflictHandler for MockDataTypeConflictHandler {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn bare_impl_stays_object_safe() {
        let mgr = MockDataTypeManager;
        let dyn_mgr: &dyn DataTypeManager = &mgr;
        assert_eq!(dyn_mgr.get_name(), "");
        assert!(!dyn_mgr.is_updatable());
        assert!(dyn_mgr.get_all_data_types().is_empty());
        assert_eq!(dyn_mgr.get_type(), ArchiveType::Temporary);
    }

    #[test]
    fn resolve_echoes_input_by_default() {
        let mut mgr = MockDataTypeManager;
        let handler = MockDataTypeConflictHandler;
        let resolved = mgr.resolve(Box::new(MockDataType), &handler);
        assert_eq!(resolved.get_name(), MockDataType.get_name());
    }

    #[test]
    fn add_data_type_delegates_to_resolve() {
        let mut mgr = MockDataTypeManager;
        let handler = MockDataTypeConflictHandler;
        let added = mgr.add_data_type(Box::new(MockDataType), &handler);
        assert_eq!(added.get_length(), 0);
    }

    #[test]
    fn get_unique_name_returns_base_name() {
        let mgr = MockDataTypeManager;
        assert_eq!(
            mgr.get_unique_name(&crate::program::model::data::category_path::ROOT, "temp"),
            "temp"
        );
    }

    #[test]
    fn remove_with_monitor_delegates_to_remove() {
        struct RemovingManager;
        impl DataTypeManager for RemovingManager {
            fn remove(&mut self, _data_type: &dyn DataType) -> bool {
                true
            }
        }
        let mut mgr = RemovingManager;
        let dt = MockDataType;
        let monitor = crate::util::task::DummyMonitor;
        assert!(mgr.remove_with_monitor(&dt, &monitor));
    }

    #[test]
    fn end_transaction_returns_commit_flag() {
        let mut mgr = MockDataTypeManager;
        assert!(mgr.end_transaction(0, true));
        assert!(!mgr.end_transaction(0, false));
    }

    #[test]
    fn with_transaction_commits_and_propagates_result() {
        let mut mgr = MockDataTypeManager;
        let ok: ExceptionalCallback<String> = Box::new(|| Ok(()));
        assert!(mgr.with_transaction("test", ok).is_ok());

        let err: ExceptionalCallback<String> = Box::new(|| Err("boom".to_string()));
        assert!(mgr.with_transaction("test", err).is_err());
    }

    #[test]
    fn with_transaction_result_returns_supplier_value() {
        let mut mgr = MockDataTypeManager;
        let supplier: ExceptionalSupplier<i32, String> = Box::new(|| Ok(42));
        assert_eq!(mgr.with_transaction_result("test", supplier), Ok(42));
    }

    #[test]
    fn get_pointer_default_points_to_nothing() {
        let mgr = MockDataTypeManager;
        let dt = MockDataType;
        let ptr = mgr.get_pointer(&dt);
        assert!(ptr.get_data_type().is_none());
    }

    #[test]
    fn add_data_types_stops_on_cancellation() {
        struct CancellingMonitor;
        impl TaskMonitor for CancellingMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                false
            }
            fn clear_cancelled(&self) {}
        }

        let mut mgr = MockDataTypeManager;
        let handler = MockDataTypeConflictHandler;
        let monitor = CancellingMonitor;
        let result = mgr.add_data_types(vec![Box::new(MockDataType)], &handler, &monitor);
        assert!(result.is_err());
    }
}
