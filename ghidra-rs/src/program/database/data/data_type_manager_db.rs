use std::collections::{HashMap, HashSet};
use std::io;

use thiserror::Error;

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use crate::util::UniversalID;

/// Error produced by [`DataTypeManagerDb::get_calling_convention_id`], standing in for the
/// checked `IOException` and `InvalidInputException` declared on the Java method
/// `DataTypeManagerDB.getCallingConventionID(String, boolean)`.
#[derive(Error, Debug)]
pub enum GetCallingConventionIdError {
    #[error("IOException: {0}")]
    Io(String),
    #[error("InvalidInputException: {0}")]
    InvalidInput(String),
}

/// Base for DB-backed data type managers.
///
/// Port of `ghidra.program.database.data.DataTypeManagerDB`.
///
/// This trait was selected as a dependency-cycle cut-point: `DataTypeManagerDB` constructs the
/// DB-backed datatype implementations (`ArrayDB`, `PointerDB`, `StructureDB`,
/// `FunctionDefinitionDB`, ...) and hands each a reference back to itself, while those same
/// classes call package-private bookkeeping methods (`dbError`, `addDataTypeToReplace`,
/// `addDataTypeToDelete`) directly on their owning manager. It was previously modeled as a
/// minimal placeholder (`DataTypeManagerDb` in `seam_stubs.rs`, see `STUBS.tsv`) declaring only
/// those three bookkeeping hooks; this promotes that placeholder in place (same trait name, same
/// three required methods, now joined by the rest of the class's genuinely new public/protected
/// surface) so the four dependent files (`array_db.rs`, `pointer_db.rs`, `structure_db.rs`,
/// `function_definition_db.rs`) keep compiling against the same trait, just from its real home.
///
/// `DataTypeManagerDB implements DataTypeManager`, so this trait is bounded by the already-ported
/// [`DataTypeManager`] rather than re-declaring its methods. Every `@Override` method whose
/// signature exactly matches a [`DataTypeManager`] method (`getProgramArchitecture`,
/// `getFavorites`, `resolve`, `addDataType`, `findDataTypes`, `getDataType(DataTypePath)`,
/// `remove`, `associateDataTypeWithArchive`, `getAllDataTypes`, `close`, `isUpdatable`,
/// `getPointer`, `dataTypeChanged`-vs-`dataTypeSettingsChanged` notwithstanding, etc.) is *not*
/// redeclared here; concrete implementations override those supertrait methods directly.
///
/// What *is* declared here is the genuinely new surface introduced by this abstract base class:
/// the abstract protected extension points concrete DB managers must implement
/// ([`get_domain_file_id`](Self::get_domain_file_id), [`get_path`](Self::get_path),
/// [`replace_data_types_used`](Self::replace_data_types_used),
/// [`delete_data_types_used`](Self::delete_data_types_used)), and the additional public/protected
/// methods that have no equivalent on [`DataTypeManager`] (`notifyRestored`, `updateID`,
/// `getUnusedConflictName` (both overloads), `replaceSourceArchive`, `getDataTypes(CategoryPath)`,
/// `isChanged`, `getSourceArchive(String)`, `dispose`, `invalidateCache`, `sourceArchiveChanged`,
/// `dataTypeChanged`/`dataTypeSettingsChanged` (the DB-internal notification hooks, distinct from
/// any same-named [`DataTypeManager`] method), the calling-convention name/ID mapping methods,
/// `fixupComposites`, `dedupeConflicts`, `dedupeAllConflicts`). The remaining protected extension
/// points (`dataTypeAdded`/`dataTypeReplaced`/`dataTypeDeleted`/`dataTypeMoved`/
/// `dataTypeNameChanged`, `categoryCreated`/`categoryRenamed`/`categoryRemoved`/`categoryMoved`,
/// `favoritesChanged`, `sourceArchiveAdded`, `isCreatingDataType`, `updateLastChangeTime`, the
/// private-database-versioning constructors and adapters) are internal wiring against
/// `CategoryDB`/`DataTypeDB`, which are not yet ported and not part of this cycle; they are left
/// for when those types are promoted.
///
/// Every method is given a default (mirroring the approach taken for [`DataTypeManager`]) so
/// existing bare/near-bare `impl DataTypeManagerDb for MockX {}` blocks stay compiling: the
/// abstract Java methods get trivial fallbacks (empty ID/path, no-op replacement/deletion) since
/// no concrete DB state is available to a default implementation, and the concrete Java methods
/// get behaviorally-faithful defaults where cheap (e.g. `get_unused_conflict_name` echoing the
/// input name) or no-ops otherwise.
pub trait DataTypeManagerDb: DataTypeManager {
    /// Stands in for `DataTypeManagerDB.dbError(IOException)`.
    fn db_error(&mut self, error: io::Error);

    /// Stands in for `DataTypeManagerDB.addDataTypeToReplace(DataTypeDB, DataType)`: schedules
    /// `replacement` to be substituted for the datatype identified by `data_type_id` (its
    /// resolved ID) once the current lock is released, avoiding a duplicate-array conflict.
    fn add_data_type_to_replace(&mut self, data_type_id: i64, replacement: Box<dyn DataType>);

    /// Stands in for `DataTypeManagerDB.addDataTypeToDelete(DataTypeDB, long)`: schedules the
    /// datatype identified by `data_type_id` for deletion once the current lock is released.
    fn add_data_type_to_delete(&mut self, data_type_id: i64);

    /// Stands in for the abstract `DataTypeManagerDB.getDomainFileID()`: the ID of the domain
    /// file backing this archive, or empty if this manager has no associated domain file.
    fn get_domain_file_id(&self) -> String {
        String::new()
    }

    /// Stands in for the abstract `DataTypeManagerDB.getPath()`: this archive's path.
    fn get_path(&self) -> String {
        String::new()
    }

    /// Stands in for the abstract `DataTypeManagerDB.replaceDataTypesUsed(Map)`: allows
    /// extensions to fix up any of their own datatype ID references following a bulk resolve
    /// where the keys were replaced by the values.
    fn replace_data_types_used(&mut self, data_type_replacement_map: &HashMap<i64, i64>) {
        let _ = data_type_replacement_map;
    }

    /// Stands in for the abstract `DataTypeManagerDB.deleteDataTypesUsed(Set)`: allows
    /// extensions to perform any necessary fixups for all datatype removals listed.
    fn delete_data_types_used(&mut self, deleted_ids: &HashSet<i64>) {
        let _ = deleted_ids;
    }

    /// Stands in for `DataTypeManagerDB.notifyRestored()`: notifies listeners that this manager
    /// has just been restored (e.g. undo/redo/rollback).
    fn notify_restored(&mut self) {}

    /// Stands in for `DataTypeManagerDB.updateID()`: refreshes this manager's [`UniversalID`]
    /// from the underlying database ID, invalidating the cached source-archive map.
    fn update_id(&mut self) {}

    /// Stands in for `DataTypeManagerDB.getUnusedConflictName(DataType)`: gets a `.conflict` name
    /// not currently used by any data type in `dt`'s category. Returns `dt`'s own name unchanged
    /// for pointers, arrays, and built-ins, since they cannot be renamed.
    fn get_unused_conflict_name(&self, dt: &dyn DataType) -> String {
        dt.get_name()
    }

    /// Stands in for `DataTypeManagerDB.getUnusedConflictName(CategoryPath, DataType)`: gets a
    /// `.conflict` name not currently used by any data type in the given category. Returns `dt`'s
    /// own name unchanged for pointers, arrays, and built-ins, since they cannot be renamed.
    fn get_unused_conflict_name_in_category(&self, path: &CategoryPath, dt: &dyn DataType) -> String {
        let _ = path;
        dt.get_name()
    }

    /// Stands in for `DataTypeManagerDB.replaceSourceArchive(SourceArchive, SourceArchive)`:
    /// replaces `old_source_archive` with `new_source_archive`, re-sourcing every data type that
    /// referenced the old archive and removing the old archive from this manager.
    fn replace_source_archive(
        &mut self,
        old_source_archive: &dyn SourceArchive,
        new_source_archive: &dyn SourceArchive,
    ) {
        let _ = (old_source_archive, new_source_archive);
    }

    /// Stands in for `DataTypeManagerDB.getDataTypes(CategoryPath)`: gets the datatypes in the
    /// given category path.
    fn get_data_types_in_category(&self, path: &CategoryPath) -> Vec<Box<dyn DataType>> {
        let _ = path;
        Vec::new()
    }

    /// Stands in for `DataTypeManagerDB.isChanged()`.
    fn is_changed(&self) -> bool {
        false
    }

    /// Stands in for `DataTypeManagerDB.getSourceArchive(String fileID)`: finds the source
    /// archive whose domain file ID matches `file_id`.
    fn get_source_archive_by_file_id(&self, file_id: &str) -> Option<Box<dyn SourceArchive>> {
        let _ = file_id;
        None
    }

    /// Stands in for `DataTypeManagerDB.dispose()`: drops lazily-built caches (the sorted
    /// datatype list, the enum value map).
    fn dispose(&mut self) {}

    /// Stands in for `DataTypeManagerDB.invalidateCache()`.
    fn invalidate_cache(&mut self) {}

    /// Stands in for `DataTypeManagerDB.sourceArchiveChanged(UniversalID)`: notifies listeners
    /// that the source archive with the given ID changed.
    fn source_archive_changed(&mut self, source_archive_id: UniversalID) {
        let _ = source_archive_id;
    }

    /// Stands in for `DataTypeManagerDB.dataTypeChanged(DataType, boolean)`: the DB-internal
    /// change notification hook invoked by owned `DataTypeDB` instances (distinct from any
    /// same-named method on [`DataTypeManager`]).
    fn data_type_changed(&mut self, dt: &dyn DataType, is_auto_change: bool) {
        let _ = (dt, is_auto_change);
    }

    /// Stands in for `DataTypeManagerDB.dataTypeSettingsChanged(DataType)`.
    fn data_type_settings_changed(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Stands in for `DataTypeManagerDB.getCallingConventionName(byte)`: gets the calling
    /// convention name corresponding to the given ID, or an "unknown" placeholder if not found.
    fn get_calling_convention_name(&self, id: u8) -> String {
        let _ = id;
        String::new()
    }

    /// Stands in for `DataTypeManagerDB.getCallingConventionID(String, boolean)`: gets (and
    /// assigns if needed) the ID associated with the given calling convention name.
    ///
    /// # Errors
    /// Returns `Err` if a database IO error occurs, or if `restrictive` is true and `name` is not
    /// a known calling convention.
    fn get_calling_convention_id(
        &mut self,
        name: &str,
        restrictive: bool,
    ) -> Result<u8, GetCallingConventionIdError> {
        let _ = (name, restrictive);
        Ok(0)
    }

    /// Stands in for `DataTypeManagerDB.fixupComposites(TaskMonitor)`: fixes up all composites
    /// and their components which may be affected by a data organization change.
    ///
    /// # Errors
    /// Returns `Err` if the monitor is cancelled.
    fn fixup_composites(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        let _ = monitor;
        Ok(())
    }

    /// Stands in for `DataTypeManagerDB.dedupeConflicts(DataType)`: de-duplicates equivalent
    /// conflict datatypes sharing a common base data type name as `data_type`. Returns true if
    /// one or more datatypes were de-duplicated.
    fn dedupe_conflicts(&mut self, data_type: &dyn DataType) -> bool {
        let _ = data_type;
        false
    }

    /// Stands in for `DataTypeManagerDB.dedupeAllConflicts(TaskMonitor)`: de-duplicates
    /// equivalent conflict datatypes throughout this manager.
    ///
    /// # Errors
    /// Returns `Err` if the monitor is cancelled.
    fn dedupe_all_conflicts(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        let _ = monitor;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType {
        name: String,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockManager {
        errors: Vec<String>,
        replacements: Vec<(i64, String)>,
        deletions: Vec<i64>,
    }

    impl DataTypeManager for MockManager {}

    impl DataTypeManagerDb for MockManager {
        fn db_error(&mut self, error: io::Error) {
            self.errors.push(error.to_string());
        }

        fn add_data_type_to_replace(&mut self, data_type_id: i64, replacement: Box<dyn DataType>) {
            self.replacements.push((data_type_id, replacement.get_name()));
        }

        fn add_data_type_to_delete(&mut self, data_type_id: i64) {
            self.deletions.push(data_type_id);
        }

        fn get_domain_file_id(&self) -> String {
            "domain-file-42".to_string()
        }

        fn is_changed(&self) -> bool {
            true
        }
    }

    #[test]
    fn usable_as_trait_object_and_dispatches_required_methods() {
        let mut mgr = MockManager {
            errors: Vec::new(),
            replacements: Vec::new(),
            deletions: Vec::new(),
        };

        {
            let dyn_mgr: &mut dyn DataTypeManagerDb = &mut mgr;
            dyn_mgr.db_error(io::Error::new(io::ErrorKind::Other, "boom"));
            dyn_mgr.add_data_type_to_replace(7, Box::new(MockDataType { name: "int".into() }));
            dyn_mgr.add_data_type_to_delete(9);
            assert_eq!(dyn_mgr.get_domain_file_id(), "domain-file-42");
            assert!(dyn_mgr.is_changed());
            // Untouched abstract/behavioral defaults still return sane, documented fallbacks.
            assert_eq!(dyn_mgr.get_path(), "");
            assert!(!dyn_mgr.dedupe_conflicts(&MockDataType { name: "foo".into() }));
        }

        assert_eq!(mgr.errors, vec!["boom".to_string()]);
        assert_eq!(mgr.replacements, vec![(7, "int".to_string())]);
        assert_eq!(mgr.deletions, vec![9]);
    }

    #[test]
    fn get_unused_conflict_name_default_echoes_input_name() {
        struct BareManager;
        impl DataTypeManager for BareManager {}
        impl DataTypeManagerDb for BareManager {
            fn db_error(&mut self, _error: io::Error) {}
            fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
            fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
        }

        let mgr = BareManager;
        let dt = MockDataType { name: "Foo.conflict".to_string() };
        assert_eq!(mgr.get_unused_conflict_name(&dt), "Foo.conflict");
        assert_eq!(
            mgr.get_unused_conflict_name_in_category(&crate::program::model::data::category_path::ROOT, &dt),
            "Foo.conflict"
        );
    }

    #[test]
    fn fixup_composites_default_succeeds_with_dummy_monitor() {
        struct BareManager;
        impl DataTypeManager for BareManager {}
        impl DataTypeManagerDb for BareManager {
            fn db_error(&mut self, _error: io::Error) {}
            fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
            fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
        }

        let mut mgr = BareManager;
        let monitor = crate::util::task::DummyMonitor;
        assert!(mgr.fixup_composites(&monitor).is_ok());
        assert!(mgr.dedupe_all_conflicts(&monitor).is_ok());
    }
}
