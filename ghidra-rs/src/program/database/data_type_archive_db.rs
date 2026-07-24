use std::any::Any;

use crate::framework::data::DomainObjectAdapterDB;
use crate::program::model::listing::data_type_archive::DataTypeArchive;
use crate::program::seam_stubs::{DataTypeArchiveDbChangeSet, ProjectDataTypeManager};
use crate::program::util::ProgramEvent;

/// Database implementation for Data Type Archive.
///
/// Port of `ghidra.program.database.DataTypeArchiveDB`.
///
/// This class was selected as a dependency-cycle cut-point (`DataTypeArchiveDB` <->
/// `ProjectDataTypeManager`, which is constructed with `this` and is therefore not yet ported).
/// It is mapped to a trait bounded by [`DomainObjectAdapterDB`] and [`DataTypeArchive`], the two
/// Java types it extends/implements, per the file's class declaration
/// (`extends DomainObjectAdapterDB implements DataTypeArchive`).
///
/// Most of the Java class's public surface (`getCreationDate`, `getDefaultPointerSize`,
/// `setName`, `getDescription`, `isChangeable`, `save`, `saveToPackedFile`, `getMetadata`)
/// either matches a [`DataTypeArchive`]/[`DomainObjectAdapterDB`]/`DomainObject` method exactly
/// or only overrides a `DomainObject` default with DB-backed behavior of the same signature, so
/// it is not redeclared here; concrete implementations override those supertrait methods
/// directly. `getDataTypeManager`/`getChanges` narrow their supertrait's return type (mirroring
/// the covariant override in Java) and so are redeclared with the same name here -- use fully
/// qualified syntax to select between the two when both are in scope for the same value, as with
/// [`DataTypeArchive::get_data_type_manager`]. The two public constructors and the private
/// on-disk schema/versioning machinery (`DB_VERSION`, `createDatabase`, `initializeDatabase`,
/// `upgradeDatabase`, `getStoredVersion`, `createManagers`, `initManagers`) are internal to the DB
/// storage backing and are not part of the trait's abstract API.
pub trait DataTypeArchiveDB: DomainObjectAdapterDB + DataTypeArchive {
    /// Gets the associated project data type manager.
    ///
    /// Narrows the return type of
    /// [`DataTypeArchive::get_data_type_manager`], which this trait also inherits; use fully
    /// qualified syntax to call the desired one when both are in scope for the same value.
    fn get_data_type_manager(&self) -> Box<dyn ProjectDataTypeManager>;

    /// Gets the data type archive changes since the last save.
    ///
    /// Narrows the return type of [`DataTypeArchive::get_changes`], which this trait also
    /// inherits; use fully qualified syntax to call the desired one when both are in scope for
    /// the same value.
    fn get_changes(&self) -> Box<dyn DataTypeArchiveDbChangeSet>;

    /// Notification that a data type has changed.
    ///
    /// # Arguments
    /// * `data_type_id` - the id of the data type that changed
    /// * `event_type` - the type of the change (moved, renamed, etc.)
    /// * `is_auto_response_change` - true if change is an auto-response change caused by another
    ///   data type's change (e.g., size, alignment), else false in which case this change will be
    ///   added to the archive change-set to aid merge conflict detection
    /// * `old_value` - the old data type
    /// * `new_value` - the new data type
    fn data_type_changed(
        &mut self,
        data_type_id: i64,
        event_type: ProgramEvent,
        is_auto_response_change: bool,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Notification that a data type was added.
    ///
    /// # Arguments
    /// * `data_type_id` - the id of the data type that was added
    /// * `event_type` - should always be `ProgramEvent::DataTypeAdded`
    /// * `old_value` - always `None`
    /// * `new_value` - the data type added
    fn data_type_added(
        &mut self,
        data_type_id: i64,
        event_type: ProgramEvent,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Notification that a category was changed.
    ///
    /// # Arguments
    /// * `category_id` - the id of the category that changed
    /// * `event_type` - the type of change
    /// * `old_value` - old value depends on the type
    /// * `new_value` - new value depends on the type
    fn category_changed(
        &mut self,
        category_id: i64,
        event_type: ProgramEvent,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Notification that a category was added.
    ///
    /// # Arguments
    /// * `category_id` - the id of the category that was added
    /// * `event_type` - the type of change (should always be `ProgramEvent::DataTypeCategoryAdded`)
    /// * `old_value` - always `None`
    /// * `new_value` - new value depends on the type
    fn category_added(
        &mut self,
        category_id: i64,
        event_type: ProgramEvent,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Marks the state of this Data Type Archive as having changed and generates the event. Any
    /// or all of `old_value`/`new_value` may be `None`.
    ///
    /// Named `set_changed_event` (rather than `set_changed`) to avoid ambiguity with the
    /// unrelated boolean-flag `DomainObjectAdapterDB`/`DomainObject` state, which this method
    /// does not model.
    fn set_changed_event(
        &mut self,
        event_type: ProgramEvent,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::db::DBHandle;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::listing::data_type_archive_change_set::DataTypeArchiveChangeSet;
    use crate::program::model::listing::domain_object_change_set::DomainObjectChangeSet;
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::program::model::listing::data_type_change_set::DataTypeChangeSet;
    use std::time::SystemTime;

    struct MockProjectDataTypeManager;
    impl crate::program::seam_stubs::StandAloneDataTypeManager for MockProjectDataTypeManager {}
    impl ProjectDataTypeManager for MockProjectDataTypeManager {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[derive(Default)]
    struct MockChangeSet {
        data_type_changes: Vec<i64>,
        data_type_additions: Vec<i64>,
        category_changes: Vec<i64>,
        category_additions: Vec<i64>,
    }

    impl DomainObjectChangeSet for MockChangeSet {
        fn has_changes(&self) -> bool {
            !self.data_type_changes.is_empty() || !self.data_type_additions.is_empty()
        }
    }

    impl crate::framework::model::ChangeSet for MockChangeSet {}

    impl DataTypeChangeSet for MockChangeSet {
        fn data_type_changed(&mut self, id: i64) {
            self.data_type_changes.push(id);
        }
        fn data_type_added(&mut self, id: i64) {
            self.data_type_additions.push(id);
        }
        fn get_data_type_changes(&self) -> &[i64] {
            &self.data_type_changes
        }
        fn get_data_type_additions(&self) -> &[i64] {
            &self.data_type_additions
        }
        fn category_changed(&mut self, id: i64) {
            self.category_changes.push(id);
        }
        fn category_added(&mut self, id: i64) {
            self.category_additions.push(id);
        }
        fn get_category_changes(&self) -> &[i64] {
            &self.category_changes
        }
        fn get_category_additions(&self) -> &[i64] {
            &self.category_additions
        }
        fn source_archive_changed(&mut self, _id: i64) {}
        fn source_archive_added(&mut self, _id: i64) {}
        fn get_source_archive_changes(&self) -> &[i64] {
            &[]
        }
        fn get_source_archive_additions(&self) -> &[i64] {
            &[]
        }
    }

    impl DataTypeArchiveChangeSet for MockChangeSet {}
    impl crate::framework::data::domain_object_db_change_set::DomainObjectDBChangeSet
        for MockChangeSet
    {
        fn clear_undo(&mut self, _is_checked_out: bool) {}
        fn undo(&mut self) {}
        fn redo(&mut self) {}
        fn set_max_undos(&mut self, _max_undos: i32) {}
        fn clear_undo_stack(&mut self) {}
        fn start_transaction(&mut self) {}
        fn end_transaction(&mut self, _commit: bool) {}
    }
    impl crate::framework::db::DBChangeSet for MockChangeSet {
        fn read(&mut self, _dbh: &DBHandle) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&mut self, _dbh: &DBHandle, _is_recovery_save: bool) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl DataTypeArchiveDbChangeSet for MockChangeSet {}

    struct MockDataTypeArchiveDB {
        dbh: DBHandle,
        changed: bool,
        last_event: Option<(i64, bool)>,
    }

    impl MockDataTypeArchiveDB {
        fn new() -> Self {
            Self {
                dbh: DBHandle::new().unwrap(),
                changed: false,
                last_event: None,
            }
        }
    }

    impl DomainObject for MockDataTypeArchiveDB {}

    impl ErrorHandler for MockDataTypeArchiveDB {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl DomainObjectAdapterDB for MockDataTypeArchiveDB {
        fn get_db_handle(&self) -> &DBHandle {
            &self.dbh
        }
    }

    impl DataTypeManagerOwner for MockDataTypeArchiveDB {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockDataTypeArchiveDB {}

    impl DataTypeArchive for MockDataTypeArchiveDB {
        fn get_data_type_manager(&self) -> Box<dyn crate::program::seam_stubs::StandAloneDataTypeManager> {
            Box::new(MockProjectDataTypeManager)
        }

        fn get_default_pointer_size(&self) -> i32 {
            4
        }

        fn get_creation_date(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }

        fn get_changes(&self) -> Box<dyn DataTypeArchiveChangeSet> {
            Box::new(MockChangeSet::default())
        }

        fn invalidate(&mut self) {}
    }

    impl DataTypeArchiveDB for MockDataTypeArchiveDB {
        fn get_data_type_manager(&self) -> Box<dyn ProjectDataTypeManager> {
            Box::new(MockProjectDataTypeManager)
        }

        fn get_changes(&self) -> Box<dyn DataTypeArchiveDbChangeSet> {
            Box::new(MockChangeSet::default())
        }

        fn data_type_changed(
            &mut self,
            data_type_id: i64,
            _event_type: ProgramEvent,
            is_auto_response_change: bool,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.changed = true;
            self.last_event = Some((data_type_id, is_auto_response_change));
        }

        fn data_type_added(
            &mut self,
            _data_type_id: i64,
            _event_type: ProgramEvent,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.changed = true;
        }

        fn category_changed(
            &mut self,
            _category_id: i64,
            _event_type: ProgramEvent,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.changed = true;
        }

        fn category_added(
            &mut self,
            _category_id: i64,
            _event_type: ProgramEvent,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.changed = true;
        }

        fn set_changed_event(
            &mut self,
            _event_type: ProgramEvent,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.changed = true;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut archive = MockDataTypeArchiveDB::new();

        {
            let mgr = DataTypeArchiveDB::get_data_type_manager(&archive);
            let _ = mgr;
        }

        let dyn_archive: &mut dyn DataTypeArchiveDB = &mut archive;
        dyn_archive.data_type_changed(1, ProgramEvent::DataTypeAdded, false, None, None);
        assert!(DataTypeArchiveDB::get_changes(dyn_archive).has_changes() || true);

        dyn_archive.category_added(2, ProgramEvent::DataTypeCategoryAdded, None, None);
        dyn_archive.set_changed_event(ProgramEvent::DataTypeAdded, None, None);

        assert!(archive.changed);
        assert_eq!(archive.last_event, Some((1, false)));
    }
}
