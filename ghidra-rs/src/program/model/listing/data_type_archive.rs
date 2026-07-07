use std::time::SystemTime;

use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
use crate::program::model::listing::data_type_archive_change_set::DataTypeArchiveChangeSet;
use crate::program::seam_stubs::StandAloneDataTypeManager;

/// Name of data type archive information property list.
pub const DATA_TYPE_ARCHIVE_INFO: &str = "Data Type Archive Information";
/// Name of data type archive settings property list.
pub const DATA_TYPE_ARCHIVE_SETTINGS: &str = "Data Type Archive Settings";
/// Name of date created property.
pub const DATE_CREATED: &str = "Date Created";
/// Name of ghidra version property.
pub const CREATED_WITH_GHIDRA_VERSION: &str = "Created With Ghidra Version";
/// A date from January 1, 1970.
pub const JANUARY_1_1970: SystemTime = SystemTime::UNIX_EPOCH;

/// The main entry point into an object which stores all information relating to a single data
/// type archive.
///
/// Port of `ghidra.program.model.listing.DataTypeArchive`.
pub trait DataTypeArchive: DataTypeManagerDomainObject {
    /// Gets the associated standalone data type manager.
    ///
    /// Narrows the return type of
    /// [`DataTypeManagerOwner::get_data_type_manager`](crate::program::seam_stubs::DataTypeManagerOwner::get_data_type_manager),
    /// which this trait also inherits (via [`DataTypeManagerDomainObject`]); use fully qualified
    /// syntax to call the desired one when both are in scope for the same value.
    fn get_data_type_manager(&self) -> Box<dyn StandAloneDataTypeManager>;

    /// Gets the default pointer size as it may be stored within the data type archive.
    fn get_default_pointer_size(&self) -> i32;

    /// Gets the creation date of this data type archive, or [`JANUARY_1_1970`] if unknown.
    fn get_creation_date(&self) -> SystemTime;

    /// Gets the data type archive changes since the last save as a set of addresses.
    fn get_changes(&self) -> Box<dyn DataTypeArchiveChangeSet>;

    /// Invalidates any caching in a data type archive.
    ///
    /// NOTE: Over-using this method can adversely affect system performance.
    fn invalidate(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::seam_stubs::DataTypeManagerOwner;

    struct MockStandAloneDataTypeManager;

    impl StandAloneDataTypeManager for MockStandAloneDataTypeManager {}

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct MockChangeSet;

    impl crate::framework::model::ChangeSet for MockChangeSet {}

    impl crate::program::model::listing::domain_object_change_set::DomainObjectChangeSet
        for MockChangeSet
    {
        fn has_changes(&self) -> bool {
            false
        }
    }

    impl crate::program::model::listing::data_type_change_set::DataTypeChangeSet for MockChangeSet {
        fn data_type_changed(&mut self, _id: i64) {}
        fn data_type_added(&mut self, _id: i64) {}
        fn get_data_type_changes(&self) -> &[i64] {
            &[]
        }
        fn get_data_type_additions(&self) -> &[i64] {
            &[]
        }
        fn category_changed(&mut self, _id: i64) {}
        fn category_added(&mut self, _id: i64) {}
        fn get_category_changes(&self) -> &[i64] {
            &[]
        }
        fn get_category_additions(&self) -> &[i64] {
            &[]
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

    struct MockDataTypeArchive {
        invalidated: bool,
    }

    impl DomainObject for MockDataTypeArchive {}

    impl DataTypeManagerOwner for MockDataTypeArchive {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockDataTypeArchive {}

    impl DataTypeArchive for MockDataTypeArchive {
        fn get_data_type_manager(&self) -> Box<dyn StandAloneDataTypeManager> {
            Box::new(MockStandAloneDataTypeManager)
        }

        fn get_default_pointer_size(&self) -> i32 {
            8
        }

        fn get_creation_date(&self) -> SystemTime {
            JANUARY_1_1970
        }

        fn get_changes(&self) -> Box<dyn DataTypeArchiveChangeSet> {
            Box::new(MockChangeSet)
        }

        fn invalidate(&mut self) {
            self.invalidated = true;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut archive = MockDataTypeArchive { invalidated: false };
        let _mgr = DataTypeArchive::get_data_type_manager(&archive);
        assert_eq!(archive.get_default_pointer_size(), 8);
        assert_eq!(archive.get_creation_date(), JANUARY_1_1970);
        let changes = archive.get_changes();
        assert!(!changes.has_changes());

        let dyn_archive: &mut dyn DataTypeArchive = &mut archive;
        dyn_archive.invalidate();
        assert!(archive.invalidated);
    }
}
