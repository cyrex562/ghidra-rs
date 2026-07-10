//! A service that manages a set of data type archives, allowing re-use of already open archives.
//!
//! Port of `ghidra.app.services.DataTypeArchiveService`. The Java `@ServiceInfo` annotation
//! (default provider `DataTypeManagerPlugin`) has no Rust equivalent and is omitted. Java's
//! overloaded `openArchive` methods each get a distinct Rust name, since Rust traits cannot
//! overload on parameter type/arity alone.

use std::io;
use std::path::Path;

use thiserror::Error;

use crate::app::plugin::core::datamgr::archive::DuplicateIdException;
use crate::app::seam_stubs::Archive;
use crate::framework::model::DomainFile;
use crate::generic::jar::ResourceFile;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::listing::DataTypeArchive;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `DataTypeArchiveService.openDataTypeArchive`,
/// `openArchive(ResourceFile, boolean)`, and `openArchive(File, boolean)`, all of which declare
/// only `IOException` and `DuplicateIdException`.
#[derive(Error, Debug)]
pub enum OpenArchiveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Duplicate(#[from] DuplicateIdException),
}

/// Combines the checked exceptions declared on `DataTypeArchiveService.openArchive(DomainFile,
/// TaskMonitor)`.
#[derive(Error, Debug)]
pub enum OpenProjectArchiveError {
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Duplicate(#[from] DuplicateIdException),
}

/// A service that manages a set of data type archives, allowing re-use of already open archives.
pub trait DataTypeArchiveService {
    /// Get the data type manager that has all of the built in types.
    fn get_built_in_data_types_manager(&self) -> Box<dyn DataTypeManager>;

    /// Gets the open data type managers.
    fn get_data_type_managers(&self) -> Vec<Box<dyn DataTypeManager>>;

    /// Closes the archive for the given [`DataTypeManager`]. This will ignore requests to close
    /// the open Program's manager and the built-in manager.
    fn close_archive(&self, dtm: &dyn DataTypeManager);

    /// Opens a data type archive that was built into the Ghidra installation.
    ///
    /// NOTE: This is predicated upon all archive files having a unique name within the
    /// installation.
    ///
    /// Any path prefix specified may prevent the file from opening (or reopening) correctly.
    ///
    /// # Errors
    /// Returns `Err` if an i/o error occurs opening the data type archive, or another archive
    /// with the same ID is already open.
    fn open_data_type_archive(
        &self,
        archive_name: &str,
    ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError>;

    /// Opens the specified gdt (file based) data type archive.
    ///
    /// # Errors
    /// Returns `Err` if an i/o error occurs opening the data type archive, or another archive
    /// with the same ID is already open.
    fn open_archive(
        &self,
        file: &ResourceFile,
        acquire_write_lock: bool,
    ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError>;

    /// Opens the specified project-located data type archive.
    ///
    /// # Errors
    /// Returns `Err` if there is a version exception, the user cancels, an i/o error occurs
    /// opening the data type archive, or another archive with the same ID is already open.
    fn open_project_archive(
        &self,
        domain_file: &dyn DomainFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DataTypeManager>, OpenProjectArchiveError>;

    /// A method to open an [`Archive`] for the given, pre-existing [`DataTypeArchive`] (like one
    /// that was opened during the import process).
    #[deprecated]
    fn open_archive_for_data_type_archive(
        &self,
        data_type_archive: &dyn DataTypeArchive,
    ) -> Box<dyn Archive>;

    /// A method to open an [`Archive`] for the given, pre-existing archive file (*.gdt).
    ///
    /// # Errors
    /// Returns `Err` if an i/o error occurs opening the data type archive, or another archive
    /// with the same ID is already open.
    #[deprecated]
    fn open_archive_file(
        &self,
        file: &Path,
        acquire_write_lock: bool,
    ) -> Result<Box<dyn Archive>, OpenArchiveError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockArchive;
    impl Archive for MockArchive {}

    struct MockDataTypeArchive;
    impl crate::framework::model::DomainObject for MockDataTypeArchive {}
    impl crate::program::seam_stubs::DataTypeManagerOwner for MockDataTypeArchive {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockDataTypeArchive
    {
    }
    impl DataTypeArchive for MockDataTypeArchive {
        fn get_data_type_manager(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::StandAloneDataTypeManager> {
            struct MockStandAlone;
            impl crate::program::seam_stubs::StandAloneDataTypeManager for MockStandAlone {}
            Box::new(MockStandAlone)
        }

        fn get_default_pointer_size(&self) -> i32 {
            8
        }

        fn get_creation_date(&self) -> std::time::SystemTime {
            crate::program::model::listing::data_type_archive::JANUARY_1_1970
        }

        fn get_changes(
            &self,
        ) -> Box<dyn crate::program::model::listing::DataTypeArchiveChangeSet> {
            struct MockChangeSet;
            impl crate::framework::model::ChangeSet for MockChangeSet {}
            impl crate::program::model::listing::domain_object_change_set::DomainObjectChangeSet
                for MockChangeSet
            {
                fn has_changes(&self) -> bool {
                    false
                }
            }
            impl crate::program::model::listing::data_type_change_set::DataTypeChangeSet
                for MockChangeSet
            {
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
            impl crate::program::model::listing::DataTypeArchiveChangeSet for MockChangeSet {}
            Box::new(MockChangeSet)
        }

        fn invalidate(&mut self) {}
    }

    struct MockService;

    impl DataTypeArchiveService for MockService {
        fn get_built_in_data_types_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }

        fn get_data_type_managers(&self) -> Vec<Box<dyn DataTypeManager>> {
            vec![Box::new(MockDataTypeManager)]
        }

        fn close_archive(&self, _dtm: &dyn DataTypeManager) {}

        fn open_data_type_archive(
            &self,
            _archive_name: &str,
        ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_archive(
            &self,
            _file: &ResourceFile,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn DataTypeManager>, OpenArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_project_archive(
            &self,
            _domain_file: &dyn DomainFile,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DataTypeManager>, OpenProjectArchiveError> {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_archive_for_data_type_archive(
            &self,
            _data_type_archive: &dyn DataTypeArchive,
        ) -> Box<dyn Archive> {
            Box::new(MockArchive)
        }

        fn open_archive_file(
            &self,
            _file: &Path,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn Archive>, OpenArchiveError> {
            Ok(Box::new(MockArchive))
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn DataTypeArchiveService> = Box::new(MockService);
        let _built_in = service.get_built_in_data_types_manager();
        assert_eq!(service.get_data_type_managers().len(), 1);
        service.close_archive(&MockDataTypeManager);
        assert!(service.open_data_type_archive("generic_C_lib").is_ok());
        let archive = MockDataTypeArchive;
        let _archive = service.open_archive_for_data_type_archive(&archive);
    }
}
