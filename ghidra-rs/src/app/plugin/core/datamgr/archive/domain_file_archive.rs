use crate::app::seam_stubs::Archive;
use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_object::DomainObject;

/// Port of `ghidra.app.plugin.core.datamgr.archive.DomainFileArchive`.
///
/// An archive that is backed by a [`DomainFile`] and can provide access to the underlying
/// [`DomainObject`]. This interface extends [`Archive`] to add domain-file-specific capabilities.
pub trait DomainFileArchive: Archive {
    /// Returns the domain file that backs this archive.
    ///
    /// Mirrors `DomainFileArchive.getDomainFile()`.
    fn get_domain_file(&self) -> Box<dyn DomainFile>;

    /// Returns the domain object associated with this archive.
    ///
    /// Mirrors `DomainFileArchive.getDomainObject()`.
    fn get_domain_object(&self) -> Box<dyn DomainObject>;

    /// Checks whether this archive has exclusive access to its underlying resource.
    ///
    /// Mirrors `DomainFileArchive.hasExclusiveAccess()`.
    fn has_exclusive_access(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal mock implementation of `DomainFileArchive` for testing.
    struct MockDomainFileArchive;

    impl Archive for MockDomainFileArchive {}

    impl DomainFileArchive for MockDomainFileArchive {
        fn get_domain_file(&self) -> Box<dyn DomainFile> {
            unimplemented!("mock implementation")
        }

        fn get_domain_object(&self) -> Box<dyn DomainObject> {
            unimplemented!("mock implementation")
        }

        fn has_exclusive_access(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_domain_file_archive_trait_object_castable_to_archive() {
        let archive: &dyn DomainFileArchive = &MockDomainFileArchive;
        // Verify it can be cast to Archive, which demonstrates the trait hierarchy
        let _as_archive: &dyn Archive = archive;
    }

    #[test]
    fn test_domain_file_archive_has_exclusive_access_method() {
        let archive = MockDomainFileArchive;
        assert!(archive.has_exclusive_access());
    }
}
