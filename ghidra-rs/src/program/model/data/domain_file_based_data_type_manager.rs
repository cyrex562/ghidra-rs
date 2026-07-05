use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
use crate::program::seam_stubs::DomainFile;

/// Extends [`FileBasedDataTypeManager`] to provide methods specific to a data type manager
/// stored as a domain file.
///
/// Port of `ghidra.program.model.data.DomainFileBasedDataTypeManager`.
pub trait DomainFileBasedDataTypeManager: FileBasedDataTypeManager {
    /// Gets the domain file backing this data type manager.
    fn get_domain_file(&self) -> Box<dyn DomainFile>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::seam_stubs::DataTypeManager;

    struct MockDomainFile;

    impl DomainFile for MockDomainFile {}

    struct MockDomainFileArchive {
        path: String,
    }

    impl DataTypeManager for MockDomainFileArchive {}

    impl FileBasedDataTypeManager for MockDomainFileArchive {
        fn get_path(&self) -> String {
            self.path.clone()
        }
    }

    impl DomainFileBasedDataTypeManager for MockDomainFileArchive {
        fn get_domain_file(&self) -> Box<dyn DomainFile> {
            Box::new(MockDomainFile)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mgr = MockDomainFileArchive { path: "/tmp/archive.gpr".to_string() };
        let dyn_mgr: &dyn DomainFileBasedDataTypeManager = &mgr;
        assert_eq!(dyn_mgr.get_path(), "/tmp/archive.gpr");
        let _domain_file = dyn_mgr.get_domain_file();
    }
}
