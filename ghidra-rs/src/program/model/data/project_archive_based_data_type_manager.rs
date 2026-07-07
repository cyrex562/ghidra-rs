use crate::program::model::data::domain_file_based_data_type_manager::DomainFileBasedDataTypeManager;

/// A [`DomainFileBasedDataTypeManager`] specific to project data type archives.
///
/// Port of `ghidra.program.model.data.ProjectArchiveBasedDataTypeManager`.
pub trait ProjectArchiveBasedDataTypeManager: DomainFileBasedDataTypeManager {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainFile;
    use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
    use crate::program::model::data::data_type_manager::DataTypeManager;

    struct MockDomainFile;

    impl DomainFile for MockDomainFile {}

    struct MockProjectArchive {
        path: String,
    }

    impl DataTypeManager for MockProjectArchive {}

    impl FileBasedDataTypeManager for MockProjectArchive {
        fn get_path(&self) -> String {
            self.path.clone()
        }
    }

    impl DomainFileBasedDataTypeManager for MockProjectArchive {
        fn get_domain_file(&self) -> Box<dyn DomainFile> {
            Box::new(MockDomainFile)
        }
    }

    impl ProjectArchiveBasedDataTypeManager for MockProjectArchive {}

    #[test]
    fn usable_as_trait_object() {
        let mgr = MockProjectArchive { path: "/tmp/archive.gpr".to_string() };
        let dyn_mgr: &dyn ProjectArchiveBasedDataTypeManager = &mgr;
        assert_eq!(dyn_mgr.get_path(), "/tmp/archive.gpr");
        let _domain_file = dyn_mgr.get_domain_file();
    }
}
