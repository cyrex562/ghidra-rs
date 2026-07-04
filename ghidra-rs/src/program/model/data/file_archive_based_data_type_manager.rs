use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;

/// A [`FileBasedDataTypeManager`] specific to file data type archives (.gdt).
///
/// Port of `ghidra.program.model.data.FileArchiveBasedDataTypeManager`.
pub trait FileArchiveBasedDataTypeManager: FileBasedDataTypeManager {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::seam_stubs::DataTypeManager;

    struct MockFileArchive {
        path: String,
    }

    impl DataTypeManager for MockFileArchive {}

    impl FileBasedDataTypeManager for MockFileArchive {
        fn get_path(&self) -> String {
            self.path.clone()
        }
    }

    impl FileArchiveBasedDataTypeManager for MockFileArchive {}

    #[test]
    fn usable_as_trait_object() {
        let mgr = MockFileArchive { path: "/tmp/archive.gdt".to_string() };
        let dyn_mgr: &dyn FileArchiveBasedDataTypeManager = &mgr;
        assert_eq!(dyn_mgr.get_path(), "/tmp/archive.gdt");
    }
}
