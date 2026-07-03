use crate::program::seam_stubs::DataTypeManager;

/// A [`DataTypeManager`] whose contents are backed by a file on disk (e.g. a standalone
/// archive), exposing the path to that file.
///
/// Port of `ghidra.program.model.data.FileBasedDataTypeManager`.
pub trait FileBasedDataTypeManager: DataTypeManager {
    /// Returns the path to the backing file for this data type manager.
    fn get_path(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFileArchive {
        path: String,
    }

    impl DataTypeManager for MockFileArchive {}

    impl FileBasedDataTypeManager for MockFileArchive {
        fn get_path(&self) -> String {
            self.path.clone()
        }
    }

    #[test]
    fn get_path_returns_expected_value() {
        let mgr = MockFileArchive { path: "/tmp/archive.gdt".to_string() };
        assert_eq!(mgr.get_path(), "/tmp/archive.gdt");
    }

    #[test]
    fn usable_as_trait_object() {
        let mgr = MockFileArchive { path: "/tmp/archive.gdt".to_string() };
        let dyn_mgr: &dyn FileBasedDataTypeManager = &mgr;
        assert_eq!(dyn_mgr.get_path(), "/tmp/archive.gdt");
    }
}
