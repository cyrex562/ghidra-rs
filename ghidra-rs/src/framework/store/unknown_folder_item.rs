use crate::framework::seam_stubs::FolderItem;

/// Corresponds to a folder item which has an unknown storage type or has encountered a storage
/// failure.
///
/// Mirrors `ghidra.framework.store.UnknownFolderItem`, which extends `FolderItem`.
pub trait UnknownFolderItem: FolderItem {
    /// Content type string used for folder items whose storage type is unknown.
    const UNKNOWN_CONTENT_TYPE: &'static str = "Unknown-File";

    /// Get the file type: `FolderItem::DATABASE_FILE_TYPE`, `FolderItem::DATAFILE_FILE_TYPE`, or
    /// `FolderItem::LINK_FILE_TYPE`.
    ///
    /// Returns the file type, or `FolderItem::UNKNOWN_FILE_TYPE` (-1) if unknown.
    fn get_file_type(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUnknownFolderItem {
        file_type: i32,
    }

    impl FolderItem for MockUnknownFolderItem {}

    impl UnknownFolderItem for MockUnknownFolderItem {
        fn get_file_type(&self) -> i32 {
            self.file_type
        }
    }

    #[test]
    fn test_unknown_folder_item_object_safety_and_dispatch() {
        let known: Box<dyn UnknownFolderItem> =
            Box::new(MockUnknownFolderItem { file_type: 2 });
        assert_eq!(known.get_file_type(), 2);

        let unknown: Box<dyn UnknownFolderItem> =
            Box::new(MockUnknownFolderItem { file_type: -1 });
        assert_eq!(unknown.get_file_type(), -1);
    }

    #[test]
    fn test_unknown_content_type_constant() {
        assert_eq!(MockUnknownFolderItem::UNKNOWN_CONTENT_TYPE, "Unknown-File");
    }
}
