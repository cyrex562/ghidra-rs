use crate::framework::store::FolderItem;

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

    impl FolderItem for MockUnknownFolderItem {
        fn get_name(&self) -> String {
            "MockUnknownFolderItem".to_string()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> std::io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn length(&self) -> std::io::Result<i64> {
            Ok(0)
        }

        fn get_content_type(&self) -> String {
            "Unknown-File".to_string()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            "/MockUnknownFolderItem".to_string()
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn set_read_only(&mut self, _state: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn get_content_type_version(&self) -> i32 {
            1
        }

        fn set_content_type_version(&mut self, _version: i32) -> std::io::Result<()> {
            Ok(())
        }

        fn last_modified(&self) -> i64 {
            0
        }

        fn get_current_version(&self) -> i32 {
            1
        }

        fn is_checked_out(&self) -> bool {
            false
        }

        fn is_checked_out_exclusive(&self) -> bool {
            false
        }

        fn is_versioned(&self) -> std::io::Result<bool> {
            Ok(false)
        }

        fn get_checkout_id(&self) -> std::io::Result<i64> {
            Ok(crate::framework::store::folder_item::DEFAULT_CHECKOUT_ID)
        }

        fn get_checkout_version(&self) -> std::io::Result<i32> {
            Ok(-1)
        }

        fn get_local_checkout_version(&self) -> i32 {
            -1
        }

        fn set_checkout(
            &mut self,
            _checkout_id: i64,
            _exclusive: bool,
            _checkout_version: i32,
            _local_version: i32,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn clear_checkout(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn delete(&mut self, _version: i32, _user: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn get_versions(
            &self,
        ) -> std::io::Result<Option<Vec<crate::framework::store::ItemVersion>>> {
            Ok(None)
        }

        fn checkout(
            &mut self,
            _checkout_type: &dyn crate::framework::store::checkout_type::CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> std::io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>>
        {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "not versioned"))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn has_checkouts(&self) -> std::io::Result<bool> {
            Ok(false)
        }

        fn can_recover(&self) -> bool {
            false
        }

        fn get_checkout(
            &self,
            _checkout_id: i64,
        ) -> std::io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>>
        {
            Ok(None)
        }

        fn get_checkouts(
            &self,
        ) -> std::io::Result<Vec<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(Vec::new())
        }

        fn is_checkin_active(&self) -> std::io::Result<bool> {
            Ok(false)
        }

        fn update_checkout_version(
            &mut self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn output(
            &self,
            _output_file: &std::path::Path,
            _version: i32,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::framework::store::local::OutputItemError> {
            Ok(())
        }

        fn refresh(&mut self) -> std::io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

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
