use crate::framework::store::FolderItem;

/// Corresponds to a file which contains text data only and relies only on property file storage
/// (i.e., no separate database or data file).
///
/// Mirrors `ghidra.framework.store.TextDataItem`, which extends `FolderItem`.
pub trait TextDataItem: FolderItem {
    /// Get the text data that was stored with this item.
    fn get_text_data(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTextDataItem {
        text: String,
    }

    impl FolderItem for MockTextDataItem {
        fn get_name(&self) -> String {
            "MockTextDataItem".to_string()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> std::io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn length(&self) -> std::io::Result<i64> {
            Ok(self.text.len() as i64)
        }

        fn get_content_type(&self) -> String {
            "Text".to_string()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            "/MockTextDataItem".to_string()
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

    impl TextDataItem for MockTextDataItem {
        fn get_text_data(&self) -> String {
            self.text.clone()
        }
    }

    #[test]
    fn test_text_data_item_object_safety_and_dispatch() {
        let item: Box<dyn TextDataItem> = Box::new(MockTextDataItem {
            text: "hello world".to_string(),
        });

        assert_eq!(item.get_text_data(), "hello world");
    }
}
