use std::io;

use crate::framework::db::buffers::ManagedBufferFile;
use crate::framework::store::FolderItem;

/// A private or versioned database within a FileSystem. Methods are provided for opening the
/// underlying database as a `BufferFile`.
///
/// Mirrors `ghidra.framework.store.DatabaseItem`, which extends `FolderItem`.
pub trait DatabaseItem: FolderItem {
    /// Open a specific version of the stored database for non-update use. Historical change
    /// data from `min_change_data_ver` through `version` is available. The returned buffer file
    /// does not support the BufferMgr's Save operation.
    ///
    /// `min_change_data_ver` indicates the oldest change data version to be included in the
    /// change set. A value of -1 indicates only the last change data buffer file is applicable.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `FileInUseException` if unable to obtain the required database
    /// lock(s)) or another IO error.
    fn open_with_change_data(
        &mut self,
        version: i32,
        min_change_data_ver: i32,
    ) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Open a specific version of the stored database for non-update use. Change data will not
    /// be available. The returned buffer file does not support the BufferMgr's Save operation.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `FileInUseException` if unable to obtain the required database
    /// lock(s)) or another IO error.
    fn open_version(&mut self, version: i32) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Open the current version of the stored database for non-update use. Change data will not
    /// be available. The returned buffer file does not support the BufferMgr's Save operation.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn open(&mut self) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Open the current version of the stored database for update use. The returned buffer file
    /// supports the Save operation. If this item is on a shared file-system, this method
    /// initiates an item checkin.
    ///
    /// `checkout_id` is the associated checkout ID if this item is stored on a versioned
    /// file-system, otherwise `FolderItem::DEFAULT_CHECKOUT_ID` can be specified.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `FileInUseException` if unable to obtain the required database
    /// lock(s)) or another IO error.
    fn open_for_update(&mut self, checkout_id: i64) -> io::Result<Box<dyn ManagedBufferFile>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDatabaseItem;

    impl FolderItem for MockDatabaseItem {
        fn get_name(&self) -> String {
            "MockDatabaseItem".to_string()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn length(&self) -> io::Result<i64> {
            Ok(0)
        }

        fn get_content_type(&self) -> String {
            "Database".to_string()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            "/MockDatabaseItem".to_string()
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn set_read_only(&mut self, _state: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_content_type_version(&self) -> i32 {
            1
        }

        fn set_content_type_version(&mut self, _version: i32) -> io::Result<()> {
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

        fn is_versioned(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_checkout_id(&self) -> io::Result<i64> {
            Ok(crate::framework::store::folder_item::DEFAULT_CHECKOUT_ID)
        }

        fn get_checkout_version(&self) -> io::Result<i32> {
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
        ) -> io::Result<()> {
            Ok(())
        }

        fn clear_checkout(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn delete(&mut self, _version: i32, _user: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_versions(&self) -> io::Result<Option<Vec<crate::framework::store::ItemVersion>>> {
            Ok(None)
        }

        fn checkout(
            &mut self,
            _checkout_type: &dyn crate::framework::store::checkout_type::CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
            Ok(())
        }

        fn has_checkouts(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn can_recover(&self) -> bool {
            false
        }

        fn get_checkout(
            &self,
            _checkout_id: i64,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn get_checkouts(
            &self,
        ) -> io::Result<Vec<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(Vec::new())
        }

        fn is_checkin_active(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn update_checkout_version(
            &mut self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> io::Result<()> {
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

        fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

    impl DatabaseItem for MockDatabaseItem {
        fn open_with_change_data(
            &mut self,
            version: i32,
            min_change_data_ver: i32,
        ) -> io::Result<Box<dyn ManagedBufferFile>> {
            if version < 0 || min_change_data_ver < -1 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad version"));
            }
            Err(io::Error::new(io::ErrorKind::Unsupported, "no backing store in mock"))
        }

        fn open_version(&mut self, version: i32) -> io::Result<Box<dyn ManagedBufferFile>> {
            if version < 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad version"));
            }
            Err(io::Error::new(io::ErrorKind::Unsupported, "no backing store in mock"))
        }

        fn open(&mut self) -> io::Result<Box<dyn ManagedBufferFile>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "no backing store in mock"))
        }

        fn open_for_update(&mut self, checkout_id: i64) -> io::Result<Box<dyn ManagedBufferFile>> {
            if checkout_id < -1 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad checkout id"));
            }
            Err(io::Error::new(io::ErrorKind::Unsupported, "no backing store in mock"))
        }
    }

    #[test]
    fn test_database_item_object_safety_and_dispatch() {
        let mut item: Box<dyn DatabaseItem> = Box::new(MockDatabaseItem);

        assert!(item.open().is_err());
        assert!(item.open_version(3).is_err());
        assert!(item.open_with_change_data(3, 1).is_err());
        assert!(item.open_for_update(-1).is_err());

        assert_eq!(
            item.open_version(-1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            item.open_for_update(-2).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
