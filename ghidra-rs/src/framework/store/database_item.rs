use std::io;

use crate::framework::db::buffers::ManagedBufferFile;
use crate::framework::seam_stubs::FolderItem;

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

    impl FolderItem for MockDatabaseItem {}

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
