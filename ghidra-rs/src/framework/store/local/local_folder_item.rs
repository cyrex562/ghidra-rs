use std::io;

use thiserror::Error;

use crate::framework::seam_stubs::{CheckoutType, FolderItem, ItemCheckoutStatus};
use crate::framework::store::ItemVersion;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on
/// `LocalFolderItem.updateCheckout(FolderItem, boolean, TaskMonitor)`.
#[derive(Error, Debug)]
pub enum UpdateCheckoutError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// An abstract implementation of a folder item which resides on a local file-system. An item is
/// defined by a property file and generally has a hidden data directory which contains the actual
/// data file(s).
///
/// An item may be either private or shared (i.e., versioned) as defined by the associated
/// file-system. A shared item utilizes a checkout manager and history manager for tracking
/// version control data related to this item.
///
/// Mirrors `ghidra.framework.store.local.LocalFolderItem`, which extends `FolderItem`. Only the
/// class's public surface is represented here; package-private helpers that operate on internal
/// state not yet ported (property file, checkout manager, history manager, owning file system)
/// are left for the concrete subclass ports (`LocalDataFileItem`, `LocalDatabaseItem`, etc.) to
/// implement directly once `LocalFileSystem` and friends exist.
pub trait LocalFolderItem: FolderItem {
    /// Property file key for the stored file type.
    const FILE_TYPE: &'static str = "FILE_TYPE";
    /// Property file key for the read-only flag.
    const READ_ONLY: &'static str = "READ_ONLY";
    /// Property file key for the content type.
    const CONTENT_TYPE: &'static str = "CONTENT_TYPE";
    /// Property file key for the checkout id.
    const CHECKOUT_ID: &'static str = "CHECKOUT_ID";
    /// Property file key for the exclusive-checkout flag.
    const EXCLUSIVE_CHECKOUT: &'static str = "EXCLUSIVE";
    /// Property file key for the checkout version.
    const CHECKOUT_VERSION: &'static str = "CHECKOUT_VERSION";
    /// Property file key for the local checkout version.
    const LOCAL_CHECKOUT_VERSION: &'static str = "LOCAL_CHECKOUT_VERSION";
    /// Property file key for the content type version.
    const CONTENT_TYPE_VERSION: &'static str = "CONTENT_TYPE_VERSION";

    /// File extension used for an item's hidden data directory.
    const DATA_DIR_EXTENSION: &'static str = ".db";

    /// Refreshes this item's cached state from its underlying property file (and data
    /// directory, if applicable). Returns `false` if the item no longer exists on disk.
    fn refresh(&mut self) -> io::Result<bool>;

    /// Returns the oldest/minimum version.
    fn get_minimum_version(&self) -> io::Result<i32>;

    /// Deletes the item or a specific version. If a specific version is specified, it must
    /// either be the oldest or latest (i.e., current).
    ///
    /// `version` is the specific version to be deleted, or -1 to remove all versions.
    ///
    /// # Errors
    /// Returns an `io::Error` if unable to delete a version because this item is checked-out,
    /// the user does not have permission, or the specified version is not the oldest or latest.
    fn delete(&mut self, version: i32, user: &str) -> io::Result<()>;

    /// Deletes the item content associated with the minimum version. Only invoked for versioned
    /// items, and never when the minimum version is the only version (i.e., `min_version` will
    /// always be less than `current_version`).
    fn delete_minimum_version(&mut self, user: &str) -> io::Result<()>;

    /// Deletes the item content associated with the current version. Only invoked for versioned
    /// items, and never when the current version is the only version.
    fn delete_current_version(&mut self, user: &str) -> io::Result<()>;

    /// Returns the content type name for this item.
    fn get_content_type(&self) -> String;

    /// Returns the file id if one has been established.
    fn get_file_id(&self) -> Option<String>;

    /// Assigns a new file id to this local non-versioned file. Only valid for a local
    /// non-versioned file-system.
    fn reset_file_id(&mut self) -> io::Result<String>;

    /// Returns the display name for this item.
    fn get_name(&self) -> String;

    /// Returns the path of the parent folder.
    fn get_parent_path(&self) -> String;

    /// Returns the concatenation of the pathname and the basename, which can be used to uniquely
    /// identify this folder item.
    fn get_path_name(&self) -> String;

    /// Returns true if this item is a checked-out copy from a versioned file system. Not
    /// applicable to a versioned item.
    fn is_checked_out(&self) -> bool;

    /// Returns true if this item is a checked-out copy with exclusive access from a versioned
    /// file system. Not applicable to a versioned item.
    fn is_checked_out_exclusive(&self) -> bool;

    /// Returns true if this is a versioned item, else false.
    fn is_versioned(&self) -> io::Result<bool>;

    /// Returns the list of all available versions.
    ///
    /// # Errors
    /// Returns an `io::Error` if the item is not versioned or history is otherwise unavailable.
    fn get_versions(&self) -> io::Result<Vec<ItemVersion>>;

    /// Returns the time that this item was last modified.
    fn last_modified(&self) -> i64;

    /// Returns true if this item can be overwritten/deleted.
    fn is_read_only(&self) -> bool;

    /// Sets the state of the read-only indicator for this non-shared item.
    fn set_read_only(&mut self, state: bool) -> io::Result<()>;

    /// Returns the version of content type (i.e., the version of the structure/storage for the
    /// content type, not the user's version of their data).
    fn get_content_type_version(&self) -> i32;

    /// Sets the version for the content type. Changes whenever the domain objects are upgraded.
    fn set_content_type_version(&mut self, version: i32) -> io::Result<()>;

    /// Checks out this folder item.
    ///
    /// Returns the checkout status, or `None` if an exclusive checkout request failed.
    ///
    /// # Errors
    /// Returns an `io::Error` if this item does not support checkin/checkout, is not versioned,
    /// or the file-system is read-only.
    fn checkout(
        &mut self,
        checkout_type: CheckoutType,
        user: &str,
        project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Terminates a checkout. The checkout id becomes invalid; the associated checkout copy
    /// should either be removed or converted to a private file. If `notify` is true, an item
    /// change notification will be sent.
    fn terminate_checkout(&mut self, checkout_id: i64, notify: bool) -> io::Result<()>;

    /// Returns the checkout status for the given checkout id, if any.
    fn get_checkout(&self, checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Returns all outstanding checkouts for this item.
    fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>>;

    /// Returns the checkout id for this file. A value of -1 indicates a private item. Only valid
    /// for a local non-versioned file-system.
    fn get_checkout_id(&self) -> i64;

    /// Returns the item version which was checked-out. A value of -1 indicates a private item.
    /// Only valid for a local non-versioned file-system.
    fn get_checkout_version(&self) -> io::Result<i32>;

    /// Returns the local item version at the time the checkout was completed. A value of -1
    /// indicates a private item. Only valid for a local non-versioned file-system.
    fn get_local_checkout_version(&self) -> i32;

    /// Sets the checkout data associated with this non-shared file.
    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> io::Result<()>;

    /// Clears the checkout data associated with this non-shared file.
    fn clear_checkout(&mut self) -> io::Result<()>;

    /// Returns true if this item is versioned and has one or more checkouts.
    fn has_checkouts(&self) -> bool;

    /// Returns true if a checkin is currently in progress for this (versioned) item.
    fn is_checkin_active(&self) -> bool;

    /// Updates the version and checkout data recorded for an existing checkout, following a
    /// checkin performed with a newer local checkout version.
    fn update_checkout_version(
        &mut self,
        checkout_id: i64,
        checkout_version: i32,
        user: &str,
    ) -> io::Result<()>;

    /// Updates this non-versioned item with the latest version of the specified versioned item.
    ///
    /// `update_item` indicates whether this item's content should be updated using
    /// `versioned_folder_item`; `monitor` tracks progress of the update.
    ///
    /// # Errors
    /// Returns [`UpdateCheckoutError::Io`] if this file is not a checked-out non-versioned file
    /// or an IO error occurs, or [`UpdateCheckoutError::Cancelled`] if `monitor` cancels the
    /// operation.
    fn update_checkout_with_monitor(
        &mut self,
        versioned_folder_item: &dyn FolderItem,
        update_item: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), UpdateCheckoutError>;

    /// Updates this non-versioned item with the contents of the specified item, which must be
    /// within the same non-versioned file-system. If successful, `item`'s content is moved into
    /// this item and `item` is removed.
    ///
    /// # Errors
    /// Returns an `io::Error` if this file is not a checked-out non-versioned file or an IO error
    /// occurs.
    fn update_checkout_from(&mut self, item: &dyn FolderItem, checkout_version: i32) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct MockItemCheckoutStatus;
    impl ItemCheckoutStatus for MockItemCheckoutStatus {}

    #[derive(Default)]
    struct MockLocalFolderItem {
        name: String,
        content_type: String,
        read_only: bool,
        checkout_id: Cell<i64>,
        versioned: bool,
        current_version: i32,
        min_version: i32,
    }

    impl FolderItem for MockLocalFolderItem {}

    impl LocalFolderItem for MockLocalFolderItem {
        fn refresh(&mut self) -> io::Result<bool> {
            Ok(true)
        }

        fn get_minimum_version(&self) -> io::Result<i32> {
            Ok(self.min_version)
        }

        fn delete(&mut self, version: i32, _user: &str) -> io::Result<()> {
            if version != -1 && version != self.min_version && version != self.current_version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only the oldest or latest version may be deleted",
                ));
            }
            Ok(())
        }

        fn delete_minimum_version(&mut self, _user: &str) -> io::Result<()> {
            self.min_version += 1;
            Ok(())
        }

        fn delete_current_version(&mut self, _user: &str) -> io::Result<()> {
            self.current_version -= 1;
            Ok(())
        }

        fn get_content_type(&self) -> String {
            self.content_type.clone()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            format!("/{}", self.name)
        }

        fn is_checked_out(&self) -> bool {
            self.checkout_id.get() != -1
        }

        fn is_checked_out_exclusive(&self) -> bool {
            false
        }

        fn is_versioned(&self) -> io::Result<bool> {
            Ok(self.versioned)
        }

        fn get_versions(&self) -> io::Result<Vec<ItemVersion>> {
            if !self.versioned {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"));
            }
            Ok(vec![ItemVersion::new(1, 0, "alice", "initial")])
        }

        fn last_modified(&self) -> i64 {
            0
        }

        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn set_read_only(&mut self, state: bool) -> io::Result<()> {
            self.read_only = state;
            Ok(())
        }

        fn get_content_type_version(&self) -> i32 {
            1
        }

        fn set_content_type_version(&mut self, _version: i32) -> io::Result<()> {
            Ok(())
        }

        fn checkout(
            &mut self,
            checkout_type: CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            if !self.versioned {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"));
            }
            if checkout_type == CheckoutType::Exclusive {
                return Ok(None);
            }
            Ok(Some(Box::new(MockItemCheckoutStatus)))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_checkout(&self, _checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
            Ok(Vec::new())
        }

        fn get_checkout_id(&self) -> i64 {
            self.checkout_id.get()
        }

        fn get_checkout_version(&self) -> io::Result<i32> {
            Ok(-1)
        }

        fn get_local_checkout_version(&self) -> i32 {
            -1
        }

        fn set_checkout(
            &mut self,
            checkout_id: i64,
            _exclusive: bool,
            checkout_version: i32,
            local_version: i32,
        ) -> io::Result<()> {
            if checkout_id <= 0 || checkout_version <= 0 || local_version < 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad checkout data"));
            }
            self.checkout_id.set(checkout_id);
            Ok(())
        }

        fn clear_checkout(&mut self) -> io::Result<()> {
            self.checkout_id.set(-1);
            Ok(())
        }

        fn has_checkouts(&self) -> bool {
            self.checkout_id.get() != -1
        }

        fn is_checkin_active(&self) -> bool {
            false
        }

        fn update_checkout_version(
            &mut self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn update_checkout_with_monitor(
            &mut self,
            _versioned_folder_item: &dyn FolderItem,
            _update_item: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), UpdateCheckoutError> {
            if monitor.is_cancelled() {
                return Err(UpdateCheckoutError::Cancelled(CancelledException::new(
                    "update cancelled",
                )));
            }
            Ok(())
        }

        fn update_checkout_from(
            &mut self,
            _item: &dyn FolderItem,
            checkout_version: i32,
        ) -> io::Result<()> {
            if checkout_version <= 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad version"));
            }
            Ok(())
        }
    }

    #[test]
    fn test_local_folder_item_object_safety_and_dispatch() {
        let mut item: Box<dyn LocalFolderItem> = Box::new(MockLocalFolderItem {
            name: "MyProgram".to_string(),
            content_type: "Program".to_string(),
            checkout_id: Cell::new(-1),
            versioned: true,
            current_version: 3,
            min_version: 1,
            ..Default::default()
        });

        assert_eq!(item.get_name(), "MyProgram");
        assert_eq!(item.get_path_name(), "/MyProgram");
        assert!(item.is_versioned().unwrap());
        assert!(!item.has_checkouts());

        // Only the oldest or latest version may be deleted.
        assert!(item.delete(2, "alice").is_err());
        assert!(item.delete(3, "alice").is_ok());

        let status = item
            .checkout(CheckoutType::Normal, "alice", "/repo/MyProgram")
            .unwrap();
        assert!(status.is_some());

        let exclusive = item
            .checkout(CheckoutType::Exclusive, "alice", "/repo/MyProgram")
            .unwrap();
        assert!(exclusive.is_none());

        assert!(item.set_checkout(1, false, 1, 0).is_ok());
        assert!(item.has_checkouts());
        assert!(item.clear_checkout().is_ok());
        assert!(!item.has_checkouts());

        let versions = item.get_versions().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].user(), "alice");
    }

    #[test]
    fn test_local_folder_item_non_versioned_rejects_get_versions() {
        let item: Box<dyn LocalFolderItem> = Box::new(MockLocalFolderItem::default());
        assert!(item.get_versions().is_err());
    }
}
