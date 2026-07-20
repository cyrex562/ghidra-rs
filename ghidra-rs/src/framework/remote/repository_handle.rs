use std::io;

use thiserror::Error;

use crate::framework::db::buffers::ManagedBufferFileHandle;
use crate::framework::remote::{RepositoryChangeEvent, User};
use crate::framework::seam_stubs::{CheckoutType, ItemCheckoutStatus, RepositoryItem};
use crate::framework::store::ItemVersion;
use crate::util::exception::InvalidNameException;
use crate::util::system_utilities::SystemUtilities;

/// Client/server heartbeat period (milliseconds) used to detect handle disposal delays caused by
/// garbage collection.
///
/// Mirrors `RepositoryHandle.CLIENT_CHECK_PERIOD`, which is computed once from
/// `SystemUtilities.isInTestingMode()`. Exposed as a function rather than an associated trait
/// constant since the value depends on a runtime environment check, not a compile-time constant,
/// and associated constants would otherwise need to be duplicated by every implementor.
pub fn client_check_period() -> u32 {
    if SystemUtilities::is_in_testing_mode() {
        2000
    }
    else {
        30000
    }
}

/// Combines the checked exceptions declared on the `RepositoryHandle` methods that create or
/// rename folders/items (`createTextDataFile`, `createDatabase`, `moveFolder`, `moveItem`), each
/// of which is declared `throws InvalidNameException, IOException`.
#[derive(Error, Debug)]
pub enum RepositoryNameError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Provides access to a repository.
///
/// Mirrors `ghidra.framework.remote.RepositoryHandle`. Implementations may be remote (RMI)
/// handles, so every method is declared to take `&self` and return `io::Result` (or
/// [`RepositoryNameError`] for the operations that may also fail with an invalid name), even
/// where a local-only implementation could use `&mut self`.
pub trait RepositoryHandle {
    /// Returns the name of this repository.
    fn get_name(&self) -> io::Result<String>;

    /// Returns user object associated with this handle.
    fn get_user(&self) -> io::Result<User>;

    /// Returns a list of users authorized for this repository.
    fn get_user_list(&self) -> io::Result<Vec<User>>;

    /// Returns true if anonymous access allowed by this repository.
    fn anonymous_access_allowed(&self) -> io::Result<bool>;

    /// Convenience method for obtaining a list of all users known to the server.
    fn get_server_user_list(&self) -> io::Result<Vec<String>>;

    /// Set the list of authorized users for this repository.
    ///
    /// `anonymous_access_allowed` indicates whether anonymous access should be permitted to this
    /// repository.
    fn set_user_list(&self, users: &[User], anonymous_access_allowed: bool) -> io::Result<()>;

    /// Get list of subfolders contained within the specified parent folder.
    fn get_subfolder_list(&self, folder_path: &str) -> io::Result<Vec<String>>;

    /// Returns the number of folder items contained within this file-system.
    fn get_item_count(&self) -> io::Result<i32>;

    /// Get of all items found within the specified parent folder path.
    fn get_item_list(&self, folder_path: &str) -> io::Result<Vec<Box<dyn RepositoryItem>>>;

    /// Returns the `RepositoryItem` in the given folder with the given name, or `None` if not
    /// found.
    fn get_item(
        &self,
        parent_path: &str,
        name: &str,
    ) -> io::Result<Option<Box<dyn RepositoryItem>>>;

    /// Returns the `RepositoryItem` with the given unique file ID, or `None` if not found.
    fn get_item_by_file_id(&self, file_id: &str) -> io::Result<Option<Box<dyn RepositoryItem>>>;

    /// Creates a new text data file within the specified parent folder.
    ///
    /// `comment` may be empty.
    fn create_text_data_file(
        &self,
        parent_path: &str,
        item_name: &str,
        file_id: &str,
        content_type: &str,
        text_data: &str,
        comment: &str,
    ) -> Result<(), RepositoryNameError>;

    /// Create a new empty database item within the repository. Returns the initial buffer file
    /// open for writing.
    fn create_database(
        &self,
        parent_path: &str,
        item_name: &str,
        file_id: &str,
        buffer_size: i32,
        content_type: &str,
        project_path: &str,
    ) -> Result<Box<dyn ManagedBufferFileHandle>, RepositoryNameError>;

    /// Open an existing version of a database buffer file for non-update read-only use.
    ///
    /// `version` is the existing version of the data file (-1 = latest version).
    /// `min_change_data_ver` indicates the oldest change data buffer file to be included; -1
    /// indicates only the last change data buffer file is applicable.
    fn open_database(
        &self,
        parent_path: &str,
        item_name: &str,
        version: i32,
        min_change_data_ver: i32,
    ) -> io::Result<Box<dyn ManagedBufferFileHandle>>;

    /// Open the current version for checkin of a new version. Returns the remote buffer file for
    /// updateable read-only use.
    fn open_database_for_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
    ) -> io::Result<Box<dyn ManagedBufferFileHandle>>;

    /// Returns a list of all versions for the specified item.
    fn get_versions(&self, parent_path: &str, item_name: &str) -> io::Result<Vec<ItemVersion>>;

    /// Delete the specified version of an item. `version` is the oldest or latest version of the
    /// item to be deleted, or -1 to delete the entire item. The caller must be Admin or owner of
    /// the version to be deleted.
    fn delete_item(&self, parent_path: &str, item_name: &str, version: i32) -> io::Result<()>;

    /// Move an entire folder.
    fn move_folder(
        &self,
        old_parent_path: &str,
        new_parent_path: &str,
        old_folder_name: &str,
        new_folder_name: &str,
    ) -> Result<(), RepositoryNameError>;

    /// Move an item to another folder.
    fn move_item(
        &self,
        old_parent_path: &str,
        new_parent_path: &str,
        old_item_name: &str,
        new_item_name: &str,
    ) -> Result<(), RepositoryNameError>;

    /// Perform a checkout on the specified item.
    ///
    /// If `checkout_type` is exclusive or transient, the checkout is only successful if no other
    /// checkouts exist. No new checkouts of the item will be permitted while an
    /// exclusive/transient checkout is active.
    fn checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_type: CheckoutType,
        project_path: &str,
    ) -> io::Result<Box<dyn ItemCheckoutStatus>>;

    /// Terminate an existing item checkout. `notify` indicates whether to notify listeners of the
    /// item status change.
    fn terminate_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
        notify: bool,
    ) -> io::Result<()>;

    /// Returns specific checkout data for an item.
    fn get_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
    ) -> io::Result<Box<dyn ItemCheckoutStatus>>;

    /// Get a list of all checkouts for an item.
    fn get_checkouts(
        &self,
        parent_path: &str,
        item_name: &str,
    ) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>>;

    /// Returns true if the specified folder path exists.
    fn folder_exists(&self, folder_path: &str) -> io::Result<bool>;

    /// Returns true if the specified item exists.
    fn file_exists(&self, parent_path: &str, item_name: &str) -> io::Result<bool>;

    /// Returns the length of this domain file. This size is the minimum disk space used for
    /// storing this file, but does not account for additional storage space used to track
    /// changes, etc.
    fn get_length(&self, parent_path: &str, item_name: &str) -> io::Result<i64>;

    /// Returns true if the specified item has one or more checkouts.
    fn has_checkouts(&self, parent_path: &str, item_name: &str) -> io::Result<bool>;

    /// Returns true if the specified item has an active checkin.
    fn is_checkin_active(&self, parent_path: &str, item_name: &str) -> io::Result<bool>;

    /// Update checkout data for an item following an update of a local checkout file.
    fn update_checkout_version(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
        checkout_version: i32,
    ) -> io::Result<()>;

    /// Get pending change events. Call will block until an event is available.
    fn get_events(&self) -> io::Result<Vec<RepositoryChangeEvent>>;

    /// Notification to server that client is dropping handle.
    fn close(&self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::user::Permission;
    use crate::framework::remote::EventType;
    use std::cell::RefCell;

    struct MockRepositoryItem;

    impl RepositoryItem for MockRepositoryItem {}

    struct MockItemCheckoutStatus;

    impl ItemCheckoutStatus for MockItemCheckoutStatus {}

    #[derive(Default)]
    struct MockRepositoryHandle {
        closed: RefCell<bool>,
    }

    impl RepositoryHandle for MockRepositoryHandle {
        fn get_name(&self) -> io::Result<String> {
            Ok("MyRepo".to_string())
        }

        fn get_user(&self) -> io::Result<User> {
            Ok(User::new("alice", Permission::Admin))
        }

        fn get_user_list(&self) -> io::Result<Vec<User>> {
            Ok(vec![User::new("alice", Permission::Admin)])
        }

        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_server_user_list(&self) -> io::Result<Vec<String>> {
            Ok(vec!["alice".to_string(), "bob".to_string()])
        }

        fn set_user_list(&self, _users: &[User], _anonymous_access_allowed: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_subfolder_list(&self, _folder_path: &str) -> io::Result<Vec<String>> {
            Ok(vec!["sub1".to_string()])
        }

        fn get_item_count(&self) -> io::Result<i32> {
            Ok(1)
        }

        fn get_item_list(&self, _folder_path: &str) -> io::Result<Vec<Box<dyn RepositoryItem>>> {
            Ok(vec![Box::new(MockRepositoryItem)])
        }

        fn get_item(
            &self,
            _parent_path: &str,
            name: &str,
        ) -> io::Result<Option<Box<dyn RepositoryItem>>> {
            if name == "item1" {
                Ok(Some(Box::new(MockRepositoryItem)))
            }
            else {
                Ok(None)
            }
        }

        fn get_item_by_file_id(
            &self,
            _file_id: &str,
        ) -> io::Result<Option<Box<dyn RepositoryItem>>> {
            Ok(None)
        }

        fn create_text_data_file(
            &self,
            _parent_path: &str,
            item_name: &str,
            _file_id: &str,
            _content_type: &str,
            _text_data: &str,
            _comment: &str,
        ) -> Result<(), RepositoryNameError> {
            if item_name.is_empty() {
                return Err(RepositoryNameError::InvalidName(
                    InvalidNameException::with_message("item name must not be empty"),
                ));
            }
            Ok(())
        }

        fn create_database(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _file_id: &str,
            _buffer_size: i32,
            _content_type: &str,
            _project_path: &str,
        ) -> Result<Box<dyn ManagedBufferFileHandle>, RepositoryNameError> {
            Err(RepositoryNameError::Io(io::Error::other(
                "createDatabase not supported by mock",
            )))
        }

        fn open_database(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _version: i32,
            _min_change_data_ver: i32,
        ) -> io::Result<Box<dyn ManagedBufferFileHandle>> {
            Err(io::Error::other("openDatabase not supported by mock"))
        }

        fn open_database_for_checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_id: i64,
        ) -> io::Result<Box<dyn ManagedBufferFileHandle>> {
            Err(io::Error::other("openDatabase not supported by mock"))
        }

        fn get_versions(
            &self,
            _parent_path: &str,
            _item_name: &str,
        ) -> io::Result<Vec<ItemVersion>> {
            Ok(vec![ItemVersion::new(1, 0, "alice", "initial")])
        }

        fn delete_item(&self, _parent_path: &str, _item_name: &str, _version: i32) -> io::Result<()> {
            Ok(())
        }

        fn move_folder(
            &self,
            _old_parent_path: &str,
            _new_parent_path: &str,
            _old_folder_name: &str,
            _new_folder_name: &str,
        ) -> Result<(), RepositoryNameError> {
            Ok(())
        }

        fn move_item(
            &self,
            _old_parent_path: &str,
            _new_parent_path: &str,
            _old_item_name: &str,
            _new_item_name: &str,
        ) -> Result<(), RepositoryNameError> {
            Ok(())
        }

        fn checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_type: CheckoutType,
            _project_path: &str,
        ) -> io::Result<Box<dyn ItemCheckoutStatus>> {
            Ok(Box::new(MockItemCheckoutStatus))
        }

        fn terminate_checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_id: i64,
            _notify: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_id: i64,
        ) -> io::Result<Box<dyn ItemCheckoutStatus>> {
            Ok(Box::new(MockItemCheckoutStatus))
        }

        fn get_checkouts(
            &self,
            _parent_path: &str,
            _item_name: &str,
        ) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
            Ok(vec![Box::new(MockItemCheckoutStatus)])
        }

        fn folder_exists(&self, folder_path: &str) -> io::Result<bool> {
            Ok(folder_path == "/exists")
        }

        fn file_exists(&self, _parent_path: &str, item_name: &str) -> io::Result<bool> {
            Ok(item_name == "item1")
        }

        fn get_length(&self, _parent_path: &str, _item_name: &str) -> io::Result<i64> {
            Ok(1024)
        }

        fn has_checkouts(&self, _parent_path: &str, _item_name: &str) -> io::Result<bool> {
            Ok(false)
        }

        fn is_checkin_active(&self, _parent_path: &str, _item_name: &str) -> io::Result<bool> {
            Ok(false)
        }

        fn update_checkout_version(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_id: i64,
            _checkout_version: i32,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_events(&self) -> io::Result<Vec<RepositoryChangeEvent>> {
            Ok(vec![RepositoryChangeEvent::new(
                EventType::ItemCreated,
                Some("/parent".to_string()),
                Some("item1".to_string()),
                None,
                None,
            )])
        }

        fn close(&self) -> io::Result<()> {
            *self.closed.borrow_mut() = true;
            Ok(())
        }
    }

    #[test]
    fn test_object_safety_and_dispatch() {
        let handle: Box<dyn RepositoryHandle> = Box::new(MockRepositoryHandle::default());

        assert_eq!(handle.get_name().unwrap(), "MyRepo");
        assert_eq!(handle.get_user().unwrap().name(), "alice");
        assert_eq!(handle.get_user_list().unwrap().len(), 1);
        assert!(!handle.anonymous_access_allowed().unwrap());
        assert_eq!(handle.get_server_user_list().unwrap().len(), 2);
        assert!(handle
            .set_user_list(&[User::new("bob", Permission::Write)], true)
            .is_ok());
        assert_eq!(handle.get_subfolder_list("/").unwrap(), vec!["sub1"]);
        assert_eq!(handle.get_item_count().unwrap(), 1);
        assert_eq!(handle.get_item_list("/").unwrap().len(), 1);
        assert!(handle.get_item("/", "item1").unwrap().is_some());
        assert!(handle.get_item("/", "missing").unwrap().is_none());
        assert!(handle.get_item_by_file_id("abc").unwrap().is_none());
    }

    #[test]
    fn test_create_text_data_file_validates_name() {
        let handle: Box<dyn RepositoryHandle> = Box::new(MockRepositoryHandle::default());

        assert!(handle
            .create_text_data_file("/", "item1", "id1", "text/plain", "hello", "")
            .is_ok());

        let err = handle
            .create_text_data_file("/", "", "id1", "text/plain", "hello", "")
            .unwrap_err();
        assert!(matches!(err, RepositoryNameError::InvalidName(_)));
    }

    #[test]
    fn test_checkout_lifecycle() {
        let handle: Box<dyn RepositoryHandle> = Box::new(MockRepositoryHandle::default());

        assert!(handle
            .checkout("/", "item1", CheckoutType::Exclusive, "/proj")
            .is_ok());
        assert!(handle.get_checkouts("/", "item1").unwrap().len() == 1);
        assert!(handle
            .terminate_checkout("/", "item1", 42, true)
            .is_ok());
        assert!(!handle.has_checkouts("/", "item1").unwrap());
    }

    #[test]
    fn test_versions_and_events() {
        let handle: Box<dyn RepositoryHandle> = Box::new(MockRepositoryHandle::default());

        let versions = handle.get_versions("/", "item1").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version(), 1);

        let events = handle.get_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::ItemCreated);
    }

    #[test]
    fn test_close() {
        let handle = MockRepositoryHandle::default();
        assert!(!*handle.closed.borrow());
        handle.close().unwrap();
        assert!(*handle.closed.borrow());
    }

    #[test]
    fn test_client_check_period_is_positive() {
        assert!(client_check_period() > 0);
    }
}
