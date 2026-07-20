use std::io;

use crate::framework::client::repository_server_adapter::RepositoryServerAdapter;
use crate::framework::db::buffers::ManagedBufferFileHandle;
use crate::framework::model::server_info::ServerInfo;
use crate::framework::remote::{RepositoryNameError, User};
use crate::framework::seam_stubs::{
    CheckoutType, ItemCheckoutStatus, RemoteAdapterListener, RepositoryItem,
};
use crate::framework::store::{DataFileHandle, FileSystemListener, ItemVersion};

/// Builds the `io::Error` returned by every default method below.
///
/// Mirrors `RepositoryAdapter.checkRepository()`, which throws `NotConnectedException` (itself an
/// `IOException` subclass) whenever the wrapped repository handle is unset. Every default trait
/// method below models a `RepositoryAdapter` that has never successfully connected, so this is the
/// error each of them naturally returns.
fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Not connected to the server")
}

/// Provides a persistent wrapper for a remote repository handle which may become invalid if the
/// remote connection were to fail. Connection recovery is provided by any method call which must
/// communicate with the server.
///
/// Mirrors `ghidra.framework.client.RepositoryAdapter`, which also implements
/// `ghidra.framework.client.RemoteAdapterListener` to react to its underlying server adapter's
/// connection-state changes; [`connection_state_changed`](Self::connection_state_changed) stands
/// in for that override.
///
/// Ported to a trait (rather than a concrete class) at a dependency-cycle cut-point identified in
/// the Java package graph, so that other core types (e.g.
/// [`ProjectManager`](crate::framework::model::ProjectManager)) can depend on repository-adapter
/// behavior without depending on a single concrete implementation. Every method takes `&self` and
/// returns owned/boxed values or trait objects, matching the same object-safety rationale used by
/// [`RepositoryHandle`](crate::framework::remote::RepositoryHandle): a resilient/remote
/// implementation needs interior mutability (e.g. a `Mutex`) even for what look like read-only
/// calls, since `connect`/`disconnect`/user-caching all mutate shared state under the hood in the
/// original Java (`synchronized (serverAdapter) { ... }`).
///
/// Every method is given a default describing a `RepositoryAdapter` that has never successfully
/// connected (see [`not_connected`]), so existing bare `impl RepositoryAdapter for MockX {}`
/// blocks (written against the placeholder trait this promotes) keep compiling. `createDataFile`
/// and `openDataFile` are the exception: the Java implementations unconditionally throw
/// `IOException` regardless of connection state ("Data file not yet supported by repository"), so
/// their defaults reproduce that fixed behavior rather than a not-connected error.
///
/// The Java `getItem(String, String)` and `getItem(String)` overloads become
/// [`get_item`](Self::get_item) and [`get_item_by_file_id`](Self::get_item_by_file_id) since Rust
/// has no method overloading, matching the naming already used by
/// [`RepositoryHandle`](crate::framework::remote::RepositoryHandle). The package-private
/// `getCurrentHandle`, `getEvents`, `recoverConnection`, and `processOpenHandleCountUpdateEvent`
/// members are internal wiring for the (unported, package-private)
/// `ghidra.framework.client.RepositoryChangeDispatcher` helper thread and are not part of this
/// trait's public capability surface.
pub trait RepositoryAdapter {
    /// Returns true if connection recently was lost unexpectedly.
    fn had_unexpected_disconnect(&self) -> bool {
        false
    }

    /// Set the file system listener associated with the remote repository. `None` clears any
    /// previously set listener.
    fn set_file_system_listener(&self, listener: Option<Box<dyn FileSystemListener>>) {
        let _ = listener;
    }

    /// Add a listener to this remote adapter.
    fn add_listener(&self, listener: Box<dyn RemoteAdapterListener>) {
        let _ = listener;
    }

    /// Remove a listener from this remote adapter.
    fn remove_listener(&self, listener: &dyn RemoteAdapterListener) {
        let _ = listener;
    }

    /// Notification callback for when the underlying server connection state changes.
    ///
    /// Mirrors `RepositoryAdapter.connectionStateChanged(Object adapter)`, which ignores its
    /// `adapter` parameter and instead reacts based on its own server adapter's state, so no
    /// parameter is modeled here.
    fn connection_state_changed(&self) {}

    /// Returns true if connected.
    fn is_connected(&self) -> bool {
        false
    }

    /// Attempt to connect to the server.
    ///
    /// # Errors
    /// Returns `Err` if the named repository does not exist on the server, or an IO error occurs.
    fn connect(&self) -> io::Result<()> {
        Err(not_connected())
    }

    /// Get the associated repository name.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Get the associated server adapter.
    fn get_server(&self) -> Box<dyn RepositoryServerAdapter> {
        Box::new(UnknownRepositoryServerAdapter)
    }

    /// Returns associated server information.
    fn get_server_info(&self) -> ServerInfo {
        ServerInfo::new("", 0)
    }

    /// Returns repository connected user object.
    ///
    /// # Errors
    /// Returns `Err` if the user no longer has permission, the connection is down, or an IO error
    /// occurs.
    fn get_user(&self) -> io::Result<User> {
        Err(not_connected())
    }

    /// Returns true if anonymous access allowed by this repository.
    fn anonymous_access_allowed(&self) -> io::Result<bool> {
        Err(not_connected())
    }

    /// Returns list of repository users with repository access permission.
    fn get_user_list(&self) -> io::Result<Vec<User>> {
        Err(not_connected())
    }

    /// Returns list of all user names known to server.
    fn get_server_user_list(&self) -> io::Result<Vec<String>> {
        Err(not_connected())
    }

    /// Set the list of authorized users for this repository. `anonymous_access_allowed` indicates
    /// whether anonymous access should be permitted to this repository (also requires anonymous
    /// access to be enabled for the server).
    ///
    /// # Errors
    /// Returns `Err` if the caller is not a repository Admin, or an IO error occurs.
    fn set_user_list(&self, users: &[User], anonymous_access_allowed: bool) -> io::Result<()> {
        let _ = (users, anonymous_access_allowed);
        Err(not_connected())
    }

    /// Creates a new text data file within the specified parent folder. `comment` may be empty.
    fn create_text_data_file(
        &self,
        parent_path: &str,
        item_name: &str,
        file_id: &str,
        content_type: &str,
        text_data: &str,
        comment: &str,
    ) -> Result<(), RepositoryNameError> {
        let _ = (parent_path, item_name, file_id, content_type, text_data, comment);
        Err(RepositoryNameError::Io(not_connected()))
    }

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
    ) -> Result<Box<dyn ManagedBufferFileHandle>, RepositoryNameError> {
        let _ = (parent_path, item_name, file_id, buffer_size, content_type, project_path);
        Err(RepositoryNameError::Io(not_connected()))
    }

    /// Open an existing version of a database buffer file for non-update read-only use. `version`
    /// is the existing version of the data file (-1 = latest version). `min_change_data_ver`
    /// indicates the oldest change data buffer file to be included; -1 indicates only the last
    /// change data buffer file is applicable.
    fn open_database(
        &self,
        parent_path: &str,
        item_name: &str,
        version: i32,
        min_change_data_ver: i32,
    ) -> io::Result<Box<dyn ManagedBufferFileHandle>> {
        let _ = (parent_path, item_name, version, min_change_data_ver);
        Err(not_connected())
    }

    /// Open the current version for checkin of a new version. Returns the remote buffer file for
    /// updateable read-only use.
    fn open_database_for_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
    ) -> io::Result<Box<dyn ManagedBufferFileHandle>> {
        let _ = (parent_path, item_name, checkout_id);
        Err(not_connected())
    }

    /// Create a new data file.
    ///
    /// Mirrors `RepositoryAdapter.createDataFile`, which unconditionally throws
    /// `IOException("Data file not yet supported by repository")`.
    fn create_data_file(&self, parent_path: &str, item_name: &str) -> io::Result<()> {
        let _ = (parent_path, item_name);
        Err(io::Error::new(io::ErrorKind::Unsupported, "Data file not yet supported by repository"))
    }

    /// Open an existing data file.
    ///
    /// Mirrors `RepositoryAdapter.openDataFile`, which unconditionally throws
    /// `IOException("Data file not yet supported by repository")`.
    fn open_data_file(
        &self,
        parent_path: &str,
        item_name: &str,
        version: i32,
    ) -> io::Result<Box<dyn DataFileHandle>> {
        let _ = (parent_path, item_name, version);
        Err(io::Error::new(io::ErrorKind::Unsupported, "Data file not yet supported by repository"))
    }

    /// Get list of subfolders contained within the specified parent folder.
    fn get_subfolder_list(&self, folder_path: &str) -> io::Result<Vec<String>> {
        let _ = folder_path;
        Err(not_connected())
    }

    /// Returns the number of folder items contained within this repository.
    fn get_item_count(&self) -> io::Result<i32> {
        Err(not_connected())
    }

    /// Get all items found within the specified parent folder path.
    fn get_item_list(&self, folder_path: &str) -> io::Result<Vec<Box<dyn RepositoryItem>>> {
        let _ = folder_path;
        Err(not_connected())
    }

    /// Returns the item in the given folder with the given name, or `None` if not found.
    fn get_item(
        &self,
        folder_path: &str,
        item_name: &str,
    ) -> io::Result<Option<Box<dyn RepositoryItem>>> {
        let _ = (folder_path, item_name);
        Err(not_connected())
    }

    /// Returns the item with the given unique file ID, or `None` if not found.
    fn get_item_by_file_id(&self, file_id: &str) -> io::Result<Option<Box<dyn RepositoryItem>>> {
        let _ = file_id;
        Err(not_connected())
    }

    /// Returns list of all versions for the specified item.
    fn get_versions(&self, parent_path: &str, item_name: &str) -> io::Result<Vec<ItemVersion>> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Delete the specified version of an item. `version` is the oldest or latest version of the
    /// item to be deleted, or -1 to delete the entire item. The caller must be Admin or owner of
    /// the version to be deleted.
    fn delete_item(&self, parent_path: &str, item_name: &str, version: i32) -> io::Result<()> {
        let _ = (parent_path, item_name, version);
        Err(not_connected())
    }

    /// Move an entire folder.
    fn move_folder(
        &self,
        old_parent_path: &str,
        new_parent_path: &str,
        old_folder_name: &str,
        new_folder_name: &str,
    ) -> Result<(), RepositoryNameError> {
        let _ = (old_parent_path, new_parent_path, old_folder_name, new_folder_name);
        Err(RepositoryNameError::Io(not_connected()))
    }

    /// Move an item to another folder.
    fn move_item(
        &self,
        old_parent_path: &str,
        new_parent_path: &str,
        old_item_name: &str,
        new_item_name: &str,
    ) -> Result<(), RepositoryNameError> {
        let _ = (old_parent_path, new_parent_path, old_item_name, new_item_name);
        Err(RepositoryNameError::Io(not_connected()))
    }

    /// Perform a checkout on the specified item. If `checkout_type` is exclusive or transient, the
    /// checkout is only successful if no other checkouts exist; no new checkouts of the item will
    /// be permitted while an exclusive/transient checkout is active.
    fn checkout(
        &self,
        folder_path: &str,
        item_name: &str,
        checkout_type: CheckoutType,
        project_path: &str,
    ) -> io::Result<Box<dyn ItemCheckoutStatus>> {
        let _ = (folder_path, item_name, checkout_type, project_path);
        Err(not_connected())
    }

    /// Terminate an existing item checkout. `notify` indicates whether to notify listeners of the
    /// item status change.
    fn terminate_checkout(
        &self,
        folder_path: &str,
        item_name: &str,
        checkout_id: i64,
        notify: bool,
    ) -> io::Result<()> {
        let _ = (folder_path, item_name, checkout_id, notify);
        Err(not_connected())
    }

    /// Returns specific checkout data for an item.
    fn get_checkout(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
    ) -> io::Result<Box<dyn ItemCheckoutStatus>> {
        let _ = (parent_path, item_name, checkout_id);
        Err(not_connected())
    }

    /// Get a list of all checkouts for an item.
    fn get_checkouts(
        &self,
        parent_path: &str,
        item_name: &str,
    ) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Returns true if the specified folder path exists.
    fn folder_exists(&self, folder_path: &str) -> io::Result<bool> {
        let _ = folder_path;
        Err(not_connected())
    }

    /// Returns true if the specified item exists.
    fn file_exists(&self, parent_path: &str, item_name: &str) -> io::Result<bool> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Returns the length of this item. This size is the minimum disk space used for storing this
    /// item, but does not account for additional storage space used to track changes, etc.
    fn get_length(&self, parent_path: &str, item_name: &str) -> io::Result<i64> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Returns true if the specified item has one or more checkouts.
    fn has_checkouts(&self, parent_path: &str, item_name: &str) -> io::Result<bool> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Returns true if the specified item has an active checkin.
    fn is_checkin_active(&self, parent_path: &str, item_name: &str) -> io::Result<bool> {
        let _ = (parent_path, item_name);
        Err(not_connected())
    }

    /// Update checkout data for an item following an update of a local checkout file.
    fn update_checkout_version(
        &self,
        parent_path: &str,
        item_name: &str,
        checkout_id: i64,
        checkout_version: i32,
    ) -> io::Result<()> {
        let _ = (parent_path, item_name, checkout_id, checkout_version);
        Err(not_connected())
    }

    /// Verify that the connection is still valid.
    ///
    /// Returns true if the connection is valid; false if the connection needs to be
    /// reestablished.
    fn verify_connection(&self) -> bool {
        false
    }

    /// Disconnect from the repository.
    fn disconnect(&self) {}

    /// Returns the number of open file handles associated with this repository connection.
    fn get_open_file_handle_count(&self) -> i32 {
        0
    }
}

/// Trivial fallback used by [`RepositoryAdapter::get_server`]'s default implementation before a
/// real `RepositoryServerAdapter` is available.
struct UnknownRepositoryServerAdapter;
impl RepositoryServerAdapter for UnknownRepositoryServerAdapter {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::user::Permission;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct MockRepositoryItem;
    impl RepositoryItem for MockRepositoryItem {}

    /// A mock that behaves like a real resilient repository adapter: `connect`/`disconnect` flip
    /// connection state, and item operations only succeed while "connected", proving the trait
    /// captures meaningful behavior rather than being a pass-through shell.
    #[derive(Default)]
    struct MockRepositoryAdapter {
        name: String,
        connected: Cell<bool>,
        items: RefCell<HashMap<String, ()>>,
    }

    impl MockRepositoryAdapter {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), connected: Cell::new(false), items: RefCell::new(HashMap::new()) }
        }
    }

    impl RepositoryAdapter for MockRepositoryAdapter {
        fn is_connected(&self) -> bool {
            self.connected.get()
        }

        fn connect(&self) -> io::Result<()> {
            self.connected.set(true);
            Ok(())
        }

        fn disconnect(&self) {
            self.connected.set(false);
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_user(&self) -> io::Result<User> {
            if !self.is_connected() {
                return Err(not_connected());
            }
            Ok(User::new("alice", Permission::Admin))
        }

        fn create_text_data_file(
            &self,
            parent_path: &str,
            item_name: &str,
            _file_id: &str,
            _content_type: &str,
            _text_data: &str,
            _comment: &str,
        ) -> Result<(), RepositoryNameError> {
            if !self.is_connected() {
                return Err(RepositoryNameError::Io(not_connected()));
            }
            self.items.borrow_mut().insert(format!("{parent_path}/{item_name}"), ());
            Ok(())
        }

        fn get_item(
            &self,
            folder_path: &str,
            item_name: &str,
        ) -> io::Result<Option<Box<dyn RepositoryItem>>> {
            if !self.is_connected() {
                return Err(not_connected());
            }
            if self.items.borrow().contains_key(&format!("{folder_path}/{item_name}")) {
                Ok(Some(Box::new(MockRepositoryItem)))
            }
            else {
                Ok(None)
            }
        }

        fn get_item_count(&self) -> io::Result<i32> {
            if !self.is_connected() {
                return Err(not_connected());
            }
            Ok(self.items.borrow().len() as i32)
        }
    }

    #[test]
    fn test_object_safety_and_connection_lifecycle() {
        let adapter: Box<dyn RepositoryAdapter> = Box::new(MockRepositoryAdapter::new("MyRepo"));

        assert_eq!(adapter.get_name(), "MyRepo");
        assert!(!adapter.is_connected());
        assert!(adapter.get_user().is_err());

        adapter.connect().unwrap();
        assert!(adapter.is_connected());
        assert_eq!(adapter.get_user().unwrap().name(), "alice");

        adapter.disconnect();
        assert!(!adapter.is_connected());
        assert!(adapter.get_user().is_err());
    }

    #[test]
    fn test_item_operations_require_connection() {
        let adapter = MockRepositoryAdapter::new("MyRepo");
        assert!(adapter.create_text_data_file("/", "item1", "id1", "text/plain", "hi", "").is_err());

        adapter.connect().unwrap();
        assert!(adapter
            .create_text_data_file("/", "item1", "id1", "text/plain", "hi", "")
            .is_ok());
        assert_eq!(adapter.get_item_count().unwrap(), 1);
        assert!(adapter.get_item("/", "item1").unwrap().is_some());
        assert!(adapter.get_item("/", "missing").unwrap().is_none());
    }

    #[test]
    fn test_bare_default_impl_reports_not_connected() {
        struct BareRepositoryAdapter;
        impl RepositoryAdapter for BareRepositoryAdapter {}

        let adapter = BareRepositoryAdapter;
        assert!(!adapter.is_connected());
        assert!(!adapter.had_unexpected_disconnect());
        assert!(!adapter.verify_connection());
        assert_eq!(adapter.get_open_file_handle_count(), 0);
        assert!(adapter.connect().is_err());
        assert!(adapter.get_user().is_err());
        assert!(adapter.get_item_list("/").is_err());
        assert!(adapter.folder_exists("/").is_err());
    }

    #[test]
    fn test_data_file_operations_are_always_unsupported() {
        struct BareRepositoryAdapter;
        impl RepositoryAdapter for BareRepositoryAdapter {}

        let adapter = BareRepositoryAdapter;
        assert!(adapter.create_data_file("/", "item1").is_err());
        assert!(adapter.open_data_file("/", "item1", -1).is_err());
    }
}
