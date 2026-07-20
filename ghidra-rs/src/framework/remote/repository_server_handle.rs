use std::io;

use crate::framework::remote::RepositoryHandle;

/// Provides access to a repository server.
///
/// Mirrors `ghidra.framework.remote.RepositoryServerHandle`. Every method is declared `throws
/// IOException` in Java (the javadoc-only `UserAccessException`/`DuplicateFileException`
/// mentions are subtypes of `IOException`, not additional checked exceptions), so every method
/// here returns `io::Result`. Implementations may be remote (RMI) handles, so every method takes
/// `&self` even where a local-only implementation could use `&mut self`.
pub trait RepositoryServerHandle {
    /// Returns true if server allows anonymous access. Individual repositories must grant
    /// anonymous access separately.
    fn anonymous_access_allowed(&self) -> io::Result<bool>;

    /// Returns true if user has restricted read-only access to server (e.g., anonymous user).
    fn is_read_only(&self) -> io::Result<bool>;

    /// Create a new repository on the server. The newly created handle will contain a unique
    /// project ID for the client, used to identify and maintain checkout data.
    fn create_repository(&self, name: &str) -> io::Result<Box<dyn RepositoryHandle>>;

    /// Get a handle to an existing repository, or `None` if the repository does not exist.
    fn get_repository(&self, name: &str) -> io::Result<Option<Box<dyn RepositoryHandle>>>;

    /// Delete a repository.
    fn delete_repository(&self, name: &str) -> io::Result<()>;

    /// Returns a list of all repository names which are accessible by the current user.
    fn get_repository_names(&self) -> io::Result<Vec<String>>;

    /// Returns current user for which this handle belongs.
    fn get_user(&self) -> io::Result<String>;

    /// Returns a list of all known users.
    fn get_all_users(&self) -> io::Result<Vec<String>>;

    /// Returns true if the user's password can be changed.
    fn can_set_password(&self) -> io::Result<bool>;

    /// Returns the amount of time in milliseconds until the user's password will expire, or -1
    /// if it will not expire.
    fn get_password_expiration(&self) -> io::Result<i64>;

    /// Set the password for the user. `salted_sha256_password_hash` is a SHA256 salted password
    /// hash. Returns true if the password changed.
    fn set_password(&self, salted_sha256_password_hash: &[u8]) -> io::Result<bool>;

    /// Verify that server is alive and connected.
    fn connected(&self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffers::ManagedBufferFileHandle;
    use crate::framework::remote::repository_handle::RepositoryNameError;
    use crate::framework::remote::{EventType, RepositoryChangeEvent, User};
    use crate::framework::seam_stubs::{CheckoutType, ItemCheckoutStatus, RepositoryItem};
    use crate::framework::store::ItemVersion;
    use std::cell::RefCell;

    struct MockRepositoryHandle {
        name: String,
    }

    impl RepositoryHandle for MockRepositoryHandle {
        fn get_name(&self) -> io::Result<String> {
            Ok(self.name.clone())
        }

        fn get_user(&self) -> io::Result<User> {
            Ok(User::new("alice", crate::framework::remote::Permission::Admin))
        }

        fn get_user_list(&self) -> io::Result<Vec<User>> {
            Ok(vec![])
        }

        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_server_user_list(&self) -> io::Result<Vec<String>> {
            Ok(vec![])
        }

        fn set_user_list(&self, _users: &[User], _anonymous_access_allowed: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_subfolder_list(&self, _folder_path: &str) -> io::Result<Vec<String>> {
            Ok(vec![])
        }

        fn get_item_count(&self) -> io::Result<i32> {
            Ok(0)
        }

        fn get_item_list(&self, _folder_path: &str) -> io::Result<Vec<Box<dyn RepositoryItem>>> {
            Ok(vec![])
        }

        fn get_item(
            &self,
            _parent_path: &str,
            _name: &str,
        ) -> io::Result<Option<Box<dyn RepositoryItem>>> {
            Ok(None)
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
            _item_name: &str,
            _file_id: &str,
            _content_type: &str,
            _text_data: &str,
            _comment: &str,
        ) -> Result<(), RepositoryNameError> {
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
            Ok(vec![])
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
            Err(io::Error::other("checkout not supported by mock"))
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
            Err(io::Error::other("checkout not supported by mock"))
        }

        fn get_checkouts(
            &self,
            _parent_path: &str,
            _item_name: &str,
        ) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
            Ok(vec![])
        }

        fn folder_exists(&self, _folder_path: &str) -> io::Result<bool> {
            Ok(false)
        }

        fn file_exists(&self, _parent_path: &str, _item_name: &str) -> io::Result<bool> {
            Ok(false)
        }

        fn get_length(&self, _parent_path: &str, _item_name: &str) -> io::Result<i64> {
            Ok(0)
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
            Ok(vec![])
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Mock server handle backed by an in-memory repository name set, proving
    /// [`RepositoryServerHandle`] is object-safe and exercising realistic create/get/delete
    /// behavior (not trivially-true asserts).
    struct MockRepositoryServerHandle {
        repositories: RefCell<Vec<String>>,
        read_only: bool,
        connected: RefCell<bool>,
    }

    impl MockRepositoryServerHandle {
        fn new(read_only: bool) -> Self {
            Self {
                repositories: RefCell::new(vec!["Repo1".to_string()]),
                read_only,
                connected: RefCell::new(true),
            }
        }
    }

    impl RepositoryServerHandle for MockRepositoryServerHandle {
        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn is_read_only(&self) -> io::Result<bool> {
            Ok(self.read_only)
        }

        fn create_repository(&self, name: &str) -> io::Result<Box<dyn RepositoryHandle>> {
            let mut repos = self.repositories.borrow_mut();
            if repos.iter().any(|r| r == name) {
                return Err(io::Error::other(format!(
                    "repository already exists: {name}"
                )));
            }
            repos.push(name.to_string());
            Ok(Box::new(MockRepositoryHandle {
                name: name.to_string(),
            }))
        }

        fn get_repository(&self, name: &str) -> io::Result<Option<Box<dyn RepositoryHandle>>> {
            if self.repositories.borrow().iter().any(|r| r == name) {
                Ok(Some(Box::new(MockRepositoryHandle {
                    name: name.to_string(),
                })))
            }
            else {
                Ok(None)
            }
        }

        fn delete_repository(&self, name: &str) -> io::Result<()> {
            let mut repos = self.repositories.borrow_mut();
            let before = repos.len();
            repos.retain(|r| r != name);
            if repos.len() == before {
                return Err(io::Error::other(format!("no such repository: {name}")));
            }
            Ok(())
        }

        fn get_repository_names(&self) -> io::Result<Vec<String>> {
            Ok(self.repositories.borrow().clone())
        }

        fn get_user(&self) -> io::Result<String> {
            Ok("alice".to_string())
        }

        fn get_all_users(&self) -> io::Result<Vec<String>> {
            Ok(vec!["alice".to_string(), "bob".to_string()])
        }

        fn can_set_password(&self) -> io::Result<bool> {
            Ok(!self.read_only)
        }

        fn get_password_expiration(&self) -> io::Result<i64> {
            Ok(-1)
        }

        fn set_password(&self, salted_sha256_password_hash: &[u8]) -> io::Result<bool> {
            if self.read_only || salted_sha256_password_hash.is_empty() {
                return Ok(false);
            }
            Ok(true)
        }

        fn connected(&self) -> io::Result<()> {
            if *self.connected.borrow() {
                Ok(())
            }
            else {
                Err(io::Error::other("not connected"))
            }
        }
    }

    #[test]
    fn test_object_safety_and_repository_lifecycle() {
        let server: Box<dyn RepositoryServerHandle> = Box::new(MockRepositoryServerHandle::new(false));

        assert!(!server.anonymous_access_allowed().unwrap());
        assert!(!server.is_read_only().unwrap());
        assert_eq!(server.get_repository_names().unwrap(), vec!["Repo1"]);

        assert!(server.get_repository("Repo1").unwrap().is_some());
        assert!(server.get_repository("NoSuchRepo").unwrap().is_none());

        let handle = server.create_repository("Repo2").unwrap();
        assert_eq!(handle.get_name().unwrap(), "Repo2");
        assert_eq!(server.get_repository_names().unwrap().len(), 2);

        let err = server.create_repository("Repo2").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        server.delete_repository("Repo2").unwrap();
        assert_eq!(server.get_repository_names().unwrap(), vec!["Repo1"]);
        assert!(server.delete_repository("Repo2").is_err());
    }

    #[test]
    fn test_password_and_connection_state() {
        let read_write: Box<dyn RepositoryServerHandle> =
            Box::new(MockRepositoryServerHandle::new(false));
        assert!(read_write.can_set_password().unwrap());
        assert!(read_write.set_password(b"salted-hash").unwrap());
        assert!(!read_write.set_password(b"").unwrap());
        assert_eq!(read_write.get_password_expiration().unwrap(), -1);
        assert!(read_write.connected().is_ok());

        let read_only: Box<dyn RepositoryServerHandle> =
            Box::new(MockRepositoryServerHandle::new(true));
        assert!(!read_only.can_set_password().unwrap());
        assert!(!read_only.set_password(b"salted-hash").unwrap());
    }
}
