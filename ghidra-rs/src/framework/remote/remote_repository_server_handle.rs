use crate::framework::remote::RepositoryServerHandle;

/// Provides access to a remote repository server via RMI.
///
/// Mirrors `ghidra.framework.remote.RemoteRepositoryServerHandle`. In Java this interface
/// re-declares every method of [`RepositoryServerHandle`] verbatim; that re-declaration exists
/// only so the JDK's RMI stub generator marshals each method for remote invocation (a quirk of
/// `RemoteObjectInvocationHandler` since OpenJDK 11.0.6). Rust has no RMI layer and
/// [`RepositoryServerHandle`]'s methods already return `io::Result` for every operation, so there
/// is no distinct signature to restate here: `RemoteRepositoryServerHandle` is declared as a
/// supertrait-bound marker, and every `RepositoryServerHandle` method remains reachable through it
/// unchanged.
pub trait RemoteRepositoryServerHandle: RepositoryServerHandle {}

/// Blanket impl: any local `RepositoryServerHandle` is usable wherever a remote handle is
/// expected, mirroring how the Java interface adds no behavior beyond `RepositoryServerHandle`
/// itself.
impl<T: RepositoryServerHandle + ?Sized> RemoteRepositoryServerHandle for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::RepositoryHandle;
    use std::cell::RefCell;
    use std::io;

    struct MockRepositoryHandle {
        name: String,
    }

    impl RepositoryHandle for MockRepositoryHandle {
        fn get_name(&self) -> io::Result<String> {
            Ok(self.name.clone())
        }

        fn get_user(&self) -> io::Result<crate::framework::remote::User> {
            Ok(crate::framework::remote::User::new(
                "alice",
                crate::framework::remote::Permission::Admin,
            ))
        }

        fn get_user_list(&self) -> io::Result<Vec<crate::framework::remote::User>> {
            Ok(vec![])
        }

        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_server_user_list(&self) -> io::Result<Vec<String>> {
            Ok(vec![])
        }

        fn set_user_list(
            &self,
            _users: &[crate::framework::remote::User],
            _anonymous_access_allowed: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_subfolder_list(&self, _folder_path: &str) -> io::Result<Vec<String>> {
            Ok(vec![])
        }

        fn get_item_count(&self) -> io::Result<i32> {
            Ok(0)
        }

        fn get_item_list(
            &self,
            _folder_path: &str,
        ) -> io::Result<Vec<Box<dyn crate::framework::seam_stubs::RepositoryItem>>> {
            Ok(vec![])
        }

        fn get_item(
            &self,
            _parent_path: &str,
            _name: &str,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::RepositoryItem>>> {
            Ok(None)
        }

        fn get_item_by_file_id(
            &self,
            _file_id: &str,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::RepositoryItem>>> {
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
        ) -> Result<(), crate::framework::remote::repository_handle::RepositoryNameError> {
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
        ) -> Result<
            Box<dyn crate::framework::db::buffers::ManagedBufferFileHandle>,
            crate::framework::remote::repository_handle::RepositoryNameError,
        > {
            Err(
                crate::framework::remote::repository_handle::RepositoryNameError::Io(
                    io::Error::other("createDatabase not supported by mock"),
                ),
            )
        }

        fn open_database(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _version: i32,
            _min_change_data_ver: i32,
        ) -> io::Result<Box<dyn crate::framework::db::buffers::ManagedBufferFileHandle>> {
            Err(io::Error::other("openDatabase not supported by mock"))
        }

        fn open_database_for_checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_id: i64,
        ) -> io::Result<Box<dyn crate::framework::db::buffers::ManagedBufferFileHandle>> {
            Err(io::Error::other("openDatabase not supported by mock"))
        }

        fn get_versions(
            &self,
            _parent_path: &str,
            _item_name: &str,
        ) -> io::Result<Vec<crate::framework::store::ItemVersion>> {
            Ok(vec![])
        }

        fn delete_item(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _version: i32,
        ) -> io::Result<()> {
            Ok(())
        }

        fn move_folder(
            &self,
            _old_parent_path: &str,
            _new_parent_path: &str,
            _old_folder_name: &str,
            _new_folder_name: &str,
        ) -> Result<(), crate::framework::remote::repository_handle::RepositoryNameError> {
            Ok(())
        }

        fn move_item(
            &self,
            _old_parent_path: &str,
            _new_parent_path: &str,
            _old_item_name: &str,
            _new_item_name: &str,
        ) -> Result<(), crate::framework::remote::repository_handle::RepositoryNameError> {
            Ok(())
        }

        fn checkout(
            &self,
            _parent_path: &str,
            _item_name: &str,
            _checkout_type: crate::framework::seam_stubs::CheckoutType,
            _project_path: &str,
        ) -> io::Result<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>> {
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
        ) -> io::Result<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>> {
            Err(io::Error::other("checkout not supported by mock"))
        }

        fn get_checkouts(
            &self,
            _parent_path: &str,
            _item_name: &str,
        ) -> io::Result<Vec<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
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

        fn get_events(
            &self,
        ) -> io::Result<Vec<crate::framework::remote::RepositoryChangeEvent>> {
            Ok(vec![])
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Mock server handle backed by an in-memory repository name set, proving
    /// [`RemoteRepositoryServerHandle`] is object-safe (via the blanket impl over
    /// [`RepositoryServerHandle`]) and exercising realistic create/get/delete behavior.
    struct MockServerHandle {
        repositories: RefCell<Vec<String>>,
    }

    impl RepositoryServerHandle for MockServerHandle {
        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn is_read_only(&self) -> io::Result<bool> {
            Ok(false)
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
            Ok(vec!["alice".to_string()])
        }

        fn can_set_password(&self) -> io::Result<bool> {
            Ok(true)
        }

        fn get_password_expiration(&self) -> io::Result<i64> {
            Ok(-1)
        }

        fn set_password(&self, salted_sha256_password_hash: &[u8]) -> io::Result<bool> {
            Ok(!salted_sha256_password_hash.is_empty())
        }

        fn connected(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_remote_handle_object_safety_and_repository_lifecycle() {
        let server: Box<dyn RemoteRepositoryServerHandle> = Box::new(MockServerHandle {
            repositories: RefCell::new(vec!["Repo1".to_string()]),
        });

        assert!(server.connected().is_ok());
        assert_eq!(server.get_repository_names().unwrap(), vec!["Repo1"]);

        assert!(server.get_repository("Repo1").unwrap().is_some());
        assert!(server.get_repository("NoSuchRepo").unwrap().is_none());

        let handle = server.create_repository("Repo2").unwrap();
        assert_eq!(handle.get_name().unwrap(), "Repo2");
        assert_eq!(server.get_repository_names().unwrap().len(), 2);

        assert!(server.create_repository("Repo2").is_err());

        server.delete_repository("Repo2").unwrap();
        assert_eq!(server.get_repository_names().unwrap(), vec!["Repo1"]);
        assert!(server.delete_repository("Repo2").is_err());
    }
}
