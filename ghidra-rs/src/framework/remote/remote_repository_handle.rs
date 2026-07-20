use crate::framework::remote::RepositoryHandle;

/// Provides access to a remote repository via RMI.
///
/// Mirrors `ghidra.framework.remote.RemoteRepositoryHandle`. In Java this interface re-declares
/// every method of [`RepositoryHandle`] verbatim (each annotated `@Override`); that re-declaration
/// exists only so the JDK's RMI stub generator marshals each method for remote invocation (a quirk
/// of `RemoteObjectInvocationHandler` since OpenJDK 11.0.6). Rust has no RMI layer and
/// [`RepositoryHandle`]'s methods already return `io::Result` (or [`RepositoryNameError`]) for
/// every operation, so there is no distinct signature to restate here: `RemoteRepositoryHandle` is
/// declared as a supertrait-bound marker, and every `RepositoryHandle` method remains reachable
/// through it unchanged.
///
/// [`RepositoryNameError`]: crate::framework::remote::RepositoryNameError
pub trait RemoteRepositoryHandle: RepositoryHandle {}

/// Blanket impl: any local `RepositoryHandle` is usable wherever a remote handle is expected,
/// mirroring how the Java interface adds no behavior beyond `RepositoryHandle` itself.
impl<T: RepositoryHandle + ?Sized> RemoteRepositoryHandle for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::repository_handle::RepositoryNameError;
    use crate::framework::remote::{Permission, User};
    use std::cell::RefCell;
    use std::io;

    /// Minimal `RepositoryHandle` impl backed by an in-memory item-name set, proving
    /// [`RemoteRepositoryHandle`] is object-safe (via the blanket impl over [`RepositoryHandle`])
    /// and exercising realistic create/exists/delete behavior.
    #[derive(Default)]
    struct MockRepositoryHandle {
        items: RefCell<Vec<String>>,
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
            Ok(vec!["alice".to_string()])
        }

        fn set_user_list(&self, _users: &[User], _anonymous_access_allowed: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_subfolder_list(&self, _folder_path: &str) -> io::Result<Vec<String>> {
            Ok(vec![])
        }

        fn get_item_count(&self) -> io::Result<i32> {
            Ok(self.items.borrow().len() as i32)
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
            item_name: &str,
            _file_id: &str,
            _content_type: &str,
            _text_data: &str,
            _comment: &str,
        ) -> Result<(), RepositoryNameError> {
            let mut items = self.items.borrow_mut();
            if items.iter().any(|i| i == item_name) {
                return Err(RepositoryNameError::Io(io::Error::other(format!(
                    "item already exists: {item_name}"
                ))));
            }
            items.push(item_name.to_string());
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
            RepositoryNameError,
        > {
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

        fn delete_item(&self, _parent_path: &str, item_name: &str, _version: i32) -> io::Result<()> {
            let mut items = self.items.borrow_mut();
            let before = items.len();
            items.retain(|i| i != item_name);
            if items.len() == before {
                return Err(io::Error::other(format!("no such item: {item_name}")));
            }
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

        fn file_exists(&self, _parent_path: &str, item_name: &str) -> io::Result<bool> {
            Ok(self.items.borrow().iter().any(|i| i == item_name))
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

        fn get_events(&self) -> io::Result<Vec<crate::framework::remote::RepositoryChangeEvent>> {
            Ok(vec![])
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_remote_handle_object_safety_and_item_lifecycle() {
        let handle: Box<dyn RemoteRepositoryHandle> = Box::new(MockRepositoryHandle::default());

        assert_eq!(handle.get_name().unwrap(), "MyRepo");
        assert_eq!(handle.get_item_count().unwrap(), 0);

        handle
            .create_text_data_file("/", "item1", "id1", "text/plain", "hello", "")
            .unwrap();
        assert!(handle.file_exists("/", "item1").unwrap());
        assert_eq!(handle.get_item_count().unwrap(), 1);

        let err = handle
            .create_text_data_file("/", "item1", "id1", "text/plain", "hello", "")
            .unwrap_err();
        assert!(matches!(err, RepositoryNameError::Io(_)));

        handle.delete_item("/", "item1", -1).unwrap();
        assert!(!handle.file_exists("/", "item1").unwrap());
        assert!(handle.delete_item("/", "item1", -1).is_err());
    }
}
