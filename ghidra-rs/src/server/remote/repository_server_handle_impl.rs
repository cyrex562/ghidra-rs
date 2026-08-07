// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/RepositoryServerHandleImpl.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use crate::framework::remote::RepositoryServerHandle;

/// Provides a Repository Server handle to a remote user.
///
/// Mirrors `ghidra.server.remote.RepositoryServerHandleImpl`, recast as a trait so callers can
/// depend on server-handle behavior without depending on any single concrete implementation.
/// `RepositoryManager` (`ghidra.server.RepositoryManager`) holds an
/// `ArrayList<RepositoryServerHandleImpl>` and calls `handle.addHandle(this)`/`dropHandle(this)`
/// directly on the concrete type from the constructor and RMI `unreferenced()` callback, while
/// `RepositoryServerHandleImpl` in turn holds a `RepositoryManager mgr` field and calls back into
/// it for every operation (`createRepository`, `getRepository`, `deleteRepository`,
/// `getRepositoryNames`, `getAllUsers`, `getUserManager`, `anonymousAccessAllowed`). That direct
/// concrete-type coupling forms the cycle `RepositoryManager` <-> `RepositoryServerHandleImpl`;
/// `RepositoryServerHandleImpl` was selected as the cut-point, so `RepositoryManager` is
/// represented here by the
/// [`RepositoryManagerLike`](crate::server::seam_stubs::RepositoryManagerLike) placeholder until
/// it is ported.
///
/// Every method the RMI interface declares (`createRepository`, `getRepository`,
/// `deleteRepository`, `getRepositoryNames`, `getUser`, `getAllUsers`, `canSetPassword`,
/// `getPasswordExpiration`, `setPassword`, `anonymousAccessAllowed`, `isReadOnly`, `connected`) is
/// already available through the [`RepositoryServerHandle`] supertrait, unchanged from the
/// concrete Java class's `@Override` implementations, which simply delegate to the wrapped
/// `RepositoryManager`/`UserManager`. This trait adds only the one additional public method the
/// concrete class declares beyond that interface: `unreferenced`, the RMI callback invoked by the
/// RMI runtime when the handle becomes unreferenced by any remote client, which drops the
/// handle's registration with the owning repository manager. The constructor's own registration
/// step (`mgr.addHandle(this)`) has no trait-method equivalent, since construction is specific to
/// each concrete implementation rather than part of this trait's dyn-dispatched surface; the
/// private per-instance fields (`currentUser`, `readOnly`, `supportPasswordChange`) are
/// constructor-supplied configuration already exposed through `RepositoryServerHandle::get_user`/
/// `is_read_only`/`can_set_password`, not additional observable behavior, so they are
/// intentionally left out here too.
pub trait RepositoryServerHandleImpl: RepositoryServerHandle {
    /// RMI callback invoked when this handle becomes unreferenced by any remote client; drops
    /// the handle's registration with the owning repository manager.
    fn unreferenced(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::repository_handle::RepositoryNameError;
    use crate::framework::remote::{RepositoryHandle, User};
    use crate::framework::db::buffers::ManagedBufferFileHandle;
    use crate::framework::remote::RepositoryChangeEvent;
    use crate::framework::seam_stubs::{ItemCheckoutStatus, RepositoryItem};
use crate::framework::store::CheckoutType;
    use crate::framework::store::ItemVersion;
    use crate::server::seam_stubs::{RepositoryLike, RepositoryManagerLike, UserManagerLike};
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Minimal `RepositoryHandle` impl wrapping just a repository name, standing in for the
    /// real `RepositoryHandleImpl` the concrete Java class constructs from a `Repository`.
    struct MinimalRepoHandle {
        name: String,
    }

    impl RepositoryHandle for MinimalRepoHandle {
        fn get_name(&self) -> io::Result<String> {
            Ok(self.name.clone())
        }
        fn get_user(&self) -> io::Result<User> {
            Err(io::Error::other("not supported by mock"))
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
        fn get_item_by_file_id(&self, _file_id: &str) -> io::Result<Option<Box<dyn RepositoryItem>>> {
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
        fn get_versions(&self, _parent_path: &str, _item_name: &str) -> io::Result<Vec<ItemVersion>> {
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

    struct MockRepository {
        name: String,
    }

    impl RepositoryLike for MockRepository {
        fn log(&self, _path: Option<&str>, _msg: &str, _user: Option<&str>) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockUserManager {
        local_passwords_enabled: bool,
    }

    impl UserManagerLike for MockUserManager {
        fn can_set_password(&self, username: &str) -> bool {
            self.local_passwords_enabled && username == "alice"
        }

        fn get_password_expiration(&self, _username: &str) -> i64 {
            -1
        }

        fn set_password(
            &self,
            username: &str,
            salted_sha256_password_hash: &[u8],
            _is_temporary: bool,
        ) -> io::Result<bool> {
            if !self.local_passwords_enabled {
                return Err(io::Error::other("Local passwords are not used"));
            }
            Ok(username == "alice" && !salted_sha256_password_hash.is_empty())
        }
    }

    /// Mock repository manager backed by an in-memory repository name set, standing in for
    /// `ghidra.server.RepositoryManager` and exercising the real create/get/delete lifecycle
    /// `RepositoryServerHandleImpl` delegates to it.
    struct MockRepositoryManager {
        repositories: Mutex<Vec<String>>,
        anonymous_access: bool,
        local_passwords_enabled: bool,
    }

    impl RepositoryManagerLike for MockRepositoryManager {
        fn anonymous_access_allowed(&self) -> bool {
            self.anonymous_access
        }

        fn create_repository(
            &self,
            _current_user: &str,
            name: &str,
        ) -> io::Result<Box<dyn RepositoryLike>> {
            let mut repos = self.repositories.lock().unwrap();
            if repos.iter().any(|r| r == name) {
                return Err(io::Error::other(format!("repository already exists: {name}")));
            }
            repos.push(name.to_string());
            Ok(Box::new(MockRepository { name: name.to_string() }))
        }

        fn get_repository(
            &self,
            _current_user: &str,
            name: &str,
        ) -> io::Result<Option<Box<dyn RepositoryLike>>> {
            if self.repositories.lock().unwrap().iter().any(|r| r == name) {
                Ok(Some(Box::new(MockRepository { name: name.to_string() })))
            }
            else {
                Ok(None)
            }
        }

        fn delete_repository(&self, _current_user: &str, name: &str) -> io::Result<()> {
            let mut repos = self.repositories.lock().unwrap();
            let before = repos.len();
            repos.retain(|r| r != name);
            if repos.len() == before {
                return Err(io::Error::other(format!("no such repository: {name}")));
            }
            Ok(())
        }

        fn get_repository_names(&self, _current_user: &str) -> Vec<String> {
            self.repositories.lock().unwrap().clone()
        }

        fn get_all_users(&self, _current_user: &str) -> Vec<String> {
            vec!["alice".to_string(), "bob".to_string()]
        }

        fn get_user_manager(&self) -> Box<dyn UserManagerLike> {
            Box::new(MockUserManager {
                local_passwords_enabled: self.local_passwords_enabled,
            })
        }
    }

    /// Minimal `RepositoryServerHandleImpl` impl proving object-safety and exercising the
    /// delegate-to-`mgr` behavior the real class implements for every `RepositoryServerHandle`
    /// method, plus the `unreferenced` lifecycle callback.
    struct MockRepositoryServerHandleImpl {
        current_user: String,
        read_only: bool,
        support_password_change: bool,
        mgr: Arc<MockRepositoryManager>,
        active: Mutex<bool>,
    }

    impl RepositoryServerHandle for MockRepositoryServerHandleImpl {
        fn anonymous_access_allowed(&self) -> io::Result<bool> {
            Ok(self.mgr.anonymous_access_allowed())
        }

        fn is_read_only(&self) -> io::Result<bool> {
            Ok(self.read_only)
        }

        fn create_repository(&self, name: &str) -> io::Result<Box<dyn RepositoryHandle>> {
            let repository = self.mgr.create_repository(&self.current_user, name)?;
            Ok(Box::new(MinimalRepoHandle {
                name: repository.get_name(),
            }))
        }

        fn get_repository(&self, name: &str) -> io::Result<Option<Box<dyn RepositoryHandle>>> {
            Ok(self
                .mgr
                .get_repository(&self.current_user, name)?
                .map(|repository| {
                    Box::new(MinimalRepoHandle {
                        name: repository.get_name(),
                    }) as Box<dyn RepositoryHandle>
                }))
        }

        fn delete_repository(&self, name: &str) -> io::Result<()> {
            self.mgr.delete_repository(&self.current_user, name)
        }

        fn get_repository_names(&self) -> io::Result<Vec<String>> {
            Ok(self.mgr.get_repository_names(&self.current_user))
        }

        fn get_user(&self) -> io::Result<String> {
            Ok(self.current_user.clone())
        }

        fn get_all_users(&self) -> io::Result<Vec<String>> {
            if self.read_only {
                return Ok(vec![]);
            }
            Ok(self.mgr.get_all_users(&self.current_user))
        }

        fn can_set_password(&self) -> io::Result<bool> {
            Ok(self.support_password_change
                && self.mgr.get_user_manager().can_set_password(&self.current_user))
        }

        fn get_password_expiration(&self) -> io::Result<i64> {
            if self.can_set_password()? {
                return Ok(self.mgr.get_user_manager().get_password_expiration(&self.current_user));
            }
            Ok(-1)
        }

        fn set_password(&self, salted_sha256_password_hash: &[u8]) -> io::Result<bool> {
            if !self.can_set_password()? {
                return Ok(false);
            }
            self.mgr.get_user_manager().set_password(
                &self.current_user,
                salted_sha256_password_hash,
                false,
            )
        }

        fn connected(&self) -> io::Result<()> {
            Ok(())
        }
    }

    impl RepositoryServerHandleImpl for MockRepositoryServerHandleImpl {
        fn unreferenced(&self) {
            *self.active.lock().unwrap() = false;
        }
    }

    fn new_handle(mgr: Arc<MockRepositoryManager>) -> MockRepositoryServerHandleImpl {
        MockRepositoryServerHandleImpl {
            current_user: "alice".to_string(),
            read_only: false,
            support_password_change: true,
            mgr,
            active: Mutex::new(true),
        }
    }

    fn new_manager() -> Arc<MockRepositoryManager> {
        Arc::new(MockRepositoryManager {
            repositories: Mutex::new(vec!["Repo1".to_string()]),
            anonymous_access: false,
            local_passwords_enabled: true,
        })
    }

    #[test]
    fn test_object_safety_and_repository_lifecycle_via_mgr() {
        let mgr = new_manager();
        let handle: Box<dyn RepositoryServerHandleImpl> = Box::new(new_handle(mgr.clone()));

        assert_eq!(handle.get_repository_names().unwrap(), vec!["Repo1"]);
        assert!(handle.get_repository("Repo1").unwrap().is_some());
        assert!(handle.get_repository("NoSuchRepo").unwrap().is_none());

        let created = handle.create_repository("Repo2").unwrap();
        assert_eq!(created.get_name().unwrap(), "Repo2");
        assert_eq!(handle.get_repository_names().unwrap().len(), 2);

        assert!(handle.create_repository("Repo2").is_err());

        handle.delete_repository("Repo2").unwrap();
        assert_eq!(handle.get_repository_names().unwrap(), vec!["Repo1"]);
        assert!(mgr.get_repository("alice", "Repo2").unwrap().is_none());
    }

    #[test]
    fn test_password_change_delegates_through_can_set_password_gate() {
        let mgr = new_manager();
        let handle = new_handle(mgr);

        assert!(handle.can_set_password().unwrap());
        assert_eq!(handle.get_password_expiration().unwrap(), -1);
        assert!(handle.set_password(b"somehash").unwrap());

        // Once support_password_change is false, every password operation is gated off even
        // though the underlying user manager would otherwise allow it.
        let gated = MockRepositoryServerHandleImpl {
            support_password_change: false,
            ..new_handle(new_manager())
        };
        assert!(!gated.can_set_password().unwrap());
        assert_eq!(gated.get_password_expiration().unwrap(), -1);
        assert!(!gated.set_password(b"somehash").unwrap());
    }

    #[test]
    fn test_read_only_hides_all_users_but_not_repository_listing() {
        let mgr = new_manager();
        let handle = MockRepositoryServerHandleImpl {
            read_only: true,
            ..new_handle(mgr)
        };

        assert!(handle.is_read_only().unwrap());
        assert!(handle.get_all_users().unwrap().is_empty());
        assert_eq!(handle.get_repository_names().unwrap(), vec!["Repo1"]);
    }

    #[test]
    fn test_unreferenced_marks_handle_inactive() {
        let handle = new_handle(new_manager());
        assert!(*handle.active.lock().unwrap());

        handle.unreferenced();
        assert!(!*handle.active.lock().unwrap());
    }
}
