// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/RepositoryHandleImpl.java
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

use crate::framework::remote::{RepositoryChangeEvent, RepositoryHandle};
use crate::server::seam_stubs::RepositoryLike;

/// Provides a repository handle to a remote user.
///
/// Mirrors `ghidra.server.remote.RepositoryHandleImpl`, recast as a trait so callers can depend on
/// handle-management behavior without depending on any single concrete implementation.
/// `Repository` (`ghidra.server.Repository`) holds an `ArrayList<RepositoryHandleImpl>` and calls
/// `handle.checkHandle()`, `handle.dispatchEvents(events)` and `handle.dispose()` directly on the
/// concrete type -- none of which are declared on the `RepositoryHandle`/`RemoteRepositoryHandle`
/// interfaces this class also implements -- while `RepositoryHandleImpl` in turn holds a
/// `Repository` field and calls back into it (`getSyncObject`, `log`, `addHandle`, `dropHandle`,
/// ...). That direct concrete-type coupling forms the cycle `Repository` <-> `RepositoryHandleImpl`;
/// `RepositoryHandleImpl` was selected as the cut-point, so `Repository` is represented here by the
/// [`RepositoryLike`] placeholder until it is ported.
///
/// Every method the RMI interface declares (`getName`, `getUser`, `checkout`, ...) is already
/// available through the [`RepositoryHandle`] supertrait, unchanged from the concrete Java class's
/// `@Override` implementations, which simply delegate to the wrapped
/// `Repository`/`RepositoryFile`/`RepositoryFolder`. This trait adds only the members reached
/// through the concrete type rather than through `RepositoryHandle`: `get_repository` and
/// `get_user_name` (read by the sibling `RemoteBufferFileImpl`/`RemoteManagedBufferFileImpl`
/// implementations for logging, neither yet ported), and `dispose`/`check_handle`/`dispatch_events`
/// (called directly by `Repository` to manage its handle list and event fan-out, bypassing the RMI
/// interface entirely). The RMI `unreferenced()` callback simply forwards to `dispose()` and adds
/// no behavior of its own, and the private per-instance bookkeeping (`isValid`, `syncObject`,
/// `eventQueue`, `transientCheckouts`, `currentUser`) is synchronization and RMI-lifecycle plumbing
/// for one concrete implementation, not part of the observable interface -- consistent with how
/// [`RepositoryFile`](crate::server::store::repository_file::RepositoryFile) omitted its own
/// private sync fields for the same reason -- so both are intentionally left out.
pub trait RepositoryHandleImpl: RepositoryHandle {
    /// Returns the repository store wrapped by this handle.
    fn get_repository(&self) -> Box<dyn RepositoryLike>;

    /// Returns the name of the user this handle was created for, or `None` if the handle has
    /// since been disposed.
    fn get_user_name(&self) -> Option<String>;

    /// Disposes this handle: terminates any transient checkouts held by the client, notifies the
    /// wrapped repository, and releases any threads waiting on pending events. Idempotent --
    /// calling this more than once after the first has no additional effect.
    fn dispose(&self);

    /// Verifies that the client is still active and reading events, disposing the handle if it
    /// has stopped listening. Invoked periodically by the owning repository.
    fn check_handle(&self);

    /// Posts repository change events to the client.
    fn dispatch_events(&self, events: &[RepositoryChangeEvent]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffers::ManagedBufferFileHandle;
    use crate::framework::remote::repository_handle::RepositoryNameError;
    use crate::framework::remote::{Permission, User};
    use crate::framework::seam_stubs::{CheckoutType, ItemCheckoutStatus, RepositoryItem};
    use crate::framework::store::ItemVersion;
    use std::cell::RefCell;
    use std::io;
    use std::sync::{Arc, Mutex};

    struct MockRepository {
        name: String,
        log_entries: Mutex<Vec<(Option<String>, String, Option<String>)>>,
    }

    impl RepositoryLike for MockRepository {
        fn log(&self, path: Option<&str>, msg: &str, user: Option<&str>) {
            self.log_entries.lock().unwrap().push((
                path.map(str::to_string),
                msg.to_string(),
                user.map(str::to_string),
            ));
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    /// Minimal `RepositoryHandleImpl` impl proving object-safety and exercising the
    /// dispose/check-handle/dispatch-events lifecycle the real `Repository` drives directly.
    struct MockRepositoryHandleImpl {
        user: RefCell<Option<String>>,
        events: RefCell<Vec<RepositoryChangeEvent>>,
        client_active: RefCell<bool>,
        repository: Arc<MockRepository>,
    }

    impl RepositoryHandle for MockRepositoryHandleImpl {
        fn get_name(&self) -> io::Result<String> {
            Ok(self.repository.get_name())
        }

        fn get_user(&self) -> io::Result<User> {
            Ok(User::new(
                self.user.borrow().as_deref().unwrap_or(""),
                Permission::Admin,
            ))
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
            let mut events = self.events.borrow_mut();
            let drained = events.clone();
            events.clear();
            Ok(drained)
        }

        fn close(&self) -> io::Result<()> {
            self.dispose();
            Ok(())
        }
    }

    impl RepositoryHandleImpl for MockRepositoryHandleImpl {
        fn get_repository(&self) -> Box<dyn RepositoryLike> {
            struct ArcRepository(Arc<MockRepository>);
            impl RepositoryLike for ArcRepository {
                fn log(&self, path: Option<&str>, msg: &str, user: Option<&str>) {
                    self.0.log(path, msg, user);
                }
                fn get_name(&self) -> String {
                    self.0.get_name()
                }
            }
            Box::new(ArcRepository(self.repository.clone()))
        }

        fn get_user_name(&self) -> Option<String> {
            self.user.borrow().clone()
        }

        fn dispose(&self) {
            if self.user.borrow().is_none() {
                return;
            }
            self.repository.log(
                None,
                "Handle disposed",
                self.user.borrow().as_deref(),
            );
            self.events.borrow_mut().clear();
            *self.user.borrow_mut() = None;
        }

        fn check_handle(&self) {
            if self.user.borrow().is_none() {
                return;
            }
            let mut active = self.client_active.borrow_mut();
            if *active {
                *active = false;
                return;
            }
            drop(active);
            self.repository
                .log(None, "Not listening (may be sleeping)!", self.user.borrow().as_deref());
            self.dispose();
        }

        fn dispatch_events(&self, events: &[RepositoryChangeEvent]) {
            if self.user.borrow().is_none() {
                return;
            }
            self.events.borrow_mut().extend_from_slice(events);
        }
    }

    fn new_handle() -> MockRepositoryHandleImpl {
        MockRepositoryHandleImpl {
            user: RefCell::new(Some("alice".to_string())),
            events: RefCell::new(vec![]),
            client_active: RefCell::new(true),
            repository: Arc::new(MockRepository {
                name: "MyRepo".to_string(),
                log_entries: Mutex::new(vec![]),
            }),
        }
    }

    #[test]
    fn test_object_safety_and_repository_hop() {
        let handle: Box<dyn RepositoryHandleImpl> = Box::new(new_handle());

        assert_eq!(handle.get_user_name().as_deref(), Some("alice"));
        assert_eq!(handle.get_repository().get_name(), "MyRepo");
        assert_eq!(handle.get_name().unwrap(), "MyRepo");
    }

    #[test]
    fn test_dispatch_events_then_drain_via_get_events() {
        let handle = new_handle();
        let ev = RepositoryChangeEvent::new(
            crate::framework::remote::EventType::ItemCreated,
            Some("/".to_string()),
            Some("item1".to_string()),
            None,
            None,
        );
        handle.dispatch_events(std::slice::from_ref(&ev));
        handle.dispatch_events(std::slice::from_ref(&ev));

        let drained = handle.get_events().unwrap();
        assert_eq!(drained.len(), 2);
        assert!(handle.get_events().unwrap().is_empty());
    }

    #[test]
    fn test_check_handle_disposes_inactive_client() {
        let handle = new_handle();

        // First check while active just flips the activity flag (mirrors the real
        // implementation waiting for the client to call getEvents() again).
        handle.check_handle();
        assert!(handle.get_user_name().is_some());

        // A second check before the client re-marks itself active means it stopped
        // listening, so the handle is disposed.
        handle.check_handle();
        assert!(handle.get_user_name().is_none());
        assert!(handle
            .repository
            .log_entries
            .lock()
            .unwrap()
            .iter()
            .any(|(_, msg, _)| msg.contains("Not listening")));
    }

    #[test]
    fn test_dispose_is_idempotent_and_clears_queued_events() {
        let handle = new_handle();
        let ev = RepositoryChangeEvent::new(
            crate::framework::remote::EventType::ItemDeleted,
            None,
            None,
            None,
            None,
        );
        handle.dispatch_events(std::slice::from_ref(&ev));

        handle.dispose();
        assert!(handle.get_user_name().is_none());
        assert!(handle.get_events().unwrap().is_empty());

        let log_count_after_first = handle.repository.log_entries.lock().unwrap().len();
        handle.dispose();
        assert_eq!(
            handle.repository.log_entries.lock().unwrap().len(),
            log_count_after_first,
            "second dispose() must be a no-op"
        );
    }
}
