// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/RepositoryManager.java
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

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::server::remote::RepositoryServerHandleImpl;
use crate::server::seam_stubs::{RepositoryLike, UserManagerLike};

/// Manages a set of Repositories under a root directory.
///
/// Mirrors `ghidra.server.RepositoryManager`, recast as a trait so callers can depend on
/// repository-management behavior without depending on any single concrete implementation.
/// `RepositoryManager` and
/// [`RepositoryServerHandleImpl`](crate::server::remote::RepositoryServerHandleImpl) form a
/// direct dependency cycle in Java (`RepositoryManager` holds an
/// `ArrayList<RepositoryServerHandleImpl>` and is itself held and delegated to by every
/// `RepositoryServerHandleImpl` method); `RepositoryServerHandleImpl` was already selected as the
/// cut-point and depends on this class only through the
/// [`RepositoryManagerLike`](crate::server::seam_stubs::RepositoryManagerLike) placeholder, so
/// this trait's `anonymous_access_allowed`/`create_repository`/`get_repository`/
/// `delete_repository`/`get_repository_names`/`get_all_users`/`get_user_manager` methods
/// intentionally reuse that placeholder's exact signatures.
///
/// `Repository` and `UserManager`, returned/produced by this manager, are not yet ported, so they
/// are represented here by the existing
/// [`RepositoryLike`](crate::server::seam_stubs::RepositoryLike) and
/// [`UserManagerLike`](crate::server::seam_stubs::UserManagerLike) placeholders.
///
/// The constructor (which validates the root directory, scans it for existing repositories, and
/// starts the command-queue watcher thread) and the private `initialize`/`validateUser`/
/// `isAnonymousUser` helpers are construction-time and per-implementation plumbing, not part of
/// the observable interface, so they are intentionally left out -- consistent with how sibling
/// ports in this module omit constructor setup logic. The package-private
/// `getRepository(String)` (privileged, no-user-check overload) and `getRepositoryNames()`
/// (no-arg) exist in Java only to implement `userRemoved`, so they are folded into this trait's
/// `user_removed` rather than exposed as separate methods. The static admin-console utilities
/// (`getRMIClient`, `listRepositories`, `markAllRepositoriesForIndexMigration`, `log`,
/// `getElapsedTimeSince`) do not operate on a `RepositoryManager` instance and depend on several
/// types that are not yet ported (`Repository.getFormattedUserPermissions`,
/// `IndexedLocalFileSystem`'s index-version statics), so they are out of scope for this
/// cycle-breaking trait.
pub trait RepositoryManager: Send + Sync {
    /// Returns true if server allows anonymous access.
    fn anonymous_access_allowed(&self) -> bool;

    /// Dispose this repository manager and all repository instances.
    fn dispose(&self);

    /// Returns the server's repositories root directory.
    fn get_root_dir(&self) -> PathBuf;

    /// Create a new repository on behalf of `current_user`.
    fn create_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> io::Result<Box<dyn RepositoryLike>>;

    /// Get the repository with the given name, or `None` if it does not exist.
    fn get_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> io::Result<Option<Box<dyn RepositoryLike>>>;

    /// Delete the named repository on behalf of `current_user`.
    fn delete_repository(&self, current_user: &str, name: &str) -> io::Result<()>;

    /// Returns the names of the known repositories which are accessible by `current_user`.
    fn get_repository_names(&self, current_user: &str) -> Vec<String>;

    /// Returns the names of all defined users, as seen by `current_user`; an anonymous
    /// `current_user` sees an empty list.
    fn get_all_users(&self, current_user: &str) -> Vec<String>;

    /// Returns the server's user manager.
    fn get_user_manager(&self) -> Box<dyn UserManagerLike>;

    /// Register a user handle with this repository server.
    fn add_handle(&self, handle: Arc<dyn RepositoryServerHandleImpl>);

    /// Drop a previously registered user handle from this repository server.
    fn drop_handle(&self, handle: Arc<dyn RepositoryServerHandleImpl>);

    /// Refresh the server's user list and process any pending UserAdmin commands.
    fn process_command_queue(&self) -> io::Result<()>;

    /// Callback when a user is removed from the server: remove the user from every repository's
    /// access list.
    fn user_removed(&self, username: &str) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockRepository {
        name: String,
    }

    impl RepositoryLike for MockRepository {
        fn log(&self, _path: Option<&str>, _msg: &str, _user: Option<&str>) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockUserManager;

    impl UserManagerLike for MockUserManager {
        fn can_set_password(&self, _username: &str) -> bool {
            true
        }

        fn get_password_expiration(&self, _username: &str) -> i64 {
            -1
        }

        fn set_password(
            &self,
            _username: &str,
            _salted_sha256_password_hash: &[u8],
            _is_temporary: bool,
        ) -> io::Result<bool> {
            Ok(true)
        }
    }

    /// Mock repository manager backed by an in-memory repository name -> user-access-list map,
    /// standing in for `ghidra.server.RepositoryManager` and exercising the real
    /// create/get/delete/user-removal lifecycle a concrete implementation drives.
    struct MockRepositoryManager {
        root_dir: PathBuf,
        repositories: Mutex<Vec<(String, Vec<String>)>>,
        anonymous_access: bool,
    }

    impl RepositoryManager for MockRepositoryManager {
        fn anonymous_access_allowed(&self) -> bool {
            self.anonymous_access
        }

        fn dispose(&self) {
            self.repositories.lock().unwrap().clear();
        }

        fn get_root_dir(&self) -> PathBuf {
            self.root_dir.clone()
        }

        fn create_repository(
            &self,
            current_user: &str,
            name: &str,
        ) -> io::Result<Box<dyn RepositoryLike>> {
            let mut repos = self.repositories.lock().unwrap();
            if repos.iter().any(|(n, _)| n == name) {
                return Err(io::Error::other(format!("repository already exists: {name}")));
            }
            repos.push((name.to_string(), vec![current_user.to_string()]));
            Ok(Box::new(MockRepository { name: name.to_string() }))
        }

        fn get_repository(
            &self,
            _current_user: &str,
            name: &str,
        ) -> io::Result<Option<Box<dyn RepositoryLike>>> {
            Ok(self
                .repositories
                .lock()
                .unwrap()
                .iter()
                .find(|(n, _)| n == name)
                .map(|_| Box::new(MockRepository { name: name.to_string() }) as Box<dyn RepositoryLike>))
        }

        fn delete_repository(&self, _current_user: &str, name: &str) -> io::Result<()> {
            let mut repos = self.repositories.lock().unwrap();
            let before = repos.len();
            repos.retain(|(n, _)| n != name);
            if repos.len() == before {
                return Err(io::Error::other(format!("no such repository: {name}")));
            }
            Ok(())
        }

        fn get_repository_names(&self, current_user: &str) -> Vec<String> {
            let repos = self.repositories.lock().unwrap();
            let mut names: Vec<String> = if self.anonymous_access && current_user == "anonymous" {
                repos.iter().map(|(n, _)| n.clone()).collect()
            }
            else {
                repos
                    .iter()
                    .filter(|(_, users)| users.iter().any(|u| u == current_user))
                    .map(|(n, _)| n.clone())
                    .collect()
            };
            names.sort();
            names
        }

        fn get_all_users(&self, current_user: &str) -> Vec<String> {
            if current_user == "anonymous" {
                return vec![];
            }
            vec!["alice".to_string(), "bob".to_string()]
        }

        fn get_user_manager(&self) -> Box<dyn UserManagerLike> {
            Box::new(MockUserManager)
        }

        fn add_handle(&self, _handle: Arc<dyn RepositoryServerHandleImpl>) {}

        fn drop_handle(&self, _handle: Arc<dyn RepositoryServerHandleImpl>) {}

        fn process_command_queue(&self) -> io::Result<()> {
            Ok(())
        }

        fn user_removed(&self, username: &str) -> io::Result<()> {
            let mut repos = self.repositories.lock().unwrap();
            for (_, users) in repos.iter_mut() {
                users.retain(|u| u != username);
            }
            Ok(())
        }
    }

    fn new_manager(anonymous_access: bool) -> Box<dyn RepositoryManager> {
        Box::new(MockRepositoryManager {
            root_dir: PathBuf::from("/tmp/repos"),
            repositories: Mutex::new(vec![]),
            anonymous_access,
        })
    }

    #[test]
    fn test_object_safety_and_repository_lifecycle() {
        let mgr = new_manager(false);

        assert_eq!(mgr.get_root_dir(), PathBuf::from("/tmp/repos"));
        assert!(!mgr.anonymous_access_allowed());

        mgr.create_repository("alice", "Repo1").unwrap();
        assert_eq!(mgr.get_repository_names("alice"), vec!["Repo1".to_string()]);
        assert!(mgr.get_repository_names("bob").is_empty());

        assert!(mgr.get_repository("alice", "Repo1").unwrap().is_some());
        assert!(mgr.get_repository("alice", "NoSuchRepo").unwrap().is_none());

        assert!(mgr.create_repository("alice", "Repo1").is_err());

        mgr.delete_repository("alice", "Repo1").unwrap();
        assert!(mgr.get_repository_names("alice").is_empty());
        assert!(mgr.delete_repository("alice", "Repo1").is_err());
    }

    #[test]
    fn test_user_removed_drops_access_from_all_repositories() {
        let mgr = new_manager(false);

        mgr.create_repository("alice", "Repo1").unwrap();
        mgr.create_repository("alice", "Repo2").unwrap();
        assert_eq!(mgr.get_repository_names("alice").len(), 2);

        mgr.user_removed("alice").unwrap();
        assert!(mgr.get_repository_names("alice").is_empty());
    }

    #[test]
    fn test_anonymous_user_sees_no_users_but_can_see_open_repositories() {
        let mgr = new_manager(true);

        mgr.create_repository("alice", "PublicRepo").unwrap();
        assert!(mgr.get_all_users("anonymous").is_empty());
        assert_eq!(mgr.get_repository_names("anonymous"), vec!["PublicRepo".to_string()]);
    }

    #[test]
    fn test_dispose_clears_all_repositories() {
        let mgr = new_manager(false);
        mgr.create_repository("alice", "Repo1").unwrap();
        mgr.dispose();
        assert!(mgr.get_repository_names("alice").is_empty());
    }
}
