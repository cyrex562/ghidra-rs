// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/store/RepositoryFile.java
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

use thiserror::Error;

use crate::framework::db::buffers::ManagedBufferFile;
use crate::framework::seam_stubs::{ItemCheckoutStatus, RepositoryItem};
use crate::framework::store::{CheckoutType, ItemVersion, SEPARATOR_CHAR};
use crate::server::seam_stubs::RepositoryFolderLike;
use crate::util::exception::{InvalidNameException, UserAccessException};

/// Combines the checked exceptions declared on `RepositoryFile.delete(int, String)`.
#[derive(Error, Debug)]
pub enum DeleteError {
    #[error(transparent)]
    UserAccess(#[from] UserAccessException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on
/// `RepositoryFile.moveTo(RepositoryFolder, String, String)`.
#[derive(Error, Debug)]
pub enum MoveToError {
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    UserAccess(#[from] UserAccessException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A persistent wrapper for a `FolderItem` stored within a repository.
///
/// Mirrors `ghidra.server.store.RepositoryFile`, recast as a trait so callers can depend on
/// file-level repository behavior without depending on any single concrete implementation. This
/// type and `RepositoryFolder` form a direct dependency cycle in Java (`RepositoryFolder` owns a
/// `fileMap` of `RepositoryFile`s and is returned by `getParent()`/accepted by `moveTo()`, while
/// `RepositoryFolder` in turn calls back into `RepositoryFile` via `fileDeleted`/`fileMoved`);
/// `RepositoryFile` was selected as the cut-point, so `RepositoryFolder` is represented here by
/// the [`RepositoryFolderLike`] placeholder until it is ported.
///
/// The private `Repository`/`LocalFileSystem` fields and the private `validate()` helper are
/// synchronization and caching plumbing for one concrete implementation, not part of the
/// observable interface, so they are intentionally left out -- consistent with how
/// [`GhidraServer`](crate::server::remote::ghidra_server::GhidraServer) omitted its constructor's
/// setup logic for the same reason. The two overloaded `openDatabase` methods are given distinct
/// names (`open_database_version`, `open_database_for_checkin`) since Rust does not support
/// overloading, and both return the already-ported
/// [`ManagedBufferFile`](crate::framework::db::buffers::ManagedBufferFile) trait object in place
/// of the concrete `db.buffers.LocalManagedBufferFile`.
pub trait RepositoryFile: Send + Sync {
    /// Returns the item/file name.
    fn get_name(&self) -> String;

    /// Returns the parent folder, or `None` if this file has been deleted.
    fn get_parent(&self) -> Option<Box<dyn RepositoryFolderLike>>;

    /// Returns the file/item path within the repository.
    fn get_pathname(&self) -> String {
        let name = self.get_name();
        match self.get_parent() {
            Some(parent) => {
                let parent_path = parent.get_pathname();
                if parent_path.len() == 1 {
                    format!("{parent_path}{name}")
                } else {
                    format!("{parent_path}{SEPARATOR_CHAR}{name}")
                }
            }
            None => name,
        }
    }

    /// Returns data pertaining to this file.
    fn get_item(&self) -> Box<dyn RepositoryItem>;

    /// Opens a specific database version for read-only use. Only valid for an underlying
    /// `FolderItem` of type database.
    ///
    /// - `version`: requested version, or -1 for the current version.
    /// - `min_change_data_ver`: minimum version to include within change data, or -1 if not
    ///   applicable.
    /// - `user`: user who initiated the request.
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied access or an IO error occurs.
    fn open_database_version(
        &self,
        version: i32,
        min_change_data_ver: i32,
        user: &str,
    ) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Opens the current version for checkin use.
    ///
    /// - `checkout_id`: checkout ID.
    /// - `user`: user who initiated the request.
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied write access or an IO error occurs.
    fn open_database_for_checkin(
        &self,
        checkout_id: i64,
        user: &str,
    ) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Returns all available versions.
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied access or an IO error occurs.
    fn get_versions(&self, user: &str) -> io::Result<Vec<ItemVersion>>;

    /// Returns the length of this file. This size is the minimum disk space used for storing
    /// this file, but does not account for additional storage space used to track changes, etc.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO or access error occurs.
    fn length(&self) -> io::Result<i64>;

    /// Deletes the oldest or current version of this file/item, or all versions if
    /// `delete_version` is -1.
    ///
    /// # Errors
    /// Returns `Err` if the user is denied the ability to delete the specified version(s), or an
    /// IO error occurs.
    fn delete(&self, delete_version: i32, user: &str) -> Result<(), DeleteError>;

    /// Moves this file/item to a new folder and optionally changes its name.
    ///
    /// # Errors
    /// Returns `Err` if `new_item_name` is invalid, the user is denied write access, or an IO
    /// error occurs.
    fn move_to(
        &self,
        new_parent: &dyn RepositoryFolderLike,
        new_item_name: &str,
        user: &str,
    ) -> Result<(), MoveToError>;

    /// Requests a checkout of the underlying item.
    ///
    /// Returns the checkout data if successful, or `None` if an exclusive checkout failed due to
    /// existing checkout(s).
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied write access or an IO error occurs.
    fn checkout(
        &self,
        checkout_type: &dyn CheckoutType,
        user: &str,
        project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Updates the checkout version for an existing checkout.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn update_checkout_version(
        &self,
        checkout_id: i64,
        checkout_version: i32,
        user: &str,
    ) -> io::Result<()>;

    /// Terminates an existing checkout.
    ///
    /// - `notify`: if true, notify listeners of the item change.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn terminate_checkout(&self, checkout_id: i64, user: &str, notify: bool) -> io::Result<()>;

    /// Returns checkout data for a specified checkout ID.
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied access or an IO error occurs.
    fn get_checkout(
        &self,
        checkout_id: i64,
        user: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Returns all checkouts for this file/item.
    ///
    /// # Errors
    /// Returns an `io::Error` if the user is denied access or an IO error occurs.
    fn get_checkouts(&self, user: &str) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>>;

    /// Returns true if one or more checkouts exist for this file/item.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn has_checkouts(&self) -> io::Result<bool>;

    /// Returns true if checkin is currently in process.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn is_checkin_active(&self) -> io::Result<bool>;

    /// Clears cached data as a result of an item-changed callback from the file-system.
    fn item_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::store::{get_checkout_type, Exclusive};
    use std::sync::{Arc, Mutex};

    struct MockRepositoryFolder {
        pathname: String,
        deleted_files: Mutex<Vec<String>>,
        moved_files: Mutex<Vec<(String, String)>>,
    }

    impl RepositoryFolderLike for MockRepositoryFolder {
        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn file_deleted(&self, file: &dyn RepositoryFile) {
            self.deleted_files.lock().unwrap().push(file.get_name());
        }

        fn file_moved(&self, file: &dyn RepositoryFile, old_name: &str, new_folder: &dyn RepositoryFolderLike) {
            self.moved_files
                .lock()
                .unwrap()
                .push((old_name.to_string(), new_folder.get_pathname()));
            let _ = file;
        }
    }

    /// Mock file whose `delete` mirrors the real `RepositoryFile.delete`'s non-admin ownership
    /// check: a non-admin user may only delete the oldest or newest version, and only if they own
    /// every version being removed.
    struct MockRepositoryFile {
        name: Mutex<String>,
        parent: Mutex<Option<Arc<MockRepositoryFolder>>>,
        versions: Vec<(i32, &'static str)>,
        is_admin: bool,
    }

    impl RepositoryFolderLike for Arc<MockRepositoryFolder> {
        fn get_pathname(&self) -> String {
            (**self).get_pathname()
        }
        fn file_deleted(&self, file: &dyn RepositoryFile) {
            (**self).file_deleted(file)
        }
        fn file_moved(&self, file: &dyn RepositoryFile, old_name: &str, new_folder: &dyn RepositoryFolderLike) {
            (**self).file_moved(file, old_name, new_folder)
        }
    }

    impl RepositoryFile for MockRepositoryFile {
        fn get_name(&self) -> String {
            self.name.lock().unwrap().clone()
        }

        fn get_parent(&self) -> Option<Box<dyn RepositoryFolderLike>> {
            self.parent
                .lock()
                .unwrap()
                .as_ref()
                .map(|p| Box::new(p.clone()) as Box<dyn RepositoryFolderLike>)
        }

        fn get_item(&self) -> Box<dyn RepositoryItem> {
            struct Item;
            impl RepositoryItem for Item {}
            Box::new(Item)
        }

        fn open_database_version(
            &self,
            _version: i32,
            _min_change_data_ver: i32,
            _user: &str,
        ) -> io::Result<Box<dyn ManagedBufferFile>> {
            Err(io::Error::other("not supported by mock"))
        }

        fn open_database_for_checkin(
            &self,
            _checkout_id: i64,
            _user: &str,
        ) -> io::Result<Box<dyn ManagedBufferFile>> {
            Err(io::Error::other("not supported by mock"))
        }

        fn get_versions(&self, _user: &str) -> io::Result<Vec<ItemVersion>> {
            Ok(self
                .versions
                .iter()
                .map(|(v, u)| ItemVersion::new(*v, 0, *u, ""))
                .collect())
        }

        fn length(&self) -> io::Result<i64> {
            Ok(0)
        }

        fn delete(&self, delete_version: i32, user: &str) -> Result<(), DeleteError> {
            if !self.is_admin {
                if delete_version == -1 {
                    for (_, owner) in &self.versions {
                        if *owner != user {
                            return Err(UserAccessException::new(&format!(
                                "version owned by {owner}"
                            ))
                            .into());
                        }
                    }
                } else {
                    let first = self.versions.first().unwrap();
                    let last = self.versions.last().unwrap();
                    let boundary = if delete_version == first.0 {
                        Some(first)
                    } else if delete_version == last.0 {
                        Some(last)
                    } else {
                        None
                    };
                    match boundary {
                        Some((_, owner)) if *owner == user => {}
                        Some((_, owner)) => {
                            return Err(UserAccessException::new(&format!(
                                "version owned by {owner}"
                            ))
                            .into());
                        }
                        None => {
                            return Err(io::Error::other(
                                "only the oldest or latest version may be deleted",
                            )
                            .into());
                        }
                    }
                }
            }
            if let Some(parent) = self.parent.lock().unwrap().take() {
                parent.file_deleted(self);
            }
            Ok(())
        }

        fn move_to(
            &self,
            new_parent: &dyn RepositoryFolderLike,
            new_item_name: &str,
            _user: &str,
        ) -> Result<(), MoveToError> {
            let old_name =
                std::mem::replace(&mut *self.name.lock().unwrap(), new_item_name.to_string());
            new_parent.file_moved(self, &old_name, new_parent);
            Ok(())
        }

        fn checkout(
            &self,
            _checkout_type: &dyn CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn update_checkout_version(
            &self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn terminate_checkout(&self, _checkout_id: i64, _user: &str, _notify: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_checkout(
            &self,
            _checkout_id: i64,
            _user: &str,
        ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn get_checkouts(&self, _user: &str) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
            Ok(vec![])
        }

        fn has_checkouts(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn is_checkin_active(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn item_changed(&self) {}
    }

    #[test]
    fn test_object_safety_and_default_pathname() {
        let root = Arc::new(MockRepositoryFolder {
            pathname: "/".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        });
        let file: Box<dyn RepositoryFile> = Box::new(MockRepositoryFile {
            name: Mutex::new("MyProgram".to_string()),
            parent: Mutex::new(Some(root.clone())),
            versions: vec![(1, "alice"), (2, "alice"), (3, "alice")],
            is_admin: false,
        });

        assert_eq!(file.get_pathname(), "/MyProgram");
    }

    #[test]
    fn test_non_admin_delete_rejects_version_owned_by_another_user() {
        let root = Arc::new(MockRepositoryFolder {
            pathname: "/".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        });
        let file = MockRepositoryFile {
            name: Mutex::new("MyProgram".to_string()),
            parent: Mutex::new(Some(root.clone())),
            versions: vec![(1, "alice"), (2, "bob"), (3, "alice")],
            is_admin: false,
        };

        // Deleting all versions (-1) fails because bob owns version 2.
        let err = file.delete(-1, "alice").unwrap_err();
        assert!(matches!(err, DeleteError::UserAccess(_)));
        assert!(root.deleted_files.lock().unwrap().is_empty());

        // Deleting the latest version (owned by alice) succeeds and notifies the parent.
        assert!(file.delete(3, "alice").is_ok());
        assert_eq!(root.deleted_files.lock().unwrap().as_slice(), ["MyProgram"]);
    }

    #[test]
    fn test_admin_delete_bypasses_ownership_check() {
        let root = Arc::new(MockRepositoryFolder {
            pathname: "/".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        });
        let file = MockRepositoryFile {
            name: Mutex::new("MyProgram".to_string()),
            parent: Mutex::new(Some(root.clone())),
            versions: vec![(1, "alice"), (2, "bob")],
            is_admin: true,
        };

        assert!(file.delete(-1, "carol").is_ok());
        assert_eq!(root.deleted_files.lock().unwrap().as_slice(), ["MyProgram"]);
    }

    #[test]
    fn test_move_to_renames_and_notifies_new_parent() {
        let old_parent = Arc::new(MockRepositoryFolder {
            pathname: "/old".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        });
        let new_parent = MockRepositoryFolder {
            pathname: "/new".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        };
        let file = MockRepositoryFile {
            name: Mutex::new("MyProgram".to_string()),
            parent: Mutex::new(Some(old_parent)),
            versions: vec![(1, "alice")],
            is_admin: false,
        };

        assert!(file.move_to(&new_parent, "RenamedProgram", "alice").is_ok());
        assert_eq!(file.get_name(), "RenamedProgram");
        assert_eq!(
            new_parent.moved_files.lock().unwrap().as_slice(),
            [("MyProgram".to_string(), "/new".to_string())]
        );
    }

    #[test]
    fn test_checkout_type_placeholder_roundtrip() {
        // Sanity check that the already-ported `CheckoutType` trait plugs into `checkout()`.
        let checkout_type = get_checkout_type(Exclusive.get_id()).unwrap();
        let root = Arc::new(MockRepositoryFolder {
            pathname: "/".to_string(),
            deleted_files: Mutex::new(vec![]),
            moved_files: Mutex::new(vec![]),
        });
        let file: Box<dyn RepositoryFile> = Box::new(MockRepositoryFile {
            name: Mutex::new("MyProgram".to_string()),
            parent: Mutex::new(Some(root)),
            versions: vec![],
            is_admin: false,
        });
        assert!(file
            .checkout(checkout_type.as_ref(), "alice", "/proj/MyProgram")
            .unwrap()
            .is_none());
    }
}
