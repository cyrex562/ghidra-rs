use std::io;

use thiserror::Error;

use crate::framework::store::local::LocalFileSystem;
use crate::framework::store::FolderItem;
use crate::util::exception::InvalidNameException;

/// Maximum item/folder name length enforced by this filesystem implementation (value is
/// arbitrary, chosen by the original Java implementation).
pub const MAX_NAME_LENGTH: i32 = 254;

/// Latest on-disk index format version understood by this implementation.
pub const LATEST_INDEX_VERSION: i32 = 1;

/// Combines the checked exceptions declared on the folder-mutation methods of
/// `IndexedLocalFileSystem` (`createFolder`, `moveItem`, `moveFolder`, `renameFolder`), each of
/// which is declared `throws InvalidNameException, IOException`. `DuplicateFileException` and
/// `FolderNotEmptyException` are Java subclasses of `IOException`, so they fold into the `Io`
/// variant via their existing `Into<std::io::Error>` conversions.
#[derive(Error, Debug)]
pub enum FileSystemOpError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Implements a case-sensitive indexed filesystem which uses a shallow storage hierarchy with no
/// restriction on file name or path length. This filesystem is identified by the existence of an
/// index file (`~index.dat`) and recovery journal (`~index.jrn`).
///
/// Mirrors `ghidra.framework.store.local.IndexedLocalFileSystem`, which extends
/// `LocalFileSystem`. Only the class's public instance API is represented here; static factory
/// and diagnostic helpers (`getFileSystem`, `isIndexed`, `hasIndexedStructure`,
/// `readIndexVersion`) do not operate on an instance and are left for a concrete implementation
/// to provide directly, since they depend on `LocalFileSystem` internals (storage layout
/// constants, hidden-name escaping) not yet ported. Package-private helpers that operate on
/// internal state not yet ported (the on-disk index, journal, and in-memory folder/item tree) are
/// left for the concrete port to implement.
///
/// Java's `getItems`/`getItem` return `LocalFolderItem`, but
/// [`LocalFolderItem`](crate::framework::store::local::LocalFolderItem) carries associated
/// constants (property-file keys) and is therefore not dyn-compatible. Items are represented here
/// via its object-safe supertrait, [`FolderItem`], so this trait itself remains dyn-compatible; a
/// concrete implementation is expected to hand back values that also implement `LocalFolderItem`.
pub trait IndexedLocalFileSystem: LocalFileSystem {
    /// Returns the maximum name length allowed for a folder or item name.
    fn get_max_name_length(&self) -> i32 {
        MAX_NAME_LENGTH
    }

    /// Returns all folder items contained within the specified folder. A `None` entry indicates
    /// an item name present in the index whose underlying storage could not be found; such
    /// entries are pruned from the index automatically when the filesystem is not read-only.
    fn get_items(&mut self, folder_path: &str) -> io::Result<Vec<Option<Box<dyn FolderItem>>>>;

    /// Releases any resources (open index/journal handles, rewrite timer) held by this
    /// filesystem. Safe to call more than once.
    fn dispose(&mut self);

    /// Returns the index format version implemented by this filesystem. The base indexed
    /// filesystem implementation uses version `0`; subclasses which alter the index format
    /// override this to force a rebuild against older indexes.
    fn get_index_implementation_version(&self) -> i32 {
        0
    }

    /// Returns the names of all items within the specified folder, optionally including hidden
    /// items (those whose name starts with the hidden-item prefix).
    fn get_item_names(
        &mut self,
        folder_path: &str,
        include_hidden_files: bool,
    ) -> io::Result<Vec<String>>;

    /// Returns the total number of items contained within this filesystem, including all
    /// subfolders.
    fn get_item_count(&mut self) -> io::Result<i32>;

    /// Returns the names of all subfolders within the specified folder.
    fn get_folder_names(&mut self, folder_path: &str) -> io::Result<Vec<String>>;

    /// Creates a new subfolder within the specified parent folder. A no-op if the folder already
    /// exists.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::InvalidName`] if `parent_path` or `folder_name` contains
    /// invalid characters, or [`FileSystemOpError::Io`] if the filesystem is read-only or the
    /// parent folder does not exist.
    fn create_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
    ) -> Result<(), FileSystemOpError>;

    /// Deletes the specified folder, which must be empty (no subfolders or items). A no-op if the
    /// folder does not exist.
    ///
    /// # Errors
    /// Returns an `io::Error` if the filesystem is read-only, the folder is the root folder, or
    /// the folder is not empty.
    fn delete_folder(&mut self, folder_path: &str) -> io::Result<()>;

    /// Moves and/or renames an item from `folder_path`/`name` to `new_folder_path`/`new_name`.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::InvalidName`] if the new folder path or name contains invalid
    /// characters, or [`FileSystemOpError::Io`] if the filesystem is read-only, the item does not
    /// exist, the item is in use, or an item already exists at the destination.
    fn move_item(
        &mut self,
        folder_path: &str,
        name: &str,
        new_folder_path: &str,
        new_name: &str,
    ) -> Result<(), FileSystemOpError>;

    /// Moves the specified folder (and its contents) to be a child of `new_parent_path`, keeping
    /// its current name.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::InvalidName`] if `new_parent_path` contains invalid
    /// characters, or [`FileSystemOpError::Io`] if the filesystem is read-only or a folder with
    /// the same name already exists at the destination.
    fn move_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
        new_parent_path: &str,
    ) -> Result<(), FileSystemOpError>;

    /// Renames the specified folder in place.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::InvalidName`] if `new_folder_name` contains invalid
    /// characters, or [`FileSystemOpError::Io`] if the filesystem is read-only, the folder does
    /// not exist, or a sibling folder with the new name already exists.
    fn rename_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> Result<(), FileSystemOpError>;

    /// Returns true if the specified folder exists within this filesystem.
    fn folder_exists(&mut self, folder_path: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::DuplicateFileException;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    /// Minimal `FolderItem` stand-in; `IndexedLocalFileSystem::get_items` only needs to prove it
    /// can hand back distinct, presence-checkable items, since the richer `LocalFolderItem` API
    /// is not dyn-compatible (see the trait's doc comment).
    struct MockItem;
    impl FolderItem for MockItem {
        fn get_name(&self) -> String {
            "MockItem".to_string()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn length(&self) -> io::Result<i64> {
            Ok(0)
        }

        fn get_content_type(&self) -> String {
            "Program".to_string()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            "/MockItem".to_string()
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn set_read_only(&mut self, _state: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_content_type_version(&self) -> i32 {
            1
        }

        fn set_content_type_version(&mut self, _version: i32) -> io::Result<()> {
            Ok(())
        }

        fn last_modified(&self) -> i64 {
            0
        }

        fn get_current_version(&self) -> i32 {
            1
        }

        fn is_checked_out(&self) -> bool {
            false
        }

        fn is_checked_out_exclusive(&self) -> bool {
            false
        }

        fn is_versioned(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_checkout_id(&self) -> io::Result<i64> {
            Ok(crate::framework::store::folder_item::DEFAULT_CHECKOUT_ID)
        }

        fn get_checkout_version(&self) -> io::Result<i32> {
            Ok(-1)
        }

        fn get_local_checkout_version(&self) -> i32 {
            -1
        }

        fn set_checkout(
            &mut self,
            _checkout_id: i64,
            _exclusive: bool,
            _checkout_version: i32,
            _local_version: i32,
        ) -> io::Result<()> {
            Ok(())
        }

        fn clear_checkout(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn delete(&mut self, _version: i32, _user: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_versions(&self) -> io::Result<Option<Vec<crate::framework::store::ItemVersion>>> {
            Ok(None)
        }

        fn checkout(
            &mut self,
            _checkout_type: &dyn crate::framework::store::checkout_type::CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
            Ok(())
        }

        fn has_checkouts(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn can_recover(&self) -> bool {
            false
        }

        fn get_checkout(
            &self,
            _checkout_id: i64,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn get_checkouts(
            &self,
        ) -> io::Result<Vec<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(Vec::new())
        }

        fn is_checkin_active(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn update_checkout_version(
            &mut self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn output(
            &self,
            _output_file: &std::path::Path,
            _version: i32,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::framework::store::local::OutputItemError> {
            Ok(())
        }

        fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

    /// In-memory `IndexedLocalFileSystem` implementation exercising the folder/item bookkeeping
    /// semantics of the Java class (duplicate rejection, non-empty-folder deletion rejection,
    /// name validation) without any real index/journal persistence.
    #[derive(Default)]
    struct MockIndexedFileSystem {
        read_only: bool,
        disposed: bool,
        // folder path -> subfolder names
        folders: BTreeMap<String, BTreeSet<String>>,
        // folder path -> item names present
        items: BTreeMap<String, BTreeSet<String>>,
    }

    impl MockIndexedFileSystem {
        fn new() -> Self {
            let mut fs = Self::default();
            fs.folders.insert("/".to_string(), BTreeSet::new());
            fs.items.insert("/".to_string(), BTreeSet::new());
            fs
        }

        fn join(parent: &str, name: &str) -> String {
            if parent == "/" {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            }
        }

        fn valid_name(name: &str) -> Result<(), InvalidNameException> {
            if name.is_empty() || name.contains('/') {
                return Err(InvalidNameException::with_message(format!(
                    "invalid name: {name}"
                )));
            }
            Ok(())
        }
    }

    impl LocalFileSystem for MockIndexedFileSystem {}

    impl IndexedLocalFileSystem for MockIndexedFileSystem {
        fn get_items(
            &mut self,
            folder_path: &str,
        ) -> io::Result<Vec<Option<Box<dyn FolderItem>>>> {
            let names = self.get_item_names(folder_path, true)?;
            Ok(names
                .into_iter()
                .map(|_| Some(Box::new(MockItem) as Box<dyn FolderItem>))
                .collect())
        }

        fn dispose(&mut self) {
            self.disposed = true;
        }

        fn get_item_names(
            &mut self,
            folder_path: &str,
            _include_hidden_files: bool,
        ) -> io::Result<Vec<String>> {
            self.items
                .get(folder_path)
                .map(|s| s.iter().cloned().collect())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "folder not found"))
        }

        fn get_item_count(&mut self) -> io::Result<i32> {
            Ok(self.items.values().map(|s| s.len() as i32).sum())
        }

        fn get_folder_names(&mut self, folder_path: &str) -> io::Result<Vec<String>> {
            self.folders
                .get(folder_path)
                .map(|s| s.iter().cloned().collect())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "folder not found"))
        }

        fn create_folder(
            &mut self,
            parent_path: &str,
            folder_name: &str,
        ) -> Result<(), FileSystemOpError> {
            if self.read_only {
                return Err(FileSystemOpError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only filesystem",
                )));
            }
            Self::valid_name(folder_name)?;
            let path = Self::join(parent_path, folder_name);
            let siblings = self
                .folders
                .get_mut(parent_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "parent not found"))?;
            if !siblings.insert(folder_name.to_string()) {
                return Ok(()); // already exists - no-op, matching Java behavior
            }
            self.folders.insert(path.clone(), BTreeSet::new());
            self.items.insert(path, BTreeSet::new());
            Ok(())
        }

        fn delete_folder(&mut self, folder_path: &str) -> io::Result<()> {
            if self.read_only {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only filesystem",
                ));
            }
            if folder_path == "/" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root folder may not be deleted",
                ));
            }
            let Some(subfolders) = self.folders.get(folder_path) else {
                return Ok(()); // already gone
            };
            let items = self.items.get(folder_path).map(|s| s.len()).unwrap_or(0);
            if !subfolders.is_empty() || items != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{folder_path} is not empty"),
                ));
            }
            self.folders.remove(folder_path);
            self.items.remove(folder_path);
            let (parent, name) = folder_path.rsplit_once('/').unwrap();
            let parent = if parent.is_empty() { "/" } else { parent };
            self.folders.get_mut(parent).unwrap().remove(name);
            Ok(())
        }

        fn move_item(
            &mut self,
            folder_path: &str,
            name: &str,
            new_folder_path: &str,
            new_name: &str,
        ) -> Result<(), FileSystemOpError> {
            if self.read_only {
                return Err(FileSystemOpError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only filesystem",
                )));
            }
            Self::valid_name(new_name)?;
            let removed = self
                .items
                .get_mut(folder_path)
                .map(|s| s.remove(name))
                .unwrap_or(false);
            if !removed {
                return Err(FileSystemOpError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("item not found: {name}"),
                )));
            }
            let dest = self
                .items
                .get_mut(new_folder_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "destination not found"))?;
            if !dest.insert(new_name.to_string()) {
                return Err(FileSystemOpError::Io(
                    DuplicateFileException::new(format!("item already exists: {new_name}"))
                        .into(),
                ));
            }
            Ok(())
        }

        fn move_folder(
            &mut self,
            _parent_path: &str,
            _folder_name: &str,
            _new_parent_path: &str,
        ) -> Result<(), FileSystemOpError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn rename_folder(
            &mut self,
            _parent_path: &str,
            _folder_name: &str,
            _new_folder_name: &str,
        ) -> Result<(), FileSystemOpError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn folder_exists(&mut self, folder_path: &str) -> bool {
            self.folders.contains_key(folder_path)
        }
    }

    #[test]
    fn test_object_safety_and_folder_item_lifecycle() {
        // Build and seed the concrete filesystem directly, then erase it behind the trait object
        // for the rest of the test to exercise the dyn-compatible public API.
        let mut concrete = MockIndexedFileSystem::new();
        concrete.folders.insert("/ProgramA".to_string(), BTreeSet::new());
        concrete.folders.get_mut("/").unwrap().insert("ProgramA".to_string());
        concrete
            .items
            .insert("/ProgramA".to_string(), BTreeSet::from(["file.gzf".to_string()]));

        let mut fs: Box<dyn IndexedLocalFileSystem> = Box::new(concrete);

        assert_eq!(fs.get_max_name_length(), MAX_NAME_LENGTH);
        assert!(fs.folder_exists("/"));
        assert!(fs.folder_exists("/ProgramA"));
        assert!(!fs.folder_exists("/missing"));

        // Invalid names are rejected before any mutation occurs.
        let err = fs.create_folder("/", "bad/name").unwrap_err();
        assert!(matches!(err, FileSystemOpError::InvalidName(_)));

        fs.create_folder("/", "Dest").unwrap();
        // Re-creating an existing folder is a silent no-op, matching Java's behavior.
        fs.create_folder("/", "Dest").unwrap();
        assert_eq!(fs.get_folder_names("/").unwrap().len(), 2);

        assert_eq!(fs.get_item_count().unwrap(), 1);
        let items = fs.get_items("/ProgramA").unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_some());

        // Deleting a non-empty folder fails.
        assert!(fs.delete_folder("/ProgramA").is_err());

        fs.move_item("/ProgramA", "file.gzf", "/Dest", "file.gzf")
            .unwrap();
        assert!(fs.get_items("/ProgramA").unwrap().is_empty());
        assert_eq!(fs.get_item_names("/Dest", true).unwrap(), vec!["file.gzf".to_string()]);

        // Moving into an occupied destination fails with a duplicate error.
        fs.move_item("/Dest", "file.gzf", "/ProgramA", "file.gzf")
            .unwrap();
        let err = fs
            .move_item("/ProgramA", "file.gzf", "/Dest", "file.gzf")
            .unwrap_err();
        assert!(matches!(err, FileSystemOpError::Io(_)));

        // Moving a non-existent item reports not-found.
        let err = fs
            .move_item("/Dest", "missing.gzf", "/Dest", "renamed.gzf")
            .unwrap_err();
        assert!(matches!(err, FileSystemOpError::Io(_)));

        // ProgramA is now empty (its item was moved to Dest above) and can be deleted.
        fs.move_item("/ProgramA", "file.gzf", "/Dest", "moved.gzf")
            .unwrap();
        assert!(fs.delete_folder("/ProgramA").is_ok());
        assert!(!fs.folder_exists("/ProgramA"));

        fs.dispose();
        assert!(fs.folder_exists("/Dest"));
    }
}
