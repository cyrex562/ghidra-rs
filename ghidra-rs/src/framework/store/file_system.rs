use std::io;
use std::path::Path;

use thiserror::Error;

use crate::framework::db::buffers::{BufferFile, ManagedBufferFile};
use crate::framework::store::{DataFileItem, DatabaseItem, FileSystemListener, FolderItem, TextDataItem};
use crate::util::exception::{CancelledException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Character used to separate folder and item names within a path string. Mirrors
/// `ghidra.framework.store.FileSystem.SEPARATOR_CHAR`.
pub const SEPARATOR_CHAR: char = '/';
/// String form of [`SEPARATOR_CHAR`]. Mirrors `ghidra.framework.store.FileSystem.SEPARATOR`.
pub const SEPARATOR: &str = "/";

/// Combines the checked exceptions declared on `FileSystem.createFolder`, `moveFolder`,
/// `renameFolder`, and `moveItem`, each of which is declared `throws InvalidNameException,
/// IOException`.
#[derive(Error, Debug)]
pub enum FileSystemError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Combines the checked exceptions declared on `FileSystem.createDatabase(..., BufferFile, ...)`,
/// `createDataFile`, and `createFile`, each of which is declared `throws InvalidNameException,
/// IOException, CancelledException`.
#[derive(Error, Debug)]
pub enum FileSystemCreateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// `FileSystem` provides a hierarchical view and management of a set of files and folders.
///
/// Mirrors `ghidra.framework.store.FileSystem`. This port maps the Java interface to an
/// object-safe trait so implementations (e.g. local vs. remote file systems) can be depended on
/// via `Box<dyn FileSystem>`/`Arc<dyn FileSystem>` rather than any single concrete type, breaking
/// a dependency cycle at this cut-point. Methods that return or accept another already-ported
/// core type ([`FolderItem`], [`DatabaseItem`], [`DataFileItem`], [`TextDataItem`],
/// [`FileSystemListener`], [`BufferFile`], [`ManagedBufferFile`]) use the real port; the Java
/// interface's checked exceptions are combined into the [`FileSystemError`] and
/// [`FileSystemCreateError`] error enums per method, matching the `throws` clause each Java method
/// declares.
///
/// The Java interface's `public static final` fields (`SEPARATOR_CHAR`, `SEPARATOR`) are ported as
/// free module-level constants rather than trait-associated constants, since associated constants
/// would make this trait dyn-incompatible.
pub trait FileSystem {
    /// Get user name associated with this filesystem. In the case of a remote filesystem this
    /// will correspond to the name used during login/authentication. `None` if unknown or
    /// not-applicable.
    fn get_user_name(&self) -> Option<String>;

    /// Returns true if the file-system requires check-outs when modifying folder items.
    fn is_versioned(&self) -> bool;

    /// Returns true if file-system is on-line.
    fn is_online(&self) -> bool;

    /// Returns true if file-system is read-only.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn is_read_only(&self) -> io::Result<bool>;

    /// Returns the number of folder items contained within this file-system.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs, or one with
    /// [`io::ErrorKind::Unsupported`] if file-system does not support this operation.
    fn get_item_count(&self) -> io::Result<i32>;

    /// Returns a list of the folder item names contained in the given folder.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_item_names(&self, folder_path: &str) -> io::Result<Vec<String>>;

    /// Returns a list of the folder items contained in the given folder. `None` items may exist
    /// if the index contained an item name while storage was not found.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_items(&self, folder_path: &str) -> io::Result<Vec<Option<Box<dyn FolderItem>>>>;

    /// Returns the `FolderItem` in the given folder with the given name, or `None` if it doesn't
    /// exist.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_item(&self, folder_path: &str, name: &str) -> io::Result<Option<Box<dyn FolderItem>>>;

    /// Returns the `FolderItem` specified by its unique File-ID, or `None` if it doesn't exist.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs, or one with
    /// [`io::ErrorKind::Unsupported`] if file-system does not support this operation.
    fn get_item_by_file_id(&self, file_id: &str) -> io::Result<Option<Box<dyn FolderItem>>>;

    /// Return a list of subfolders (by name) that are stored within the specified folder path.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `FileNotFoundException`-equivalent if folder path does not
    /// exist) or another IO error.
    fn get_folder_names(&self, folder_path: &str) -> io::Result<Vec<String>>;

    /// Creates a new subfolder within the specified parent folder.
    ///
    /// # Errors
    /// Returns [`FileSystemError::InvalidName`] if `folder_name` does not consist of all
    /// alphanumerics, or [`FileSystemError::Io`] if a folder already exists with this name or
    /// another IO error occurs.
    fn create_folder(&mut self, parent_path: &str, folder_name: &str) -> Result<(), FileSystemError>;

    /// Determine if the specified folder item is supported by this filesystem's interface and
    /// storage. This method primarily exists to determine if a remote server can support the
    /// specified content.
    fn is_supported_item_type(&self, folder_item: &dyn FolderItem) -> bool;

    /// Create a new database item within the specified parent folder using the contents of the
    /// specified `BufferFile`.
    ///
    /// - `file_id`: file ID to be associated with new database, or `None`.
    /// - `comment`: version comment (used for versioned file system only).
    /// - `content_type`: application defined content type.
    /// - `reset_database_id`: if true, database ID will be reset for the new database.
    /// - `monitor`: allows the database copy to be monitored and cancelled.
    /// - `user`: name of user creating item (required for versioned item).
    ///
    /// # Errors
    /// Returns [`FileSystemCreateError::Io`] if the parent folder does not exist, a folder item
    /// exists with this name, or another IO error occurs; [`FileSystemCreateError::InvalidName`]
    /// if `name` does not consist of all alphanumerics; or
    /// [`FileSystemCreateError::Cancelled`] if cancelled by `monitor`.
    fn create_database(
        &mut self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        buffer_file: &mut dyn BufferFile,
        comment: Option<&str>,
        content_type: &str,
        reset_database_id: bool,
        monitor: &dyn TaskMonitor,
        user: Option<&str>,
    ) -> Result<Box<dyn DatabaseItem>, FileSystemCreateError>;

    /// Create a new empty database item within the specified parent folder. If this is a
    /// versioned file-system, the associated item is checked-out. The resulting checkout ID can
    /// be obtained from the returned buffer file.
    ///
    /// - `file_id`: file ID to be associated with new database, or `None`.
    /// - `content_type`: application defined content type.
    /// - `buffer_size`: buffer size. If copying an existing `BufferFile`, the buffer size must be
    ///   the same as the source file.
    /// - `user`: name of user creating item (required for versioned item).
    /// - `project_path`: path of project in which database is checked-out (required for
    ///   versioned item).
    ///
    /// # Errors
    /// Returns [`FileSystemError::Io`] if the parent folder does not exist, a folder item exists
    /// with this name, or another IO error occurs; or [`FileSystemError::InvalidName`] if `name`
    /// has illegal characters.
    fn create_managed_database(
        &mut self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        buffer_size: i32,
        user: Option<&str>,
        project_path: &str,
    ) -> Result<Box<dyn ManagedBufferFile>, FileSystemError>;

    /// Creates a new empty data file within the specified parent folder.
    ///
    /// - `istream`: source data.
    /// - `comment`: version comment (used for versioned file system only).
    /// - `content_type`: application defined content type.
    /// - `monitor`: progress monitor (used for cancel support; progress is not used since the
    ///   length of the input stream is unknown).
    ///
    /// # Errors
    /// Returns [`FileSystemCreateError::Io`] if a folder item with this name already exists or
    /// another IO error occurs; [`FileSystemCreateError::InvalidName`] if `name` has illegal
    /// characters; or [`FileSystemCreateError::Cancelled`] if cancelled by `monitor`.
    fn create_data_file(
        &mut self,
        parent_path: &str,
        name: &str,
        istream: &mut dyn io::Read,
        comment: Option<&str>,
        content_type: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DataFileItem>, FileSystemCreateError>;

    /// Creates a new text data file within the specified parent folder.
    ///
    /// - `file_id`: file ID to be associated with new file, or `None`.
    /// - `content_type`: application defined content type.
    /// - `text_data`: text data (required).
    /// - `comment`: file comment (may be `None`, only used if versioning is enabled).
    /// - `user`: name of user creating item (required for local versioned item).
    ///
    /// # Errors
    /// Returns [`FileSystemError::Io`] if a folder item with this name already exists or another
    /// IO error occurs, or [`FileSystemError::InvalidName`] if `name` has illegal characters.
    fn create_text_data_item(
        &mut self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        text_data: &str,
        comment: Option<&str>,
        user: Option<&str>,
    ) -> Result<Box<dyn TextDataItem>, FileSystemError>;

    /// Creates a new file item from a packed file. The content/item type must be determined from
    /// the input stream.
    ///
    /// - `packed_file`: packed file data.
    /// - `monitor`: progress monitor (used for cancel support; progress is not used since the
    ///   length of the input stream is unknown).
    /// - `user`: name of user creating item (required for versioned item).
    ///
    /// # Errors
    /// Returns [`FileSystemCreateError::InvalidName`] if `name` has illegal characters;
    /// [`FileSystemCreateError::Io`] if another IO error occurs; or
    /// [`FileSystemCreateError::Cancelled`] if cancelled by `monitor`.
    fn create_file(
        &mut self,
        parent_path: &str,
        name: &str,
        packed_file: &Path,
        monitor: &dyn TaskMonitor,
        user: Option<&str>,
    ) -> Result<Box<dyn FolderItem>, FileSystemCreateError>;

    /// Delete the specified folder.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `FolderNotEmptyException`-equivalent if the folder is not empty,
    /// a `FileNotFoundException`-equivalent if there is no folder with the given path name) if
    /// unable to delete.
    fn delete_folder(&mut self, folder_path: &str) -> io::Result<()>;

    /// Move the specified folder to the path specified by `new_parent_path`. The moved folder
    /// must not be an ancestor of the new parent.
    ///
    /// - `parent_path`: path of parent folder that the moving folder currently resides in.
    /// - `folder_name`: name of the folder within `parent_path` to be moved.
    /// - `new_parent_path`: path to where the folder is to be moved.
    ///
    /// # Errors
    /// Returns [`FileSystemError::InvalidName`] if the new folder path contains an illegal file
    /// name, or [`FileSystemError::Io`] (a `FileNotFoundException`-equivalent if the moved folder
    /// does not exist, a `DuplicateFileException`-equivalent if a folder with the same name
    /// exists within the new parent folder, a `FileInUseException`-equivalent if any file within
    /// this folder or its descendants are in-use or checked-out) if unable to move.
    fn move_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
        new_parent_path: &str,
    ) -> Result<(), FileSystemError>;

    /// Renames the specified folder to a new name.
    ///
    /// # Errors
    /// Returns [`FileSystemError::InvalidName`] if the new folder name contains an illegal file
    /// name, or [`FileSystemError::Io`] (a `FileNotFoundException`-equivalent if the folder to be
    /// renamed does not exist, a `DuplicateFileException`-equivalent if a folder with the new name
    /// already exists, a `FileInUseException`-equivalent if any file within this folder or its
    /// descendants are in-use or checked-out) if unable to rename.
    fn rename_folder(
        &mut self,
        parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> Result<(), FileSystemError>;

    /// Moves the specified item to a new folder.
    ///
    /// # Errors
    /// Returns [`FileSystemError::InvalidName`] if `new_name` is invalid, or
    /// [`FileSystemError::Io`] (a `FileNotFoundException`-equivalent if the item does not exist, a
    /// `DuplicateFileException`-equivalent if an item with the same name exists within the new
    /// parent folder, a `FileInUseException`-equivalent if the item is in-use or checked-out) if
    /// unable to move.
    fn move_item(
        &mut self,
        folder_path: &str,
        name: &str,
        new_folder_path: &str,
        new_name: &str,
    ) -> Result<(), FileSystemError>;

    /// Adds a file system listener to be notified of file system changes.
    fn add_file_system_listener(&mut self, listener: Box<dyn FileSystemListener>);

    /// Removes a file system listener from being notified of file system changes.
    fn remove_file_system_listener(&mut self, listener: &dyn FileSystemListener);

    /// Returns true if the folder specified by the path exists.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn folder_exists(&self, folder_path: &str) -> io::Result<bool>;

    /// Returns true if the file exists.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn file_exists(&self, folder_path: &str, name: &str) -> io::Result<bool>;

    /// Returns true if this file system is shared.
    fn is_shared(&self) -> bool;

    /// Cleanup and release resources.
    fn dispose(&mut self);
}

/// Normalize an absolute path, removing all "." and ".." use.
///
/// NOTE: This function does not consider possible linked folder traversal which may get ignored
/// when flattening/simplifying a path.
///
/// Mirrors the Java interface's static `FileSystem.normalizePath(String)` method.
///
/// # Errors
/// Returns `Err` if an absolute path starting with [`SEPARATOR`] was not specified or an illegal
/// path was specified.
pub fn normalize_path(path: &str) -> Result<String, String> {
    if !path.starts_with(SEPARATOR) {
        return Err(format!("Absolute path required: {path}"));
    }

    let split = java_style_split(path);

    let mut elements: Vec<String> = vec![SEPARATOR.to_string()];
    for (i, e) in split.iter().enumerate().skip(1) {
        if e.is_empty() {
            return Err(format!("Invalid path with empty element: {path}"));
        }
        if *e == ".." {
            elements.pop();
            if elements.is_empty() {
                return Err(format!("Invalid path: {path}"));
            }
        } else if *e == "." {
            continue;
        } else {
            let mut owned = (*e).to_string();
            if i < split.len() - 1 {
                owned.push(SEPARATOR_CHAR);
            }
            elements.push(owned);
        }
    }

    if elements.is_empty() {
        return Ok(SEPARATOR.to_string());
    }

    let mut buf = String::new();
    for e in &elements {
        buf.push_str(e);
    }
    if path.ends_with(SEPARATOR) {
        buf.push_str(SEPARATOR);
    }
    Ok(buf)
}

/// Splits `path` on [`SEPARATOR_CHAR`], mirroring `String.split(String)`'s default behavior of
/// dropping trailing empty strings from the result (unlike [`str::split`], which keeps them).
fn java_style_split(path: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = path.split(SEPARATOR_CHAR).collect();
    while parts.last().is_some_and(|s| s.is_empty()) {
        parts.pop();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    struct MockFolderItem {
        name: String,
    }

    impl FolderItem for MockFolderItem {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_file_id(&self) -> Option<String> {
            None
        }
        fn reset_file_id(&mut self) -> io::Result<String> {
            Ok("id".to_string())
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
            format!("/{}", self.name)
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
            _output_file: &Path,
            _version: i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::framework::store::local::OutputItemError> {
            Ok(())
        }
        fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

    /// A minimal in-memory `FileSystem` proving the trait is object-safe and that folder
    /// creation / item creation / listener notification actually mutate observable state.
    #[derive(Default)]
    struct MockFileSystem {
        read_only: bool,
        folders: BTreeMap<String, Vec<String>>,
        items: BTreeMap<String, Vec<String>>,
        listeners: Vec<Box<dyn FileSystemListener>>,
    }

    impl FileSystem for MockFileSystem {
        fn get_user_name(&self) -> Option<String> {
            Some("alice".to_string())
        }
        fn is_versioned(&self) -> bool {
            false
        }
        fn is_online(&self) -> bool {
            true
        }
        fn is_read_only(&self) -> io::Result<bool> {
            Ok(self.read_only)
        }
        fn get_item_count(&self) -> io::Result<i32> {
            Ok(self.items.values().map(|v| v.len() as i32).sum())
        }
        fn get_item_names(&self, folder_path: &str) -> io::Result<Vec<String>> {
            Ok(self.items.get(folder_path).cloned().unwrap_or_default())
        }
        fn get_items(&self, folder_path: &str) -> io::Result<Vec<Option<Box<dyn FolderItem>>>> {
            Ok(self
                .get_item_names(folder_path)?
                .into_iter()
                .map(|name| Some(Box::new(MockFolderItem { name }) as Box<dyn FolderItem>))
                .collect())
        }
        fn get_item(&self, folder_path: &str, name: &str) -> io::Result<Option<Box<dyn FolderItem>>> {
            if self.items.get(folder_path).is_some_and(|v| v.iter().any(|n| n == name)) {
                Ok(Some(Box::new(MockFolderItem { name: name.to_string() })))
            } else {
                Ok(None)
            }
        }
        fn get_item_by_file_id(&self, _file_id: &str) -> io::Result<Option<Box<dyn FolderItem>>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "getItem by File-ID"))
        }
        fn get_folder_names(&self, folder_path: &str) -> io::Result<Vec<String>> {
            self.folders
                .get(folder_path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "folder not found"))
        }
        fn create_folder(&mut self, parent_path: &str, folder_name: &str) -> Result<(), FileSystemError> {
            if self.read_only {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into());
            }
            if folder_name.is_empty() {
                return Err(InvalidNameException::with_message("folder name is empty").into());
            }
            self.folders.entry(parent_path.to_string()).or_default().push(folder_name.to_string());
            let path = format!("{parent_path}{folder_name}{SEPARATOR}");
            self.folders.entry(path).or_default();
            Ok(())
        }
        fn is_supported_item_type(&self, _folder_item: &dyn FolderItem) -> bool {
            true
        }
        fn create_database(
            &mut self,
            _parent_path: &str,
            _name: &str,
            _file_id: Option<&str>,
            _buffer_file: &mut dyn BufferFile,
            _comment: Option<&str>,
            _content_type: &str,
            _reset_database_id: bool,
            _monitor: &dyn TaskMonitor,
            _user: Option<&str>,
        ) -> Result<Box<dyn DatabaseItem>, FileSystemCreateError> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not implemented in mock").into())
        }
        fn create_managed_database(
            &mut self,
            _parent_path: &str,
            _name: &str,
            _file_id: Option<&str>,
            _content_type: &str,
            _buffer_size: i32,
            _user: Option<&str>,
            _project_path: &str,
        ) -> Result<Box<dyn ManagedBufferFile>, FileSystemError> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not implemented in mock").into())
        }
        fn create_data_file(
            &mut self,
            _parent_path: &str,
            _name: &str,
            _istream: &mut dyn io::Read,
            _comment: Option<&str>,
            _content_type: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DataFileItem>, FileSystemCreateError> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not implemented in mock").into())
        }
        fn create_text_data_item(
            &mut self,
            parent_path: &str,
            name: &str,
            _file_id: Option<&str>,
            _content_type: &str,
            _text_data: &str,
            _comment: Option<&str>,
            _user: Option<&str>,
        ) -> Result<Box<dyn TextDataItem>, FileSystemError> {
            if self.read_only {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into());
            }
            self.items.entry(parent_path.to_string()).or_default().push(name.to_string());
            for listener in &self.listeners {
                listener.item_created(parent_path, name);
            }
            Err(io::Error::new(io::ErrorKind::Unsupported, "TextDataItem construction not implemented in mock")
                .into())
        }
        fn create_file(
            &mut self,
            _parent_path: &str,
            _name: &str,
            _packed_file: &Path,
            _monitor: &dyn TaskMonitor,
            _user: Option<&str>,
        ) -> Result<Box<dyn FolderItem>, FileSystemCreateError> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not implemented in mock").into())
        }
        fn delete_folder(&mut self, folder_path: &str) -> io::Result<()> {
            if self.folders.get(folder_path).is_some_and(|v| !v.is_empty())
                || self.items.get(folder_path).is_some_and(|v| !v.is_empty())
            {
                return Err(io::Error::new(io::ErrorKind::Other, "folder not empty"));
            }
            self.folders.remove(folder_path);
            Ok(())
        }
        fn move_folder(
            &mut self,
            _parent_path: &str,
            _folder_name: &str,
            _new_parent_path: &str,
        ) -> Result<(), FileSystemError> {
            Ok(())
        }
        fn rename_folder(
            &mut self,
            _parent_path: &str,
            _folder_name: &str,
            _new_folder_name: &str,
        ) -> Result<(), FileSystemError> {
            Ok(())
        }
        fn move_item(
            &mut self,
            folder_path: &str,
            name: &str,
            new_folder_path: &str,
            new_name: &str,
        ) -> Result<(), FileSystemError> {
            let names = self.items.entry(folder_path.to_string()).or_default();
            let Some(pos) = names.iter().position(|n| n == name) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "item not found").into());
            };
            names.remove(pos);
            self.items.entry(new_folder_path.to_string()).or_default().push(new_name.to_string());
            Ok(())
        }
        fn add_file_system_listener(&mut self, listener: Box<dyn FileSystemListener>) {
            self.listeners.push(listener);
        }
        fn remove_file_system_listener(&mut self, _listener: &dyn FileSystemListener) {
            // MockFileSystem never needs to remove a listener in these tests; identity-based
            // removal is left to a concrete implementation.
        }
        fn folder_exists(&self, folder_path: &str) -> io::Result<bool> {
            Ok(self.folders.contains_key(folder_path))
        }
        fn file_exists(&self, folder_path: &str, name: &str) -> io::Result<bool> {
            Ok(self.items.get(folder_path).is_some_and(|v| v.iter().any(|n| n == name)))
        }
        fn is_shared(&self) -> bool {
            false
        }
        fn dispose(&mut self) {
            self.folders.clear();
            self.items.clear();
        }
    }

    #[test]
    fn test_object_safety_and_folder_item_lifecycle() {
        let mut fs: Box<dyn FileSystem> = Box::new(MockFileSystem {
            folders: BTreeMap::from([(SEPARATOR.to_string(), Vec::new())]),
            ..Default::default()
        });

        assert!(fs.folder_exists(SEPARATOR).unwrap());
        assert!(!fs.folder_exists("/missing").unwrap());

        fs.create_folder(SEPARATOR, "a").unwrap();
        assert!(fs.folder_exists("/a/").unwrap());
        assert_eq!(fs.get_folder_names(SEPARATOR).unwrap(), vec!["a".to_string()]);

        let err = fs.create_folder(SEPARATOR, "").unwrap_err();
        assert!(matches!(err, FileSystemError::InvalidName(_)));

        assert!(fs.get_item(SEPARATOR, "x").unwrap().is_none());
        let _ = fs.create_text_data_item(SEPARATOR, "x", None, "Text", "hello", None, Some("alice"));
        assert!(fs.file_exists(SEPARATOR, "x").unwrap());
        assert!(fs.get_item(SEPARATOR, "x").unwrap().is_some());
        assert_eq!(fs.get_item_count().unwrap(), 1);

        fs.move_item(SEPARATOR, "x", "/a/", "y").unwrap();
        assert!(!fs.file_exists(SEPARATOR, "x").unwrap());
        assert!(fs.file_exists("/a/", "y").unwrap());

        let err = fs.move_item(SEPARATOR, "x", "/a/", "z").unwrap_err();
        assert!(matches!(err, FileSystemError::Io(e) if e.kind() == io::ErrorKind::NotFound));

        assert_eq!(
            fs.get_item_by_file_id("abc").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn test_listener_notified_on_item_creation() {
        let mut fs = MockFileSystem::default();
        struct RecordingListener<'a>(&'a RefCell<Vec<String>>);
        impl FileSystemListener for RecordingListener<'_> {
            fn folder_created(&self, _parent_path: &str, _name: &str) {}
            fn item_created(&self, parent_path: &str, name: &str) {
                self.0.borrow_mut().push(format!("item_created:{parent_path}:{name}"));
            }
            fn folder_deleted(&self, _parent_path: &str, _folder_name: &str) {}
            fn folder_moved(&self, _parent_path: &str, _folder_name: &str, _new_parent_path: &str) {}
            fn folder_renamed(&self, _parent_path: &str, _old_folder_name: &str, _new_folder_name: &str) {}
            fn item_deleted(&self, _folder_path: &str, _item_name: &str) {}
            fn item_renamed(&self, _folder_path: &str, _old_item_name: &str, _new_item_name: &str) {}
            fn item_moved(&self, _parent_path: &str, _name: &str, _new_parent_path: &str, _new_name: &str) {}
            fn item_changed(&self, _parent_path: &str, _item_name: &str) {}
            fn synchronize(&self) {}
        }
        let events = RefCell::new(Vec::new());
        fs.add_file_system_listener(Box::new(RecordingListener(&events)));
        let _ = fs.create_text_data_item(SEPARATOR, "note", None, "Text", "hi", None, None);
        assert_eq!(events.borrow().as_slice(), &["item_created:/:note".to_string()]);
    }

    #[test]
    fn test_normalize_path_requires_absolute() {
        assert!(normalize_path("relative").is_err());
    }

    #[test]
    fn test_normalize_path_resolves_dot_and_dotdot() {
        assert_eq!(normalize_path("/a/./b/../c").unwrap(), "/a/c");
        assert_eq!(normalize_path("/a/./b/../c/").unwrap(), "/a/c/");
        assert_eq!(normalize_path("/a/b/c").unwrap(), "/a/b/c");
    }

    #[test]
    fn test_normalize_path_rejects_dotdot_past_root() {
        assert!(normalize_path("/../a").is_err());
    }

    #[test]
    fn test_normalize_path_rejects_empty_element() {
        assert!(normalize_path("/a//b").is_err());
    }
}
