use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

use crate::framework::db::buffers::{BufferFile, ManagedBufferFile};
use crate::framework::seam_stubs::FolderItem;
use crate::framework::store::local::{FileSystemOpError, RepositoryLogger};
use crate::framework::store::FileSystemListener;
use crate::util::exception::{CancelledException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Character used to separate folder and item names within a path string. Mirrors
/// `ghidra.framework.store.FileSystem.SEPARATOR_CHAR`, which has not been ported yet (see
/// [`crate::framework::store::local`] module docs); duplicated here since it is a trivial
/// constant rather than a type requiring a placeholder trait.
pub const SEPARATOR_CHAR: char = '/';
/// String form of [`SEPARATOR_CHAR`]. Mirrors `ghidra.framework.store.FileSystem.SEPARATOR`.
pub const SEPARATOR: &str = "/";

/// Hidden directory name prefix. Should only be prepended to an escaped base-name.
/// See [`escape_hidden_dir_prefix_chars`].
pub const HIDDEN_DIR_PREFIX_CHAR: char = '~';
/// String form of [`HIDDEN_DIR_PREFIX_CHAR`].
pub const HIDDEN_DIR_PREFIX: &str = "~";

/// Hidden item name prefix.
pub const HIDDEN_ITEM_PREFIX: &str = ".ghidra.";

// NOTE: The / and : chars are reserved for use by the file system and should always be
// disallowed!
const INVALID_FILENAME_CHARS: &str = "/\\'`\"*:<>?|";

/// If set, the state of folder item resources will be continually refreshed. This is required if
/// multiple instances exist for a single item. The default is disabled. This feature should be
/// enabled for testing only since it may have a significant performance impact. This does not
/// provide locking which may be required for a shared environment (e.g., checkin locking is only
/// managed by a single instance).
///
/// Mirrors the private static `LocalFileSystem.refreshRequired` field, exposed via
/// [`set_validation_required`] and [`is_refresh_required`].
static REFRESH_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Combines the checked exceptions declared on `LocalFileSystem.createDatabase(..., BufferFile,
/// ...)`, `createDataFile`, and `createFile`, each of which is declared `throws
/// InvalidNameException, IOException, CancelledException`.
#[derive(Error, Debug)]
pub enum CreateItemError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Provides access to `FolderItem`s which exist within a File-based directory structure. Although
/// `FolderItem` caching is highly recommended, it is not provided by this implementation and
/// should be provided by an encompassing set of folder/file objects.
///
/// A `LocalFileSystem` may optionally support version control of its `FolderItem`s. When
/// versioned, `FolderItem`s must be checked-out to create new versions. When not versioned, the
/// check-out mechanism is not used.
///
/// Mirrors `ghidra.framework.store.local.LocalFileSystem`, which is an abstract class that
/// implements `ghidra.framework.store.FileSystem`. Since `FileSystem` has not been ported yet,
/// its methods that `LocalFileSystem` overrides/implements are folded directly into this trait
/// rather than modeled as a separate supertrait.
///
/// This trait was promoted from a minimal placeholder (see
/// [`seam_stubs`](crate::framework::seam_stubs)) that declared no methods. To keep existing bare
/// `impl LocalFileSystem for X {}` blocks compiling, every method here is given a default
/// describing an empty, read-only, non-versioned filesystem (matching the behavior of Java's
/// protected no-arg `LocalFileSystem()` constructor used for "an empty read-only file-system").
///
/// [`IndexedLocalFileSystem`](crate::framework::store::local::IndexedLocalFileSystem) extends
/// this trait (`IndexedLocalFileSystem extends LocalFileSystem` in Java) but already declares its
/// own `folder_exists`, `get_max_name_length`, `dispose`, `move_item`, `get_item_names`,
/// `get_item_count`, `get_folder_names`, `create_folder`, `delete_folder`, `move_folder`,
/// `rename_folder`, and `get_items` methods (added back when this trait was still an empty
/// placeholder). Those method names are intentionally *not* redeclared here: a Rust subtrait
/// redeclaring a same-named supertrait method makes any call through a value known to implement
/// both traits ambiguous (`error[E0034]`), which would break every existing call site in
/// `IndexedLocalFileSystem`'s tests. The corresponding Java abstract methods
/// (`folderExists`/`getMaxNameLength`) and concrete `FileSystem` overrides
/// (`dispose`/`moveItem`/`getItemNames`/etc.) are therefore considered covered by that subtrait
/// instead.
///
/// Static factory (`getLocalFileSystem`) and package-private helpers that operate on internal
/// state not yet ported (property files, the event manager, `LocalDatabaseItem`/`LocalDataFileItem`
/// /`LocalTextDataItem`) are left for a concrete implementation to provide; item-creation methods
/// return the object-safe [`FolderItem`] placeholder rather than the not-yet-ported concrete item
/// types.
pub trait LocalFileSystem {
    /// Get user name associated with this filesystem. In the case of a remote filesystem this
    /// will correspond to the name used during login/authentication. `None` if not-applicable.
    fn get_user_name(&self) -> Option<String> {
        None
    }

    /// Returns true if the file-system requires check-outs when modifying folder items.
    fn is_versioned(&self) -> bool {
        false
    }

    /// Returns true if file-system is on-line.
    fn is_online(&self) -> bool {
        true
    }

    /// Returns true if file-system is read-only.
    fn is_read_only(&self) -> bool {
        true
    }

    /// Returns the `FolderItem` in the given folder with the given name, or `None` if it doesn't
    /// exist.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_item(&self, folder_path: &str, name: &str) -> io::Result<Option<Box<dyn FolderItem>>> {
        let _ = (folder_path, name);
        Ok(None)
    }

    /// Returns the `FolderItem` specified by its unique File-ID, or `None` if it doesn't exist.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs, or one with
    /// [`io::ErrorKind::Unsupported`] if file-ID lookup is not supported (the default, matching
    /// Java's `UnsupportedOperationException("getItem by File-ID")`).
    fn get_item_by_file_id(&self, file_id: &str) -> io::Result<Option<Box<dyn FolderItem>>> {
        let _ = file_id;
        Err(io::Error::new(io::ErrorKind::Unsupported, "getItem by File-ID"))
    }

    /// Determine if the specified folder item is supported by this filesystem's interface and
    /// storage. This method primarily exists to determine if a remote server can support the
    /// specified content.
    ///
    /// The Java implementation checks `folderItem instanceof DatabaseItem || ... TextDataItem ||
    /// ... DataFileItem`; since the object-safe [`FolderItem`] placeholder carries no type
    /// information to downcast, the default here is permissive (`true`) and concrete
    /// implementations that can distinguish item types should override it.
    fn is_supported_item_type(&self, folder_item: &dyn FolderItem) -> bool {
        let _ = folder_item;
        true
    }

    /// Create a new database item within the specified parent folder using the contents of the
    /// specified `BufferFile`.
    ///
    /// `comment` is the version comment (used for versioned file system only). `user` is the name
    /// of the user creating the item (required for a versioned item).
    ///
    /// # Errors
    /// Returns [`CreateItemError::Io`] if the filesystem is read-only, the parent folder does not
    /// exist, or another IO error occurs; [`CreateItemError::InvalidName`] if `name` is invalid;
    /// or [`CreateItemError::Cancelled`] if `monitor` reports cancellation.
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
    ) -> Result<Box<dyn FolderItem>, CreateItemError> {
        let _ = (
            parent_path,
            name,
            file_id,
            buffer_file,
            comment,
            content_type,
            reset_database_id,
            monitor,
            user,
        );
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into())
    }

    /// Create a new empty database item within the specified parent folder, returning an empty
    /// `ManagedBufferFile` open for read-write. If this is a versioned file-system, the
    /// associated item is checked-out.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::Io`] if the filesystem is read-only, the parent folder does
    /// not exist, or another IO error occurs; [`FileSystemOpError::InvalidName`] if `name` is
    /// invalid.
    fn create_managed_database(
        &mut self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        buffer_size: i32,
        user: Option<&str>,
        project_path: &str,
    ) -> Result<Box<dyn ManagedBufferFile>, FileSystemOpError> {
        let _ = (parent_path, name, file_id, content_type, buffer_size, user, project_path);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into())
    }

    /// Creates a new empty data file within the specified parent folder, reading its content from
    /// `data`.
    ///
    /// # Errors
    /// Returns [`CreateItemError::Io`] if the filesystem is read-only or another IO error occurs;
    /// [`CreateItemError::InvalidName`] if `name` is invalid; or [`CreateItemError::Cancelled`] if
    /// `monitor` reports cancellation.
    fn create_data_file(
        &mut self,
        parent_path: &str,
        name: &str,
        data: &mut dyn io::Read,
        comment: Option<&str>,
        content_type: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn FolderItem>, CreateItemError> {
        let _ = (parent_path, name, data, comment, content_type, monitor);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into())
    }

    /// Creates a new text data file within the specified parent folder. `comment` is ignored
    /// unless versioning is enabled, matching the Java implementation.
    ///
    /// # Errors
    /// Returns [`FileSystemOpError::Io`] if the filesystem is read-only or another IO error
    /// occurs, or [`FileSystemOpError::InvalidName`] if `name` is invalid.
    fn create_text_data_item(
        &mut self,
        parent_path: &str,
        name: &str,
        file_id: Option<&str>,
        content_type: &str,
        text_data: &str,
        comment: Option<&str>,
        user: Option<&str>,
    ) -> Result<Box<dyn FolderItem>, FileSystemOpError> {
        let _ = (parent_path, name, file_id, content_type, text_data, comment, user);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into())
    }

    /// Creates a new file item from a packed file at `packed_file`. The content/item type must be
    /// determined from the file itself. If `name` is `None`, the name is taken from the packed
    /// file.
    ///
    /// # Errors
    /// Returns [`CreateItemError::Io`] if the filesystem is read-only or another IO error occurs;
    /// [`CreateItemError::InvalidName`] if `name` is invalid; or [`CreateItemError::Cancelled`] if
    /// `monitor` reports cancellation.
    fn create_file(
        &mut self,
        parent_path: &str,
        name: Option<&str>,
        packed_file: &std::path::Path,
        monitor: &dyn TaskMonitor,
        user: Option<&str>,
    ) -> Result<Box<dyn FolderItem>, CreateItemError> {
        let _ = (parent_path, name, packed_file, monitor, user);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into())
    }

    /// Returns true if the file exists.
    fn file_exists(&self, folder_path: &str, name: &str) -> bool {
        let _ = (folder_path, name);
        false
    }

    /// Adds a file system listener to be notified of file system changes.
    fn add_file_system_listener(&mut self, listener: Box<dyn FileSystemListener>) {
        let _ = listener;
    }

    /// Removes a file system listener from being notified of file system changes.
    fn remove_file_system_listener(&mut self, listener: &dyn FileSystemListener) {
        let _ = listener;
    }

    /// Returns true if this file system is shared.
    fn is_shared(&self) -> bool {
        false
    }

    /// Validate a folder/item name or path.
    ///
    /// The Java implementation also rejects names longer than `getMaxNameLength()`; since that
    /// bound is owned by concrete implementations (e.g.
    /// [`IndexedLocalFileSystem::get_max_name_length`](crate::framework::store::local::IndexedLocalFileSystem::get_max_name_length)),
    /// this default only performs the length-independent checks (empty name, reserved hidden-item
    /// prefix, invalid characters) and concrete implementations that enforce a maximum length
    /// should check it themselves before or after calling this default.
    ///
    /// # Errors
    /// Returns `Err` if `name` is invalid.
    fn test_valid_name(&self, name: &str, is_path: bool) -> Result<(), InvalidNameException> {
        if name.is_empty() {
            return Err(InvalidNameException::with_message("path or name is empty or null"));
        }

        if is_path {
            if name == SEPARATOR {
                return Ok(());
            }
            let trimmed = name.strip_prefix(SEPARATOR_CHAR).unwrap_or(name);
            for element in trimmed.split(SEPARATOR_CHAR) {
                self.test_valid_name(element, false)?;
            }
            return Ok(());
        }

        if name.starts_with(HIDDEN_ITEM_PREFIX) {
            return Err(InvalidNameException::with_message(format!(
                "{name} starts with a reserved prefix '{HIDDEN_ITEM_PREFIX}'"
            )));
        }

        for c in name.chars() {
            if !is_valid_name_character(c) {
                return Err(InvalidNameException::with_message(format!(
                    "{name} contains an invalid character: '{c}'"
                )));
            }
        }

        Ok(())
    }

    /// Returns true if a migration is currently in progress for this filesystem.
    fn migration_in_progress(&self) -> bool {
        false
    }

    /// Associate file system with a specific repository logger.
    fn set_associated_repository_logger(&mut self, repository_logger: Option<Box<dyn RepositoryLogger>>) {
        let _ = repository_logger;
    }

    /// Log an activity message for the given item path. The Java implementation delegates to a
    /// stored `repositoryLogger` if one has been associated via
    /// [`set_associated_repository_logger`](Self::set_associated_repository_logger), falling back
    /// to a plain log message otherwise; since a default trait method has no access to per-instance
    /// state, this default is a no-op and concrete implementations that store a repository logger
    /// should override it to delegate to that logger's
    /// [`log`](crate::framework::store::RepositoryLogger::log) method.
    fn log(&self, path: Option<&str>, msg: &str, user: Option<&str>) {
        let _ = (path, msg, user);
    }
}

/// Returns the full path for a named folder or item within a parent folder.
pub fn get_path(parent_path: &str, name: &str) -> String {
    if parent_path.len() == 1 {
        format!("{parent_path}{name}")
    } else {
        format!("{parent_path}{SEPARATOR_CHAR}{name}")
    }
}

/// Returns the full parent path for a specific folder or item path, or `None` if the root path
/// (`"/"`) was specified.
pub fn get_parent_path(path: &str) -> Option<String> {
    let index = path.rfind(SEPARATOR_CHAR).unwrap_or(0);
    if index == 0 {
        if path.len() == 1 {
            return None;
        }
        return Some(SEPARATOR.to_string());
    }
    Some(path[..index].to_string())
}

/// Returns the name for a specific folder or item path.
pub fn get_name(path: &str) -> String {
    if path.len() == 1 {
        return path.to_string();
    }
    let trimmed = path.strip_suffix(SEPARATOR_CHAR).unwrap_or(path);
    match trimmed.rfind(SEPARATOR_CHAR) {
        Some(index) => trimmed[index + 1..].to_string(),
        None => trimmed.to_string(),
    }
}

/// Returns true if `c` is a valid character within the FileSystem.
pub fn is_valid_name_character(c: char) -> bool {
    !(c < ' ' || INVALID_FILENAME_CHARS.contains(c) || (c as u32) > 255)
}

/// Determines if the specified storage directory name corresponds to a hidden directory
/// (includes both system and application hidden directories).
pub fn is_hidden_dir_name(name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    // odd number of prefix chars at start of name indicates hidden name
    count_hidden_dir_prefix_chars(name) % 2 == 1
}

/// Escape hidden prefix chars in name.
pub fn escape_hidden_dir_prefix_chars(name: &str) -> String {
    let prefix_count = count_hidden_dir_prefix_chars(name);
    if prefix_count == 0 {
        return name.to_string();
    }
    let mut buf = String::with_capacity(name.len() + prefix_count);
    // keep number of hidden prefix chars even
    for _ in 0..prefix_count {
        buf.push(HIDDEN_DIR_PREFIX_CHAR);
    }
    buf.push_str(name);
    buf
}

/// Unescape a non-hidden directory name, or `None` if `name` is a hidden name.
pub fn unescape_hidden_dir_prefix_chars(name: &str) -> Option<String> {
    let prefix_count = count_hidden_dir_prefix_chars(name);
    if prefix_count % 2 == 1 {
        return None;
    }
    let skip = prefix_count / 2;
    Some(name.chars().skip(skip).collect())
}

fn count_hidden_dir_prefix_chars(name: &str) -> usize {
    name.chars().take_while(|&c| c == HIDDEN_DIR_PREFIX_CHAR).count()
}

/// Sets that the state of folder item resources must be continually refreshed. See the
/// [`LocalFileSystem`] trait docs for caveats (testing-only; no locking is provided).
pub fn set_validation_required() {
    REFRESH_REQUIRED.store(true, Ordering::SeqCst);
}

/// Returns true if folder item resources must be refreshed. See [`set_validation_required`].
pub fn is_refresh_required() -> bool {
    REFRESH_REQUIRED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[derive(Default)]
    struct MockFolderItem;
    impl FolderItem for MockFolderItem {}

    #[derive(Default)]
    struct MockLocalFileSystem {
        read_only: bool,
        items: Vec<(String, String)>,
    }

    impl LocalFileSystem for MockLocalFileSystem {
        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn get_item(
            &self,
            folder_path: &str,
            name: &str,
        ) -> io::Result<Option<Box<dyn FolderItem>>> {
            if self.items.iter().any(|(p, n)| p == folder_path && n == name) {
                Ok(Some(Box::new(MockFolderItem)))
            } else {
                Ok(None)
            }
        }

        fn file_exists(&self, folder_path: &str, name: &str) -> bool {
            self.items.iter().any(|(p, n)| p == folder_path && n == name)
        }

        fn create_data_file(
            &mut self,
            parent_path: &str,
            name: &str,
            _data: &mut dyn io::Read,
            _comment: Option<&str>,
            _content_type: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn FolderItem>, CreateItemError> {
            if self.read_only {
                return Err(
                    io::Error::new(io::ErrorKind::PermissionDenied, "read-only filesystem").into(),
                );
            }
            self.test_valid_name(name, false)?;
            self.items.push((parent_path.to_string(), name.to_string()));
            Ok(Box::new(MockFolderItem))
        }
    }

    #[test]
    fn bare_default_impl_describes_an_empty_read_only_filesystem() {
        struct BareLocalFileSystem;
        impl LocalFileSystem for BareLocalFileSystem {}

        let fs = BareLocalFileSystem;
        assert!(fs.is_read_only());
        assert!(!fs.is_versioned());
        assert!(fs.is_online());
        assert!(fs.get_item("/", "x").unwrap().is_none());
        assert!(!fs.file_exists("/", "x"));
        assert_eq!(
            fs.get_item_by_file_id("abc").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn object_safety_and_create_data_file_round_trip() {
        let mut fs: Box<dyn LocalFileSystem> = Box::new(MockLocalFileSystem::default());

        assert!(fs.get_item("/", "prog.gzf").unwrap().is_none());

        let mut data: &[u8] = b"hello";
        fs.create_data_file("/", "prog.gzf", &mut data, None, "Program", &DummyMonitor)
            .unwrap();

        assert!(fs.file_exists("/", "prog.gzf"));
        assert!(fs.get_item("/", "prog.gzf").unwrap().is_some());
        assert!(fs.get_item("/", "missing.gzf").unwrap().is_none());

        // Invalid characters are rejected before the item is recorded.
        let mut more_data: &[u8] = b"x";
        let err = fs
            .create_data_file("/", "bad:name", &mut more_data, None, "Program", &DummyMonitor)
            .unwrap_err();
        assert!(matches!(err, CreateItemError::InvalidName(_)));
        assert!(!fs.file_exists("/", "bad:name"));
    }

    #[test]
    fn read_only_filesystem_rejects_creation() {
        let mut fs: Box<dyn LocalFileSystem> = Box::new(MockLocalFileSystem { read_only: true, items: Vec::new() });
        let mut data: &[u8] = b"hello";
        let err = fs
            .create_data_file("/", "prog.gzf", &mut data, None, "Program", &DummyMonitor)
            .unwrap_err();
        assert!(matches!(err, CreateItemError::Io(_)));
    }

    #[test]
    fn test_valid_name_matches_java_semantics() {
        let fs = MockLocalFileSystem::default();
        assert!(fs.test_valid_name("Program1", false).is_ok());
        assert!(fs.test_valid_name("/a/b/c", true).is_ok());
        assert!(fs.test_valid_name(SEPARATOR, true).is_ok());

        assert!(fs.test_valid_name("", false).is_err());
        assert!(fs.test_valid_name("bad:name", false).is_err());
        // Path form splits on '/' and validates each element, so an invalid character in any
        // element still fails even though the path itself contains the separator character.
        assert!(fs.test_valid_name("/a/bad:name/c", true).is_err());
        let err = fs.test_valid_name(&format!("{HIDDEN_ITEM_PREFIX}x"), false).unwrap_err();
        assert!(err.0.contains("reserved prefix"));
    }

    #[test]
    fn path_helpers_match_java_semantics() {
        assert_eq!(get_path("/", "a"), "/a");
        assert_eq!(get_path("/a", "b"), "/a/b");

        assert_eq!(get_parent_path("/a/b"), Some("/a".to_string()));
        assert_eq!(get_parent_path("/a"), Some(SEPARATOR.to_string()));
        assert_eq!(get_parent_path("/"), None);

        assert_eq!(get_name("/a/b"), "b");
        assert_eq!(get_name("/a/b/"), "b");
        assert_eq!(get_name("/"), "/");
    }

    #[test]
    fn hidden_dir_prefix_helpers_round_trip() {
        assert!(!is_hidden_dir_name("Program"));
        assert!(is_hidden_dir_name(".hidden"));
        assert!(is_hidden_dir_name("~Program"));
        assert!(!is_hidden_dir_name("~~Program"));

        let escaped = escape_hidden_dir_prefix_chars("~Program");
        assert_eq!(escaped, "~~Program");
        assert!(!is_hidden_dir_name(&escaped));
        assert_eq!(unescape_hidden_dir_prefix_chars(&escaped).as_deref(), Some("~Program"));

        assert_eq!(unescape_hidden_dir_prefix_chars("~oddprefix"), None);
    }

    #[test]
    fn refresh_required_flag_defaults_false_and_can_be_set() {
        // NOTE: shared global state; only assert monotonic set -> true, not the initial value,
        // since other tests in this binary may run concurrently against the same static.
        set_validation_required();
        assert!(is_refresh_required());
    }
}
