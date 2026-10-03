//! Port of `ghidra.framework.store.local.LocalDataFileItem`.
//!
//! Java's `LocalDataFileItem extends LocalFolderItem implements DataFileItem`, where
//! `LocalFolderItem` is itself an abstract class carrying real shared state (`fileSystem`,
//! `propertyFile`, `isVersioned`, `lastModified`, ...) and real shared behavior for every
//! `FolderItem`/`LocalFolderItem` method not overridden by a concrete subclass.
//! [`LocalFolderItem`](crate::framework::store::local::LocalFolderItem) was ported here as a pure
//! object-safe trait carrying none of that state (see its own doc comment), so this is the first
//! concrete implementor in this crate and must supply that shared behavior itself rather than
//! inheriting it. Since `LocalDataFileItem` only ever exists on a *non-versioned* file-system
//! (its constructors reject a versioned one -- see below), the relevant subset of
//! `LocalFolderItem`'s behavior is the "non-versioned, `useDataDir=true`, no checkout/history
//! manager" case; that specialization is reproduced directly on this struct, including the
//! Java abstract class's real quirks (documented at each call site below).
//!
//! Two package-private `LocalFolderItem` helpers this class would have inherited --
//! `moveTo(File, String, String, String)` (used by `LocalFileSystem`-level move operations) and
//! `checkInUse`/`checkInUse(int)` (used by checkout/checkin machinery this item never exercises,
//! since it is always non-versioned) -- are not reproduced here: neither is part of the
//! `FolderItem`/`LocalFolderItem`/`DataFileItem` trait surface this struct must implement, and no
//! concrete `LocalFileSystem` exists yet in this crate to call them.
//!
//! Likewise, `LocalFolderItem.fireItemCreated`/`fireItemChanged` (which notify
//! `fileSystem.getListener()`) and `fileSystem.fileIdChanged`/`itemDeleted`/
//! `deleteEmptyVersionedFolders` have no equivalent on the
//! [`LocalFileSystem`](crate::framework::store::local::LocalFileSystem) trait (which exposes only
//! `add_file_system_listener`/`remove_file_system_listener`, not a way to fire a notification
//! through to registered listeners, nor those bookkeeping hooks) -- see that trait's own doc
//! comment for why. Call sites that would fire these in Java are marked with a comment below;
//! they are no-ops here.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::framework::seam_stubs::ItemCheckoutStatus;
use crate::framework::store::data_file_item::DataFileItem;
use crate::framework::store::file_id_factory::FileIDFactory;
use crate::framework::store::folder_item::{DATAFILE_FILE_TYPE, DEFAULT_CHECKOUT_ID};
use crate::framework::store::local::item_property_file::ItemPropertyFile;
use crate::framework::store::local::local_file_system::{
    escape_hidden_dir_prefix_chars, LocalFileSystem, HIDDEN_DIR_PREFIX,
};
use crate::framework::store::local::local_folder_item::{
    LocalFolderItem, UpdateCheckoutError, CHECKOUT_ID, CHECKOUT_VERSION, CONTENT_TYPE,
    CONTENT_TYPE_VERSION, DATA_DIR_EXTENSION, EXCLUSIVE_CHECKOUT, FILE_TYPE, LOCAL_CHECKOUT_VERSION,
    READ_ONLY,
};
use crate::framework::store::local::OutputItemError;
use crate::framework::store::unknown_folder_item::UNKNOWN_CONTENT_TYPE;
use crate::framework::store::{CheckoutType, FolderItem, ItemVersion};
use crate::util::exception::DuplicateFileException;
use crate::util::property_file::PropertyFile;
use crate::util::task::TaskMonitor;
use crate::util::ReadOnlyException;

const DATA_FILE: &str = "data.1.gdf";

/// `LocalDataFileItem` provides a `FolderItem` implementation for a local serialized data file.
/// This implementation supports a non-versioned file-system only.
///
/// This item utilizes a data directory for storing the serialized data file.
///
/// NOTE: The use of this file item type is not fully supported.
///
/// Mirrors `ghidra.framework.store.local.LocalDataFileItem`. See the module doc comment above for
/// how the `extends LocalFolderItem` relationship is handled.
pub struct LocalDataFileItem {
    fs: Arc<dyn LocalFileSystem>,
    property_file: Box<dyn ItemPropertyFile>,
    /// Cached at construction, mirroring `LocalFolderItem.isVersioned`. Every internal check below
    /// uses this cached value rather than re-querying `fs`, exactly as Java's `LocalFolderItem`
    /// does -- except [`FolderItem::is_versioned`]/[`LocalFolderItem::is_versioned`] themselves,
    /// which (matching `FolderItem.isVersioned()`) query `fs` live instead. In practice a
    /// `LocalDataFileItem` can only ever be constructed when `fs.is_versioned()` is false (see the
    /// constructors), so the two never observably disagree.
    is_versioned: bool,
    /// Cached at construction and never updated afterward, exactly like Java's `LocalFolderItem`
    /// `lastModified` field -- later operations that mutate the property file (e.g.
    /// [`Self::set_read_only`]) do not refresh it. See [`Self::last_modified_impl`].
    last_modified: i64,
}

impl LocalDataFileItem {
    /// Constructor for an existing local serialized-data file item which corresponds to the
    /// specified property file.
    ///
    /// Mirrors `LocalDataFileItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if `fs` is versioned, the property file or data file does not
    /// exist, or another IO error occurs.
    pub fn new(fs: Arc<dyn LocalFileSystem>, property_file: Box<dyn ItemPropertyFile>) -> io::Result<Self> {
        // ---- LocalFolderItem(fileSystem, propertyFile, useDataDir = true, create = false) ----
        let data_dir = data_dir_for(property_file.as_ref());
        if !data_dir.exists() || !property_file.exists() {
            let label = property_file.get_name().unwrap_or_default();
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{label} not found")));
        }
        let is_versioned = fs.is_versioned();
        let last_modified = property_file.last_modified();
        let item = Self { fs, property_file, is_versioned, last_modified };

        // ---- LocalDataFileItem's own constructor body ----
        if item.fs.is_versioned() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Item may be corrupt: {}", item.name_impl()),
            ));
        }
        if !item.data_file().exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} not found", item.name_impl())));
        }
        Ok(item)
    }

    /// Create a new local serialized-data file item.
    ///
    /// - `fs`: file system.
    /// - `property_file`: serialized data property file.
    /// - `data`: data source to read from (should be positioned at the start of data and will be
    ///   read to the end). `None` creates an empty data file.
    /// - `content_type`: user content type; must not be blank.
    /// - `monitor`: accepted for signature fidelity with `LocalDataFileItem(..., TaskMonitor
    ///   monitor)`, which declares `throws ... CancelledException` "for cancel support" but --
    ///   like the Java constructor, which never actually calls `monitor.checkCancelled()` in its
    ///   copy loop -- never checks it; this parameter is therefore unused.
    ///
    /// Mirrors `LocalDataFileItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile,
    /// InputStream istream, String contentType, TaskMonitor monitor)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if `fs` is read-only, `property_file` or its data directory already
    /// exists, `fs` is versioned, `content_type` is blank, the data file already exists, or
    /// another IO error occurs.
    pub fn create(
        fs: Arc<dyn LocalFileSystem>,
        mut property_file: Box<dyn ItemPropertyFile>,
        data: Option<&mut dyn Read>,
        content_type: &str,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Self> {
        // ---- LocalFolderItem(fileSystem, propertyFile, useDataDir = true, create = true) ----
        let data_dir = data_dir_for(property_file.as_ref());
        let setup: io::Result<()> = (|| {
            if fs.is_read_only() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
            }
            if property_file.exists() {
                let label = property_file.get_name().unwrap_or_default();
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    DuplicateFileException::new(format!("{label} already exists.")),
                ));
            }
            if data_dir.exists() {
                return Err(crate::framework::store::local::DataDirectoryException::new(
                    "Data directory already exists",
                    data_dir.clone(),
                )
                .into());
            }
            fs::create_dir(&data_dir)?;
            property_file.write_state()?;
            Ok(())
        })();
        if let Err(e) = setup {
            abort_create(property_file.as_mut(), &data_dir);
            return Err(e);
        }

        let is_versioned = fs.is_versioned();
        let last_modified = property_file.last_modified();
        let mut item = Self { fs, property_file, is_versioned, last_modified };

        // ---- LocalDataFileItem's own constructor body ----
        if item.fs.is_versioned() {
            abort_create(item.property_file.as_mut(), &data_dir);
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Versioning not yet supported for DataFiles"));
        }
        if content_type.trim().is_empty() {
            abort_create(item.property_file.as_mut(), &data_dir);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Missing content-type"));
        }

        let data_file = item.data_file();
        if data_file.exists() {
            // Real Java quirk, preserved: unlike the two checks just above, this branch does
            // *not* call `abortCreate()` before throwing -- the property file and data directory
            // created by the superclass constructor above would be left behind on disk. In
            // practice this branch is unreachable through single-threaded use of the public
            // constructor: `data_file` lives inside `data_dir`, which was just freshly created a
            // few lines above (`fs::create_dir`/Java's `dir.mkdir()`) and is therefore always
            // empty at this point -- the only way to reach this check with `data_file` already
            // present is a genuine concurrent race with another process/thread creating the same
            // file between that `mkdir` and this check. It is preserved here, unreachable-in-
            // practice asymmetry and all, as a faithful port of that defensive (if largely
            // dead) guard rather than "fixed" by adding a cleanup call the original doesn't have.
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                DuplicateFileException::new(format!("{} already exists.", item.name_impl())),
            ));
        }

        item.property_file.put_int(FILE_TYPE, DATAFILE_FILE_TYPE);
        item.property_file.put_boolean(READ_ONLY, false);
        item.property_file.put_string(CONTENT_TYPE, Some(content_type));
        item.property_file.write_state()?;

        match data {
            Some(reader) => {
                if let Err(e) = write_data_file(&data_file, reader) {
                    abort_create(item.property_file.as_mut(), &data_dir);
                    return Err(e);
                }
            }
            None => {
                if fs::OpenOptions::new().write(true).create_new(true).open(&data_file).is_err() {
                    abort_create(item.property_file.as_mut(), &data_dir);
                }
            }
        }

        Ok(item)
    }

    fn data_dir(&self) -> PathBuf {
        data_dir_for(self.property_file.as_ref())
    }

    fn data_file(&self) -> PathBuf {
        self.data_dir().join(DATA_FILE)
    }

    // ---- Shared helpers backing both `FolderItem` and `LocalFolderItem` impls below ----

    fn name_impl(&self) -> String {
        self.property_file.get_name().unwrap_or_default()
    }

    fn file_id_impl(&self) -> Option<String> {
        self.property_file.get_file_id()
    }

    fn reset_file_id_impl(&mut self) -> io::Result<String> {
        let file_id = FileIDFactory::create_file_id();
        self.property_file.set_file_id(Some(&file_id));
        self.property_file.write_state()?;
        // Java also calls `fileSystem.fileIdChanged(propertyFile, oldFileId)`; no equivalent
        // hook exists on the `LocalFileSystem` trait (see module doc comment).
        Ok(file_id)
    }

    fn content_type_impl(&self) -> String {
        self.property_file
            .get_string(CONTENT_TYPE, Some(UNKNOWN_CONTENT_TYPE))
            .unwrap_or_else(|| UNKNOWN_CONTENT_TYPE.to_string())
    }

    fn parent_path_impl(&self) -> String {
        self.property_file.get_parent_path().unwrap_or_default()
    }

    fn path_name_impl(&self) -> String {
        self.property_file.get_path().unwrap_or_default()
    }

    fn is_read_only_impl(&self) -> bool {
        self.property_file.get_boolean(READ_ONLY, false)
    }

    fn set_read_only_impl(&mut self, state: bool) -> io::Result<()> {
        if self.fs.is_read_only() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
        }
        self.property_file.put_boolean(READ_ONLY, state);
        self.property_file.write_state()?;
        // Java also calls `fireItemChanged()`; no-op here (see module doc comment).
        Ok(())
    }

    fn content_type_version_impl(&self) -> i32 {
        self.property_file.get_int(CONTENT_TYPE_VERSION, 1)
    }

    fn set_content_type_version_impl(&mut self, version: i32) -> io::Result<()> {
        if self.fs.is_read_only() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
        }
        self.property_file.put_int(CONTENT_TYPE_VERSION, version);
        self.property_file.write_state()?;
        Ok(())
    }

    /// See the `last_modified` field's own doc comment: this is a cached, never-refreshed value.
    fn last_modified_impl(&self) -> i64 {
        self.last_modified
    }

    fn is_checked_out_impl(&self) -> bool {
        // `isVersioned` is always false for a valid `LocalDataFileItem`, so the Java
        // `UnsupportedOperationException` guard here never fires.
        self.checkout_id_impl() != DEFAULT_CHECKOUT_ID
    }

    fn is_checked_out_exclusive_impl(&self) -> bool {
        if self.property_file.get_long(CHECKOUT_ID, DEFAULT_CHECKOUT_ID) != DEFAULT_CHECKOUT_ID {
            return self.property_file.get_boolean(EXCLUSIVE_CHECKOUT, false);
        }
        false
    }

    fn checkout_id_impl(&self) -> i64 {
        self.property_file.get_long(CHECKOUT_ID, DEFAULT_CHECKOUT_ID)
    }

    fn checkout_version_impl(&self) -> io::Result<i32> {
        Ok(self.property_file.get_int(CHECKOUT_VERSION, -1))
    }

    fn local_checkout_version_impl(&self) -> i32 {
        self.property_file.get_int(LOCAL_CHECKOUT_VERSION, -1)
    }

    fn set_checkout_impl(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> io::Result<()> {
        if self.fs.is_read_only() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
        }
        if checkout_id <= 0 || checkout_version <= 0 || local_version < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Bad checkout data: {checkout_id},{checkout_version},{local_version}"),
            ));
        }
        self.property_file.put_long(CHECKOUT_ID, checkout_id);
        self.property_file.put_boolean(EXCLUSIVE_CHECKOUT, exclusive);
        self.property_file.put_int(CHECKOUT_VERSION, checkout_version);
        self.property_file.put_int(LOCAL_CHECKOUT_VERSION, local_version);
        self.property_file.write_state()?;
        Ok(())
    }

    fn clear_checkout_impl(&mut self) -> io::Result<()> {
        if self.fs.is_read_only() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
        }
        self.property_file.put_long(CHECKOUT_ID, DEFAULT_CHECKOUT_ID);
        self.property_file.put_boolean(EXCLUSIVE_CHECKOUT, false);
        self.property_file.put_int(CHECKOUT_VERSION, -1);
        self.property_file.put_int(LOCAL_CHECKOUT_VERSION, -1);
        self.property_file.write_state()?;
        Ok(())
    }

    /// `checkoutMgr` is always `None` for a `LocalDataFileItem` (it is only ever constructed for
    /// a non-versioned file-system), so this always fails, matching `checkoutMgr == null ->
    /// UnsupportedOperationException("item does not support checkin/checkout")`.
    fn checkout_impl(
        &mut self,
        _checkout_type: CheckoutType,
        _user: &str,
        _project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "item does not support checkin/checkout"))
    }

    fn terminate_checkout_impl(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "item does not support checkin/checkout"))
    }

    /// `isVersioned` is always false, matching `!isVersioned ->
    /// UnsupportedOperationException("Non-versioned item does not support checkout")`.
    fn get_checkout_impl(&self, _checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Non-versioned item does not support checkout"))
    }

    fn get_checkouts_impl(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Non-versioned item does not support checkout"))
    }

    fn has_checkouts_impl(&self) -> bool {
        // `isVersioned` is always false, so this always returns false (no error).
        false
    }

    fn is_checkin_active_impl(&self) -> bool {
        false
    }

    fn update_checkout_version_impl(
        &mut self,
        _checkout_id: i64,
        _checkout_version: i32,
        _user: &str,
    ) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "item does not support checkin/checkout"))
    }

    /// Mirrors `LocalFolderItem.delete(int, String)`, specialized to the always-non-versioned
    /// case.
    fn delete_impl(&mut self, version: i32, user: &str) -> io::Result<()> {
        if self.fs.is_read_only() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ReadOnlyException::default()));
        }
        if version != -1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "delete version must be -1 for non-versioned items",
            ));
        }
        self.delete_content(user)
        // Java also notifies `fileSystem.itemDeleted`/the listener and calls
        // `fileSystem.deleteEmptyVersionedFolders` here; no equivalents exist on the
        // `LocalFileSystem` trait (see module doc comment). Note `currentVersion` (used to gate
        // the listener notification in Java) is always -1 for this item type anyway (see
        // `get_current_version`), so that particular notification would never have fired even
        // with a real listener hook.
    }

    /// Mirrors `LocalFolderItem.deleteContent(String)`.
    fn delete_content(&mut self, user: &str) -> io::Result<()> {
        let data_dir = self.data_dir();
        let chk_dir = {
            let mut name = data_dir.file_name().unwrap_or_default().to_os_string();
            name.push(".delete");
            data_dir.with_file_name(name)
        };
        let _ = fs::remove_dir_all(&chk_dir);
        if data_dir.exists() && fs::rename(&data_dir, &chk_dir).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                crate::util::exception::FileInUseException::new(format!("{} is in use", self.name_impl())),
            ));
        }

        self.property_file.delete();
        if self.property_file.exists() {
            // Attempt to restore.
            if !data_dir.exists() && chk_dir.exists() {
                let _ = fs::rename(&chk_dir, &data_dir);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                crate::util::exception::FileInUseException::new(format!("{} is in use", self.name_impl())),
            ));
        }

        let _ = fs::remove_dir_all(&chk_dir);
        self.log_impl("file deleted", Some(user));
        Ok(())
    }

    fn log_impl(&self, msg: &str, user: Option<&str>) {
        self.fs.log(Some(&self.path_name_impl()), msg, user);
    }
}

fn data_dir_for(pf: &dyn ItemPropertyFile) -> PathBuf {
    let escaped = escape_hidden_dir_prefix_chars(&pf.get_storage_name());
    pf.get_parent_storage_directory()
        .join(format!("{HIDDEN_DIR_PREFIX}{escaped}{DATA_DIR_EXTENSION}"))
}

fn abort_create(pf: &mut dyn ItemPropertyFile, data_dir: &std::path::Path) {
    pf.delete();
    let _ = fs::remove_dir_all(data_dir);
}

fn write_data_file(path: &std::path::Path, reader: &mut dyn Read) -> io::Result<()> {
    let mut out = File::create(path)?;
    io::copy(reader, &mut out)?;
    Ok(())
}

impl FolderItem for LocalDataFileItem {
    fn get_name(&self) -> String {
        self.name_impl()
    }

    fn get_file_id(&self) -> Option<String> {
        self.file_id_impl()
    }

    fn reset_file_id(&mut self) -> io::Result<String> {
        self.reset_file_id_impl()
    }

    /// Mirrors `LocalDataFileItem.length()`: `getDataFile().length()`. Java's `File.length()`
    /// never throws, returning `0` if the file does not exist or another IO error occurs; this
    /// forgiving behavior is preserved here rather than surfacing an `io::Error`.
    fn length(&self) -> io::Result<i64> {
        Ok(fs::metadata(self.data_file()).map(|m| m.len() as i64).unwrap_or(0))
    }

    fn get_content_type(&self) -> String {
        self.content_type_impl()
    }

    fn get_parent_path(&self) -> String {
        self.parent_path_impl()
    }

    fn get_path_name(&self) -> String {
        self.path_name_impl()
    }

    fn is_read_only(&self) -> bool {
        self.is_read_only_impl()
    }

    fn set_read_only(&mut self, state: bool) -> io::Result<()> {
        self.set_read_only_impl(state)
    }

    fn get_content_type_version(&self) -> i32 {
        self.content_type_version_impl()
    }

    fn set_content_type_version(&mut self, version: i32) -> io::Result<()> {
        self.set_content_type_version_impl(version)
    }

    fn last_modified(&self) -> i64 {
        self.last_modified_impl()
    }

    /// Mirrors `LocalDataFileItem.getCurrentVersion()`: always `-1` (versions are not supported
    /// for data files).
    fn get_current_version(&self) -> i32 {
        -1
    }

    fn is_checked_out(&self) -> bool {
        self.is_checked_out_impl()
    }

    fn is_checked_out_exclusive(&self) -> bool {
        self.is_checked_out_exclusive_impl()
    }

    fn is_versioned(&self) -> io::Result<bool> {
        Ok(self.fs.is_versioned())
    }

    fn get_checkout_id(&self) -> io::Result<i64> {
        Ok(self.checkout_id_impl())
    }

    fn get_checkout_version(&self) -> io::Result<i32> {
        self.checkout_version_impl()
    }

    fn get_local_checkout_version(&self) -> i32 {
        self.local_checkout_version_impl()
    }

    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> io::Result<()> {
        self.set_checkout_impl(checkout_id, exclusive, checkout_version, local_version)
    }

    fn clear_checkout(&mut self) -> io::Result<()> {
        self.clear_checkout_impl()
    }

    fn delete(&mut self, version: i32, user: &str) -> io::Result<()> {
        self.delete_impl(version, user)
    }

    /// Real Java quirk preserved: `LocalFolderItem.getVersions()` (which implements
    /// `FolderItem.getVersions()`) *throws* `UnsupportedOperationException` for a non-versioned
    /// item rather than returning `null`/`None`, even though this trait's own doc comment
    /// (mirroring `FolderItem`'s interface javadoc) describes `None` as the "not versioned"
    /// signal. Since `is_versioned` is always false for this item, this always errs.
    fn get_versions(&self) -> io::Result<Option<Vec<ItemVersion>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Non-versioned item does not support getVersions"))
    }

    fn checkout(
        &mut self,
        checkout_type: CheckoutType,
        user: &str,
        project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        self.checkout_impl(checkout_type, user, project_path)
    }

    fn terminate_checkout(&mut self, checkout_id: i64, notify: bool) -> io::Result<()> {
        self.terminate_checkout_impl(checkout_id, notify)
    }

    fn has_checkouts(&self) -> io::Result<bool> {
        Ok(self.has_checkouts_impl())
    }

    /// Mirrors `LocalDataFileItem.canRecover()`: always `false`.
    fn can_recover(&self) -> bool {
        false
    }

    fn get_checkout(&self, checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        self.get_checkout_impl(checkout_id)
    }

    fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
        self.get_checkouts_impl()
    }

    fn is_checkin_active(&self) -> io::Result<bool> {
        Ok(self.is_checkin_active_impl())
    }

    fn update_checkout_version(&mut self, checkout_id: i64, checkout_version: i32, user: &str) -> io::Result<()> {
        self.update_checkout_version_impl(checkout_id, checkout_version, user)
    }

    /// Mirrors `LocalDataFileItem.output(...)`: always fails with "Packed output not yet
    /// supported for DataFiles".
    fn output(
        &self,
        _output_file: &std::path::Path,
        _version: i32,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), OutputItemError> {
        Err(OutputItemError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "Packed output not yet supported for DataFiles",
        )))
    }

    /// See this module's doc comment for why this always returns `Ok(None)`: `&mut self` cannot
    /// produce a `Box<dyn FolderItem>` alias to `self` without `Clone`, which no `FolderItem`
    /// implementor (including this one) provides. The real refresh side effect (re-reading the
    /// property file, or detecting the item no longer exists) is still performed in place; use
    /// [`LocalFolderItem::refresh`] for a faithful `bool` "does it still exist" result instead.
    fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
        LocalFolderItem::refresh(self)?;
        Ok(None)
    }
}

impl LocalFolderItem for LocalDataFileItem {
    fn refresh(&mut self) -> io::Result<bool> {
        if !self.data_dir().exists() || !self.property_file.exists() {
            return Ok(false);
        }
        self.property_file.read_state()?;
        Ok(true)
    }

    /// Mirrors `LocalDataFileItem.getMinimumVersion()`: always `-1`.
    fn get_minimum_version(&self) -> io::Result<i32> {
        Ok(-1)
    }

    fn delete(&mut self, version: i32, user: &str) -> io::Result<()> {
        self.delete_impl(version, user)
    }

    /// Mirrors `LocalDataFileItem.deleteMinimumVersion(String)`: always unsupported.
    fn delete_minimum_version(&mut self, _user: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Versioning not yet supported for DataFiles"))
    }

    /// Mirrors `LocalDataFileItem.deleteCurrentVersion(String)`: always unsupported.
    fn delete_current_version(&mut self, _user: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Versioning not yet supported for DataFiles"))
    }

    fn get_content_type(&self) -> String {
        self.content_type_impl()
    }

    fn get_file_id(&self) -> Option<String> {
        self.file_id_impl()
    }

    fn reset_file_id(&mut self) -> io::Result<String> {
        self.reset_file_id_impl()
    }

    fn get_name(&self) -> String {
        self.name_impl()
    }

    fn get_parent_path(&self) -> String {
        self.parent_path_impl()
    }

    fn get_path_name(&self) -> String {
        self.path_name_impl()
    }

    fn is_checked_out(&self) -> bool {
        self.is_checked_out_impl()
    }

    fn is_checked_out_exclusive(&self) -> bool {
        self.is_checked_out_exclusive_impl()
    }

    fn is_versioned(&self) -> io::Result<bool> {
        Ok(self.fs.is_versioned())
    }

    /// See [`FolderItem::get_versions`] above for the preserved quirk this mirrors.
    fn get_versions(&self) -> io::Result<Vec<ItemVersion>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Non-versioned item does not support getVersions"))
    }

    fn last_modified(&self) -> i64 {
        self.last_modified_impl()
    }

    fn is_read_only(&self) -> bool {
        self.is_read_only_impl()
    }

    fn set_read_only(&mut self, state: bool) -> io::Result<()> {
        self.set_read_only_impl(state)
    }

    fn get_content_type_version(&self) -> i32 {
        self.content_type_version_impl()
    }

    fn set_content_type_version(&mut self, version: i32) -> io::Result<()> {
        self.set_content_type_version_impl(version)
    }

    fn checkout(
        &mut self,
        checkout_type: CheckoutType,
        user: &str,
        project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        self.checkout_impl(checkout_type, user, project_path)
    }

    fn terminate_checkout(&mut self, checkout_id: i64, notify: bool) -> io::Result<()> {
        self.terminate_checkout_impl(checkout_id, notify)
    }

    fn get_checkout(&self, checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        self.get_checkout_impl(checkout_id)
    }

    fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
        self.get_checkouts_impl()
    }

    fn get_checkout_id(&self) -> i64 {
        self.checkout_id_impl()
    }

    fn get_checkout_version(&self) -> io::Result<i32> {
        self.checkout_version_impl()
    }

    fn get_local_checkout_version(&self) -> i32 {
        self.local_checkout_version_impl()
    }

    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> io::Result<()> {
        self.set_checkout_impl(checkout_id, exclusive, checkout_version, local_version)
    }

    fn clear_checkout(&mut self) -> io::Result<()> {
        self.clear_checkout_impl()
    }

    fn has_checkouts(&self) -> bool {
        self.has_checkouts_impl()
    }

    fn is_checkin_active(&self) -> bool {
        self.is_checkin_active_impl()
    }

    fn update_checkout_version(&mut self, checkout_id: i64, checkout_version: i32, user: &str) -> io::Result<()> {
        self.update_checkout_version_impl(checkout_id, checkout_version, user)
    }

    /// Mirrors `LocalFolderItem.updateCheckout(FolderItem, boolean, TaskMonitor)`, overridden by
    /// `LocalDataFileItem` to always throw `UnsupportedOperationException("Versioning not yet
    /// supported for DataFiles")`.
    fn update_checkout_with_monitor(
        &mut self,
        _versioned_folder_item: &dyn FolderItem,
        _update_item: bool,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), UpdateCheckoutError> {
        Err(UpdateCheckoutError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "Versioning not yet supported for DataFiles",
        )))
    }

    /// Mirrors `LocalFolderItem.updateCheckout(FolderItem, int)`, overridden the same way.
    fn update_checkout_from(&mut self, _item: &dyn FolderItem, _checkout_version: i32) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Versioning not yet supported for DataFiles"))
    }
}

impl DataFileItem for LocalDataFileItem {
    fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(File::open(self.data_file())?))
    }

    fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
        Ok(Box::new(File::create(self.data_file())?))
    }

    /// Real Java quirk preserved: `version` is ignored entirely -- "Versions for DataFiles are
    /// not supported" (a `// TODO` in the Java source), and this always returns the *current*
    /// data file's content regardless of which version was requested.
    fn get_input_stream_for_version(&self, _version: i32) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(File::open(self.data_file())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::store::local::local_property_file::LocalItemPropertyFile;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_dir(label: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("local_data_file_item_test_{}_{}_{}", std::process::id(), label, id));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[derive(Default)]
    struct TestFs {
        read_only: bool,
        versioned: bool,
    }

    impl LocalFileSystem for TestFs {
        fn is_read_only(&self) -> bool {
            self.read_only
        }
        fn is_versioned(&self) -> bool {
            self.versioned
        }
    }

    fn property_file(dir: &std::path::Path, storage_name: &str, parent_path: &str, name: &str) -> Box<dyn ItemPropertyFile> {
        Box::new(LocalItemPropertyFile::new(dir, storage_name, Some(parent_path), Some(name)).unwrap())
    }

    #[test]
    fn create_with_data_then_read_back() {
        let dir = tmp_dir("create_data");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let mut content = Cursor::new(b"hello world".to_vec());
        let monitor = crate::util::task::DummyMonitor;

        let item =
            LocalDataFileItem::create(fs_handle, pf, Some(&mut content), "TextFile", &monitor).unwrap();

        assert_eq!(FolderItem::get_name(&item), "item");
        assert_eq!(FolderItem::get_content_type(&item), "TextFile");
        assert_eq!(FolderItem::get_current_version(&item), -1);
        assert_eq!(item.length().unwrap(), 11);

        let mut buf = Vec::new();
        item.get_input_stream().unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[test]
    fn create_without_data_makes_empty_file() {
        let dir = tmp_dir("create_empty");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;

        let item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();
        assert_eq!(item.length().unwrap(), 0);
    }

    #[test]
    fn create_rejects_blank_content_type_and_cleans_up() {
        let dir = tmp_dir("blank_content_type");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;

        let err = LocalDataFileItem::create(fs_handle, pf, None, "   ", &monitor).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // abortCreate() ran: neither the property file nor the data directory should remain.
        assert!(!dir.join("item.prp").exists());
    }

    #[test]
    fn create_rejects_versioned_filesystem_and_cleans_up() {
        let dir = tmp_dir("versioned_reject");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs { versioned: true, ..Default::default() });
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;

        let err = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!dir.join("item.prp").exists());
    }

    #[test]
    fn create_rejects_read_only_filesystem() {
        let dir = tmp_dir("read_only_reject");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs { read_only: true, ..Default::default() });
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;

        let err = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn create_over_existing_item_wipes_out_the_original_quirk() {
        // Real Java quirk, preserved: `abortCreate()` deletes the property file and data
        // directory *by path*, regardless of whether the current (failed) `create()` attempt is
        // the one that made them. So attempting to `create()` a second item at a location that
        // already holds a *successfully created* item does not just fail with
        // `DuplicateFileException` -- it destroys the original item's storage as a side effect,
        // since `LocalFolderItem`'s `finally { if (!success && create) abortCreate(); }` fires for
        // this failure path too.
        let dir = tmp_dir("wipe_quirk");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let monitor = crate::util::task::DummyMonitor;

        {
            let pf = property_file(&dir, "item", "/", "item");
            let mut content = Cursor::new(b"original content".to_vec());
            LocalDataFileItem::create(fs_handle.clone(), pf, Some(&mut content), "TextFile", &monitor)
                .unwrap();
        }
        assert!(dir.join("item.prp").exists());

        // A second `create()` targeting the exact same storage location.
        let pf2 = property_file(&dir, "item", "/", "item");
        let err = LocalDataFileItem::create(fs_handle, pf2, None, "TextFile", &monitor).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // The original item's property file and data directory are gone.
        assert!(!dir.join("item.prp").exists());
    }

    #[test]
    fn reopen_existing_item() {
        let dir = tmp_dir("reopen");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        {
            let mut content = Cursor::new(b"persisted".to_vec());
            LocalDataFileItem::create(fs_handle.clone(), pf, Some(&mut content), "TextFile", &monitor)
                .unwrap();
        }

        let pf2 = property_file(&dir, "item", "/", "item");
        let reopened = LocalDataFileItem::new(fs_handle, pf2).unwrap();
        let mut buf = Vec::new();
        reopened.get_input_stream().unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"persisted");
        assert_eq!(FolderItem::get_content_type(&reopened), "TextFile");
    }

    #[test]
    fn new_rejects_versioned_filesystem() {
        let dir = tmp_dir("new_versioned_reject");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        let versioned_fs: Arc<dyn LocalFileSystem> = Arc::new(TestFs { versioned: true, ..Default::default() });
        let pf2 = property_file(&dir, "item", "/", "item");
        let err = LocalDataFileItem::new(versioned_fs, pf2).err().unwrap();
        assert!(err.to_string().contains("Item may be corrupt"));
    }

    #[test]
    fn get_input_stream_for_version_ignores_version_quirk() {
        let dir = tmp_dir("version_ignored");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut content = Cursor::new(b"only-version".to_vec());
        let item =
            LocalDataFileItem::create(fs_handle, pf, Some(&mut content), "TextFile", &monitor).unwrap();

        let mut buf_v0 = Vec::new();
        item.get_input_stream_for_version(0).unwrap().read_to_end(&mut buf_v0).unwrap();
        let mut buf_v99 = Vec::new();
        item.get_input_stream_for_version(99).unwrap().read_to_end(&mut buf_v99).unwrap();
        assert_eq!(buf_v0, b"only-version");
        assert_eq!(buf_v99, b"only-version");
    }

    #[test]
    fn get_versions_always_errors_even_though_folder_item_docs_say_none() {
        let dir = tmp_dir("get_versions_quirk");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        assert!(FolderItem::get_versions(&item).is_err());
        assert!(LocalFolderItem::get_versions(&item).is_err());
    }

    #[test]
    fn checkout_and_related_operations_are_unsupported() {
        let dir = tmp_dir("checkout_unsupported");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        assert!(FolderItem::checkout(&mut item, CheckoutType::Normal, "alice", "/repo/item").is_err());
        assert!(FolderItem::get_checkout(&item, 1).is_err());
        assert!(FolderItem::get_checkouts(&item).is_err());
        assert!(!FolderItem::has_checkouts(&item).unwrap());
        assert!(!FolderItem::is_checkin_active(&item).unwrap());
        assert!(LocalFolderItem::delete_minimum_version(&mut item, "alice").is_err());
        assert!(LocalFolderItem::delete_current_version(&mut item, "alice").is_err());
    }

    #[test]
    fn set_checkout_and_clear_checkout_round_trip_since_non_versioned() {
        // These *are* legal for a non-versioned item (the `isVersioned` guard never fires),
        // unlike `checkout()`/`get_checkout()` above.
        let dir = tmp_dir("set_checkout_ok");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        assert!(!FolderItem::is_checked_out(&item));
        FolderItem::set_checkout(&mut item, 5, true, 3, 2).unwrap();
        assert!(FolderItem::is_checked_out(&item));
        assert_eq!(FolderItem::get_checkout_id(&item).unwrap(), 5);
        assert!(FolderItem::is_checked_out_exclusive(&item));

        FolderItem::clear_checkout(&mut item).unwrap();
        assert!(!FolderItem::is_checked_out(&item));
    }

    #[test]
    fn last_modified_is_frozen_at_construction_quirk() {
        let dir = tmp_dir("last_modified_frozen");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        let initial = FolderItem::last_modified(&item);
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Mutating the property file (which touches its on-disk mtime) does not refresh the
        // cached `last_modified` value.
        FolderItem::set_content_type_version(&mut item, 7).unwrap();
        assert_eq!(FolderItem::last_modified(&item), initial);
    }

    #[test]
    fn delete_removes_property_file_and_data_directory() {
        let dir = tmp_dir("delete");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();
        let data_dir = item.data_dir();
        assert!(data_dir.exists());

        FolderItem::delete(&mut item, -1, "alice").unwrap();
        assert!(!data_dir.exists());
        assert!(!dir.join("item.prp").exists());
    }

    #[test]
    fn delete_rejects_specific_version_for_non_versioned_item() {
        let dir = tmp_dir("delete_specific_version");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        let err = FolderItem::delete(&mut item, 3, "alice").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn output_is_always_unsupported() {
        let dir = tmp_dir("output_unsupported");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        let out_path = dir.join("out.zip");
        let result = FolderItem::output(&item, &out_path, -1, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn reset_file_id_persists_a_new_id() {
        let dir = tmp_dir("reset_file_id");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        assert_eq!(FolderItem::get_file_id(&item), None);
        let id = FolderItem::reset_file_id(&mut item).unwrap();
        assert!(!id.is_empty());
        assert_eq!(FolderItem::get_file_id(&item), Some(id));
    }

    #[test]
    fn local_folder_item_refresh_reports_existence_and_folder_item_refresh_always_returns_none() {
        let dir = tmp_dir("refresh");
        let fs_handle: Arc<dyn LocalFileSystem> = Arc::new(TestFs::default());
        let pf = property_file(&dir, "item", "/", "item");
        let monitor = crate::util::task::DummyMonitor;
        let mut item = LocalDataFileItem::create(fs_handle, pf, None, "TextFile", &monitor).unwrap();

        assert!(LocalFolderItem::refresh(&mut item).unwrap());
        assert_eq!(FolderItem::refresh(&mut item).unwrap().is_none(), true);

        // Now remove the backing storage out from under the item and confirm refresh reports
        // non-existence.
        fs::remove_file(dir.join("item.prp")).unwrap();
        assert!(!LocalFolderItem::refresh(&mut item).unwrap());
    }
}
