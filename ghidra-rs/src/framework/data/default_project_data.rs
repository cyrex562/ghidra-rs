use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use crate::framework::data::ghidra_folder_data::GhidraFolderData;
use crate::framework::model::{DomainObject, DomainObjectConsumer, ProjectData};
use crate::framework::seam_stubs::{GhidraFileDataLike, ProjectLockLike};
use crate::framework::store::local::LocalFileSystem;
use crate::framework::store::FileSystem;
use crate::util::property_file::PropertyFile;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Name of the folder that stores the (legacy, mangled) private project data.
pub const MANGLED_DATA_FOLDER_NAME: &str = "data";
/// Name of the folder that stores the indexed private project data.
pub const INDEXED_DATA_FOLDER_NAME: &str = "idata";
/// Name of the folder that stores per-user data.
pub const USER_FOLDER_NAME: &str = "user";
/// Name of the folder that stores versioned project data.
pub const VERSIONED_FOLDER_NAME: &str = "versioned";

/// Project property key for the associated repository server name.
pub const SERVER_NAME: &str = "SERVER";
/// Project property key for the associated repository server port number.
pub const PORT_NUMBER: &str = "PORT_NUMBER";
/// Project property key for the associated repository name.
pub const REPOSITORY_NAME: &str = "REPOSITORY_NAME";
/// Project property key for the project owner.
pub const OWNER: &str = "OWNER";

/// Native storage name (sans extension) of the project properties file within the project
/// directory (`*.rep`).
pub const PROPERTY_FILENAME: &str = "project";

/// Prefix prepended to the file ID to form a user data file's item name.
const USER_DATA_FILE_PREFIX: &str = "udf_";

/// Helper trait to manage files within a project.
///
/// Port of `ghidra.framework.data.DefaultProjectData`, selected as a cycle cut-point: several
/// sibling classes in the `ghidra.framework.data` package (`GhidraFolderData`, `RootGhidraFolderData`,
/// `GhidraFileData`, `DomainFileIndex`, `GhidraFile`, ...) hold and call back into a
/// `DefaultProjectData` directly (not merely through the already-ported
/// [`ProjectData`](crate::framework::model::ProjectData) interface), which is what created the
/// cycle. Mapping the concrete class to an object-safe trait lets those sibling ports depend on
/// `Box<dyn DefaultProjectData>`/`&dyn DefaultProjectData` instead of a single concrete
/// implementation.
///
/// This trait extends [`ProjectData`] (the interface the Java class `implements`) and adds the
/// additional public and package-private members that sibling classes in the package call
/// directly on a `DefaultProjectData` receiver -- determined by grepping every `projectData.<call>`
/// site across `GhidraFolderData.java`, `RootGhidraFolderData.java`, `GhidraFileData.java`,
/// `GhidraFile.java`, `DomainFileIndex.java`, and `DomainFileProxy.java`. `ProjectData`-interface
/// overrides (`getFolder`, `getFile`, `getRepository`, `refresh`, `close`, etc.) are inherited from
/// the supertrait and are not redeclared here.
///
/// Not ported here:
/// - The three constructors: construction is implementation-specific and not part of a trait's
///   contract (mirroring how [`PropertyFile`]'s construction is likewise left to implementors).
/// - Private helpers (`init`, `initLock`, `getProjectLock`, `createVersionedFileSystem`,
///   `updatePropertiesFile`, `getVersionedFileSystem(boolean)`, `getRepositoryAdapter`,
///   `getPrivateFileSystem(boolean, boolean)`, `getUserFileSystem(boolean)`,
///   `initVersionedFSListener`, `isOwner`, `getUserName`, `hasInvalidCheckout`,
///   `findInvalidCheckouts`, `undoCheckouts`, `findCheckedOutFiles(String, ...)`,
///   `convertFilesToPrivate`, `scheduleUserDataReconcilation`, `startReconcileUserDataFiles`,
///   `reconcileUserDataFiles`, `decrementInUseCount`, `incrementInUseCount`, `domainObjectClosed`)
///   and the private inner `MyFileSystemListener` class are implementation detail with no
///   cross-class API surface.
/// - `getMaxNameLength`, `testValidName`, `getLocalStorageClass`, and `makeValidName`: these
///   override [`ProjectData`] methods with behavior delegating to the private `fileSystem` field;
///   the override is an implementation detail of a concrete `DefaultProjectData`, not a new trait
///   member (the [`ProjectData`] supertrait already declares the method).
///
/// `DomainObjectAdapter` (the concrete type of the Java `openDomainObjects` map's values and
/// several method parameters) is mapped directly to the already-ported
/// [`DomainObject`](crate::framework::model::DomainObject) trait rather than a new placeholder,
/// following the precedent set by
/// [`DomainObjectAdapterDB`](crate::framework::data::DomainObjectAdapterDB)'s own port: in Java,
/// `DomainObjectAdapter` is an intermediate abstract class that implements `DomainObject` with no
/// additional public surface any caller here needs.
///
/// `RootGhidraFolderData` (the concrete type of the private `rootFolderData` field) is mapped to
/// the already-ported [`GhidraFolderData`] trait rather than a new placeholder: the only
/// `RootGhidraFolderData`-specific member (`mustVisit`) is consulted solely from within the
/// private `MyFileSystemListener` inner class, which is out of scope per the omissions above.
pub trait DefaultProjectData: ProjectData {
    /// Returns the owner of the project associated with this project data. `None` indicates an
    /// old multiuser project.
    fn get_owner(&self) -> Option<String> {
        None
    }

    /// Returns the project directory (the `*.rep` directory).
    fn get_project_dir(&self) -> PathBuf {
        PathBuf::new()
    }

    /// Returns true if this project data has been closed (or is in the process of closing).
    fn is_closed(&self) -> bool {
        false
    }

    /// Returns true if this project data has been fully disposed.
    fn is_disposed(&self) -> bool {
        false
    }

    /// Get the private (non-versioned) local file system.
    fn get_local_file_system(&self) -> Box<dyn LocalFileSystem> {
        Box::new(EmptyLocalFileSystem)
    }

    /// Get the local user data file system, or `None` if this project data was not opened for a
    /// writable project (in which case no user file system is established).
    fn get_user_file_system(&self) -> Option<Box<dyn LocalFileSystem>> {
        None
    }

    /// Get the versioned file system.
    fn get_versioned_file_system(&self) -> Box<dyn FileSystem> {
        Box::new(EmptyFileSystem)
    }

    /// Change the versioned filesystem associated with this project file manager. This method is
    /// provided for testing (see `FakeSharedProject`). Care should be taken when using a
    /// [`LocalFileSystem`] in a shared capacity since locking is not supported.
    ///
    /// # Errors
    /// Returns `Err` (an `IllegalArgumentException`-equivalent) if `fs` is not versioned, or an
    /// IO error occurs while installing the new file system listener.
    fn set_versioned_file_system(&mut self, fs: Box<dyn FileSystem>) -> io::Result<()> {
        if !fs.is_versioned() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "versioned filesystem required"));
        }
        Ok(())
    }

    /// Get the private (non-versioned) file system, exposed as a [`FileSystem`].
    fn get_private_file_system(&self) -> Box<dyn FileSystem> {
        Box::new(EmptyFileSystem)
    }

    /// Get the root folder data for this project.
    fn get_root_folder_data(&self) -> Box<dyn GhidraFolderData> {
        Box::new(EmptyFolderData)
    }

    /// Get monitor which will be cancelled if the project is closed.
    fn get_project_disposal_monitor(&self) -> Box<dyn TaskMonitor> {
        Box::new(DummyMonitor)
    }

    /// Set the open domain object (opened for update) associated with a file. The caller is
    /// responsible for setting the domain file on the domain object after invoking this method.
    ///
    /// # Errors
    /// Returns `Err` if a domain object is already tracked as open for `pathname`.
    fn set_domain_object(
        &mut self,
        pathname: &str,
        doa: Box<dyn DomainObject>,
    ) -> Result<(), String> {
        let _ = (pathname, doa);
        Ok(())
    }

    /// Returns the open domain object (opened for update) for the specified path, or `None` if
    /// not open.
    fn get_opened_domain_object(&self, pathname: &str) -> Option<Box<dyn DomainObject>> {
        let _ = pathname;
        None
    }

    /// Clears the previously open domain object which has been closed, returning true if a
    /// previously open domain file was cleared.
    fn clear_domain_object(&mut self, pathname: &str) -> bool {
        let _ = pathname;
        false
    }

    /// Update the file index for the specified file data.
    fn update_file_index(&mut self, file_data: &dyn GhidraFileDataLike) {
        let _ = file_data;
    }

    /// Remove the specified fileID from the index.
    fn remove_from_index(&mut self, file_id: &str) {
        let _ = file_id;
    }

    /// Signals the start of a complex merge operation. [`Self::merge_ended`] must be invoked
    /// after this call once the merge operation has completed.
    fn merge_started(&mut self) {}

    /// Signals the completion of a complex merge operation (see [`Self::merge_started`]).
    fn merge_ended(&mut self) {}

    /// Signals that a non-link file has been opened as the specified domain object from this
    /// project data store and should be tracked. This delays disposal of this project data until
    /// the specified domain object is either closed or saved to a different project store.
    fn track_domain_file_in_use(&mut self, doa: Box<dyn DomainObject>) {
        let _ = doa;
    }

    /// Releases all open domain files matching the specified consumer.
    fn release_domain_files(&mut self, consumer: DomainObjectConsumer) {
        let _ = consumer;
    }
}

/// Compute the standard user data filename associated with the specified file ID.
///
/// Mirrors the `static` `DefaultProjectData.getUserDataFilename(String)` utility method.
pub fn user_data_filename(associated_file_id: &str) -> String {
    format!("{USER_DATA_FILE_PREFIX}{associated_file_id}")
}

/// Determine if the specified project location currently has a write lock.
///
/// Mirrors the `static` `DefaultProjectData.isLocked(ProjectLocator)` utility method. Since
/// `ProjectLock` (the type the Java method constructs and queries) is not yet ported, this takes
/// an already-constructed lock probe rather than a `ProjectLocator`, deferring construction to
/// the caller; see [`ProjectLockLike`].
pub fn is_locked(lock: &dyn ProjectLockLike) -> bool {
    lock.is_locked()
}

/// Read the contents of an already-opened project properties file, extracting the following
/// values if present: [`OWNER`], [`SERVER_NAME`], [`REPOSITORY_NAME`], [`PORT_NUMBER`]. Returns
/// `None` if the property file does not exist.
///
/// Mirrors the `static` `DefaultProjectData.readProjectProperties(File)` utility method. Since
/// constructing a [`PropertyFile`] from a directory path is implementation-specific (see
/// [`PropertyFile`]'s own port), this takes an already-opened property file rather than a
/// directory path, deferring construction/opening to the caller.
pub fn read_project_properties(pf: &dyn PropertyFile) -> Option<HashMap<String, String>> {
    if !pf.exists() {
        return None;
    }

    let mut properties = HashMap::new();
    if let Some(owner) = pf.get_string(OWNER, None) {
        properties.insert(OWNER.to_string(), owner);
    }

    let server_name = pf.get_string(SERVER_NAME, None);
    let repository_name = pf.get_string(REPOSITORY_NAME, None);
    let port = pf.get_int(PORT_NUMBER, 0);
    if let (Some(server_name), Some(repository_name)) = (server_name, repository_name) {
        properties.insert(SERVER_NAME.to_string(), server_name);
        properties.insert(REPOSITORY_NAME.to_string(), repository_name);
        properties.insert(PORT_NUMBER.to_string(), port.to_string());
    }

    Some(properties)
}

/// Trivial fallback used by [`DefaultProjectData::get_local_file_system`]'s default
/// implementation before a real local file system is available.
struct EmptyLocalFileSystem;
impl LocalFileSystem for EmptyLocalFileSystem {}

/// Trivial fallback used by [`DefaultProjectData::get_root_folder_data`]'s default implementation
/// before a real root folder data instance is available.
struct EmptyFolderData;
impl GhidraFolderData for EmptyFolderData {}

/// Trivial fallback used by [`DefaultProjectData::get_versioned_file_system`] and
/// [`DefaultProjectData::get_private_file_system`]'s default implementations before a real file
/// system is available. Reports itself as offline/read-only and rejects mutation, since
/// [`FileSystem`] declares no default method bodies.
struct EmptyFileSystem;
impl FileSystem for EmptyFileSystem {
    fn get_user_name(&self) -> Option<String> {
        None
    }
    fn is_versioned(&self) -> bool {
        false
    }
    fn is_online(&self) -> bool {
        false
    }
    fn is_read_only(&self) -> io::Result<bool> {
        Ok(true)
    }
    fn get_item_count(&self) -> io::Result<i32> {
        Ok(0)
    }
    fn get_item_names(&self, _folder_path: &str) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn get_items(
        &self,
        _folder_path: &str,
    ) -> io::Result<Vec<Option<Box<dyn crate::framework::store::FolderItem>>>> {
        Ok(Vec::new())
    }
    fn get_item(
        &self,
        _folder_path: &str,
        _name: &str,
    ) -> io::Result<Option<Box<dyn crate::framework::store::FolderItem>>> {
        Ok(None)
    }
    fn get_item_by_file_id(
        &self,
        _file_id: &str,
    ) -> io::Result<Option<Box<dyn crate::framework::store::FolderItem>>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "not available"))
    }
    fn get_folder_names(&self, _folder_path: &str) -> io::Result<Vec<String>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "not available"))
    }
    fn create_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn is_supported_item_type(&self, _folder_item: &dyn crate::framework::store::FolderItem) -> bool {
        false
    }
    fn create_database(
        &mut self,
        _parent_path: &str,
        _name: &str,
        _file_id: Option<&str>,
        _buffer_file: &mut dyn crate::framework::db::buffers::BufferFile,
        _comment: Option<&str>,
        _content_type: &str,
        _reset_database_id: bool,
        _monitor: &dyn TaskMonitor,
        _user: Option<&str>,
    ) -> Result<Box<dyn crate::framework::store::DatabaseItem>, crate::framework::store::FileSystemCreateError>
    {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
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
    ) -> Result<
        Box<dyn crate::framework::db::buffers::ManagedBufferFile>,
        crate::framework::store::FileSystemError,
    > {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn create_data_file(
        &mut self,
        _parent_path: &str,
        _name: &str,
        _istream: &mut dyn io::Read,
        _comment: Option<&str>,
        _content_type: &str,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn crate::framework::store::DataFileItem>, crate::framework::store::FileSystemCreateError>
    {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn create_text_data_item(
        &mut self,
        _parent_path: &str,
        _name: &str,
        _file_id: Option<&str>,
        _content_type: &str,
        _text_data: &str,
        _comment: Option<&str>,
        _user: Option<&str>,
    ) -> Result<Box<dyn crate::framework::store::TextDataItem>, crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn create_file(
        &mut self,
        _parent_path: &str,
        _name: &str,
        _packed_file: &std::path::Path,
        _monitor: &dyn TaskMonitor,
        _user: Option<&str>,
    ) -> Result<Box<dyn crate::framework::store::FolderItem>, crate::framework::store::FileSystemCreateError>
    {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn delete_folder(&mut self, _folder_path: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available"))
    }
    fn move_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
        _new_parent_path: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn rename_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
        _new_folder_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn move_item(
        &mut self,
        _folder_path: &str,
        _name: &str,
        _new_folder_path: &str,
        _new_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not available").into())
    }
    fn add_file_system_listener(&mut self, _listener: Box<dyn crate::framework::store::FileSystemListener>) {
    }
    fn remove_file_system_listener(&mut self, _listener: &dyn crate::framework::store::FileSystemListener) {}
    fn folder_exists(&self, _folder_path: &str) -> io::Result<bool> {
        Ok(false)
    }
    fn file_exists(&self, _folder_path: &str, _name: &str) -> io::Result<bool> {
        Ok(false)
    }
    fn is_shared(&self) -> bool {
        false
    }
    fn dispose(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;

    struct MockOpenDomainObject;
    impl DomainObject for MockOpenDomainObject {}

    #[derive(Default)]
    struct MockProjectData {
        owner: Option<String>,
        closed: bool,
        disposed: bool,
        open_paths: RefCell<HashSet<String>>,
        merge_depth: RefCell<i32>,
    }

    impl ProjectData for MockProjectData {}

    impl DefaultProjectData for MockProjectData {
        fn get_owner(&self) -> Option<String> {
            self.owner.clone()
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn is_disposed(&self) -> bool {
            self.disposed
        }

        fn set_domain_object(
            &mut self,
            pathname: &str,
            _doa: Box<dyn DomainObject>,
        ) -> Result<(), String> {
            if !self.open_paths.borrow_mut().insert(pathname.to_string()) {
                return Err(format!("Attempted to re-open domain object: {pathname}"));
            }
            Ok(())
        }

        fn get_opened_domain_object(&self, pathname: &str) -> Option<Box<dyn DomainObject>> {
            if self.open_paths.borrow().contains(pathname) {
                Some(Box::new(MockOpenDomainObject))
            } else {
                None
            }
        }

        fn clear_domain_object(&mut self, pathname: &str) -> bool {
            self.open_paths.borrow_mut().remove(pathname)
        }

        fn merge_started(&mut self) {
            *self.merge_depth.borrow_mut() += 1;
        }

        fn merge_ended(&mut self) {
            *self.merge_depth.borrow_mut() -= 1;
        }
    }

    #[test]
    fn usable_as_trait_object_and_tracks_open_domain_objects() {
        let mut data = MockProjectData { owner: Some("alice".to_string()), ..Default::default() };
        let dyn_data: &mut dyn DefaultProjectData = &mut data;

        assert_eq!(dyn_data.get_owner(), Some("alice".to_string()));
        assert!(!dyn_data.is_closed());

        assert!(dyn_data.set_domain_object("/a/prog", Box::new(MockOpenDomainObject)).is_ok());
        assert!(dyn_data.get_opened_domain_object("/a/prog").is_some());

        // Re-opening the same path while still tracked is rejected, mirroring the Java
        // RuntimeException thrown by DefaultProjectData.setDomainObject.
        let err = dyn_data.set_domain_object("/a/prog", Box::new(MockOpenDomainObject)).unwrap_err();
        assert!(err.contains("/a/prog"));

        assert!(dyn_data.clear_domain_object("/a/prog"));
        assert!(dyn_data.get_opened_domain_object("/a/prog").is_none());
        // Clearing an already-cleared path reports false, mirroring the Java boolean return.
        assert!(!dyn_data.clear_domain_object("/a/prog"));
    }

    #[test]
    fn merge_started_and_ended_are_paired() {
        let mut data = MockProjectData::default();
        data.merge_started();
        data.merge_started();
        data.merge_ended();
        data.merge_ended();
        assert_eq!(*data.merge_depth.borrow(), 0);
    }

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_an_empty_project() {
        struct BareDefaultProjectData;
        impl ProjectData for BareDefaultProjectData {}
        impl DefaultProjectData for BareDefaultProjectData {}

        let mut data = BareDefaultProjectData;
        assert!(data.get_owner().is_none());
        assert!(!data.is_closed());
        assert!(!data.is_disposed());
        assert!(data.get_user_file_system().is_none());
        assert!(data.get_opened_domain_object("/x").is_none());
        assert!(!data.clear_domain_object("/x"));
        data.merge_started();
        data.merge_ended();
        assert!(data.set_domain_object("/x", Box::new(MockOpenDomainObject)).is_ok());
    }

    #[test]
    fn user_data_filename_adds_prefix() {
        assert_eq!(user_data_filename("abc123"), "udf_abc123");
    }

    struct MockLock {
        locked: bool,
    }
    impl ProjectLockLike for MockLock {
        fn is_locked(&self) -> bool {
            self.locked
        }
    }

    #[test]
    fn is_locked_delegates_to_lock_probe() {
        assert!(is_locked(&MockLock { locked: true }));
        assert!(!is_locked(&MockLock { locked: false }));
    }

    struct MockPropertyFile {
        exists: bool,
        values: HashMap<String, String>,
    }

    impl PropertyFile for MockPropertyFile {
        fn is_read_only(&self) -> bool {
            false
        }
        fn get_parent_storage_directory(&self) -> PathBuf {
            PathBuf::new()
        }
        fn get_storage_name(&self) -> String {
            PROPERTY_FILENAME.to_string()
        }
        fn get_int(&self, property_name: &str, default_value: i32) -> i32 {
            self.values.get(property_name).and_then(|v| v.parse().ok()).unwrap_or(default_value)
        }
        fn put_int(&mut self, property_name: &str, value: i32) {
            self.values.insert(property_name.to_string(), value.to_string());
        }
        fn get_long(&self, _property_name: &str, default_value: i64) -> i64 {
            default_value
        }
        fn put_long(&mut self, _property_name: &str, _value: i64) {}
        fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String> {
            self.values.get(property_name).cloned().or_else(|| default_value.map(str::to_string))
        }
        fn put_string(&mut self, property_name: &str, value: Option<&str>) {
            match value {
                Some(v) => {
                    self.values.insert(property_name.to_string(), v.to_string());
                }
                None => {
                    self.values.remove(property_name);
                }
            }
        }
        fn get_boolean(&self, _property_name: &str, default_value: bool) -> bool {
            default_value
        }
        fn put_boolean(&mut self, _property_name: &str, _value: bool) {}
        fn remove(&mut self, property_name: &str) {
            self.values.remove(property_name);
        }
        fn last_modified(&self) -> i64 {
            0
        }
        fn write_state(&self) -> io::Result<()> {
            Ok(())
        }
        fn read_state(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn move_to(&mut self, _new_storage_parent: &std::path::Path, _new_storage_name: &str) -> io::Result<()> {
            Ok(())
        }
        fn exists(&self) -> bool {
            self.exists
        }
        fn delete(&self) {}
    }

    #[test]
    fn read_project_properties_returns_none_when_missing() {
        let pf = MockPropertyFile { exists: false, values: HashMap::new() };
        assert!(read_project_properties(&pf).is_none());
    }

    #[test]
    fn read_project_properties_extracts_owner_and_repository_fields() {
        let mut values = HashMap::new();
        values.insert(OWNER.to_string(), "bob".to_string());
        values.insert(SERVER_NAME.to_string(), "myserver".to_string());
        values.insert(REPOSITORY_NAME.to_string(), "MyRepo".to_string());
        values.insert(PORT_NUMBER.to_string(), "13100".to_string());
        let pf = MockPropertyFile { exists: true, values };

        let properties = read_project_properties(&pf).unwrap();
        assert_eq!(properties.get(OWNER), Some(&"bob".to_string()));
        assert_eq!(properties.get(SERVER_NAME), Some(&"myserver".to_string()));
        assert_eq!(properties.get(REPOSITORY_NAME), Some(&"MyRepo".to_string()));
        assert_eq!(properties.get(PORT_NUMBER), Some(&"13100".to_string()));
    }

    #[test]
    fn read_project_properties_omits_repository_fields_when_private() {
        let mut values = HashMap::new();
        values.insert(OWNER.to_string(), "carol".to_string());
        let pf = MockPropertyFile { exists: true, values };

        let properties = read_project_properties(&pf).unwrap();
        assert_eq!(properties.get(OWNER), Some(&"carol".to_string()));
        assert!(!properties.contains_key(SERVER_NAME));
    }
}
