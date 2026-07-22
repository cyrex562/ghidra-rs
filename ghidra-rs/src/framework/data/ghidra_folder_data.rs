use std::io;
use std::path::Path;

use crate::framework::model::domain_folder::{
    CopyError, CreateFileError, CreateFolderError, DeleteError, MoveError, SetNameError,
};
use crate::framework::model::{
    DomainFile, DomainFolder, DomainFolderChangeListener, DomainObject, ProjectData,
};
use crate::framework::seam_stubs::{GhidraFileDataLike, LinkHandler, ProjectLocator};
use crate::framework::store::local::LocalFileSystem;
use crate::framework::store::{FileSystem, SEPARATOR};
use crate::util::task::TaskMonitor;

/// `GhidraFolderData` provides the managed object which represents a project folder that
/// corresponds to matched folder paths across both a versioned and private filesystem and viewed
/// as a single folder at the project level.
///
/// Port of `ghidra.framework.data.GhidraFolderData`.
///
/// The Java class is package-private and closely mirrors the already-ported
/// [`DomainFolder`] interface -- this port follows the same style: an object-safe trait with
/// trivial defaults so mock implementations (and the placeholder proxy used by several defaults
/// below) compile without overriding every method. Only the non-`private` members of the Java
/// class are exposed here; its two constructors and private helpers (`checkFolderLinkConflict`,
/// `checkInUse`, `updateExistenceState`, `refreshFiles`, `refreshFolders`, `addFileData`,
/// `addFolderData`, `fileRemoved`, `folderRemoved`, `itemMapOf`, `getUniqueName`) are
/// implementation detail with no cross-class API surface and are therefore omitted.
///
/// Java's `GhidraFolder`/`GhidraFile` (returned by several methods here) implement the
/// already-ported [`DomainFolder`]/[`DomainFile`] interfaces respectively, so this port returns
/// those trait objects directly rather than introducing new placeholder types for them. Likewise
/// `DefaultProjectData` (the concrete type of the Java `projectData` field) implements the
/// already-ported [`ProjectData`] interface, so [`get_project_data`](Self::get_project_data)
/// returns `Box<dyn ProjectData>`. `GhidraFileData` has no already-ported interface to reuse, so
/// it gets a minimal marker placeholder,
/// [`GhidraFileDataLike`](crate::framework::seam_stubs::GhidraFileDataLike) (see `STUBS.tsv`).
///
/// `RootGhidraFolderData` (a subclass adding `mustVisit(String)`) is not exposed anywhere in this
/// trait's public surface -- it is only consulted from within the private body of
/// [`must_visit`](Self::must_visit) -- so no placeholder is needed for it either.
pub trait GhidraFolderData {
    /// Returns true if folder has complete list of children.
    fn visited(&self) -> bool {
        false
    }

    /// Returns true if this folder must be visited when created to ensure that related change
    /// notifications are properly conveyed.
    fn must_visit(&self) -> bool {
        false
    }

    /// Get the local file system.
    fn get_local_file_system(&self) -> Box<dyn LocalFileSystem> {
        Box::new(NoLocalFileSystem)
    }

    /// Get the versioned file system.
    fn get_versioned_file_system(&self) -> Box<dyn FileSystem> {
        Box::new(NoVersionedFileSystem)
    }

    /// Get the local user data file system.
    fn get_user_file_system(&self) -> Box<dyn LocalFileSystem> {
        Box::new(NoLocalFileSystem)
    }

    /// Get the folder change listener.
    fn get_change_listener(&self) -> Box<dyn DomainFolderChangeListener> {
        Box::new(NoOpChangeListener)
    }

    /// Get the project data instance.
    fn get_project_data(&self) -> Box<dyn ProjectData> {
        Box::new(NoProjectData)
    }

    /// Get the project locator which identifies the system storage area for the local file
    /// system and other project related resources.
    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        Box::new(NoProjectLocator)
    }

    /// Returns this folder's parent folder data, or `None` if this is the root folder.
    fn get_parent_data(&self) -> Option<Box<dyn GhidraFolderData>> {
        None
    }

    /// Get folder data for specified absolute or relative `folder_path`. If `lazy` is true, the
    /// folder will not be searched for if not already discovered -- in that case `None` will be
    /// returned.
    fn get_folder_path_data(
        &self,
        folder_path: &str,
        lazy: bool,
    ) -> Option<Box<dyn GhidraFolderData>> {
        let _ = (folder_path, lazy);
        None
    }

    /// This folder's name. The root folder will return the project or repository name.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Set the name on this domain folder.
    ///
    /// # Errors
    /// Returns `Err` if `new_name` contains illegal characters, a folder or folder-link named
    /// `new_name` already exists in this folder, a file within this folder or its descendants is
    /// in-use/checked-out, or an IO/access error occurs.
    fn set_name(&mut self, new_name: &str) -> Result<Box<dyn DomainFolder>, SetNameError> {
        let _ = new_name;
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Returns the full pathname of the given child of this folder.
    fn get_child_pathname(&self, child_name: &str) -> String {
        let mut path = self.get_pathname();
        if path.len() != SEPARATOR.len() {
            path.push_str(SEPARATOR);
        }
        path.push_str(child_name);
        path
    }

    /// Returns the full path name to this folder.
    fn get_pathname(&self) -> String {
        SEPARATOR.to_string()
    }

    /// Determine if this folder contains any sub-folders or domain files.
    fn is_empty(&self) -> bool {
        true
    }

    /// Get the list of names for all files contained within this folder.
    fn get_file_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get the list of names for all subfolders contained within this folder.
    fn get_folder_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Update file list/cache based upon rename of a file. If this folder has been visited the
    /// listener will be notified with the rename.
    fn file_renamed(&mut self, old_file_name: &str, new_file_name: &str) {
        let _ = (old_file_name, new_file_name);
    }

    /// Update file list/cache based upon change of parent for a file. If this folder or
    /// `new_parent` has been visited the listener will be notified with add/move details.
    fn file_moved(
        &mut self,
        new_parent: &mut dyn GhidraFolderData,
        old_file_name: &str,
        new_file_name: &str,
    ) {
        let _ = (new_parent, old_file_name, new_file_name);
    }

    /// Notification that the specified file has changed due to an add or remove of the
    /// underlying local or versioned file. If this folder has been visited an appropriate
    /// add/remove/change notification will be provided to the listener.
    fn file_changed(&mut self, file_name: &str) {
        let _ = file_name;
    }

    /// Notification that the specified subfolder has changed due to an add or remove of the
    /// underlying local or version folder.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during the associated refresh.
    fn folder_changed(&mut self, folder_name: &str) -> io::Result<()> {
        let _ = folder_name;
        Ok(())
    }

    /// Disposes the cached data for this folder and all of its children recursively.
    fn dispose(&mut self) {}

    /// Full refresh of names of children is performed. `recursive` recurses into visited
    /// subfolders (only valid combined with `force`). `force` performs the refresh regardless of
    /// visited state. `monitor`, if given, may cancel a recursive refresh.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during the refresh.
    fn refresh(
        &mut self,
        recursive: bool,
        force: bool,
        monitor: Option<&dyn TaskMonitor>,
    ) -> io::Result<()> {
        let _ = (recursive, force, monitor);
        Ok(())
    }

    /// Check for existence of subfolder.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs when checking for the folder's existence.
    fn contains_folder(&self, folder_name: &str) -> io::Result<bool> {
        let _ = folder_name;
        Ok(false)
    }

    /// Get folder data for child folder specified by `folder_name`. If `lazy` is true, the folder
    /// will not be searched for if not already discovered -- in that case `None` will be
    /// returned.
    fn get_folder_data(&self, folder_name: &str, lazy: bool) -> Option<Box<dyn GhidraFolderData>> {
        let _ = (folder_name, lazy);
        None
    }

    /// Check for existence of file.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs while checking for the file's existence.
    fn contains_file(&self, file_name: &str) -> io::Result<bool> {
        let _ = file_name;
        Ok(false)
    }

    /// Get file data for child specified by `file_name`. If `lazy` is true, the file will not be
    /// searched for if not already discovered -- in that case `None` will be returned.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs while checking for the file's existence.
    fn get_file_data(
        &self,
        file_name: &str,
        lazy: bool,
    ) -> io::Result<Option<Box<dyn GhidraFileDataLike>>> {
        let _ = (file_name, lazy);
        Ok(None)
    }

    /// Get the domain file in this folder with the given `file_name`, or `None` if there is no
    /// file in this folder with the given name.
    fn get_domain_file(&self, file_name: &str) -> Option<Box<dyn DomainFile>> {
        let _ = file_name;
        None
    }

    /// Get the domain folder in this folder with the given `subfolder_name`, or `None` if there
    /// is no subfolder in this folder with the given name.
    fn get_domain_subfolder(&self, subfolder_name: &str) -> Option<Box<dyn DomainFolder>> {
        let _ = subfolder_name;
        None
    }

    /// A [`DomainFolder`] instance which corresponds to this folder.
    fn get_domain_folder(&self) -> Box<dyn DomainFolder> {
        Box::new(ProxyDomainFolder)
    }

    /// Add a domain object to this folder, returning the domain file created as a result.
    ///
    /// # Errors
    /// Returns `Err` if `file_name` already exists, `file_name` is an empty string or contains
    /// characters other than alphanumerics, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn create_file(
        &mut self,
        file_name: &str,
        obj: &mut dyn DomainObject,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, CreateFileError> {
        let _ = (file_name, obj, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Add a new domain file to this folder from a packed file, returning the domain file created
    /// as a result.
    ///
    /// # Errors
    /// Returns `Err` if `file_name` already exists, `file_name` is an empty string or contains
    /// characters other than alphanumerics, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn create_file_from_packed(
        &mut self,
        file_name: &str,
        pack_file: &Path,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, CreateFileError> {
        let _ = (file_name, pack_file, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Create a subfolder within this folder.
    ///
    /// # Errors
    /// Returns `Err` if a folder or folder-link with this name already exists, `folder_name` is
    /// an empty string or contains characters other than alphanumerics, or an IO or access error
    /// occurs.
    fn create_folder(
        &mut self,
        folder_name: &str,
    ) -> Result<Box<dyn GhidraFolderData>, CreateFolderError> {
        let _ = folder_name;
        Ok(Box::new(ProxyGhidraFolderData))
    }

    /// Deletes this folder, if empty, from the local filesystem.
    ///
    /// # Errors
    /// Returns `Err` if the folder is not empty, or an IO or access error occurs.
    fn delete(&mut self) -> Result<(), DeleteError> {
        Ok(())
    }

    /// Delete this folder from the local filesystem if empty.
    fn delete_local_folder_if_empty(&mut self) {}

    /// Move this folder into `new_parent`, returning the newly relocated folder (the original
    /// domain folder object becomes invalid since it is immutable).
    ///
    /// # Errors
    /// Returns `Err` if a folder with the same name already exists in `new_parent`, this folder
    /// or one of its descendants contains a file which is in-use/checked-out, or an IO or access
    /// error occurs.
    fn move_to(
        &mut self,
        new_parent: &mut dyn GhidraFolderData,
    ) -> Result<Box<dyn DomainFolder>, MoveError> {
        let _ = new_parent;
        Ok(Box::new(ProxyDomainFolder))
    }

    /// True if `folder_data` is an ancestor of this folder (i.e., parent, grand-parent, etc.).
    fn is_ancestor(&self, folder_data: &dyn GhidraFolderData) -> bool {
        let _ = folder_data;
        false
    }

    /// True if `folder_data` is associated with the same project or repository as this folder.
    fn has_same_project_or_repository(&self, folder_data: &dyn GhidraFolderData) -> bool {
        let _ = folder_data;
        false
    }

    /// True if `folder_data` is considered the same as this folder.
    fn is_same(&self, folder_data: &dyn GhidraFolderData) -> bool {
        let _ = folder_data;
        false
    }

    /// Copy this folder into `new_parent`.
    ///
    /// # Errors
    /// Returns `Err` if a folder or file by this name already exists in `new_parent`, an IO or
    /// access error occurs, or `monitor` reports cancellation.
    fn copy_to(
        &self,
        new_parent: &mut dyn GhidraFolderData,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFolder>, CopyError> {
        let _ = (new_parent, monitor);
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Create a new link-file in `new_parent` which references this folder (i.e., a
    /// linked-folder).
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn copy_to_as_link(
        &self,
        new_parent: &mut dyn GhidraFolderData,
        relative: bool,
    ) -> io::Result<Box<dyn DomainFile>> {
        let _ = (new_parent, relative);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Create a link-file within this folder which references the specified file or folder
    /// `pathname` within the project specified by `source_project_data`. Returns `None` in the
    /// one case where local internal linking is not supported (mirroring the Java method's
    /// documented `null` return in that case).
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during link creation.
    fn create_link_file(
        &mut self,
        source_project_data: &dyn ProjectData,
        pathname: &str,
        make_relative: bool,
        link_filename: &str,
        lh: &dyn LinkHandler,
    ) -> io::Result<Option<Box<dyn DomainFile>>> {
        let _ = (source_project_data, pathname, make_relative, link_filename, lh);
        Ok(Some(Box::new(ProxyDomainFile)))
    }

    /// Create an external link-file within this folder which references the specified
    /// `ghidra_url` and whose content is defined by the specified [`LinkHandler`] instance.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during link creation.
    fn create_link_file_from_url(
        &mut self,
        ghidra_url: &str,
        link_filename: &str,
        lh: &dyn LinkHandler,
    ) -> io::Result<Box<dyn DomainFile>> {
        let _ = (ghidra_url, link_filename, lh);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Generate a non-conflicting file name for this destination folder based upon the specified
    /// preferred name.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during file checks.
    fn get_unique_file_name(
        &self,
        preferred_name: &str,
        check_files_and_folders: bool,
    ) -> io::Result<String> {
        let _ = check_files_and_folders;
        Ok(preferred_name.to_string())
    }

    /// Used for testing: true if this folder exists in the private filesystem.
    fn private_exists(&self) -> bool {
        false
    }

    /// Used for testing: true if this folder exists in the shared (versioned) filesystem.
    fn shared_exists(&self) -> bool {
        false
    }
}

/// Compute a relative path from `link_parent_pathname` (an absolute Ghidra folder pathname, the
/// origin of the returned relative path) to `normalized_referenced_pathname` (an absolute
/// normalized folder/file reference path).
///
/// Port of the `static` `GhidraFolderData.getRelativePath(String, String, boolean)` utility
/// method. Unlike the rest of this port, this function carries real logic rather than a trivial
/// default: it depends on no unported type, and is a pure string computation over `/`-separated
/// paths (mirroring `java.nio.file.Path.relativize`, which the original delegates to).
pub fn get_relative_path(
    normalized_referenced_pathname: &str,
    link_parent_pathname: &str,
    is_folder_ref: bool,
) -> String {
    let original_referenced_pathname = normalized_referenced_pathname;
    let mut referenced_pathname = normalized_referenced_pathname.to_string();

    let mut final_ref_element: Option<String> = None;
    if !is_folder_ref && !referenced_pathname.ends_with(SEPARATOR) {
        if let Some(last_sep_ix) = referenced_pathname.rfind(SEPARATOR) {
            if last_sep_ix != 0 {
                final_ref_element = Some(referenced_pathname[last_sep_ix + 1..].to_string());
                referenced_pathname.truncate(last_sep_ix);
            }
        }
    }

    let referenced_components: Vec<&str> =
        referenced_pathname.split(SEPARATOR).filter(|s| !s.is_empty()).collect();
    let parent_components: Vec<&str> =
        link_parent_pathname.split(SEPARATOR).filter(|s| !s.is_empty()).collect();

    let common_len = referenced_components
        .iter()
        .zip(parent_components.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut segments: Vec<&str> = Vec::with_capacity(
        (parent_components.len() - common_len) + (referenced_components.len() - common_len),
    );
    for _ in common_len..parent_components.len() {
        segments.push("..");
    }
    segments.extend_from_slice(&referenced_components[common_len..]);

    let mut path = segments.join(SEPARATOR);

    if let Some(final_element) = final_ref_element {
        if !path.is_empty() {
            path.push_str(SEPARATOR);
        }
        path.push_str(&final_element);
    }

    if path.is_empty() {
        return ".".to_string();
    }

    if original_referenced_pathname.ends_with(SEPARATOR) && !path.ends_with(SEPARATOR) {
        path.push_str(SEPARATOR);
    }

    path
}

/// Trivial fallback used by [`GhidraFolderData::get_local_file_system`] and
/// [`GhidraFolderData::get_user_file_system`]'s default implementations before a real file system
/// is available.
struct NoLocalFileSystem;
impl LocalFileSystem for NoLocalFileSystem {}

/// Trivial fallback used by [`GhidraFolderData::get_versioned_file_system`]'s default
/// implementation before a real file system is available. Reports itself as offline (mirroring an
/// unconnected repository), since [`FileSystem`] declares no default method bodies.
struct NoVersionedFileSystem;
impl FileSystem for NoVersionedFileSystem {
    fn get_user_name(&self) -> Option<String> {
        None
    }
    fn is_versioned(&self) -> bool {
        true
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
        Err(io::Error::new(io::ErrorKind::Unsupported, "not connected"))
    }
    fn get_folder_names(&self, _folder_path: &str) -> io::Result<Vec<String>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "not connected"))
    }
    fn create_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
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
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
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
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
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
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
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
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
    }
    fn create_file(
        &mut self,
        _parent_path: &str,
        _name: &str,
        _packed_file: &Path,
        _monitor: &dyn TaskMonitor,
        _user: Option<&str>,
    ) -> Result<Box<dyn crate::framework::store::FolderItem>, crate::framework::store::FileSystemCreateError>
    {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
    }
    fn delete_folder(&mut self, _folder_path: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected"))
    }
    fn move_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
        _new_parent_path: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
    }
    fn rename_folder(
        &mut self,
        _parent_path: &str,
        _folder_name: &str,
        _new_folder_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
    }
    fn move_item(
        &mut self,
        _folder_path: &str,
        _name: &str,
        _new_folder_path: &str,
        _new_name: &str,
    ) -> Result<(), crate::framework::store::FileSystemError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "not connected").into())
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
        true
    }
    fn dispose(&mut self) {}
}

/// Trivial fallback used by [`GhidraFolderData::get_change_listener`]'s default implementation.
struct NoOpChangeListener;
impl DomainFolderChangeListener for NoOpChangeListener {}

/// Trivial fallback used by [`GhidraFolderData::get_project_data`]'s default implementation
/// before a real project data instance is available.
struct NoProjectData;
impl ProjectData for NoProjectData {}

/// Trivial fallback used by [`GhidraFolderData::get_project_locator`]'s default implementation
/// before a real project location is available.
struct NoProjectLocator;
impl ProjectLocator for NoProjectLocator {}

/// Trivial fallback used by several [`GhidraFolderData`] default implementations that must
/// fabricate a new [`DomainFolder`]: an empty proxy folder.
struct ProxyDomainFolder;
impl DomainFolder for ProxyDomainFolder {}

/// Trivial fallback used by several [`GhidraFolderData`] default implementations that must
/// fabricate a new [`DomainFile`]: an empty proxy file.
struct ProxyDomainFile;
impl DomainFile for ProxyDomainFile {}

/// Trivial fallback used by [`GhidraFolderData::create_folder`]'s default implementation: an
/// empty proxy folder-data.
struct ProxyGhidraFolderData;
impl GhidraFolderData for ProxyGhidraFolderData {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockGhidraFolderData {
        name: String,
        pathname: String,
        folder_names: Vec<String>,
    }

    impl GhidraFolderData for MockGhidraFolderData {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn get_folder_names(&self) -> Vec<String> {
            self.folder_names.clone()
        }

        fn is_empty(&self) -> bool {
            self.folder_names.is_empty()
        }

        fn contains_folder(&self, folder_name: &str) -> io::Result<bool> {
            Ok(self.folder_names.iter().any(|f| f == folder_name))
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let data = MockGhidraFolderData {
            name: "sub".to_string(),
            pathname: "/a/sub".to_string(),
            folder_names: vec!["child".to_string()],
        };
        let dyn_data: &dyn GhidraFolderData = &data;
        assert_eq!(dyn_data.get_name(), "sub");
        assert_eq!(dyn_data.get_pathname(), "/a/sub");
        assert!(!dyn_data.is_empty());
        assert!(dyn_data.contains_folder("child").unwrap());
        assert!(!dyn_data.contains_folder("missing").unwrap());
    }

    #[test]
    fn get_child_pathname_appends_separator_for_non_root() {
        let data = MockGhidraFolderData { pathname: "/a/sub".to_string(), ..Default::default() };
        assert_eq!(data.get_child_pathname("child"), "/a/sub/child");
    }

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_an_empty_folder() {
        struct BareGhidraFolderData;
        impl GhidraFolderData for BareGhidraFolderData {}

        let mut data = BareGhidraFolderData;
        assert!(data.is_empty());
        assert!(data.get_file_names().is_empty());
        assert!(data.get_folder_data("x", true).is_none());
        assert!(data.get_file_data("x", true).unwrap().is_none());
        assert!(data.delete().is_ok());
        data.dispose();
    }

    #[test]
    fn get_relative_path_same_folder_returns_dot() {
        assert_eq!(get_relative_path("/a/b", "/a/b", true), ".");
    }

    #[test]
    fn get_relative_path_sibling_file() {
        // referencing a file "/a/c" from a link stored in folder "/a/b"
        assert_eq!(get_relative_path("/a/c", "/a/b", false), "../c");
    }

    #[test]
    fn get_relative_path_descendant_folder() {
        assert_eq!(get_relative_path("/a/b/c/", "/a/b", true), "c/");
    }

    #[test]
    fn get_relative_path_ancestor_folder() {
        assert_eq!(get_relative_path("/a/", "/a/b/c", true), "../../");
    }
}
