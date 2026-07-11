use std::cmp::Ordering;
use std::io;
use std::path::Path;

use thiserror::Error;

use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_object::DomainObject;
use crate::framework::model::project_data::ProjectData;
use crate::framework::seam_stubs::{LinkHandler, ProjectLocator};
use crate::framework::store::FolderNotEmptyException;
use crate::util::exception::{
    CancelledException, DuplicateFileException, FileInUseException, InvalidNameException,
};
use crate::util::task::TaskMonitor;

/// Theme icon key for the icon shown for an open domain folder.
///
/// Stands in for `DomainFolder.OPEN_FOLDER_ICON`, which is a `new GIcon(..)` instance rather than
/// a plain constant.
pub const OPEN_FOLDER_ICON_ID: &str = "icon.datatree.node.domain.folder.open";

/// Theme icon key for the icon shown for a closed domain folder.
///
/// Stands in for `DomainFolder.CLOSED_FOLDER_ICON`, which is a `new GIcon(..)` instance rather
/// than a plain constant.
pub const CLOSED_FOLDER_ICON_ID: &str = "icon.datatree.node.domain.folder.closed";

/// Character used to separate folder and item names within a path string.
///
/// Port of `DomainFolder.SEPARATOR`.
pub const SEPARATOR: &str = "/";

/// Name extension to add when attempting to avoid a duplicate name.
///
/// Port of `DomainFolder.COPY_SUFFIX`.
pub const COPY_SUFFIX: &str = ".copy";

/// Combines the checked exceptions declared on `DomainFolder.setName(String)`.
#[derive(Error, Debug)]
pub enum SetNameError {
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    FileInUse(#[from] FileInUseException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFolder.createFile(String, DomainObject,
/// TaskMonitor)` and `DomainFolder.createFile(String, File, TaskMonitor)`.
#[derive(Error, Debug)]
pub enum CreateFileError {
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions declared on `DomainFolder.createFolder(String)`.
#[derive(Error, Debug)]
pub enum CreateFolderError {
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFolder.delete()`.
#[derive(Error, Debug)]
pub enum DeleteError {
    #[error(transparent)]
    FolderNotEmpty(#[from] FolderNotEmptyException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFolder.moveTo(DomainFolder)`.
#[derive(Error, Debug)]
pub enum MoveError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    FileInUse(#[from] FileInUseException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFolder.copyTo(DomainFolder, TaskMonitor)`.
#[derive(Error, Debug)]
pub enum CopyError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// `DomainFolder` provides a storage interface for a project folder. A domain folder is an
/// immutable reference to a folder contained within a project. Provided the corresponding path
/// exists within the project it may continue to be used to create and access its files and
/// sub-folders. The state of a folder object does not track name/parent changes made to the
/// referenced project file.
///
/// Port of `ghidra.framework.model.DomainFolder`.
///
/// This trait was promoted from a minimal placeholder (see
/// [`seam_stubs`](crate::framework::seam_stubs)) that declared no methods, so there is nothing to
/// retain as a superset here. Every method is given a default so that existing bare
/// `impl DomainFolder for MockX {}` blocks keep compiling unmodified. The defaults describe a
/// non-existent, empty "proxy" folder, mirroring the style used for
/// [`DomainFile`]'s defaults (e.g. `DomainFileProxy`).
///
/// The Java interface extends `Comparable<DomainFolder>`;
/// [`compare_to`](DomainFolder::compare_to) stands in for that so the trait remains object-safe
/// (`dyn DomainFolder` cannot itself implement `Ord`/`PartialOrd`, which require `Sized`).
pub trait DomainFolder {
    /// Return this folder's name.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Set the name on this domain folder, returning the renamed domain folder (the original
    /// `DomainFolder` object becomes invalid since it is immutable).
    ///
    /// # Errors
    /// Returns `Err` if `new_name` contains illegal characters, a folder named `new_name` already
    /// exists in this folder's domain folder, a file within this folder or its descendants is
    /// in-use/checked-out, or an IO/access error occurs.
    fn set_name(&mut self, new_name: &str) -> Result<Box<dyn DomainFolder>, SetNameError> {
        let _ = new_name;
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Returns the local storage location for the project that this `DomainFolder` belongs to.
    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        Box::new(UnknownProjectLocator)
    }

    /// Returns the project data.
    fn get_project_data(&self) -> Box<dyn ProjectData> {
        Box::new(UnknownProjectData)
    }

    /// Returns the full path name to this folder.
    fn get_pathname(&self) -> String {
        String::new()
    }

    /// Returns true if the given folder is the same as this folder based on path and underlying
    /// project/repository.
    fn is_same(&self, folder: &dyn DomainFolder) -> bool {
        let _ = folder;
        false
    }

    /// Returns true if the given folder is the same or a child of this folder or one of its
    /// descendants based on path and underlying project/repository.
    fn is_same_or_ancestor(&self, folder: &dyn DomainFolder) -> bool {
        let _ = folder;
        false
    }

    /// Get a remote Ghidra URL for this domain folder if available within an associated shared
    /// project repository, or `None` if the shared folder does not exist, the repository is not
    /// connected, or a connection error occurs.
    fn get_shared_project_url(&self) -> Option<String> {
        None
    }

    /// Get a local Ghidra URL for this domain folder if available within the associated
    /// non-transient local project, or `None` if the project is transient.
    fn get_local_project_url(&self) -> Option<String> {
        None
    }

    /// Returns true if this folder is in a writable project.
    fn is_in_writable_project(&self) -> bool {
        false
    }

    /// Return parent folder or `None` if this `DomainFolder` is the root folder.
    fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
        None
    }

    /// Get sub-folders in this folder. This may return cached information and does not force a
    /// full refresh.
    fn get_folders(&self) -> Vec<Box<dyn DomainFolder>> {
        Vec::new()
    }

    /// Return the folder for the given name, or `None` if there is no folder by the given name.
    /// Folder link-files are ignored.
    fn get_folder(&self, name: &str) -> Option<Box<dyn DomainFolder>> {
        let _ = name;
        None
    }

    /// Get the domain file in this folder with the given name, or `None` if there is no domain
    /// file in this folder with the given name.
    fn get_file(&self, name: &str) -> Option<Box<dyn DomainFile>> {
        let _ = name;
        None
    }

    /// Determine if this folder contains any sub-folders or domain files.
    fn is_empty(&self) -> bool {
        true
    }

    /// Get all domain files in this folder. This may return cached information and does not
    /// force a full refresh.
    fn get_files(&self) -> Vec<Box<dyn DomainFile>> {
        Vec::new()
    }

    /// Add a domain object to this folder, returning the domain file created as a result.
    ///
    /// # Errors
    /// Returns `Err` if the file name already exists, `name` is an empty string or contains
    /// characters other than alphanumerics, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn create_file(
        &mut self,
        name: &str,
        obj: &dyn DomainObject,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, CreateFileError> {
        let _ = (name, obj, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Add a new domain file to this folder from a packed file, returning the domain file created
    /// as a result.
    ///
    /// # Errors
    /// Returns `Err` if the file name already exists, `name` is an empty string or contains
    /// characters other than alphanumerics, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn create_packed_file(
        &mut self,
        name: &str,
        pack_file: &Path,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, CreateFileError> {
        let _ = (name, pack_file, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Create a link-file within this folder which references the specified file or folder
    /// `pathname` within the project specified by `source_project_data`.
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
    ) -> io::Result<Box<dyn DomainFile>> {
        let _ = (source_project_data, pathname, make_relative, link_filename, lh);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Create an external link-file within this folder which references the specified
    /// `ghidra_url` and whose content is defined by the specified [`LinkHandler`] instance.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs during link creation.
    fn create_external_link_file(
        &mut self,
        ghidra_url: &str,
        link_filename: &str,
        lh: &dyn LinkHandler,
    ) -> io::Result<Box<dyn DomainFile>> {
        let _ = (ghidra_url, link_filename, lh);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Create a subfolder within this folder.
    ///
    /// # Errors
    /// Returns `Err` if a folder by this name already exists, `folder_name` is an empty string or
    /// contains characters other than alphanumerics, or an IO or access error occurs.
    fn create_folder(&mut self, folder_name: &str) -> Result<Box<dyn DomainFolder>, CreateFolderError> {
        let _ = folder_name;
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Deletes this folder, if empty, from the local filesystem.
    ///
    /// # Errors
    /// Returns `Err` if this folder is not empty, or an IO or access error occurs.
    fn delete(&mut self) -> Result<(), DeleteError> {
        Ok(())
    }

    /// Move this folder into `new_parent`, returning the newly relocated folder (the original
    /// `DomainFolder` object becomes invalid since it is immutable).
    ///
    /// # Errors
    /// Returns `Err` if a folder with the same name already exists in `new_parent`, this folder
    /// or one of its descendants contains a file which is in-use/checked-out, or an IO or access
    /// error occurs.
    fn move_to(&mut self, new_parent: &dyn DomainFolder) -> Result<Box<dyn DomainFolder>, MoveError> {
        let _ = new_parent;
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Copy this folder into `new_parent`.
    ///
    /// # Errors
    /// Returns `Err` if a folder or file by this name already exists in `new_parent`, an IO or
    /// access error occurs, or `monitor` reports cancellation.
    fn copy_to(
        &self,
        new_parent: &dyn DomainFolder,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFolder>, CopyError> {
        let _ = (new_parent, monitor);
        Ok(Box::new(ProxyDomainFolder))
    }

    /// Copy this folder into `new_parent` as a folder-link, returning the newly created domain
    /// file which is a folder-link (i.e., link-file).
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn copy_to_as_link(
        &self,
        new_parent: &dyn DomainFolder,
        relative: bool,
    ) -> io::Result<Box<dyn DomainFile>> {
        let _ = (new_parent, relative);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Allows the framework to react to a request to make this folder the "active" one.
    fn set_active(&mut self) {}

    /// Determine if this folder corresponds to a linked-folder which directly corresponds to a
    /// folder-link file.
    fn is_linked(&self) -> bool {
        false
    }

    /// Compares this domain folder to another. Stands in for the Java `Comparable<DomainFolder>`
    /// contract.
    fn compare_to(&self, other: &dyn DomainFolder) -> Ordering {
        self.get_pathname().cmp(&other.get_pathname())
    }
}

/// Trivial fallback used by several [`DomainFolder`] default implementations that must fabricate
/// a new `DomainFolder` (e.g. [`DomainFolder::set_name`], [`DomainFolder::move_to`]): an empty
/// proxy folder.
struct ProxyDomainFolder;
impl DomainFolder for ProxyDomainFolder {}

/// Trivial fallback used by several [`DomainFolder`] default implementations that must fabricate
/// a new `DomainFile` (e.g. [`DomainFolder::create_file`], [`DomainFolder::copy_to_as_link`]).
struct ProxyDomainFile;
impl DomainFile for ProxyDomainFile {}

/// Trivial fallback used by [`DomainFolder::get_project_locator`] before a real project location
/// is available.
struct UnknownProjectLocator;
impl ProjectLocator for UnknownProjectLocator {}

/// Trivial fallback used by [`DomainFolder::get_project_data`] before a real project data
/// instance is available.
struct UnknownProjectData;
impl ProjectData for UnknownProjectData {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDomainFolder {
        name: String,
        pathname: String,
    }

    impl DomainFolder for MockDomainFolder {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn is_same(&self, folder: &dyn DomainFolder) -> bool {
            self.get_pathname() == folder.get_pathname()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let folder = MockDomainFolder { name: "a".to_string(), pathname: "/a".to_string() };
        let dyn_folder: &dyn DomainFolder = &folder;
        assert_eq!(dyn_folder.get_name(), "a");
        assert_eq!(dyn_folder.get_pathname(), "/a");
        assert!(dyn_folder.is_empty());
        assert!(!dyn_folder.is_linked());
    }

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_a_proxy() {
        struct BareDomainFolder;
        impl DomainFolder for BareDomainFolder {}

        let folder = BareDomainFolder;
        assert!(folder.is_empty());
        assert!(folder.get_folders().is_empty());
        assert!(folder.get_files().is_empty());
        assert!(folder.get_parent().is_none());
    }

    #[test]
    fn compare_to_orders_by_pathname() {
        let a = MockDomainFolder { name: "a".to_string(), pathname: "/a".to_string() };
        let b = MockDomainFolder { name: "b".to_string(), pathname: "/b".to_string() };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }

    #[test]
    fn is_same_uses_pathname_when_overridden() {
        let a = MockDomainFolder { name: "a".to_string(), pathname: "/x/a".to_string() };
        let b = MockDomainFolder { name: "a".to_string(), pathname: "/x/a".to_string() };
        assert!(a.is_same(&b));
    }

    #[test]
    fn set_name_default_returns_proxy_folder() {
        let mut folder = MockDomainFolder { name: "old".to_string(), pathname: "/old".to_string() };
        let renamed = folder.set_name("new").unwrap();
        assert!(renamed.is_empty());
    }
}
