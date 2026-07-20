use std::any::TypeId;
use std::io;

use thiserror::Error;

use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_file_filter::DomainFileFilter;
use crate::framework::model::domain_folder::DomainFolder;
use crate::framework::model::domain_folder_change_listener::DomainFolderChangeListener;
use crate::framework::model::domain_folder_filter::DomainFolderFilter;
use crate::framework::remote::User;
use crate::framework::seam_stubs::{ProjectLocator, RepositoryAdapter};
use crate::framework::store::local::LocalFileSystem;
use crate::util::exception::{CancelledException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on several `ProjectData` methods
/// (`findCheckedOutFiles`, `hasInvalidCheckouts`, `convertProjectToShared`,
/// `updateRepositoryInfo`), all of which declare only `IOException` and `CancelledException`.
#[derive(Error, Debug)]
pub enum IoCancelledError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// The `ProjectData` trait provides access to all the data files and folders in a project.
///
/// Port of `ghidra.framework.model.ProjectData`.
///
/// This trait was promoted from a minimal placeholder (see
/// [`seam_stubs`](crate::framework::seam_stubs)) that declared no methods, so there is nothing to
/// retain as a superset here. Every method is given a default so that existing bare
/// `impl ProjectData for MockX {}` blocks (e.g.
/// [`DomainFolder::get_project_data`](crate::framework::model::DomainFolder::get_project_data)'s
/// default) keep compiling unmodified. The defaults describe a non-existent, empty project.
///
/// The Java interface's two `getFolder`/`getFile` overloads (unfiltered and filtered) become
/// distinct `_with_filter` methods since Rust has no method overloading.
///
/// The Java interface extends `Iterable<DomainFile>`, whose default `iterator()` delegates to
/// `ProjectDataUtils.descendantFiles(getRootFolder())`; [`iter_files`](Self::iter_files) stands
/// in for that so the trait remains object-safe (`dyn ProjectData` cannot itself implement
/// `Iterator`, and `ProjectDataUtils` has not been ported yet).
pub trait ProjectData {
    /// Returns local storage implementation class, identified via [`TypeId`] since Rust has no
    /// direct equivalent of Java's `Class<? extends LocalFileSystem>`.
    fn get_local_storage_class(&self) -> TypeId {
        TypeId::of::<UnknownLocalFileSystem>()
    }

    /// Returns the root folder of the project.
    fn get_root_folder(&self) -> Box<dyn DomainFolder> {
        Box::new(EmptyProjectFolder)
    }

    /// Get domain folder specified by an absolute data path. All internal folder-links will be
    /// followed. Returns `None` if folder not found.
    fn get_folder(&self, path: &str) -> Option<Box<dyn DomainFolder>> {
        let _ = path;
        None
    }

    /// Get domain folder specified by an absolute data path, constrained by `filter`. Returns
    /// `None` if folder not found.
    fn get_folder_with_filter(
        &self,
        path: &str,
        filter: &dyn DomainFolderFilter,
    ) -> Option<Box<dyn DomainFolder>> {
        let _ = (path, filter);
        None
    }

    /// Get the approximate number of files contained within the project, or -1 if unknown.
    fn get_file_count(&self) -> i32 {
        -1
    }

    /// Get domain file specified by an absolute data path. All internal folder-links will be
    /// followed. Returns `None` if file not found.
    fn get_file(&self, path: &str) -> Option<Box<dyn DomainFile>> {
        let _ = path;
        None
    }

    /// Get domain file specified by an absolute data path which satisfies `filter`. Returns
    /// `None` if file not found.
    fn get_file_with_filter(
        &self,
        path: &str,
        filter: &dyn DomainFileFilter,
    ) -> Option<Box<dyn DomainFile>> {
        let _ = (path, filter);
        None
    }

    /// Finds all open domain files and appends them to `list`.
    fn find_open_files(&self, list: &mut Vec<Box<dyn DomainFile>>) {
        let _ = list;
    }

    /// Find all project files which are currently checked-out to this project.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs or `monitor` reports cancellation.
    fn find_checked_out_files(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Box<dyn DomainFile>>, IoCancelledError> {
        let _ = monitor;
        Ok(Vec::new())
    }

    /// Determine if any domain files listed do not correspond to a checkout in
    /// `new_repository` prior to invoking [`Self::update_repository_info`].
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs or `monitor` reports cancellation.
    fn has_invalid_checkouts(
        &self,
        checkout_list: &[Box<dyn DomainFile>],
        new_repository: &dyn RepositoryAdapter,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, IoCancelledError> {
        let _ = (checkout_list, new_repository, monitor);
        Ok(false)
    }

    /// Get domain file specified by its unique fileID. Link following is not performed. Returns
    /// `None` if file not found.
    fn get_file_by_id(&self, file_id: &str) -> Option<Box<dyn DomainFile>> {
        let _ = file_id;
        None
    }

    /// Transform the specified name into an acceptable folder or file item name.
    fn make_valid_name(&self, name: &str) -> String {
        let _ = name;
        "unknown".to_string()
    }

    /// Returns the projectLocator for this `ProjectData`.
    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        Box::new(UnknownProjectLocator)
    }

    /// Adds a listener that will be notified when any folder or file changes in the project.
    fn add_domain_folder_change_listener(&mut self, listener: Box<dyn DomainFolderChangeListener>) {
        let _ = listener;
    }

    /// Removes the listener to be notified of folder and file changes.
    fn remove_domain_folder_change_listener(&mut self, listener: &dyn DomainFolderChangeListener) {
        let _ = listener;
    }

    /// Sync the Domain folder/file structure with the underlying file structure.
    fn refresh(&mut self, force: bool) {
        let _ = force;
    }

    /// Returns User object associated with remote repository or `None` if a remote repository is
    /// not used.
    fn get_user(&self) -> Option<User> {
        None
    }

    /// Return the repository for this project data, or `None` if the project is not associated
    /// with a repository.
    fn get_repository(&self) -> Option<Box<dyn RepositoryAdapter>> {
        None
    }

    /// Convert a local project to a shared project. NOTE: The project should be closed and then
    /// reopened after this method is called.
    ///
    /// # Errors
    /// Returns `Err` if files under version control are still checked out, a problem accessing
    /// the filesystem occurs, or `monitor` reports cancellation.
    fn convert_project_to_shared(
        &mut self,
        repository: &dyn RepositoryAdapter,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), IoCancelledError> {
        let _ = (repository, monitor);
        Ok(())
    }

    /// Update the repository for this project; the server may have changed or a different
    /// repository is being used. NOTE: The project should be closed and then reopened after this
    /// method is called.
    ///
    /// # Errors
    /// Returns `Err` if files are still checked out, a problem accessing the filesystem occurs,
    /// or `monitor` reports cancellation.
    fn update_repository_info(
        &mut self,
        new_repository: &dyn RepositoryAdapter,
        force: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), IoCancelledError> {
        let _ = (new_repository, force, monitor);
        Ok(())
    }

    /// Initiate disposal of this project data object. Any files already open will delay disposal
    /// until they are closed.
    fn close(&mut self) {}

    /// Returns the maximum name length permitted for folders or items.
    fn get_max_name_length(&self) -> i32 {
        0
    }

    /// Validate a folder/item name or path.
    ///
    /// # Errors
    /// Returns `Err` if name is invalid.
    fn test_valid_name(&self, name: &str, is_path: bool) -> Result<(), InvalidNameException> {
        let _ = (name, is_path);
        Ok(())
    }

    /// Generate a repository URL which corresponds to this project data if applicable. Local
    /// private projects will return `None`.
    fn get_shared_project_url(&self) -> Option<String> {
        None
    }

    /// Generate a local URL which corresponds to this project data if applicable. Remote
    /// transient project data will return `None`.
    fn get_local_project_url(&self) -> Option<String> {
        None
    }

    /// Return an iterator over all non-link files within this project data store. Stands in for
    /// the Java `Iterable<DomainFile>` default `iterator()`.
    fn iter_files(&self) -> Vec<Box<dyn DomainFile>> {
        Vec::new()
    }
}

/// Trivial fallback used by [`ProjectData::get_local_storage_class`]'s default implementation
/// before a real local storage implementation is available.
struct UnknownLocalFileSystem;
impl LocalFileSystem for UnknownLocalFileSystem {}

/// Trivial fallback used by [`ProjectData::get_root_folder`]'s default implementation: an empty
/// proxy folder.
struct EmptyProjectFolder;
impl DomainFolder for EmptyProjectFolder {}

/// Trivial fallback used by [`ProjectData::get_project_locator`]'s default implementation before
/// a real project location is available.
struct UnknownProjectLocator;
impl ProjectLocator for UnknownProjectLocator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockProjectData {
        file_count: i32,
    }

    impl ProjectData for MockProjectData {
        fn get_file_count(&self) -> i32 {
            self.file_count
        }

        fn make_valid_name(&self, name: &str) -> String {
            name.to_string()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let data = MockProjectData { file_count: 3 };
        let dyn_data: &dyn ProjectData = &data;
        assert_eq!(dyn_data.get_file_count(), 3);
        assert_eq!(dyn_data.make_valid_name("foo"), "foo");
        assert!(dyn_data.get_folder("/x").is_none());
        assert!(dyn_data.get_user().is_none());
    }

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_an_empty_project() {
        struct BareProjectData;
        impl ProjectData for BareProjectData {}

        let mut data = BareProjectData;
        assert_eq!(data.get_file_count(), -1);
        assert_eq!(data.make_valid_name("anything"), "unknown");
        assert!(data.get_root_folder().is_empty());
        assert!(data.iter_files().is_empty());
        assert!(data.test_valid_name("ok", false).is_ok());
        data.refresh(true);
        data.close();
    }

    #[test]
    fn find_open_files_default_leaves_list_untouched() {
        let data_holder: Box<dyn ProjectData> = Box::new(MockProjectData::default());
        let mut list: Vec<Box<dyn DomainFile>> = Vec::new();
        data_holder.find_open_files(&mut list);
        assert!(list.is_empty());
    }
}
