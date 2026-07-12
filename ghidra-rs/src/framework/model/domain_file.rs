use std::any::TypeId;
use std::cmp::Ordering;
use std::io;
use std::path::Path;

use thiserror::Error;

use crate::framework::client::NotConnectedException;
use crate::framework::data::CheckinHandler;
use crate::framework::model::change_set::ChangeSet;
use crate::framework::model::domain_folder::DomainFolder;
use crate::framework::model::domain_object::{DomainObject, DomainObjectConsumer};
use crate::framework::model::link_file_info::LinkFileInfo;
use crate::framework::seam_stubs::{ItemCheckoutStatus, ProjectLocator, Version};
use crate::program::model::data::playable::Icon;
use crate::util::exception::{
    CancelledException, DuplicateFileException, FileInUseException, InvalidNameException,
    UserAccessException, VersionException,
};
use crate::util::task::TaskMonitor;

/// Use with [`DomainFile::get_version_history`]/friends to request the default version. The
/// default version is the private file or check-out file if one exists, or the latest version
/// from the version controlled file system.
///
/// Stands in for `DomainFile.DEFAULT_VERSION`, which aliases `FolderItem.LATEST_VERSION`.
pub const DEFAULT_VERSION: i32 = -1;

/// Event property name for the read-only setting.
///
/// Port of `DomainFile.READ_ONLY_PROPERTY`.
pub const READ_ONLY_PROPERTY: &str = "READ_ONLY";

/// Theme icon key for the icon shown for a domain file of unsupported/unknown content type.
///
/// Stands in for `DomainFile.UNSUPPORTED_FILE_ICON`, which is a `new GIcon(..)` instance rather
/// than a plain constant; see [`DomainFile::get_icon`]'s default for how this key is used.
pub const UNSUPPORTED_FILE_ICON_ID: &str = "icon.domain.file.uknown";

/// Combines the checked exceptions declared on `DomainFile.setName(String)`.
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

/// Combines the checked exceptions declared on `DomainFile.getChangesByOthersSinceCheckout()`.
#[derive(Error, Debug)]
pub enum GetChangesError {
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFile.getDomainObject`,
/// `getReadOnlyDomainObject`, and `getImmutableDomainObject`.
#[derive(Error, Debug)]
pub enum OpenDomainObjectError {
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions declared on `DomainFile.save(TaskMonitor)`.
#[derive(Error, Debug)]
pub enum FileSaveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions shared by `DomainFile.addToVersionControl`,
/// `DomainFile.checkout`, `DomainFile.copyVersionTo`, and `DomainFile.packFile`, all of which
/// declare only `IOException` and `CancelledException`.
#[derive(Error, Debug)]
pub enum IoCancelledError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions shared by `DomainFile.checkin` and `DomainFile.merge`.
#[derive(Error, Debug)]
pub enum CheckinError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions declared on `DomainFile.undoCheckout(boolean, boolean)`.
#[derive(Error, Debug)]
pub enum UndoCheckoutError {
    #[error(transparent)]
    NotConnected(#[from] NotConnectedException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFile.delete()`.
#[derive(Error, Debug)]
pub enum DeleteError {
    #[error(transparent)]
    FileInUse(#[from] FileInUseException),
    #[error(transparent)]
    UserAccess(#[from] UserAccessException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFile.moveTo(DomainFolder)`.
#[derive(Error, Debug)]
pub enum MoveError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error(transparent)]
    FileInUse(#[from] FileInUseException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Combines the checked exceptions declared on `DomainFile.copyTo(DomainFolder, TaskMonitor)`.
#[derive(Error, Debug)]
pub enum CopyError {
    #[error(transparent)]
    FileInUse(#[from] FileInUseException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// `DomainFile` provides a storage interface for a project file. A domain file provides an
/// immutable reference to a stored file contained within a project. The state of a file object
/// does not track name/parent changes made to the referenced project file.
///
/// Port of `ghidra.framework.model.DomainFile`.
///
/// This trait was promoted from a minimal placeholder (see `program::seam_stubs`) that declared
/// no methods, so there is nothing to retain as a superset here. Every method is given a default
/// so that the existing bare `impl DomainFile for MockX {}` blocks (in
/// [`DomainFileBasedDataTypeManager`](crate::program::model::data::domain_file_based_data_type_manager::DomainFileBasedDataTypeManager)
/// and its sibling ports) keep compiling unmodified. The defaults describe a non-existent,
/// unversioned, never-checked-out "proxy" file, mirroring the documented behavior of
/// `DomainFileProxy` (e.g. `exists()` always false).
///
/// The Java interface extends `Comparable<DomainFile>`; [`compare_to`](DomainFile::compare_to)
/// stands in for that so the trait remains object-safe (`dyn DomainFile` cannot itself implement
/// `Ord`/`PartialOrd`, which require `Sized`).
pub trait DomainFile {
    /// Get the name of this project file.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Check for existence of domain file. A proxy domain file will always return false.
    fn exists(&self) -> bool {
        false
    }

    /// Returns a unique file-ID if one has been established, or `None` if it could not be
    /// obtained.
    fn get_file_id(&self) -> Option<String> {
        None
    }

    /// Set the name on this domain file, returning the renamed domain file (the original
    /// `DomainFile` object becomes invalid since it is immutable).
    ///
    /// # Errors
    /// Returns `Err` if `new_name` contains illegal characters, a file named `new_name` already
    /// exists in this file's domain folder, this file is in-use/checked-out, or an IO/access
    /// error occurs.
    fn set_name(&mut self, new_name: &str) -> Result<Box<dyn DomainFile>, SetNameError> {
        let _ = new_name;
        Ok(Box::new(ProxyDomainFile))
    }

    /// Returns the full path name to this file.
    fn get_pathname(&self) -> String {
        String::new()
    }

    /// Get a remote Ghidra URL for this domain file if available within an associated shared
    /// project repository, or `None` if the shared file does not exist, the repository is not
    /// connected, or a connection error occurs.
    fn get_shared_project_url(&self, reference: Option<&str>) -> Option<String> {
        let _ = reference;
        None
    }

    /// Get a local Ghidra URL for this domain file if available within the associated
    /// non-transient local project, or `None` if the project is transient.
    fn get_local_project_url(&self, reference: Option<&str>) -> Option<String> {
        let _ = reference;
        None
    }

    /// Returns the local storage location for the project that this `DomainFile` belongs to.
    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        Box::new(UnknownProjectLocator)
    }

    /// Returns the content-type string for this file.
    fn get_content_type(&self) -> String {
        String::new()
    }

    /// Returns the underlying type for the domain object in this domain file, or `None` if it
    /// does not correspond to a domain object.
    fn get_domain_object_class(&self) -> Option<TypeId> {
        None
    }

    /// Get the parent domain folder for this domain file.
    fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
        None
    }

    /// Returns changes made to versioned file by others since checkout was performed.
    ///
    /// # Errors
    /// Returns `Err` if the latest version was created with a different version of software that
    /// prevents rapid determination of the change set, or a folder item access error occurs.
    fn get_changes_by_others_since_checkout(
        &self,
    ) -> Result<Option<Box<dyn ChangeSet>>, GetChangesError> {
        Ok(None)
    }

    /// Opens and returns the current domain object. If the domain object is already opened, the
    /// existing open domain object is returned.
    ///
    /// # Errors
    /// Returns `Err` if the domain object could not be read due to a version format change, an
    /// IO or access error occurs, or `monitor` reports cancellation.
    fn get_domain_object(
        &self,
        consumer: DomainObjectConsumer,
        ok_to_upgrade: bool,
        ok_to_recover: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainObject>, OpenDomainObjectError> {
        let _ = (consumer, ok_to_upgrade, ok_to_recover, monitor);
        Ok(Box::new(EmptyDomainObject))
    }

    /// Returns the domain object for this `DomainFile` only if it is already open.
    fn get_opened_domain_object(&self, consumer: DomainObjectConsumer) -> Option<Box<dyn DomainObject>> {
        let _ = consumer;
        None
    }

    /// Returns a "read-only" version of the domain object, disassociated from its original
    /// domain file.
    ///
    /// # Errors
    /// Returns `Err` if the domain object could not be read due to a version format change, the
    /// stored file/version was not found, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn get_read_only_domain_object(
        &self,
        consumer: DomainObjectConsumer,
        version: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainObject>, OpenDomainObjectError> {
        let _ = (consumer, version, monitor);
        Ok(Box::new(EmptyDomainObject))
    }

    /// Returns a new domain object that cannot be changed or saved to its original file.
    ///
    /// # Errors
    /// Returns `Err` if the domain object could not be read due to a version format change, the
    /// stored file/version was not found, an IO or access error occurs, or `monitor` reports
    /// cancellation.
    fn get_immutable_domain_object(
        &self,
        consumer: DomainObjectConsumer,
        version: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainObject>, OpenDomainObjectError> {
        let _ = (consumer, version, monitor);
        Ok(Box::new(EmptyDomainObject))
    }

    /// Save the domain object associated with this file.
    ///
    /// # Errors
    /// Returns `Err` if the file is open for update by someone else, a transient-read is in
    /// progress, an IO error occurs, or `monitor` reports cancellation.
    fn save(&mut self, monitor: &dyn TaskMonitor) -> Result<(), FileSaveError> {
        let _ = monitor;
        Ok(())
    }

    /// Return whether this domain object can be saved (i.e., updated/overwritten).
    fn can_save(&self) -> bool {
        false
    }

    /// Prior to invoking [`Self::get_domain_object`], this method can be used to determine if
    /// unsaved changes can be recovered on the next open.
    fn can_recover(&self) -> bool {
        false
    }

    /// If the file has an updatable domain object with unsaved changes, generate a recovery
    /// snapshot.
    ///
    /// # Errors
    /// Returns `Err` if there is an exception saving the snapshot.
    fn take_recovery_snapshot(&mut self) -> io::Result<bool> {
        Ok(true)
    }

    /// Returns true if this file is in a writable project.
    fn is_in_writable_project(&self) -> bool {
        false
    }

    /// Get a value representing the time when the data was last modified.
    fn get_last_modified_time(&self) -> i64 {
        0
    }

    /// Get the state based icon for the domain file based upon its content class.
    fn get_icon(&self, disabled: bool) -> Box<dyn Icon> {
        let _ = disabled;
        Box::new(UnsupportedFileIcon)
    }

    /// Returns true if this is a checked-out file.
    fn is_checked_out(&self) -> bool {
        false
    }

    /// Returns true if this a checked-out file with exclusive access.
    fn is_checked_out_exclusive(&self) -> bool {
        false
    }

    /// Returns true if this is a checked-out file which has been modified since it was
    /// checked-out.
    fn modified_since_checkout(&self) -> bool {
        false
    }

    /// Returns true if this file may be checked-out from the associated repository.
    fn can_checkout(&self) -> bool {
        false
    }

    /// Returns true if this file may be checked-in to the associated repository.
    fn can_checkin(&self) -> bool {
        false
    }

    /// Returns true if this file can be merged with the current versioned file.
    fn can_merge(&self) -> bool {
        false
    }

    /// Returns true if this private file may be added to the associated repository.
    fn can_add_to_repository(&self) -> bool {
        false
    }

    /// Sets the object to read-only. This method may only be invoked for private files (i.e.,
    /// not versioned).
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs.
    fn set_read_only(&mut self, state: bool) -> io::Result<()> {
        let _ = state;
        Ok(())
    }

    /// Returns whether this file is explicitly marked as read-only.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Return true if this is a versioned database, else false.
    fn is_versioned(&self) -> bool {
        false
    }

    /// Returns true if the file is versioned but a private copy also exists.
    fn is_hijacked(&self) -> bool {
        false
    }

    /// Return the latest version.
    fn get_latest_version(&self) -> i32 {
        DEFAULT_VERSION
    }

    /// Returns true if this file represents the latest version of the associated domain object.
    fn is_latest_version(&self) -> bool {
        true
    }

    /// Return either the latest version if the file is not checked-out or the version that was
    /// checked-out or a specific version that was requested.
    fn get_version(&self) -> i32 {
        DEFAULT_VERSION
    }

    /// Returns list of all available versions.
    ///
    /// # Errors
    /// Returns `Err` if there is an exception getting the history.
    fn get_version_history(&self) -> io::Result<Vec<Box<dyn Version>>> {
        Ok(Vec::new())
    }

    /// Adds this private file to version control.
    ///
    /// # Errors
    /// Returns `Err` if this file is in-use, an IO or access error occurs (also if the file is
    /// not private), or `monitor` reports cancellation.
    fn add_to_version_control(
        &mut self,
        comment: &str,
        keep_checked_out: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), IoCancelledError> {
        let _ = (comment, keep_checked_out, monitor);
        Ok(())
    }

    /// Checkout this file for update. If this file is already private, this method does nothing.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs, or `monitor` reports cancellation.
    fn checkout(&mut self, exclusive: bool, monitor: &dyn TaskMonitor) -> Result<bool, IoCancelledError> {
        let _ = (exclusive, monitor);
        Ok(true)
    }

    /// Performs check in to associated repository. File must be checked-out and modified since
    /// checkout.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs, the domain object version in the versioned
    /// filesystem cannot be handled, or `monitor` reports cancellation.
    fn checkin(
        &mut self,
        checkin_handler: &dyn CheckinHandler,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CheckinError> {
        let _ = (checkin_handler, monitor);
        Ok(())
    }

    /// Performs check in to associated repository, ignoring `ok_to_upgrade` since an upgrade
    /// cannot be performed during checkin.
    ///
    /// # Errors
    /// See [`Self::checkin`].
    #[deprecated(
        since = "11.1",
        note = "use checkin() instead; ok_to_upgrade cannot be respected and is ignored"
    )]
    fn checkin_ok_to_upgrade(
        &mut self,
        checkin_handler: &dyn CheckinHandler,
        ok_to_upgrade: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CheckinError> {
        let _ = ok_to_upgrade;
        self.checkin(checkin_handler, monitor)
    }

    /// Performs merge from current version of versioned file into local checked-out file.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs, the domain object version in the versioned
    /// filesystem cannot be handled, or `monitor` reports cancellation.
    fn merge(&mut self, ok_to_upgrade: bool, monitor: &dyn TaskMonitor) -> Result<(), CheckinError> {
        let _ = (ok_to_upgrade, monitor);
        Ok(())
    }

    /// Undo "checked-out" file. The original repository file is restored.
    ///
    /// # Errors
    /// Returns `Err` if the file is not checked-out or an IO/access error occurs.
    fn undo_checkout(&mut self, keep: bool) -> io::Result<()> {
        let _ = keep;
        Ok(())
    }

    /// Undo "checked-out" file, optionally forcing removal of the local checkout file if not
    /// connected to the repository.
    ///
    /// # Errors
    /// Returns `Err` if not connected to the repository and `force` is false, this file is
    /// in-use/checked-out, or the file is not checked-out or an IO/access error occurs.
    fn undo_checkout_forced(&mut self, keep: bool, force: bool) -> Result<(), UndoCheckoutError> {
        let _ = (keep, force);
        Ok(())
    }

    /// Forcefully terminate a checkout for the associated versioned file.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn terminate_checkout(&mut self, checkout_id: i64) -> io::Result<()> {
        let _ = checkout_id;
        Ok(())
    }

    /// Get a list of checkouts by all users for the associated versioned file.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
        Ok(Vec::new())
    }

    /// Get checkout status associated with a versioned file, or `None` if not checked-out to the
    /// current associated project.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn get_checkout_status(&self) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
        Ok(None)
    }

    /// Delete the entire database for this file, including any version files.
    ///
    /// # Errors
    /// Returns `Err` if this file is in-use/checked-out, the user does not have permission to
    /// delete the file, or an IO or access error occurs.
    fn delete(&mut self) -> Result<(), DeleteError> {
        Ok(())
    }

    /// Deletes a specific version of a file from the versioned filesystem. The version must
    /// either be the oldest or latest, or -1 which attempts to remove all versions.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs, including inability to delete a version because this
    /// item is checked-out, the user does not have permission, or the specified version is not
    /// the oldest or latest.
    fn delete_version(&mut self, version: i32) -> io::Result<()> {
        let _ = version;
        Ok(())
    }

    /// Move this file into `new_parent`, returning the newly relocated domain file (the original
    /// `DomainFile` object becomes invalid since it is immutable).
    ///
    /// # Errors
    /// Returns `Err` if a file with the same name already exists in `new_parent`, this file is
    /// in-use/checked-out, or an IO or access error occurs.
    fn move_to(&mut self, new_parent: &dyn DomainFolder) -> Result<Box<dyn DomainFile>, MoveError> {
        let _ = new_parent;
        Ok(Box::new(ProxyDomainFile))
    }

    /// Copy this file into `new_parent` as a private file.
    ///
    /// # Errors
    /// Returns `Err` if this file is in-use/checked-out, an IO or access error occurs, or
    /// `monitor` reports cancellation.
    fn copy_to(
        &self,
        new_parent: &dyn DomainFolder,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, CopyError> {
        let _ = (new_parent, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Copy a specific version of this file to `dest_folder`.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs, or `monitor` reports cancellation.
    fn copy_version_to(
        &self,
        version: i32,
        dest_folder: &dyn DomainFolder,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn DomainFile>, IoCancelledError> {
        let _ = (version, dest_folder, monitor);
        Ok(Box::new(ProxyDomainFile))
    }

    /// Copy this file into `new_parent` as a file-link, returning `None` if the content type
    /// does not support link use.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn copy_to_as_link(
        &self,
        new_parent: &dyn DomainFolder,
        relative: bool,
    ) -> io::Result<Option<Box<dyn DomainFile>>> {
        let _ = (new_parent, relative);
        Ok(None)
    }

    /// Determine if this file's content type supports linking.
    fn is_linking_supported(&self) -> bool {
        false
    }

    /// Get the list of consumers for this domain file.
    fn get_consumers(&self) -> Vec<DomainObjectConsumer> {
        Vec::new()
    }

    /// Return whether the domain object in this domain file has changed.
    fn is_changed(&self) -> bool {
        false
    }

    /// Returns true if there is an open domain object for this file.
    fn is_open(&self) -> bool {
        false
    }

    /// Returns true if the domain object in this domain file exists and has an open transaction.
    fn is_busy(&self) -> bool {
        false
    }

    /// Pack domain file into `file`. The destination file will be overwritten if it already
    /// exists.
    ///
    /// # Errors
    /// Returns `Err` if there is an exception packing the file, or `monitor` reports
    /// cancellation.
    fn pack_file(&self, file: &Path, monitor: &dyn TaskMonitor) -> Result<(), IoCancelledError> {
        let _ = (file, monitor);
        Ok(())
    }

    /// Returns an ordered list of metadata key/value pairs associated with the corresponding
    /// domain object, in insertion order (mirrors the Java `LinkedHashMap`).
    fn get_metadata(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Returns the length of this domain file. This size is the minimum disk space used for
    /// storing this file, but does not account for additional storage space used to track
    /// changes, etc.
    ///
    /// # Errors
    /// Returns `Err` if an IO or access error occurs.
    fn length(&self) -> io::Result<u64> {
        Ok(0)
    }

    /// Determine if this file is a link-file which corresponds to either a file or folder link.
    fn is_link(&self) -> bool {
        false
    }

    /// If this file is a [`Self::is_link`] link-file, the link information will be returned.
    fn get_link_info(&self) -> Option<Box<dyn LinkFileInfo>> {
        None
    }

    /// Compares this domain file to another. Stands in for the Java `Comparable<DomainFile>`
    /// contract.
    fn compare_to(&self, other: &dyn DomainFile) -> Ordering {
        self.get_pathname().cmp(&other.get_pathname())
    }
}

/// Trivial fallback used by several [`DomainFile`] default implementations that must fabricate a
/// new `DomainFile` (e.g. [`DomainFile::set_name`], [`DomainFile::move_to`]): a proxy file that
/// does not exist, matching the documented behavior of `DomainFileProxy`.
struct ProxyDomainFile;
impl DomainFile for ProxyDomainFile {}

/// Trivial fallback used by [`DomainFile::get_domain_object`] and its read-only/immutable
/// siblings: a fresh, unshared, never-saved domain object.
struct EmptyDomainObject;
impl DomainObject for EmptyDomainObject {}

/// Trivial fallback used by [`DomainFile::get_project_locator`] before a real project location
/// is available.
struct UnknownProjectLocator;
impl ProjectLocator for UnknownProjectLocator {}

/// Trivial fallback used by [`DomainFile::get_icon`]'s default implementation, identified by
/// [`UNSUPPORTED_FILE_ICON_ID`].
struct UnsupportedFileIcon;
impl Icon for UnsupportedFileIcon {
    fn icon_id(&self) -> &str {
        UNSUPPORTED_FILE_ICON_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDomainFile {
        name: String,
        exists: bool,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn exists(&self) -> bool {
            self.exists
        }

        fn get_pathname(&self) -> String {
            format!("/{}", self.name)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let file = MockDomainFile { name: "a".to_string(), exists: true };
        let dyn_file: &dyn DomainFile = &file;
        assert_eq!(dyn_file.get_name(), "a");
        assert!(dyn_file.exists());
        assert!(!dyn_file.is_versioned());
        assert!(!dyn_file.is_checked_out());
        assert_eq!(dyn_file.get_version(), DEFAULT_VERSION);
    }

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_a_proxy() {
        struct BareDomainFile;
        impl DomainFile for BareDomainFile {}

        let file = BareDomainFile;
        assert!(!file.exists());
        assert!(file.get_metadata().is_empty());
        assert!(file.get_consumers().is_empty());
    }

    #[test]
    fn compare_to_orders_by_pathname() {
        let a = MockDomainFile { name: "a".to_string(), exists: false };
        let b = MockDomainFile { name: "b".to_string(), exists: false };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }

    #[test]
    fn set_name_default_returns_proxy_file() {
        let mut file = MockDomainFile { name: "old".to_string(), exists: true };
        let renamed = file.set_name("new").unwrap();
        assert!(!renamed.exists());
    }

    #[test]
    fn get_icon_default_uses_unsupported_icon_id() {
        let file = MockDomainFile::default();
        assert_eq!(file.get_icon(false).icon_id(), UNSUPPORTED_FILE_ICON_ID);
    }
}
