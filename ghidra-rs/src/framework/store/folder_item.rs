use std::io;
use std::path::Path;

use crate::framework::seam_stubs::ItemCheckoutStatus;
use crate::framework::store::checkout_type::CheckoutType;
use crate::framework::store::local::OutputItemError;
use crate::framework::store::ItemVersion;
use crate::util::task::TaskMonitor;

/// Underlying file is an unknown/unsupported type.
pub const UNKNOWN_FILE_TYPE: i32 = -1;
/// Underlying file is a database.
pub const DATABASE_FILE_TYPE: i32 = 0;
/// Underlying file is a serialized data file.
pub const DATAFILE_FILE_TYPE: i32 = 1;
/// Item type is associated with metadata only (e.g., URL).
pub const LINK_FILE_TYPE: i32 = 2;
/// Default checkout ID used when a checkout is not applicable.
pub const DEFAULT_CHECKOUT_ID: i64 = -1;
/// Default file version number used to indicate the latest/current version.
pub const LATEST_VERSION: i32 = -1;

/// An individual file contained within a file-system, uniquely identified by a path string.
///
/// Mirrors `ghidra.framework.store.FolderItem`. This port maps the Java interface to an
/// object-safe trait so that other core types (e.g.
/// [`DatabaseItem`](crate::framework::store::DatabaseItem)) can depend on folder-item behavior
/// without depending on any single concrete implementation, breaking a dependency cycle at this
/// cut-point. Methods that return or accept another not-yet-ported core type
/// ([`ItemCheckoutStatus`]) use the object-safe placeholder for that type; methods that return or
/// accept an already-ported core type ([`CheckoutType`], [`ItemVersion`]) use the real port.
///
/// The Java interface's `public static final` fields (`UNKNOWN_FILE_TYPE`, `DATABASE_FILE_TYPE`,
/// `DATAFILE_FILE_TYPE`, `LINK_FILE_TYPE`, `DEFAULT_CHECKOUT_ID`, `LATEST_VERSION`) are ported as
/// free module-level constants rather than trait-associated constants, since associated
/// constants would make this trait dyn-incompatible.
pub trait FolderItem {
    /// Returns the display name for this item.
    fn get_name(&self) -> String;

    /// Returns the file ID if one has been established.
    fn get_file_id(&self) -> Option<String>;

    /// Assigns a new file-ID to this local non-versioned file.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO or access error occurs.
    fn reset_file_id(&mut self) -> io::Result<String>;

    /// Returns the length of this domain file. This size is the minimum disk space used for
    /// storing this file, but does not account for additional storage space used to track
    /// changes, etc.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO or access error occurs.
    fn length(&self) -> io::Result<i64>;

    /// Returns the content type name for this item.
    fn get_content_type(&self) -> String;

    /// Returns the path of the parent folder.
    fn get_parent_path(&self) -> String;

    /// Returns the concatenation of the pathname and the basename, which can be used to uniquely
    /// identify this folder item.
    fn get_path_name(&self) -> String;

    /// Returns true if this item can be overwritten/deleted.
    fn is_read_only(&self) -> bool;

    /// Sets the state of the read-only indicator for this non-shared item.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is stored on a shared
    /// file-system.
    fn set_read_only(&mut self, state: bool) -> io::Result<()>;

    /// Returns the version of the content type. Note this is the version of the
    /// structure/storage for the content type, not the user's version of their data.
    fn get_content_type_version(&self) -> i32;

    /// Sets the version for the content type. This will change whenever the domain objects are
    /// upgraded.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is stored on a shared
    /// file-system.
    fn set_content_type_version(&mut self, version: i32) -> io::Result<()>;

    /// Returns the time that this item was last modified.
    fn last_modified(&self) -> i64;

    /// Returns the latest/current version.
    fn get_current_version(&self) -> i32;

    /// Returns true if this item is a checked-out copy from a versioned file system.
    fn is_checked_out(&self) -> bool;

    /// Returns true if this item is a checked-out copy with exclusive access from a versioned
    /// file system.
    fn is_checked_out_exclusive(&self) -> bool;

    /// Returns true if this is a versioned item, else false.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn is_versioned(&self) -> io::Result<bool>;

    /// Returns the checkout ID for this file. A value of -1 (`DEFAULT_CHECKOUT_ID`) indicates a
    /// private item.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_checkout_id(&self) -> io::Result<i64>;

    /// Returns the item version which was checked out. A value of -1 indicates a private item.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_checkout_version(&self) -> io::Result<i32>;

    /// Returns the local item version at the time the checkout was completed. A value of -1
    /// indicates a private item.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    fn get_local_checkout_version(&self) -> i32;

    /// Sets the checkout data associated with this non-shared file.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    ///
    /// - `checkout_id`: checkout ID (provided by `ItemCheckoutStatus`).
    /// - `exclusive`: true if the checkout is exclusive.
    /// - `checkout_version`: the item version which was checked out (provided by
    ///   `ItemCheckoutStatus`).
    /// - `local_version`: the local item version at the time the checkout was completed.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is stored on a shared
    /// file-system.
    fn set_checkout(
        &mut self,
        checkout_id: i64,
        exclusive: bool,
        checkout_version: i32,
        local_version: i32,
    ) -> io::Result<()>;

    /// Clears the checkout data associated with this non-shared file.
    ///
    /// NOTE: This method is only valid for a local non-versioned file-system.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn clear_checkout(&mut self) -> io::Result<()>;

    /// Deletes the item or a specific version. If a specific version is specified, it must
    /// either be the oldest or latest (i.e., current).
    ///
    /// - `version`: specific version to be deleted, or -1 to remove all versions.
    /// - `user`: user name.
    ///
    /// # Errors
    /// Returns an `io::Error` if unable to delete a version because this item is checked out,
    /// the user does not have permission, or the specified version is not the oldest or latest.
    fn delete(&mut self, version: i32, user: &str) -> io::Result<()>;

    /// Returns the list of all available versions, or `None` if this item is not versioned.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn get_versions(&self) -> io::Result<Option<Vec<ItemVersion>>>;

    /// Checks out this folder item.
    ///
    /// Returns the checkout status, or `None` if an exclusive checkout request failed.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is not versioned.
    fn checkout(
        &mut self,
        checkout_type: &dyn CheckoutType,
        user: &str,
        project_path: &str,
    ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Terminates a checkout. The checkout ID becomes invalid, therefore the associated checkout
    /// copy should either be removed or converted to a private file.
    ///
    /// - `checkout_id`: checkout ID.
    /// - `notify`: if true, an item change notification will be sent.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is not versioned.
    fn terminate_checkout(&mut self, checkout_id: i64, notify: bool) -> io::Result<()>;

    /// Returns true if this item is versioned and has one or more checkouts.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn has_checkouts(&self) -> io::Result<bool>;

    /// Returns true if unsaved file changes can be recovered.
    fn can_recover(&self) -> bool;

    /// Gets the checkout status which corresponds to the specified checkout ID, or `None` if the
    /// checkout ID was not found.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is not versioned.
    fn get_checkout(&self, checkout_id: i64) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>;

    /// Gets all current checkouts for this item.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs or this item is not versioned.
    fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>>;

    /// Returns true if this item is versioned and has a checkin in progress.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn is_checkin_active(&self) -> io::Result<bool>;

    /// Updates the checkout version associated with this versioned item.
    ///
    /// - `checkout_id`: id corresponding to an existing checkout.
    /// - `checkout_version`: current checkout version.
    /// - `user`: user performing the update.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn update_checkout_version(
        &mut self,
        checkout_id: i64,
        checkout_version: i32,
        user: &str,
    ) -> io::Result<()>;

    /// Serializes (i.e., packs) this item into the specified output file.
    ///
    /// - `output_file`: packed output file to be created.
    /// - `version`: if this item is versioned, the version to output, otherwise -1
    ///   (`LATEST_VERSION`) should be specified.
    /// - `monitor`: progress monitor.
    ///
    /// # Errors
    /// Returns an error if the packed file could not be saved or the operation was cancelled via
    /// `monitor`.
    fn output(
        &self,
        output_file: &Path,
        version: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), OutputItemError>;

    /// Returns this instance after refresh, or `None` if the item no longer exists.
    ///
    /// # Errors
    /// Returns an `io::Error` if an error occurred during refresh.
    fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct MockItemCheckoutStatus;
    impl ItemCheckoutStatus for MockItemCheckoutStatus {}

    struct MockFolderItem {
        name: String,
        content_type: String,
        read_only: Cell<bool>,
        versioned: bool,
        current_version: i32,
        checkout_id: Cell<i64>,
    }

    impl Default for MockFolderItem {
        fn default() -> Self {
            Self {
                name: String::new(),
                content_type: String::new(),
                read_only: Cell::new(false),
                versioned: false,
                current_version: 0,
                checkout_id: Cell::new(-1),
            }
        }
    }

    impl FolderItem for MockFolderItem {
        fn get_name(&self) -> String {
            self.name.clone()
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
            self.content_type.clone()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            format!("/{}", self.name)
        }

        fn is_read_only(&self) -> bool {
            self.read_only.get()
        }

        fn set_read_only(&mut self, state: bool) -> io::Result<()> {
            self.read_only.set(state);
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
            self.current_version
        }

        fn is_checked_out(&self) -> bool {
            self.checkout_id.get() != DEFAULT_CHECKOUT_ID
        }

        fn is_checked_out_exclusive(&self) -> bool {
            false
        }

        fn is_versioned(&self) -> io::Result<bool> {
            Ok(self.versioned)
        }

        fn get_checkout_id(&self) -> io::Result<i64> {
            Ok(self.checkout_id.get())
        }

        fn get_checkout_version(&self) -> io::Result<i32> {
            Ok(-1)
        }

        fn get_local_checkout_version(&self) -> i32 {
            -1
        }

        fn set_checkout(
            &mut self,
            checkout_id: i64,
            _exclusive: bool,
            _checkout_version: i32,
            _local_version: i32,
        ) -> io::Result<()> {
            self.checkout_id.set(checkout_id);
            Ok(())
        }

        fn clear_checkout(&mut self) -> io::Result<()> {
            self.checkout_id.set(DEFAULT_CHECKOUT_ID);
            Ok(())
        }

        fn delete(&mut self, version: i32, _user: &str) -> io::Result<()> {
            if version != -1 && version != self.current_version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only the oldest or latest version may be deleted",
                ));
            }
            Ok(())
        }

        fn get_versions(&self) -> io::Result<Option<Vec<ItemVersion>>> {
            if !self.versioned {
                return Ok(None);
            }
            Ok(Some(vec![ItemVersion::new(
                self.current_version,
                0,
                "alice",
                "initial",
            )]))
        }

        fn checkout(
            &mut self,
            _checkout_type: &dyn CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            if !self.versioned {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"));
            }
            Ok(Some(Box::new(MockItemCheckoutStatus)))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
            self.checkout_id.set(DEFAULT_CHECKOUT_ID);
            Ok(())
        }

        fn has_checkouts(&self) -> io::Result<bool> {
            Ok(self.checkout_id.get() != DEFAULT_CHECKOUT_ID)
        }

        fn can_recover(&self) -> bool {
            false
        }

        fn get_checkout(
            &self,
            checkout_id: i64,
        ) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            if checkout_id == self.checkout_id.get() {
                Ok(Some(Box::new(MockItemCheckoutStatus)))
            } else {
                Ok(None)
            }
        }

        fn get_checkouts(&self) -> io::Result<Vec<Box<dyn ItemCheckoutStatus>>> {
            if self.checkout_id.get() == DEFAULT_CHECKOUT_ID {
                Ok(Vec::new())
            } else {
                Ok(vec![Box::new(MockItemCheckoutStatus)])
            }
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
            monitor: &dyn TaskMonitor,
        ) -> Result<(), OutputItemError> {
            if monitor.is_cancelled() {
                return Err(OutputItemError::Cancelled(Default::default()));
            }
            Ok(())
        }

        fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

    struct RecordingMonitor {
        cancelled: bool,
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
    }

    #[test]
    fn test_object_safety_and_checkout_lifecycle() {
        let mut item: Box<dyn FolderItem> = Box::new(MockFolderItem {
            name: "MyProgram".to_string(),
            content_type: "Program".to_string(),
            versioned: true,
            current_version: 3,
            checkout_id: Cell::new(-1),
            ..Default::default()
        });

        assert_eq!(item.get_name(), "MyProgram");
        assert_eq!(item.get_path_name(), "/MyProgram");
        assert!(item.is_versioned().unwrap());
        assert!(!item.has_checkouts().unwrap());

        assert!(item.set_checkout(42, false, 1, 0).is_ok());
        assert!(item.has_checkouts().unwrap());
        assert!(item.get_checkout(42).unwrap().is_some());
        assert!(item.get_checkout(7).unwrap().is_none());

        assert!(item.clear_checkout().is_ok());
        assert!(!item.has_checkouts().unwrap());

        let versions = item.get_versions().unwrap().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].user(), "alice");
    }

    #[test]
    fn test_non_versioned_get_versions_returns_none() {
        let item: Box<dyn FolderItem> = Box::new(MockFolderItem::default());
        assert_eq!(item.get_versions().unwrap(), None);
    }

    #[test]
    fn test_output_reports_cancellation() {
        let item: Box<dyn FolderItem> = Box::new(MockFolderItem::default());
        let monitor = RecordingMonitor { cancelled: true };
        let err = item
            .output(Path::new("/tmp/out.zip"), -1, &monitor)
            .unwrap_err();
        assert!(matches!(err, OutputItemError::Cancelled(_)));
    }

    #[test]
    fn test_delete_rejects_non_boundary_version() {
        let mut item: Box<dyn FolderItem> = Box::new(MockFolderItem {
            current_version: 5,
            ..Default::default()
        });
        assert!(item.delete(3, "alice").is_err());
        assert!(item.delete(5, "alice").is_ok());
        assert!(item.delete(-1, "alice").is_ok());
    }
}
