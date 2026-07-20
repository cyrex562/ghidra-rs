use std::io;
use std::path::Path;

use thiserror::Error;

use crate::framework::db::buffers::ManagedBufferFile;
use crate::framework::seam_stubs::Database;
use crate::framework::store::local::OutputItemError;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error type returned by [`PrivateDatabase::update_checkout_copy`], combining the checked
/// exceptions declared on `PrivateDatabase.updateCheckoutCopy(ManagedBufferFile, int,
/// TaskMonitor)` (`CancelledException`, `IOException`).
#[derive(Error, Debug)]
pub enum UpdateCheckoutCopyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// A non-versioned database.
///
/// Mirrors `ghidra.framework.store.db.PrivateDatabase`, which extends `db.Database`; that
/// relationship is preserved via the [`Database`](crate::framework::seam_stubs::Database)
/// supertrait placeholder (`db.Database` has not been ported yet).
///
/// Constructors and the static `createDatabase` factory are not represented as trait methods,
/// since Rust traits cannot express `Self`-returning constructors while remaining object-safe.
/// A concrete implementation is expected to provide its own associated `new`/`create` functions,
/// mirroring the convention established by
/// [`LocalFileSystem`](crate::framework::store::local::LocalFileSystem). Likewise, the buffer
/// files this trait's methods return are represented as
/// [`Box<dyn ManagedBufferFile>`](ManagedBufferFile) rather than the concrete (and not yet
/// ported) `db.buffers.LocalManagedBufferFile`.
///
/// The two Java `updateCheckoutCopy` overloads are combined into a single
/// [`update_checkout_copy`](Self::update_checkout_copy) method: the no-arg overload corresponds
/// to passing `src_file: None`.
pub trait PrivateDatabase: Database {
    /// If this is a checked-out copy and a cumulative change file should be maintained, this
    /// method must be invoked following construction.
    fn set_is_checkout_copy(&mut self, state: bool);

    /// Open the current version of this database for non-update use.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    fn open_buffer_file(&self) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Open the current version of this database for update use.
    ///
    /// # Errors
    /// Returns an `io::Error` if updating this database file is not allowed, or another IO error
    /// occurs.
    fn open_buffer_file_for_update(&self) -> io::Result<Box<dyn ManagedBufferFile>>;

    /// Returns true if recovery data exists which may enable recovery of unsaved changes
    /// resulting from a previous crash.
    fn can_recover(&self) -> bool;

    /// Following a move of the database directory, this method should be invoked if this
    /// instance will continue to be used.
    ///
    /// # Errors
    /// Returns an `io::Error` if the database directory cannot be found.
    fn db_moved(&mut self, dir: &Path) -> io::Result<()>;

    /// If this is a checked-out copy, replace the buffer file content with that provided by the
    /// specified `src_file` (or leave the current version unchanged if `None`, since it is
    /// already up-to-date). If a cumulative change file exists, it is deleted following the
    /// update.
    ///
    /// # Errors
    /// Returns an error if this database is not a checkout copy, an I/O error occurs, or the
    /// operation is cancelled via `monitor`.
    fn update_checkout_copy(
        &mut self,
        src_file: Option<&mut dyn ManagedBufferFile>,
        old_version: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), UpdateCheckoutCopyError>;

    /// Move the content of `other_db` into this database. `other_db` will no longer exist if
    /// this method is successful. If already open for update, a save should not be done or the
    /// database may become corrupted. All existing handles should be closed and reopened when
    /// this method is complete.
    ///
    /// # Errors
    /// Returns an `io::Error` if this database is not a checkout copy or an I/O error occurs. An
    /// attempt will be made to restore this database to its original state, however `other_db`
    /// will not be repaired and may become unusable.
    fn update_checkout_from(&mut self, other_db: &mut dyn PrivateDatabase) -> io::Result<()>;

    /// Output the current version of this database to a packed storage file.
    ///
    /// # Errors
    /// Returns an error if an I/O error occurs or the operation is cancelled via `monitor`.
    fn output(
        &self,
        output_file: &Path,
        name: &str,
        filetype: i32,
        content_type: Option<&str>,
        monitor: Option<&dyn TaskMonitor>,
    ) -> Result<(), OutputItemError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct MockPrivateDatabase {
        is_checkout_copy: Cell<bool>,
        recoverable: Cell<bool>,
        dir: RefCell<std::path::PathBuf>,
        cumulative_change_cleared: Cell<bool>,
    }

    impl Database for MockPrivateDatabase {}

    impl PrivateDatabase for MockPrivateDatabase {
        fn set_is_checkout_copy(&mut self, state: bool) {
            self.is_checkout_copy.set(state);
        }

        fn open_buffer_file(&self) -> io::Result<Box<dyn ManagedBufferFile>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "no backing store in mock"))
        }

        fn open_buffer_file_for_update(&self) -> io::Result<Box<dyn ManagedBufferFile>> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "Update use not permitted"))
        }

        fn can_recover(&self) -> bool {
            self.recoverable.get()
        }

        fn db_moved(&mut self, dir: &Path) -> io::Result<()> {
            if !dir.exists() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "database directory not found"));
            }
            *self.dir.borrow_mut() = dir.to_path_buf();
            Ok(())
        }

        fn update_checkout_copy(
            &mut self,
            _src_file: Option<&mut dyn ManagedBufferFile>,
            _old_version: i32,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), UpdateCheckoutCopyError> {
            if !self.is_checkout_copy.get() {
                return Err(UpdateCheckoutCopyError::Io(io::Error::new(
                    io::ErrorKind::Other,
                    "Database is not a checkout copy",
                )));
            }
            if monitor.is_cancelled() {
                return Err(UpdateCheckoutCopyError::Cancelled(CancelledException::default()));
            }
            self.cumulative_change_cleared.set(true);
            Ok(())
        }

        fn update_checkout_from(&mut self, other_db: &mut dyn PrivateDatabase) -> io::Result<()> {
            if !self.is_checkout_copy.get() {
                return Err(io::Error::new(io::ErrorKind::Other, "Database is not a checkout copy"));
            }
            other_db.set_is_checkout_copy(false);
            Ok(())
        }

        fn output(
            &self,
            _output_file: &Path,
            _name: &str,
            _filetype: i32,
            _content_type: Option<&str>,
            _monitor: Option<&dyn TaskMonitor>,
        ) -> Result<(), OutputItemError> {
            Ok(())
        }
    }

    #[test]
    fn test_object_safe_dyn_usage_and_checkout_lifecycle() {
        let mut db: Box<dyn PrivateDatabase> = Box::new(MockPrivateDatabase::default());

        assert!(!db.can_recover());
        db.set_is_checkout_copy(true);

        let monitor = crate::util::task::DummyMonitor;
        assert!(db.update_checkout_copy(None, 3, &monitor).is_ok());

        let mut other: Box<dyn PrivateDatabase> = Box::new(MockPrivateDatabase::default());
        other.set_is_checkout_copy(true);
        assert!(db.update_checkout_from(other.as_mut()).is_ok());
        assert!(!other.can_recover());

        assert!(db.open_buffer_file().is_err());
        assert!(db.open_buffer_file_for_update().is_err());
        assert!(db
            .output(Path::new("/tmp/does-not-matter.pdb"), "name", 1, Some("Program"), None)
            .is_ok());
    }

    #[test]
    fn test_update_checkout_copy_rejects_non_checkout_database() {
        let mut db = MockPrivateDatabase::default();
        let monitor = crate::util::task::DummyMonitor;

        let err = db.update_checkout_copy(None, 0, &monitor).unwrap_err();
        assert!(matches!(err, UpdateCheckoutCopyError::Io(_)));
    }

    #[test]
    fn test_db_moved_rejects_missing_directory() {
        let mut db = MockPrivateDatabase::default();
        let err = db.db_moved(Path::new("/does/not/exist/at/all")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
