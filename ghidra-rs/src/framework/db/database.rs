use std::io;

use thiserror::Error;

use crate::framework::db::db_handle::DBHandle;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error returned by [`Database::open`] and [`Database::open_for_update`], combining the checked
/// exceptions declared on `Database.open(TaskMonitor)` / `Database.openForUpdate(TaskMonitor)`
/// (`IOException` -- including the `FileInUseException` subtype thrown when the required database
/// lock(s) cannot be obtained -- and `CancelledException`).
#[derive(Error, Debug)]
pub enum OpenError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Facilitates the creation of a [`DBHandle`] for accessing a database.
///
/// Mirrors `db.Database`, an abstract class extended when additional management features are
/// needed, such as versioning (see e.g.
/// [`PrivateDatabase`](crate::framework::store::db::PrivateDatabase), which extends `db.Database`
/// in Java). Also referenced opaquely by
/// [`DBFileListener`](crate::framework::db::DBFileListener) before this port existed.
///
/// The `File dbDir`-based constructors are not represented as trait members, since Rust traits
/// cannot express `Self`-returning constructors while remaining object-safe (mirroring the
/// convention established by
/// [`PrivateDatabase`](crate::framework::store::db::PrivateDatabase)). Likewise,
/// `setSynchronizationObject` has no Rust equivalent -- implementors are expected to choose their
/// own interior-mutability/locking strategy instead of an externally supplied sync object.
pub trait Database {
    /// Returns the time at which this database was last saved.
    fn last_modified(&self) -> i64;

    /// Returns the version number associated with the latest buffer file version.
    fn get_current_version(&self) -> i32;

    /// Open the stored database for non-update use. The returned handle does not support the
    /// Save operation.
    ///
    /// # Errors
    /// Returns [`OpenError::Io`] (a `FileInUseException` if unable to obtain the required
    /// database lock(s)) or [`OpenError::Cancelled`] if cancelled via `monitor`.
    fn open(&self, monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError>;

    /// Open the stored database for update use.
    ///
    /// # Errors
    /// Returns [`OpenError::Io`] if update use is not permitted, or if unable to obtain the
    /// required database lock(s) (`FileInUseException`), or [`OpenError::Cancelled`] if
    /// cancelled via `monitor`.
    fn open_for_update(&self, monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError>;

    /// Returns the length of this domain file. This size is the minimum disk space used for
    /// storing this file, but does not account for additional storage space used to track
    /// changes, etc.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO or access error occurs.
    fn length(&self) -> io::Result<u64>;

    /// Scan files and update state.
    ///
    /// # Errors
    /// Returns an `io::Error` (a Java `FileNotFoundException`) if the database files are not
    /// found.
    fn refresh(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::cell::Cell;

    struct MockDatabase {
        current_version: Cell<i32>,
        last_modified: i64,
        update_allowed: bool,
    }

    impl Database for MockDatabase {
        fn last_modified(&self) -> i64 {
            self.last_modified
        }

        fn get_current_version(&self) -> i32 {
            self.current_version.get()
        }

        fn open(&self, _monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError> {
            Ok(DBHandle::new()?)
        }

        fn open_for_update(
            &self,
            monitor: Option<&dyn TaskMonitor>,
        ) -> Result<DBHandle, OpenError> {
            if !self.update_allowed {
                return Err(OpenError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Update use not permitted",
                )));
            }
            if let Some(m) = monitor {
                m.check_cancelled()?;
            }
            Ok(DBHandle::new()?)
        }

        fn length(&self) -> io::Result<u64> {
            Ok(4096)
        }

        fn refresh(&mut self) -> io::Result<()> {
            self.current_version.set(self.current_version.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn test_object_safe_dyn_usage_and_refresh() {
        let mut db: Box<dyn Database> = Box::new(MockDatabase {
            current_version: Cell::new(3),
            last_modified: 1000,
            update_allowed: true,
        });

        assert_eq!(db.get_current_version(), 3);
        assert_eq!(db.last_modified(), 1000);
        assert_eq!(db.length().unwrap(), 4096);

        let monitor = DummyMonitor;
        assert!(db.open(Some(&monitor)).is_ok());
        assert!(db.open_for_update(Some(&monitor)).is_ok());

        db.refresh().unwrap();
        assert_eq!(db.get_current_version(), 4);
    }

    #[test]
    fn test_open_for_update_rejected_when_not_allowed() {
        let db = MockDatabase {
            current_version: Cell::new(1),
            last_modified: 0,
            update_allowed: false,
        };

        let err = db.open_for_update(None).unwrap_err();
        assert!(matches!(err, OpenError::Io(_)));
    }
}
