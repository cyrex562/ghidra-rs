use std::io;

use thiserror::Error;

use crate::framework::db::database::Database;
use crate::generic::jar::ResourceFile;
use crate::util::ReadOnlyException;

/// Error type returned by [`PackedDatabase::delete`], combining the checked exceptions declared
/// on `PackedDatabase.delete()` (`ReadOnlyException`, `IOException`).
#[derive(Error, Debug)]
pub enum DeleteError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    ReadOnly(#[from] ReadOnlyException),
}

/// A packed form of [`Database`] which compresses a single version into a file.
///
/// Mirrors `ghidra.framework.store.db.PackedDatabase`, which extends `db.Database`; that
/// relationship is preserved via the [`Database`] supertrait. When opening a packed database, an
/// implementation is expected to unpack the file into a temporary database directory and expose a
/// handle to that expanded copy via the inherited [`Database::open`]/[`Database::open_for_update`].
///
/// The `getPackedDatabase`/`unpackDatabase`/`packDatabase`/`cleanupOldTempDatabases`/
/// `isReadOnlyPDBDirectory`/`delete(File)` static factory and utility methods are not represented
/// as trait members, since Rust traits cannot express `Self`-returning constructors while
/// remaining object safe (mirroring the convention established by
/// [`PrivateDatabase`](crate::framework::store::db::PrivateDatabase)); implementors are expected
/// to provide their own associated functions for these, mirroring the convention established by
/// [`LocalFileSystem`](crate::framework::store::local::LocalFileSystem).
pub trait PackedDatabase: Database {
    /// Returns true if this database is backed by a read-only directory lock, which prevents the
    /// creation or modification of any packed database files.
    fn is_read_only(&self) -> bool;

    /// Returns the user defined content type associated with this database.
    fn get_content_type(&self) -> &str;

    /// Returns the storage file associated with this packed database.
    fn get_packed_file(&self) -> &ResourceFile;

    /// Deletes the storage file associated with this packed database. This method should not be
    /// called while the database is open; if it is, an attempt will be made to close the handle
    /// first.
    ///
    /// # Errors
    /// Returns [`DeleteError::ReadOnly`] if backed by a read-only directory lock, preventing file
    /// removal, or [`DeleteError::Io`] if the file is in use or write protected.
    fn delete(&mut self) -> Result<(), DeleteError>;

    /// Free resources consumed by this object. If there is an associated database handle it will
    /// be closed.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::database::OpenError;
    use crate::framework::db::db_handle::DBHandle;
    use crate::util::task::TaskMonitor;
    use std::cell::Cell;
    use std::path::PathBuf;

    struct MockPackedDatabase {
        read_only: bool,
        content_type: String,
        packed_file: ResourceFile,
        disposed: Cell<bool>,
        deleted: Cell<bool>,
        current_version: Cell<i32>,
    }

    impl Database for MockPackedDatabase {
        fn last_modified(&self) -> i64 {
            0
        }

        fn get_current_version(&self) -> i32 {
            self.current_version.get()
        }

        fn open(&self, _monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError> {
            Ok(DBHandle::new()?)
        }

        fn open_for_update(
            &self,
            _monitor: Option<&dyn TaskMonitor>,
        ) -> Result<DBHandle, OpenError> {
            if self.read_only {
                return Err(OpenError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Read-only DB directory lock, file update not allowed",
                )));
            }
            Ok(DBHandle::new()?)
        }

        fn length(&self) -> io::Result<u64> {
            Ok(0)
        }

        fn refresh(&mut self) -> io::Result<()> {
            self.current_version.set(self.current_version.get() + 1);
            Ok(())
        }
    }

    impl PackedDatabase for MockPackedDatabase {
        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn get_content_type(&self) -> &str {
            &self.content_type
        }

        fn get_packed_file(&self) -> &ResourceFile {
            &self.packed_file
        }

        fn delete(&mut self) -> Result<(), DeleteError> {
            if self.read_only {
                return Err(DeleteError::ReadOnly(ReadOnlyException::default()));
            }
            self.deleted.set(true);
            Ok(())
        }

        fn dispose(&mut self) {
            self.disposed.set(true);
        }
    }

    #[test]
    fn test_object_safe_dyn_usage_and_delete_lifecycle() {
        let mut db: Box<dyn PackedDatabase> = Box::new(MockPackedDatabase {
            read_only: false,
            content_type: "Program".to_string(),
            packed_file: ResourceFile::new(PathBuf::from("/tmp/test.gpr")),
            disposed: Cell::new(false),
            deleted: Cell::new(false),
            current_version: Cell::new(1),
        });

        assert!(!db.is_read_only());
        assert_eq!(db.get_content_type(), "Program");
        assert_eq!(db.get_packed_file().name(), "test.gpr");

        assert!(db.open(None).is_ok());
        db.refresh().unwrap();
        assert_eq!(db.get_current_version(), 2);

        assert!(db.delete().is_ok());
        db.dispose();
    }

    #[test]
    fn test_delete_and_update_rejected_for_read_only_directory() {
        let mut db = MockPackedDatabase {
            read_only: true,
            content_type: "Program".to_string(),
            packed_file: ResourceFile::new(PathBuf::from("/tmp/test.gpr")),
            disposed: Cell::new(false),
            deleted: Cell::new(false),
            current_version: Cell::new(1),
        };

        let err = db.delete().unwrap_err();
        assert!(matches!(err, DeleteError::ReadOnly(_)));
        assert!(!db.deleted.get());

        let err = db.open_for_update(None).unwrap_err();
        assert!(matches!(err, OpenError::Io(_)));
    }
}
