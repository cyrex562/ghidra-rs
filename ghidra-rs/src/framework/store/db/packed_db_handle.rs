//! Port of `ghidra.framework.store.db.PackedDBHandle`.

use std::io;
use std::path::Path;

use crate::framework::db::db_handle::{DBHandle, SaveAsError};
use crate::framework::store::db::PackedDatabase;
use crate::util::task::TaskMonitor;

/// Provides access to a `PackedDatabase`.
///
/// Mirrors `ghidra.framework.store.db.PackedDBHandle`, which extends `db.DBHandle`; the Java
/// `extends` relationship is represented here as composition (`base: DBHandle`), per this
/// project's convention.
///
/// NOTE: If `saveAs` is used to save to a non-packed database, `pdb` becomes `None` and this
/// handle should behave like a normal `DBHandle`.
///
/// [`DBHandle`] itself is a reduced, in-memory-only stand-in for Java's real disk-backed,
/// checkpointed `db.DBHandle` (see its own doc comment) -- it does not (yet) implement `save`,
/// `close`, `isTransactionActive`, or a `BufferFile`-based `saveAs(BufferFile, Long, boolean,
/// TaskMonitor)` / `saveAs(BufferFile, boolean, TaskMonitor)` pair, only a single
/// [`DBHandle::save_as`] that writes straight to a fresh native-path file. This port's API
/// surface is adapted accordingly:
/// - The public `saveAs(BufferFile outFile, boolean associateWithNewFile, TaskMonitor monitor)`
///   override is represented by [`Self::save_as`], delegating to [`DBHandle::save_as`].
/// - `save(String comment, DBChangeSet changeSet, TaskMonitor monitor)` (which packs the
///   associated `PackedDatabase` after a successful save) and the convenience `save(TaskMonitor)`
///   are **not** mirrored: the composed `DBHandle` has no "save in place" operation to delegate
///   to, and [`PackedDatabase`]'s `packDatabase`/`unpackDatabase` are documented (on that trait)
///   as implementation-specific static/associated functions rather than trait methods, so there
///   is no object-safe way to invoke packing here either.
/// - The protected 4-arg `saveAs(BufferFile outFile, Long newDatabaseId, boolean
///   associateWithNewFile, TaskMonitor monitor)` override and `close()` are likewise not
///   mirrored, for the same reason.
///
/// One real quirk *is* preserved between the two `saveAs` overloads that Java declares: the
/// protected 4-arg `saveAs` unconditionally disposes an associated `PackedDatabase` (`if (pdb !=
/// null) { pdb.dispose(); pdb = null; }`), while the public 3-arg `saveAs` -- the one represented
/// here as [`Self::save_as`] -- only does so when `associateWithNewFile` is true. That
/// conditional-disposal behavior is what [`Self::save_as`] implements below.
pub struct PackedDBHandle {
    base: DBHandle,
    pdb: Option<Box<dyn PackedDatabase>>,
    content_type: String,
}

impl PackedDBHandle {
    /// Constructs a temporary packed database handle.
    ///
    /// Mirrors `PackedDBHandle(String contentType)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if the underlying [`DBHandle`] could not be constructed.
    pub fn new(content_type: impl Into<String>) -> io::Result<Self> {
        Ok(Self {
            base: DBHandle::new()?,
            pdb: None,
            content_type: content_type.into(),
        })
    }

    /// Constructs a database handle for an existing packed database, given a [`DBHandle`] already
    /// opened against that packed database's temporary unpacked copy.
    ///
    /// Mirrors the package-private `PackedDBHandle(PackedDatabase pdb, BufferFile bfile)`
    /// constructor, whose update mode is determined by `bfile` (it calls `super(bfile)`
    /// internally). Since the composed [`DBHandle`] has no `BufferFile`-based constructor to call
    /// on `pdb`'s behalf, this port instead accepts the already-opened handle directly, leaving
    /// that responsibility to the caller.
    pub(crate) fn from_existing(base: DBHandle, pdb: Box<dyn PackedDatabase>) -> Self {
        let content_type = pdb.get_content_type().to_string();
        Self { base, pdb: Some(pdb), content_type }
    }

    /// Returns a reference to the composed [`DBHandle`].
    pub fn base(&self) -> &DBHandle {
        &self.base
    }

    /// Returns a mutable reference to the composed [`DBHandle`].
    pub fn base_mut(&mut self) -> &mut DBHandle {
        &mut self.base
    }

    /// Saves the open database to `path`. If `associate_with_new_file` is true and a
    /// [`PackedDatabase`] was previously associated with this handle, it is disposed (its
    /// resources cleaned up) since this handle is no longer associated with it.
    ///
    /// Mirrors the public `saveAs(BufferFile outFile, boolean associateWithNewFile, TaskMonitor
    /// monitor)`.
    ///
    /// # Errors
    /// See [`DBHandle::save_as`].
    pub fn save_as(
        &mut self,
        path: &Path,
        associate_with_new_file: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SaveAsError> {
        self.base.save_as(path, associate_with_new_file, monitor)?;
        if associate_with_new_file {
            if let Some(mut pdb) = self.pdb.take() {
                pdb.dispose();
            }
        }
        Ok(())
    }

    /// Returns the user-defined content type associated with this handle.
    ///
    /// Mirrors `getContentType()`.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns the [`PackedDatabase`] associated with this handle, or `None` if this is a
    /// temporary handle which has not yet been associated with one.
    ///
    /// Mirrors `getPackedDatabase()`.
    pub fn packed_database(&self) -> Option<&dyn PackedDatabase> {
        self.pdb.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::database::{Database, OpenError};
    use crate::generic::jar::ResourceFile;
    use crate::framework::store::db::DeleteError;
    use std::cell::Cell;
    use std::path::PathBuf;

    struct MockPackedDatabase {
        content_type: String,
        packed_file: ResourceFile,
        disposed: Cell<bool>,
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
        fn open_for_update(&self, _monitor: Option<&dyn TaskMonitor>) -> Result<DBHandle, OpenError> {
            Ok(DBHandle::new()?)
        }
        fn length(&self) -> io::Result<u64> {
            Ok(0)
        }
        fn refresh(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PackedDatabase for MockPackedDatabase {
        fn is_read_only(&self) -> bool {
            false
        }
        fn get_content_type(&self) -> &str {
            &self.content_type
        }
        fn get_packed_file(&self) -> &ResourceFile {
            &self.packed_file
        }
        fn delete(&mut self) -> Result<(), DeleteError> {
            Ok(())
        }
        fn dispose(&mut self) {
            self.disposed.set(true);
        }
    }

    fn mock_pdb(content_type: &str) -> Box<dyn PackedDatabase> {
        Box::new(MockPackedDatabase {
            content_type: content_type.to_string(),
            packed_file: ResourceFile::new(PathBuf::from("/tmp/test.gpr")),
            disposed: Cell::new(false),
            current_version: Cell::new(1),
        })
    }

    #[test]
    fn new_handle_has_no_packed_database() {
        let handle = PackedDBHandle::new("Program").unwrap();
        assert_eq!(handle.content_type(), "Program");
        assert!(handle.packed_database().is_none());
    }

    #[test]
    fn from_existing_derives_content_type_from_packed_database() {
        let base = DBHandle::new().unwrap();
        let pdb = mock_pdb("Program");
        let handle = PackedDBHandle::from_existing(base, pdb);
        assert_eq!(handle.content_type(), "Program");
        assert!(handle.packed_database().is_some());
    }

    #[test]
    fn save_as_disposes_associated_packed_database_when_associating_with_new_file() {
        let base = DBHandle::new().unwrap();
        let pdb = mock_pdb("Program");
        let mut handle = PackedDBHandle::from_existing(base, pdb);

        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("saved.db");
        let monitor = crate::util::task::DummyMonitor;
        handle.save_as(&out_path, true, &monitor).unwrap();

        assert!(handle.packed_database().is_none());
        assert!(out_path.exists());
    }

    #[test]
    fn save_as_keeps_associated_packed_database_when_not_associating_with_new_file() {
        let base = DBHandle::new().unwrap();
        let pdb = mock_pdb("Program");
        let mut handle = PackedDBHandle::from_existing(base, pdb);

        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("saved.db");
        let monitor = crate::util::task::DummyMonitor;
        handle.save_as(&out_path, false, &monitor).unwrap();

        // Matches the public 3-arg `saveAs`'s conditional-disposal behavior (see this module's
        // doc comment): the associated `PackedDatabase` survives when `associateWithNewFile` is
        // false.
        assert!(handle.packed_database().is_some());
    }

    #[test]
    fn base_accessors_expose_the_composed_dbhandle() {
        let mut handle = PackedDBHandle::new("Program").unwrap();
        // Exercise both accessors against real `DBHandle` functionality.
        assert!(handle.base().get_table("nonexistent").is_none());
        let _ = handle.base_mut();
    }
}
