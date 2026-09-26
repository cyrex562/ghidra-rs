//! Port of `ghidra.formats.gfilesystem.FileSystemRef`.
//!
//! A handle to a filesystem that pins it (tells its
//! [`FileSystemRefManager`](super::file_system_ref_manager::FileSystemRefManager) someone is
//! still using it). Refs are created by the ref manager and must be closed when no longer
//! needed.
//!
//! Java's `finalize()` only *warns* if a ref is garbage-collected while still open. Rust has
//! deterministic destruction, so a ref that is dropped unclosed is closed (released from its
//! manager) instead -- the RAII reading of Java's `Closeable`.

use std::fmt;

use super::file_system_ref_manager::FileSystemRefManagerError;
use super::g_file_system::FsHandle;

/// The identity of one [`FileSystemRef`] within its filesystem's ref manager (Java compares
/// the ref objects themselves with `==`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileSystemRefId(pub(super) u64);

/// A handle to a filesystem which allows tracking the current users of the filesystem.
///
/// Mirrors `ghidra.formats.gfilesystem.FileSystemRef`.
pub struct FileSystemRef {
    fs: FsHandle,
    id: FileSystemRefId,
    ref_closed: bool,
}

impl FileSystemRef {
    /// Only [`FileSystemRefManager::create`](super::file_system_ref_manager::FileSystemRefManager::create)
    /// creates refs (Java's constructor is package-private).
    pub(super) fn new(fs: FsHandle, id: FileSystemRefId) -> Self {
        FileSystemRef { fs, id, ref_closed: false }
    }

    /// Creates a duplicate ref to the same filesystem. Mirrors `dup()`.
    ///
    /// # Errors
    /// If the filesystem has been closed.
    pub fn dup(&self) -> Result<FileSystemRef, FileSystemRefManagerError> {
        self.fs.get_ref_manager().create(&self.fs)
    }

    /// The filesystem this ref points to. Mirrors `getFilesystem()`.
    pub fn get_filesystem(&self) -> &FsHandle {
        &self.fs
    }

    /// This ref's identity within its ref manager.
    pub fn id(&self) -> FileSystemRefId {
        self.id
    }

    /// Closes this reference, releasing it from the filesystem's ref manager. Mirrors
    /// `close()`.
    ///
    /// # Errors
    /// [`FileSystemRefManagerError::UnknownRef`] if the manager no longer knows this ref (it was
    /// already closed, or the filesystem was closed underneath it) -- Java's
    /// `IllegalArgumentException`. The ref is marked closed either way.
    pub fn close(&mut self) -> Result<(), FileSystemRefManagerError> {
        let result = self.fs.get_ref_manager().release(&*self.fs, self.id);
        self.ref_closed = true;
        result
    }

    /// Returns `true` if this ref was [`close`](FileSystemRef::close)d. Mirrors `isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.ref_closed
    }
}

impl Drop for FileSystemRef {
    fn drop(&mut self) {
        if !self.ref_closed && !self.fs.get_ref_manager().is_closed() {
            let _ = self.close();
        }
    }
}

/// Mirrors `toString()`: the filesystem's FSRL.
impl fmt::Display for FileSystemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fs.get_fsrl())
    }
}

impl fmt::Debug for FileSystemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileSystemRef({}, {:?}, closed={})", self.fs.get_fsrl(), self.id, self.ref_closed)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::super::file_system_ref_manager::test_support::EmptyFs;
    use super::*;

    fn fs() -> FsHandle {
        Rc::new(EmptyFs::new("empty"))
    }

    #[test]
    fn new_ref_is_open_and_points_at_fs() {
        let fs = fs();
        let r = fs.get_ref_manager().create(&fs).unwrap();
        assert!(!r.is_closed());
        assert!(Rc::ptr_eq(r.get_filesystem(), &fs));
        assert_eq!(r.to_string(), "empty://");
    }

    #[test]
    fn dup_is_independent() {
        let fs = fs();
        let mut r1 = fs.get_ref_manager().create(&fs).unwrap();
        let r2 = r1.dup().unwrap();
        r1.close().unwrap();
        assert!(r1.is_closed());
        assert!(!r2.is_closed());
        assert_eq!(fs.get_ref_manager().ref_count(), 1);
    }

    #[test]
    fn double_close_is_unknown_ref() {
        let fs = fs();
        let mut r = fs.get_ref_manager().create(&fs).unwrap();
        r.close().unwrap();
        assert!(matches!(r.close(), Err(FileSystemRefManagerError::UnknownRef(_))));
    }

    #[test]
    fn dropping_an_open_ref_releases_it() {
        let fs = fs();
        {
            let _r = fs.get_ref_manager().create(&fs).unwrap();
            assert_eq!(fs.get_ref_manager().ref_count(), 1);
        }
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }

    #[test]
    fn dup_after_fs_close_fails() {
        let fs = fs();
        let r = fs.get_ref_manager().create(&fs).unwrap();
        fs.close().unwrap();
        assert!(matches!(r.dup(), Err(FileSystemRefManagerError::FileSystemAlreadyClosed(_))));
        // Dropping the ref after the manager closed must not panic.
        drop(r);
    }
}
