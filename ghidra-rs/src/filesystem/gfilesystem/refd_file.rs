//! Port of `ghidra.formats.gfilesystem.RefdFile`.

use super::file_system_ref::FileSystemRef;
use super::file_system_ref_manager::FileSystemRefManagerError;
use super::g_file_system::DynGFile;

/// A [`GFile`](super::g_file::GFile) along with a [`FileSystemRef`] that keeps its filesystem
/// pinned in memory.
///
/// The caller is responsible for releasing this object ([`close`](RefdFile::close), or
/// dropping it -- the ref releases itself on drop).
///
/// Mirrors `ghidra.formats.gfilesystem.RefdFile`. The file is the type-erased
/// [`DynGFile`] that [`FileSystemService`](super::file_system_service::FileSystemService)
/// lookups produce.
pub struct RefdFile {
    /// The filesystem reference that pins the owning filesystem open.
    pub fs_ref: FileSystemRef,
    /// The file inside the pinned filesystem.
    pub file: DynGFile,
}

impl RefdFile {
    /// Creates a `RefdFile`, taking ownership of `fs_ref`. Mirrors
    /// `RefdFile(FileSystemRef, GFile)`.
    pub fn new(fs_ref: FileSystemRef, file: DynGFile) -> Self {
        RefdFile { fs_ref, file }
    }

    /// Releases the filesystem reference. Mirrors `close()`.
    ///
    /// # Errors
    /// If the ref was already released.
    pub fn close(mut self) -> Result<(), FileSystemRefManagerError> {
        self.fs_ref.close()
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::super::file_system_ref_manager::test_support::EmptyFs;
    use super::super::fsrl::Fsrl;
    use super::super::g_file::GFile;
    use super::super::g_file_system::FsHandle;
    use super::*;

    #[test]
    fn close_releases_the_ref() {
        let fs: FsHandle = Rc::new(EmptyFs::new("empty"));
        let fs_ref = fs.get_ref_manager().create(&fs).unwrap();
        // A file handle only needs an FSRL here; `()` stands in for the owning fs handle.
        let file = test_file(Fsrl::from_string("empty:///a.txt").unwrap());
        let refd = RefdFile::new(fs_ref, Box::new(file));
        assert_eq!(refd.file.get_name(), "a.txt");
        assert_eq!(fs.get_ref_manager().ref_count(), 1);
        refd.close().unwrap();
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }

    #[test]
    fn drop_releases_the_ref() {
        let fs: FsHandle = Rc::new(EmptyFs::new("empty"));
        {
            let fs_ref = fs.get_ref_manager().create(&fs).unwrap();
            let file = test_file(Fsrl::from_string("empty:///b").unwrap());
            let _refd = RefdFile::new(fs_ref, Box::new(file));
        }
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }

    /// A trivial file-handle type for building test files.
    struct Unit;

    struct F(Fsrl, String);

    impl GFile<Unit> for F {
        fn get_filesystem(&self) -> &Unit {
            &Unit
        }
        fn get_fsrl(&self) -> &Fsrl {
            &self.0
        }
        fn get_parent_file(&self) -> Option<&dyn GFile<Unit>> {
            None
        }
        fn get_path(&self) -> &str {
            self.0.path().unwrap_or("")
        }
        fn get_name(&self) -> &str {
            &self.1
        }
        fn is_directory(&self) -> bool {
            false
        }
        fn get_length(&self) -> i64 {
            0
        }
        fn get_listing(&self) -> std::io::Result<Vec<Box<dyn GFile<Unit>>>> {
            Ok(Vec::new())
        }
    }

    fn test_file(fsrl: Fsrl) -> Box<dyn GFile<Unit>> {
        let name = fsrl.name().unwrap_or_default();
        Box::new(F(fsrl, name))
    }
}
