use super::g_file::GFile;

/// A [`GFile`] along with a filesystem reference that keeps the filesystem pinned in memory.
///
/// The caller is responsible for releasing this object (dropping it or calling
/// [`RefdFile::close`]), which releases the filesystem reference.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.RefdFile`.  The type
/// parameter `R` stands in for `FileSystemRef` until that class is ported; any owned
/// type whose `Drop` impl releases the filesystem reference will satisfy the bound.
pub struct RefdFile<R, FS, Fsrl> {
    /// The filesystem reference that pins the owning filesystem open.
    pub fs_ref: R,
    /// The file inside the pinned filesystem.
    pub file: Box<dyn GFile<FS, Fsrl>>,
}

impl<R, FS, Fsrl> RefdFile<R, FS, Fsrl> {
    /// Creates a `RefdFile`, taking ownership of `fs_ref`.
    ///
    /// Mirrors `RefdFile(FileSystemRef, GFile)` from the Java source.
    pub fn new(fs_ref: R, file: Box<dyn GFile<FS, Fsrl>>) -> Self {
        RefdFile { fs_ref, file }
    }

    /// Releases the filesystem reference by consuming this `RefdFile`.
    ///
    /// Equivalent to Java's `Closeable.close()`: ownership of `fs_ref` is dropped here,
    /// which triggers its cleanup and unpins the owning filesystem.
    pub fn close(self) {
        // Moving self out of scope drops fs_ref, releasing the filesystem reference.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io;
    use std::rc::Rc;

    // ── Minimal GFile mock ────────────────────────────────────────────────────

    struct MockFs;
    struct MockFsrl;

    struct MockFile {
        name: &'static str,
    }

    impl GFile<MockFs, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFs {
            &MockFs
        }

        fn get_fsrl(&self) -> &MockFsrl {
            &MockFsrl
        }

        fn get_parent_file(&self) -> Option<&dyn GFile<MockFs, MockFsrl>> {
            None
        }

        fn get_path(&self) -> &str {
            self.name
        }

        fn get_name(&self) -> &str {
            self.name
        }

        fn is_directory(&self) -> bool {
            false
        }

        fn get_length(&self) -> i64 {
            0
        }

        fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            Err(io::Error::new(io::ErrorKind::Other, "not a directory"))
        }
    }

    // ── Drop-tracking filesystem ref mock ─────────────────────────────────────

    struct MockRef {
        closed: Rc<Cell<bool>>,
    }

    impl Drop for MockRef {
        fn drop(&mut self) {
            self.closed.set(true);
        }
    }

    fn make_ref() -> (MockRef, Rc<Cell<bool>>) {
        let flag = Rc::new(Cell::new(false));
        let r = MockRef { closed: Rc::clone(&flag) };
        (r, flag)
    }

    fn make_file(name: &'static str) -> Box<dyn GFile<MockFs, MockFsrl>> {
        Box::new(MockFile { name })
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn new_stores_fs_ref_and_file() {
        let (r, _flag) = make_ref();
        let refd = RefdFile::new(r, make_file("foo.txt"));
        assert_eq!(refd.file.get_name(), "foo.txt");
    }

    #[test]
    fn fs_ref_is_publicly_accessible() {
        let (r, flag) = make_ref();
        let refd = RefdFile::new(r, make_file("bar.bin"));
        // Access fs_ref directly (public field).
        assert!(!refd.fs_ref.closed.get());
        drop(refd);
        assert!(flag.get(), "fs_ref should be released when RefdFile is dropped");
    }

    #[test]
    fn close_releases_filesystem_ref() {
        let (r, flag) = make_ref();
        let refd = RefdFile::new(r, make_file("data.bin"));
        assert!(!flag.get());
        refd.close();
        assert!(flag.get(), "fs_ref should be released after close()");
    }

    #[test]
    fn drop_releases_filesystem_ref_without_explicit_close() {
        let (r, flag) = make_ref();
        {
            let _refd = RefdFile::new(r, make_file("temp.bin"));
            assert!(!flag.get());
        }
        assert!(flag.get(), "fs_ref should be released on drop");
    }

    #[test]
    fn file_field_is_publicly_accessible() {
        let (r, _flag) = make_ref();
        let refd = RefdFile::new(r, make_file("readme.txt"));
        assert_eq!(refd.file.get_name(), "readme.txt");
        assert!(!refd.file.is_directory());
    }
}
