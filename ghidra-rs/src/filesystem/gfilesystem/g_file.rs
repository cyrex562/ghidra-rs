use std::io;

/// Represents a file in a [`GFileSystem`] filesystem.
///
/// Only valid while the owning filesystem object is still open and not closed.
///
/// The type parameters `FS` and `Fsrl` represent the filesystem and FSRL types
/// respectively; they will be instantiated with the concrete Rust ports of `GFileSystem`
/// and `FSRL` once those classes are ported.
pub trait GFile<FS, Fsrl> {
    /// The filesystem that owns this file.
    fn get_filesystem(&self) -> &FS;

    /// The FSRL (File System Resource Locator) of this file.
    fn get_fsrl(&self) -> &Fsrl;

    /// The parent directory of this file, or `None` for the root.
    fn get_parent_file(&self) -> Option<&dyn GFile<FS, Fsrl>>;

    /// The path and filename of this file, relative to its owning filesystem.
    fn get_path(&self) -> &str;

    /// The name of this file.
    fn get_name(&self) -> &str;

    /// Returns `true` if this is a directory.
    fn is_directory(&self) -> bool;

    /// Returns the length of this file in bytes, or `-1` if not known.
    fn get_length(&self) -> i64;

    /// Returns a listing of files in this sub-directory.
    ///
    /// # Errors
    /// Returns an error if this file is not a directory or if accessing the listing fails.
    fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<FS, Fsrl>>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFs {
        pub name: &'static str,
    }

    struct MockFsrl {
        pub path: String,
    }

    struct MockFile {
        fs: MockFs,
        fsrl: MockFsrl,
        path: String,
        name: String,
        is_dir: bool,
        length: i64,
        children: Vec<MockFile>,
    }

    impl MockFile {
        fn file(path: &str, name: &str, length: i64) -> Self {
            MockFile {
                fs: MockFs { name: "testfs" },
                fsrl: MockFsrl { path: path.to_owned() },
                path: path.to_owned(),
                name: name.to_owned(),
                is_dir: false,
                length,
                children: vec![],
            }
        }

        fn dir(path: &str, name: &str) -> Self {
            MockFile {
                fs: MockFs { name: "testfs" },
                fsrl: MockFsrl { path: path.to_owned() },
                path: path.to_owned(),
                name: name.to_owned(),
                is_dir: true,
                length: -1,
                children: vec![],
            }
        }
    }

    impl GFile<MockFs, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFs {
            &self.fs
        }

        fn get_fsrl(&self) -> &MockFsrl {
            &self.fsrl
        }

        fn get_parent_file(&self) -> Option<&dyn GFile<MockFs, MockFsrl>> {
            None
        }

        fn get_path(&self) -> &str {
            &self.path
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn is_directory(&self) -> bool {
            self.is_dir
        }

        fn get_length(&self) -> i64 {
            self.length
        }

        fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            if !self.is_dir {
                return Err(io::Error::new(io::ErrorKind::Other, "not a directory"));
            }
            Ok(self
                .children
                .iter()
                .map(|c| -> Box<dyn GFile<MockFs, MockFsrl>> {
                    Box::new(MockFile::file(c.path.as_str(), c.name.as_str(), c.length))
                })
                .collect())
        }
    }

    #[test]
    fn get_path_returns_full_path() {
        let f = MockFile::file("/foo/bar.txt", "bar.txt", 42);
        assert_eq!(f.get_path(), "/foo/bar.txt");
    }

    #[test]
    fn get_name_returns_filename() {
        let f = MockFile::file("/foo/bar.txt", "bar.txt", 42);
        assert_eq!(f.get_name(), "bar.txt");
    }

    #[test]
    fn is_directory_false_for_regular_file() {
        let f = MockFile::file("/foo/bar.txt", "bar.txt", 100);
        assert!(!f.is_directory());
    }

    #[test]
    fn is_directory_true_for_directory() {
        let d = MockFile::dir("/foo", "foo");
        assert!(d.is_directory());
    }

    #[test]
    fn get_length_returns_byte_count() {
        let f = MockFile::file("/a", "a", 1024);
        assert_eq!(f.get_length(), 1024);
    }

    #[test]
    fn get_length_minus_one_when_unknown() {
        let d = MockFile::dir("/root", "root");
        assert_eq!(d.get_length(), -1);
    }

    #[test]
    fn get_parent_file_none_for_root() {
        let f = MockFile::file("/a.txt", "a.txt", 0);
        assert!(f.get_parent_file().is_none());
    }

    #[test]
    fn get_filesystem_returns_associated_fs() {
        let f = MockFile::file("/a.txt", "a.txt", 0);
        assert_eq!(f.get_filesystem().name, "testfs");
    }

    #[test]
    fn get_fsrl_returns_associated_fsrl() {
        let f = MockFile::file("/a.txt", "a.txt", 0);
        assert_eq!(f.get_fsrl().path, "/a.txt");
    }

    #[test]
    fn get_listing_errors_on_regular_file() {
        let f = MockFile::file("/a.txt", "a.txt", 10);
        let err = f.get_listing().err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn get_listing_returns_empty_for_empty_dir() {
        let d = MockFile::dir("/empty", "empty");
        let listing = d.get_listing().unwrap();
        assert!(listing.is_empty());
    }

    #[test]
    fn get_listing_returns_children() {
        let mut d = MockFile::dir("/mydir", "mydir");
        d.children.push(MockFile::file("/mydir/a.txt", "a.txt", 5));
        d.children.push(MockFile::file("/mydir/b.txt", "b.txt", 10));
        let listing = d.get_listing().unwrap();
        assert_eq!(listing.len(), 2);
        assert_eq!(listing[0].get_name(), "a.txt");
        assert_eq!(listing[1].get_name(), "b.txt");
    }
}
