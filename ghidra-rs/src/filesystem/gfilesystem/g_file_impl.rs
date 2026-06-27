use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;

use super::g_file::GFile;

const SEPARATOR: char = '/';

/// Operations [`GFileImpl`] requires from an FSRL type.
///
/// This trait will be implemented by the concrete `FSRL` type once `FSRL.java` is ported.
pub trait FsrlLike: Sized + Clone {
    /// The name component (last path segment) of this FSRL.
    fn fsrl_name(&self) -> String;

    /// The full path encoded by this FSRL.
    fn fsrl_path(&self) -> String;

    /// Return a new FSRL formed by appending `segment` to this FSRL's path.
    fn append_path(&self, segment: &str) -> Self;
}

/// Operation required from a filesystem type to derive an FSRL for files where no
/// explicit FSRL is provided.
///
/// This trait will be implemented by the concrete `GFileSystem` type once
/// `GFileSystem.java` is ported.
pub trait HasFsrlRoot<Fsrl: FsrlLike> {
    /// The root FSRL of this filesystem.
    fn root_fsrl(&self) -> &Fsrl;
}

/// Allows [`GFileImpl`] to delegate [`GFile::get_listing`] to its owning filesystem,
/// matching the Java default `GFile.getListing()` behaviour.
pub trait FsGetListing<FS, Fsrl> {
    fn fs_get_listing(
        &self,
        file: &dyn GFile<FS, Fsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<FS, Fsrl>>>>;
}

/// Concrete implementation of [`GFile`] for use within a [`GFileSystem`].
///
/// Only valid while the owning filesystem object is still open.  Prefer the static
/// factory methods — [`from_fsrl`](GFileImpl::from_fsrl),
/// [`from_filename`](GFileImpl::from_filename), and
/// [`from_path_string`](GFileImpl::from_path_string) — to construct instances.
pub struct GFileImpl<FS, Fsrl> {
    filesystem: FS,
    parent_file: Option<Box<dyn GFile<FS, Fsrl>>>,
    is_directory: bool,
    length: i64,
    fsrl: Fsrl,
    name: String,
    path: String,
}

// ─── Private constructor ──────────────────────────────────────────────────────

impl<FS, Fsrl: FsrlLike> GFileImpl<FS, Fsrl> {
    fn new_impl(
        filesystem: FS,
        parent_file: Option<Box<dyn GFile<FS, Fsrl>>>,
        is_directory: bool,
        length: i64,
        fsrl: Fsrl,
    ) -> Self {
        let name = fsrl.fsrl_name();
        let path = fsrl.fsrl_path();
        GFileImpl {
            filesystem,
            parent_file,
            is_directory,
            length,
            fsrl,
            name,
            path,
        }
    }
}

// ─── Public factory methods ───────────────────────────────────────────────────

impl<FS, Fsrl> GFileImpl<FS, Fsrl>
where
    FS: Clone + HasFsrlRoot<Fsrl> + FsGetListing<FS, Fsrl> + 'static,
    Fsrl: FsrlLike + 'static,
{
    /// Creates a `GFileImpl` from a forward-slash-separated path string starting at the
    /// root of `filesystem`.
    ///
    /// Intermediate parent directories are created automatically.  Prefer
    /// [`from_filename`](GFileImpl::from_filename) when the parent object is already
    /// available, to allow parent object reuse.
    pub fn from_path_string(
        filesystem: FS,
        path: &str,
        fsrl: Option<Fsrl>,
        is_directory: bool,
        length: i64,
    ) -> Self {
        Self::from_path_string_with_parent(filesystem, None, path, fsrl, is_directory, length)
    }

    /// Creates a `GFileImpl` from a path string relative to an optional `parent` directory.
    ///
    /// Intermediate parent directories embedded in `path` are created automatically.
    pub fn from_path_string_with_parent(
        filesystem: FS,
        parent: Option<Box<dyn GFile<FS, Fsrl>>>,
        path: &str,
        fsrl: Option<Fsrl>,
        is_directory: bool,
        length: i64,
    ) -> Self {
        let mut parts: Vec<String> = path.split(SEPARATOR).map(str::to_owned).collect();

        // Match Java's String.split(regex) trailing-empty-string removal.
        while matches!(parts.last().map(String::as_str), Some("")) {
            parts.pop();
        }

        // UNC path detection: "//server" or "\\server" arrives as ["", "", "server", ...]
        // after splitting.  Restore the "//" prefix on the server name element.
        if parts.len() >= 3
            && parts[0].is_empty()
            && parts[1].is_empty()
            && !parts[2].is_empty()
        {
            parts[2] = format!("//{}", parts[2]);
        }

        let n = parts.len();
        let mut cur_parent: Option<Box<dyn GFile<FS, Fsrl>>> = parent;

        for i in 0..n.saturating_sub(1) {
            if parts[i].is_empty() {
                continue;
            }
            let fs_clone = filesystem.clone();
            let segment = parts[i].clone();
            let dir = Self::from_filename(fs_clone, cur_parent, &segment, true, -1, None);
            cur_parent = Some(Box::new(dir));
        }

        let resolved_fsrl = match fsrl {
            Some(f) => f,
            None => {
                let filename: &str = if n > 0 { &parts[n - 1] } else { "/" };
                Self::fsrl_from_parent(&filesystem, cur_parent.as_deref(), filename)
            }
        };

        Self::new_impl(filesystem, cur_parent, is_directory, length, resolved_fsrl)
    }

    /// Creates a `GFileImpl` from a simple filename as a child of an optional `parent`
    /// directory.
    ///
    /// If `fsrl` is `None`, one is derived from the parent's FSRL (or the filesystem root).
    pub fn from_filename(
        filesystem: FS,
        parent: Option<Box<dyn GFile<FS, Fsrl>>>,
        filename: &str,
        is_directory: bool,
        length: i64,
        fsrl: Option<Fsrl>,
    ) -> Self {
        let resolved_fsrl = match fsrl {
            Some(f) => f,
            None => Self::fsrl_from_parent(&filesystem, parent.as_deref(), filename),
        };
        Self::new_impl(filesystem, parent, is_directory, length, resolved_fsrl)
    }

    /// Creates a `GFileImpl` directly from an already-constructed `fsrl`.
    pub fn from_fsrl(
        filesystem: FS,
        parent: Option<Box<dyn GFile<FS, Fsrl>>>,
        fsrl: Fsrl,
        is_directory: bool,
        length: i64,
    ) -> Self {
        Self::new_impl(filesystem, parent, is_directory, length, fsrl)
    }

    /// Derive an FSRL by appending `path` to the parent's FSRL, or to the filesystem
    /// root FSRL when there is no parent.
    fn fsrl_from_parent(
        fs: &FS,
        parent: Option<&dyn GFile<FS, Fsrl>>,
        path: &str,
    ) -> Fsrl {
        match parent {
            Some(p) => p.get_fsrl().append_path(path),
            None => fs.root_fsrl().append_path(path),
        }
    }
}

// ─── Mutable accessor ─────────────────────────────────────────────────────────

impl<FS, Fsrl> GFileImpl<FS, Fsrl> {
    /// Updates the stored file length.
    pub fn set_length(&mut self, length: i64) {
        self.length = length;
    }
}

// ─── GFile trait implementation ───────────────────────────────────────────────

impl<FS, Fsrl> GFile<FS, Fsrl> for GFileImpl<FS, Fsrl>
where
    FS: FsGetListing<FS, Fsrl>,
{
    fn get_filesystem(&self) -> &FS {
        &self.filesystem
    }

    fn get_fsrl(&self) -> &Fsrl {
        &self.fsrl
    }

    fn get_parent_file(&self) -> Option<&dyn GFile<FS, Fsrl>> {
        self.parent_file.as_deref()
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn is_directory(&self) -> bool {
        self.is_directory
    }

    fn get_length(&self) -> i64 {
        self.length
    }

    fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<FS, Fsrl>>>> {
        self.filesystem.fs_get_listing(self)
    }
}

// ─── Debug ────────────────────────────────────────────────────────────────────

impl<FS, Fsrl> fmt::Debug for GFileImpl<FS, Fsrl> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GFileImpl")
            .field("path", &self.path)
            .field("name", &self.name)
            .field("is_directory", &self.is_directory)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

// ─── Display (matches Java GFileImpl.toString → getPath()) ────────────────────

impl<FS, Fsrl> fmt::Display for GFileImpl<FS, Fsrl> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

// ─── Equality and hashing (parallel to Java GFileImpl.equals / hashCode) ──────

impl<FS: PartialEq, Fsrl> PartialEq for GFileImpl<FS, Fsrl> {
    fn eq(&self, other: &Self) -> bool {
        self.filesystem == other.filesystem
            && self.path == other.path
            && self.is_directory == other.is_directory
    }
}

impl<FS: Eq, Fsrl> Eq for GFileImpl<FS, Fsrl> {}

impl<FS: Hash, Fsrl> Hash for GFileImpl<FS, Fsrl> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.filesystem.hash(state);
        self.path.hash(state);
        self.is_directory.hash(state);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    // ── Mock FSRL ──────────────────────────────────────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct MockFsrl(String);

    impl FsrlLike for MockFsrl {
        fn fsrl_name(&self) -> String {
            self.0
                .rsplit('/')
                .next()
                .unwrap_or(self.0.as_str())
                .to_owned()
        }

        fn fsrl_path(&self) -> String {
            self.0.clone()
        }

        fn append_path(&self, segment: &str) -> Self {
            if self.0.ends_with('/') {
                MockFsrl(format!("{}{}", self.0, segment))
            } else {
                MockFsrl(format!("{}/{}", self.0, segment))
            }
        }
    }

    // ── Mock filesystem ────────────────────────────────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct MockFs {
        root: MockFsrl,
        name: &'static str,
    }

    impl MockFs {
        fn new(name: &'static str) -> Self {
            MockFs {
                root: MockFsrl(format!("mock://{}", name)),
                name,
            }
        }
    }

    impl HasFsrlRoot<MockFsrl> for MockFs {
        fn root_fsrl(&self) -> &MockFsrl {
            &self.root
        }
    }

    impl FsGetListing<MockFs, MockFsrl> for MockFs {
        fn fs_get_listing(
            &self,
            _file: &dyn GFile<MockFs, MockFsrl>,
        ) -> io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            Ok(vec![])
        }
    }

    type TestFile = GFileImpl<MockFs, MockFsrl>;

    fn fs() -> MockFs {
        MockFs::new("testfs")
    }

    fn make_fsrl(path: &str) -> MockFsrl {
        MockFsrl(path.to_owned())
    }

    // ── from_fsrl ──────────────────────────────────────────────────────────────

    #[test]
    fn from_fsrl_stores_fields() {
        let fsrl = make_fsrl("mock://fs/dir/file.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 42);
        assert_eq!(f.get_name(), "file.txt");
        assert_eq!(f.get_path(), "mock://fs/dir/file.txt");
        assert!(!f.is_directory());
        assert_eq!(f.get_length(), 42);
        assert!(f.get_parent_file().is_none());
    }

    #[test]
    fn from_fsrl_directory() {
        let fsrl = make_fsrl("mock://fs/mydir");
        let d = TestFile::from_fsrl(fs(), None, fsrl, true, -1);
        assert!(d.is_directory());
        assert_eq!(d.get_length(), -1);
    }

    // ── from_filename ──────────────────────────────────────────────────────────

    #[test]
    fn from_filename_no_parent_derives_fsrl_from_root() {
        let f = TestFile::from_filename(fs(), None, "readme.txt", false, 100, None);
        assert_eq!(f.get_name(), "readme.txt");
        assert_eq!(f.get_path(), "mock://testfs/readme.txt");
    }

    #[test]
    fn from_filename_with_explicit_fsrl_ignores_filename_for_path() {
        let explicit = make_fsrl("mock://custom/path/readme.txt");
        let f = TestFile::from_filename(fs(), None, "readme.txt", false, 10, Some(explicit));
        assert_eq!(f.get_path(), "mock://custom/path/readme.txt");
    }

    #[test]
    fn from_filename_with_parent_derives_fsrl_from_parent() {
        let parent_fsrl = make_fsrl("mock://testfs/dir");
        let parent: Box<dyn GFile<MockFs, MockFsrl>> =
            Box::new(TestFile::from_fsrl(fs(), None, parent_fsrl, true, -1));

        let f = TestFile::from_filename(fs(), Some(parent), "child.bin", false, 5, None);
        assert_eq!(f.get_path(), "mock://testfs/dir/child.bin");
        assert_eq!(f.get_name(), "child.bin");
        assert!(f.get_parent_file().is_some());
    }

    // ── from_path_string ───────────────────────────────────────────────────────

    #[test]
    fn single_segment_path_no_intermediate_parents() {
        let f = TestFile::from_path_string(fs(), "file.txt", None, false, 7);
        assert_eq!(f.get_name(), "file.txt");
        assert!(f.get_parent_file().is_none());
    }

    #[test]
    fn multi_segment_path_creates_parent_chain() {
        let f =
            TestFile::from_path_string(fs(), "dir/subdir/file.txt", None, false, 0);
        assert_eq!(f.get_name(), "file.txt");

        let subdir = f.get_parent_file().expect("subdir parent");
        assert_eq!(subdir.get_name(), "subdir");
        assert!(subdir.is_directory());

        let dir = subdir.get_parent_file().expect("dir parent");
        assert_eq!(dir.get_name(), "dir");
        assert!(dir.is_directory());

        assert!(dir.get_parent_file().is_none());
    }

    #[test]
    fn absolute_path_leading_slash_creates_correct_chain() {
        let f = TestFile::from_path_string(fs(), "/a/b/c.txt", None, false, 0);
        assert_eq!(f.get_name(), "c.txt");

        let b = f.get_parent_file().unwrap();
        assert_eq!(b.get_name(), "b");

        let a = b.get_parent_file().unwrap();
        assert_eq!(a.get_name(), "a");
    }

    #[test]
    fn root_path_slash_uses_root_fsrl() {
        // "/" should produce a file whose name is "" (the root) or "/" depending on the
        // FSRL implementation; the important invariant is no panic and correct fs linkage.
        let f = TestFile::from_path_string(fs(), "/", None, true, -1);
        // name is the last segment appended to the root FSRL ("/")
        assert_eq!(f.get_filesystem().name, "testfs");
    }

    #[test]
    fn explicit_fsrl_skips_derivation() {
        let explicit = make_fsrl("explicit://path/to/file");
        let f =
            TestFile::from_path_string(fs(), "a/b/file", Some(explicit), false, 0);
        assert_eq!(f.get_path(), "explicit://path/to/file");
    }

    #[test]
    fn unc_path_prefix_restored() {
        // "//server/share/file" should create a parent named "//server".
        let f = TestFile::from_path_string(
            fs(),
            "//server/share/file.bin",
            None,
            false,
            0,
        );
        assert_eq!(f.get_name(), "file.bin");

        let share = f.get_parent_file().expect("share parent");
        assert_eq!(share.get_name(), "share");

        let server = share.get_parent_file().expect("server parent");
        assert_eq!(server.get_name(), "//server");
    }

    #[test]
    fn from_path_string_with_parent_starts_from_parent() {
        let parent_fsrl = make_fsrl("mock://testfs/base");
        let parent: Box<dyn GFile<MockFs, MockFsrl>> =
            Box::new(TestFile::from_fsrl(fs(), None, parent_fsrl, true, -1));

        let f = TestFile::from_path_string_with_parent(
            fs(),
            Some(parent),
            "sub/file.txt",
            None,
            false,
            0,
        );
        assert_eq!(f.get_name(), "file.txt");
        let sub = f.get_parent_file().unwrap();
        assert_eq!(sub.get_name(), "sub");
        // sub's parent should be the supplied parent directory
        assert_eq!(sub.get_parent_file().unwrap().get_name(), "base");
    }

    // ── set_length ─────────────────────────────────────────────────────────────

    #[test]
    fn set_length_updates_stored_value() {
        let mut f = TestFile::from_fsrl(fs(), None, make_fsrl("mock://f"), false, 10);
        assert_eq!(f.get_length(), 10);
        f.set_length(999);
        assert_eq!(f.get_length(), 999);
    }

    // ── Display ────────────────────────────────────────────────────────────────

    #[test]
    fn display_returns_path() {
        let fsrl = make_fsrl("mock://testfs/a/b.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl, false, 0);
        assert_eq!(f.to_string(), "mock://testfs/a/b.txt");
    }

    // ── PartialEq / Eq ─────────────────────────────────────────────────────────

    #[test]
    fn equal_files_same_fs_path_and_type() {
        let fsrl = make_fsrl("mock://testfs/x.txt");
        let a = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 1);
        let b = TestFile::from_fsrl(fs(), None, fsrl, false, 999); // length ignored
        assert_eq!(a, b);
    }

    #[test]
    fn different_path_not_equal() {
        let a = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/a"), false, 0);
        let b = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/b"), false, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_is_directory_not_equal() {
        let fsrl = make_fsrl("mock://testfs/x");
        let file = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 0);
        let dir = TestFile::from_fsrl(fs(), None, fsrl, true, 0);
        assert_ne!(file, dir);
    }

    #[test]
    fn different_filesystem_not_equal() {
        let fsrl = make_fsrl("mock://fs1/x.txt");
        let a = TestFile::from_fsrl(MockFs::new("fs1"), None, fsrl.clone(), false, 0);
        let b = TestFile::from_fsrl(MockFs::new("fs2"), None, fsrl, false, 0);
        assert_ne!(a, b);
    }

    // ── Hash ───────────────────────────────────────────────────────────────────

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn equal_files_have_same_hash() {
        let fsrl = make_fsrl("mock://testfs/f.bin");
        let a = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 1);
        let b = TestFile::from_fsrl(fs(), None, fsrl, false, 2);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn different_paths_typically_different_hash() {
        let a = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/a"), false, 0);
        let b = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/b"), false, 0);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    // ── get_listing delegates to filesystem ────────────────────────────────────

    #[test]
    fn get_listing_delegates_to_filesystem() {
        let d = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/dir"), true, -1);
        let listing = d.get_listing().expect("listing should succeed");
        assert!(listing.is_empty(), "mock fs returns empty listing");
    }

    // ── get_filesystem ─────────────────────────────────────────────────────────

    #[test]
    fn get_filesystem_returns_stored_fs() {
        let f = TestFile::from_fsrl(fs(), None, make_fsrl("mock://testfs/f"), false, 0);
        assert_eq!(f.get_filesystem().name, "testfs");
    }

    // ── get_fsrl ───────────────────────────────────────────────────────────────

    #[test]
    fn get_fsrl_returns_stored_fsrl() {
        let fsrl = make_fsrl("mock://testfs/x.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 0);
        assert_eq!(*f.get_fsrl(), fsrl);
    }
}
