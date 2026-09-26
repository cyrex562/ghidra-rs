use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;

use super::fsrl::Fsrl;
use super::g_file::GFile;

const SEPARATOR: char = '/';

/// Operation required from a filesystem type to derive an FSRL for files where no
/// explicit FSRL is provided.
///
/// Implemented by the filesystem handle types that own [`GFileImpl`]s (Java reads
/// `fileSystem.getFSRL()` directly; the handle types here are not `GFileSystem`s themselves).
pub trait HasFsrlRoot {
    /// The root FSRL of this filesystem.
    fn root_fsrl(&self) -> &Fsrl;
}

/// Allows [`GFileImpl`] to delegate [`GFile::get_listing`] to its owning filesystem,
/// matching the Java default `GFile.getListing()` behaviour.
pub trait FsGetListing<FS> {
    fn fs_get_listing(
        &self,
        file: &dyn GFile<FS>,
    ) -> io::Result<Vec<Box<dyn GFile<FS>>>>;
}

/// Concrete implementation of [`GFile`] for use within a [`GFileSystem`].
///
/// Only valid while the owning filesystem object is still open.  Prefer the static
/// factory methods — [`from_fsrl`](GFileImpl::from_fsrl),
/// [`from_filename`](GFileImpl::from_filename), and
/// [`from_path_string`](GFileImpl::from_path_string) — to construct instances.
pub struct GFileImpl<FS> {
    filesystem: FS,
    parent_file: Option<Box<dyn GFile<FS>>>,
    is_directory: bool,
    length: i64,
    fsrl: Fsrl,
    name: String,
    path: String,
}

// ─── Private constructor ──────────────────────────────────────────────────────

impl<FS> GFileImpl<FS> {
    fn new_impl(
        filesystem: FS,
        parent_file: Option<Box<dyn GFile<FS>>>,
        is_directory: bool,
        length: i64,
        fsrl: Fsrl,
    ) -> Self {
        // Java: `name = fsrl.getName(); path = fsrl.getPath();` (empty for a path-less FSRL).
        let name = fsrl.name().unwrap_or_default();
        let path = fsrl.path().unwrap_or_default().to_owned();
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

impl<FS> GFileImpl<FS>
where
    FS: Clone + HasFsrlRoot + FsGetListing<FS> + 'static,
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
        parent: Option<Box<dyn GFile<FS>>>,
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
        let mut cur_parent: Option<Box<dyn GFile<FS>>> = parent;

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
        parent: Option<Box<dyn GFile<FS>>>,
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
        parent: Option<Box<dyn GFile<FS>>>,
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
        parent: Option<&dyn GFile<FS>>,
        path: &str,
    ) -> Fsrl {
        match parent {
            Some(p) => p.get_fsrl().append_path(path),
            None => fs.root_fsrl().append_path(path),
        }
    }
}

// ─── Mutable accessor ─────────────────────────────────────────────────────────

impl<FS> GFileImpl<FS> {
    /// Updates the stored file length.
    pub fn set_length(&mut self, length: i64) {
        self.length = length;
    }
}

// ─── GFile trait implementation ───────────────────────────────────────────────

impl<FS> GFile<FS> for GFileImpl<FS>
where
    FS: FsGetListing<FS>,
{
    fn get_filesystem(&self) -> &FS {
        &self.filesystem
    }

    fn get_fsrl(&self) -> &Fsrl {
        &self.fsrl
    }

    fn get_parent_file(&self) -> Option<&dyn GFile<FS>> {
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

    fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<FS>>>> {
        self.filesystem.fs_get_listing(self)
    }
}

// ─── Debug ────────────────────────────────────────────────────────────────────

impl<FS> fmt::Debug for GFileImpl<FS> {
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

impl<FS> fmt::Display for GFileImpl<FS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

// ─── Equality and hashing (parallel to Java GFileImpl.equals / hashCode) ──────

impl<FS: PartialEq> PartialEq for GFileImpl<FS> {
    fn eq(&self, other: &Self) -> bool {
        self.filesystem == other.filesystem
            && self.path == other.path
            && self.is_directory == other.is_directory
    }
}

impl<FS: Eq> Eq for GFileImpl<FS> {}

impl<FS: Hash> Hash for GFileImpl<FS> {
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
    use super::super::fsrl_root::FsrlRoot;
    use std::collections::hash_map::DefaultHasher;

    // ── Mock filesystem ────────────────────────────────────────────────────────

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct MockFs {
        root: Fsrl,
        name: &'static str,
    }

    impl MockFs {
        fn new(name: &'static str) -> Self {
            MockFs {
                root: FsrlRoot::make_root("mock").into_fsrl(),
                name,
            }
        }
    }

    impl HasFsrlRoot for MockFs {
        fn root_fsrl(&self) -> &Fsrl {
            &self.root
        }
    }

    impl FsGetListing<MockFs> for MockFs {
        fn fs_get_listing(
            &self,
            _file: &dyn GFile<MockFs>,
        ) -> io::Result<Vec<Box<dyn GFile<MockFs>>>> {
            Ok(vec![])
        }
    }

    type TestFile = GFileImpl<MockFs>;

    fn fs() -> MockFs {
        MockFs::new("testfs")
    }

    fn make_fsrl(fsrl_str: &str) -> Fsrl {
        Fsrl::from_string(fsrl_str).unwrap()
    }

    // ── from_fsrl ──────────────────────────────────────────────────────────────

    #[test]
    fn from_fsrl_stores_fields() {
        let fsrl = make_fsrl("mock:///dir/file.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 42);
        assert_eq!(f.get_name(), "file.txt");
        assert_eq!(f.get_path(), "/dir/file.txt");
        assert!(!f.is_directory());
        assert_eq!(f.get_length(), 42);
        assert!(f.get_parent_file().is_none());
    }

    #[test]
    fn from_fsrl_directory() {
        let fsrl = make_fsrl("mock:///mydir");
        let d = TestFile::from_fsrl(fs(), None, fsrl, true, -1);
        assert!(d.is_directory());
        assert_eq!(d.get_length(), -1);
    }

    // ── from_filename ──────────────────────────────────────────────────────────

    #[test]
    fn from_filename_no_parent_derives_fsrl_from_root() {
        let f = TestFile::from_filename(fs(), None, "readme.txt", false, 100, None);
        assert_eq!(f.get_name(), "readme.txt");
        assert_eq!(f.get_path(), "/readme.txt");
    }

    #[test]
    fn from_filename_with_explicit_fsrl_ignores_filename_for_path() {
        let explicit = make_fsrl("mock:///custom/path/readme.txt");
        let f = TestFile::from_filename(fs(), None, "readme.txt", false, 10, Some(explicit));
        assert_eq!(f.get_path(), "/custom/path/readme.txt");
    }

    #[test]
    fn from_filename_with_parent_derives_fsrl_from_parent() {
        let parent_fsrl = make_fsrl("mock:///dir");
        let parent: Box<dyn GFile<MockFs>> =
            Box::new(TestFile::from_fsrl(fs(), None, parent_fsrl, true, -1));

        let f = TestFile::from_filename(fs(), Some(parent), "child.bin", false, 5, None);
        assert_eq!(f.get_path(), "/dir/child.bin");
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
        let explicit = make_fsrl("explicit:///path/to/file");
        let f =
            TestFile::from_path_string(fs(), "a/b/file", Some(explicit), false, 0);
        assert_eq!(f.get_path(), "/path/to/file");
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

        // The UNC "//" prefix is restored onto the server path element while building the
        // parentage, but the file's name is derived from its FSRL, and FSRL.getName()
        // returns everything after the last '/', so the reported name is "server"
        // (matching Java's GFileImpl.getName() -> FSRL.getName() behaviour).
        let server = share.get_parent_file().expect("server parent");
        assert_eq!(server.get_name(), "server");
    }

    #[test]
    fn from_path_string_with_parent_starts_from_parent() {
        let parent_fsrl = make_fsrl("mock:///base");
        let parent: Box<dyn GFile<MockFs>> =
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
        let mut f = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///f"), false, 10);
        assert_eq!(f.get_length(), 10);
        f.set_length(999);
        assert_eq!(f.get_length(), 999);
    }

    // ── Display ────────────────────────────────────────────────────────────────

    #[test]
    fn display_returns_path() {
        let fsrl = make_fsrl("mock:///a/b.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl, false, 0);
        assert_eq!(f.to_string(), "/a/b.txt");
    }

    // ── PartialEq / Eq ─────────────────────────────────────────────────────────

    #[test]
    fn equal_files_same_fs_path_and_type() {
        let fsrl = make_fsrl("mock:///x.txt");
        let a = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 1);
        let b = TestFile::from_fsrl(fs(), None, fsrl, false, 999); // length ignored
        assert_eq!(a, b);
    }

    #[test]
    fn different_path_not_equal() {
        let a = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///a"), false, 0);
        let b = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///b"), false, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_is_directory_not_equal() {
        let fsrl = make_fsrl("mock:///x");
        let file = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 0);
        let dir = TestFile::from_fsrl(fs(), None, fsrl, true, 0);
        assert_ne!(file, dir);
    }

    #[test]
    fn different_filesystem_not_equal() {
        let fsrl = make_fsrl("mock:///x.txt");
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
        let fsrl = make_fsrl("mock:///f.bin");
        let a = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 1);
        let b = TestFile::from_fsrl(fs(), None, fsrl, false, 2);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn different_paths_typically_different_hash() {
        let a = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///a"), false, 0);
        let b = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///b"), false, 0);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    // ── get_listing delegates to filesystem ────────────────────────────────────

    #[test]
    fn get_listing_delegates_to_filesystem() {
        let d = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///dir"), true, -1);
        let listing = d.get_listing().expect("listing should succeed");
        assert!(listing.is_empty(), "mock fs returns empty listing");
    }

    // ── get_filesystem ─────────────────────────────────────────────────────────

    #[test]
    fn get_filesystem_returns_stored_fs() {
        let f = TestFile::from_fsrl(fs(), None, make_fsrl("mock:///f"), false, 0);
        assert_eq!(f.get_filesystem().name, "testfs");
    }

    // ── get_fsrl ───────────────────────────────────────────────────────────────

    #[test]
    fn get_fsrl_returns_stored_fsrl() {
        let fsrl = make_fsrl("mock:///x.txt");
        let f = TestFile::from_fsrl(fs(), None, fsrl.clone(), false, 0);
        assert_eq!(*f.get_fsrl(), fsrl);
    }
}
