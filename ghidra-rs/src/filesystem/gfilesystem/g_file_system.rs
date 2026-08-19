use std::cmp::Ordering;
use std::io;

use thiserror::Error;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::seam_stubs::{FileAttributesLike, FileSystemRefManagerLike, FsrlRootLike};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::fileinfo::file_type::FileType;
use super::g_file::GFile;
use super::g_file_system_iterator::GFileSystemIterator;

/// Failure mode shared by [`GFileSystem`] operations that mirror Java methods declared
/// `throws IOException, CancelledException`.
#[derive(Error, Debug)]
pub enum GFileSystemError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// A filesystem that contains files, mirroring `ghidra.formats.gfilesystem.GFileSystem`.
///
/// This is a cycle cut-point: the Java interface references `FSRLRoot`,
/// `FileSystemRefManager`, and `fileinfo.FileAttributes`, none of which are ported yet. Those
/// are represented here by the [`FsrlRootLike`], [`FileSystemRefManagerLike`], and
/// [`FileAttributesLike`] seams (see `crate::filesystem::seam_stubs`) until the real types
/// land.
///
/// `FS` and `Fsrl` are the same kind of type parameters used by [`GFile`] -- `FS` will be
/// instantiated with the concrete implementing filesystem type and `Fsrl` with the ported
/// `FSRL` type. `FS` is intentionally NOT tied to `Self`: like
/// [`FileSystemEventListener`](super::file_system_event_listener::FileSystemEventListener) and
/// [`FsGetListing`](super::g_file_impl::FsGetListing), coupling it to `Self` instead of a free
/// generic parameter would make this trait dyn-incompatible.
pub trait GFileSystem<FS, Fsrl, FsrlRoot, RefManager>
where
    FS: 'static,
    Fsrl: 'static,
    FsrlRoot: FsrlRootLike,
    RefManager: FileSystemRefManagerLike,
{
    /// File system volume name -- typically the name of the container file or an internally
    /// stored 'volume' name.
    fn get_name(&self) -> &str;

    /// The short (`[a-z0-9]+`) type string of this filesystem.
    ///
    /// Java's default implementation derives this by reflecting on the `FileSystemInfo`
    /// annotation attached to the implementing class; Rust has no such reflection, so
    /// implementors must supply their own type string directly (typically the same value they
    /// expose through their `FileSystemInfo` port).
    fn get_type(&self) -> String;

    /// A longer description of this filesystem.
    ///
    /// See [`get_type`](GFileSystem::get_type) for why this has no annotation-derived default.
    fn get_description(&self) -> String;

    /// This filesystem's FSRL root.
    fn get_fsrl(&self) -> &FsrlRoot;

    /// Returns `true` if this filesystem has been [`close`](GFileSystem::close)d.
    fn is_closed(&self) -> bool;

    /// Indicates if this filesystem is a static snapshot (`true`, the default) or changes.
    fn is_static(&self) -> bool {
        true
    }

    /// The ref manager responsible for creating and releasing references to this filesystem.
    fn get_ref_manager(&self) -> &RefManager;

    /// Number of files in the filesystem, if known, otherwise `-1`.
    fn get_file_count(&self) -> i32 {
        -1
    }

    /// Retrieves a file by its full path and filename, using this filesystem's default name
    /// comparison logic. `None` or `"/"` retrieves the root directory. Returns `Ok(None)` if not
    /// found.
    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<FS, Fsrl>>>>;

    /// Retrieves a file using the specified name comparison logic. `None` requests the
    /// filesystem's native comparison logic.
    ///
    /// Implementors that don't override this fall back to [`lookup`](GFileSystem::lookup),
    /// ignoring `name_comp` -- matching the Java default, which does the same (and additionally
    /// logs a warning that the comparator-aware overload is unimplemented).
    fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        _name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> io::Result<Option<Box<dyn GFile<FS, Fsrl>>>> {
        self.lookup(path)
    }

    /// The file system's root directory, or `None` if the lookup fails.
    fn get_root_dir(&self) -> Option<Box<dyn GFile<FS, Fsrl>>> {
        self.lookup(None).ok().flatten()
    }

    /// A [`ByteProvider`] over the contents of `file`, or `None` if the file has no data.
    fn get_byte_provider(
        &self,
        file: &dyn GFile<FS, Fsrl>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError>;

    /// All bytes of `file`'s contents, or `None` if the file has no data.
    ///
    /// Java's default wraps the [`get_byte_provider`](GFileSystem::get_byte_provider) result in
    /// a closing `InputStream`. `ByteProvider` here is index-addressed rather than a stream, so
    /// this reads the provider's full contents eagerly instead of returning a lazy reader.
    fn get_input_stream(
        &self,
        file: &dyn GFile<FS, Fsrl>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Vec<u8>>, GFileSystemError> {
        let Some(mut bp) = self.get_byte_provider(file, monitor)? else {
            return Ok(None);
        };
        let len = bp.length()?;
        let bytes = bp.read_bytes(0, len as usize)?;
        Ok(Some(bytes))
    }

    /// Files residing in `directory` (`None` means the filesystem root).
    fn get_listing(
        &self,
        directory: Option<&dyn GFile<FS, Fsrl>>,
    ) -> io::Result<Vec<Box<dyn GFile<FS, Fsrl>>>>;

    /// Attribute values for `file`. Implementors are not required to add FSRL, NAME, or PATH
    /// values unless non-standard.
    fn get_file_attributes(
        &self,
        file: &dyn GFile<FS, Fsrl>,
        monitor: &dyn TaskMonitor,
    ) -> Box<dyn FileAttributesLike>;

    /// Converts `file` into its symlink destination, or `None` if not a symlink or the
    /// destination is invalid.
    ///
    /// This default always returns `None`, matching Java's default (for which "not a symlink"
    /// and "invalid symlink destination" are indistinguishable at this default level).
    fn resolve_symlinks(
        &self,
        _file: &dyn GFile<FS, Fsrl>,
    ) -> io::Result<Option<Box<dyn GFile<FS, Fsrl>>>> {
        Ok(None)
    }

    /// The [`FileType`] of `file`.
    fn get_file_type(&self, file: &dyn GFile<FS, Fsrl>, monitor: &dyn TaskMonitor) -> FileType {
        self.get_file_attributes(file, monitor)
            .file_type_attr()
            .unwrap_or_else(|| {
                if file.is_directory() {
                    FileType::Directory
                } else {
                    FileType::File
                }
            })
    }

    /// Closes the filesystem, releasing any resources it holds.
    fn close(&mut self) -> io::Result<()>;

    /// Iterates depth-first over all files in this filesystem, starting at the root.
    fn files(&self) -> io::Result<GFileSystemIterator<FS, Fsrl>> {
        self.files_with(None, None)
    }

    /// Iterates depth-first over the files in this filesystem, optionally starting at `dir`
    /// (defaulting to the root) and optionally filtering leaf files with `filter`.
    fn files_with(
        &self,
        dir: Option<Box<dyn GFile<FS, Fsrl>>>,
        filter: Option<Box<dyn Fn(&dyn GFile<FS, Fsrl>) -> bool>>,
    ) -> io::Result<GFileSystemIterator<FS, Fsrl>> {
        let dir = match dir {
            Some(d) => d,
            None => self
                .get_root_dir()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no root directory"))?,
        };
        match filter {
            Some(f) => GFileSystemIterator::with_filter(dir, move |file| f(file)),
            None => GFileSystemIterator::new(dir),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // ── Mock seam types ─────────────────────────────────────────────────────

    struct MockFsrlRoot;
    impl FsrlRootLike for MockFsrlRoot {}

    struct MockRefManager;
    impl FileSystemRefManagerLike for MockRefManager {}

    struct MockAttrs(Option<FileType>);
    impl FileAttributesLike for MockAttrs {
        fn file_type_attr(&self) -> Option<FileType> {
            self.0
        }
    }

    // ── Mock GFile ────────────────────────────────────────────────────────────
    //
    // `FS` (the GFile type parameter) is deliberately a bare marker unrelated to
    // `MockFileSystem` below, demonstrating the decoupling documented on `GFileSystem`.

    struct MockFsMarker;

    #[derive(Clone)]
    struct MockFsrl(String);

    #[derive(Clone)]
    struct MockNodeData {
        path: String,
        name: String,
        is_dir: bool,
        parent: Option<String>,
        content: Vec<u8>,
    }

    struct MockFile {
        node: MockNodeData,
        fsrl: MockFsrl,
        // Shared with the owning `MockFileSystem` so `GFile::get_listing` (used internally by
        // `GFileSystemIterator`) can find children without a back-reference to the filesystem.
        all_nodes: std::rc::Rc<Vec<MockNodeData>>,
    }

    impl MockFile {
        fn new(node: MockNodeData, all_nodes: std::rc::Rc<Vec<MockNodeData>>) -> Self {
            let fsrl = MockFsrl(node.path.clone());
            MockFile { node, fsrl, all_nodes }
        }
    }

    impl GFile<MockFsMarker, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFsMarker {
            &MockFsMarker
        }

        fn get_fsrl(&self) -> &MockFsrl {
            &self.fsrl
        }

        fn get_parent_file(&self) -> Option<&dyn GFile<MockFsMarker, MockFsrl>> {
            None
        }

        fn get_path(&self) -> &str {
            &self.node.path
        }

        fn get_name(&self) -> &str {
            &self.node.name
        }

        fn is_directory(&self) -> bool {
            self.node.is_dir
        }

        fn get_length(&self) -> i64 {
            if self.node.is_dir {
                -1
            } else {
                self.node.content.len() as i64
            }
        }

        fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<MockFsMarker, MockFsrl>>>> {
            Ok(self
                .all_nodes
                .iter()
                .filter(|n| n.parent.as_deref() == Some(self.node.path.as_str()))
                .map(|n| -> Box<dyn GFile<MockFsMarker, MockFsrl>> {
                    Box::new(MockFile::new(n.clone(), self.all_nodes.clone()))
                })
                .collect())
        }
    }

    // ── Mock ByteProvider ───────────────────────────────────────────────────────

    struct VecByteProvider(Vec<u8>);

    impl ByteProvider for VecByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.0.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.0[start..end].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
    }

    // ── Mock GFileSystem ─────────────────────────────────────────────────────

    struct MockFileSystem {
        closed: Cell<bool>,
        fsrl_root: MockFsrlRoot,
        ref_manager: MockRefManager,
        nodes: std::rc::Rc<Vec<MockNodeData>>,
    }

    impl GFileSystem<MockFsMarker, MockFsrl, MockFsrlRoot, MockRefManager> for MockFileSystem {
        fn get_name(&self) -> &str {
            "mockfs"
        }

        fn get_type(&self) -> String {
            "mock".to_string()
        }

        fn get_description(&self) -> String {
            "Mock filesystem".to_string()
        }

        fn get_fsrl(&self) -> &MockFsrlRoot {
            &self.fsrl_root
        }

        fn is_closed(&self) -> bool {
            self.closed.get()
        }

        fn get_ref_manager(&self) -> &MockRefManager {
            &self.ref_manager
        }

        fn lookup(
            &self,
            path: Option<&str>,
        ) -> io::Result<Option<Box<dyn GFile<MockFsMarker, MockFsrl>>>> {
            let key = path.unwrap_or("/");
            Ok(self.nodes.iter().find(|n| n.path == key).map(|n| {
                let boxed: Box<dyn GFile<MockFsMarker, MockFsrl>> =
                    Box::new(MockFile::new(n.clone(), self.nodes.clone()));
                boxed
            }))
        }

        fn get_byte_provider(
            &self,
            file: &dyn GFile<MockFsMarker, MockFsrl>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
            let node = self.nodes.iter().find(|n| n.path == file.get_path());
            match node {
                Some(n) if !n.is_dir => Ok(Some(Box::new(VecByteProvider(n.content.clone())))),
                _ => Ok(None),
            }
        }

        fn get_listing(
            &self,
            directory: Option<&dyn GFile<MockFsMarker, MockFsrl>>,
        ) -> io::Result<Vec<Box<dyn GFile<MockFsMarker, MockFsrl>>>> {
            let parent_path = directory
                .map(|d| d.get_path().to_string())
                .unwrap_or_else(|| "/".to_string());
            Ok(self
                .nodes
                .iter()
                .filter(|n| n.parent.as_deref() == Some(parent_path.as_str()))
                .map(|n| -> Box<dyn GFile<MockFsMarker, MockFsrl>> {
                    Box::new(MockFile::new(n.clone(), self.nodes.clone()))
                })
                .collect())
        }

        fn get_file_attributes(
            &self,
            _file: &dyn GFile<MockFsMarker, MockFsrl>,
            _monitor: &dyn TaskMonitor,
        ) -> Box<dyn FileAttributesLike> {
            Box::new(MockAttrs(None))
        }

        fn close(&mut self) -> io::Result<()> {
            self.closed.set(true);
            Ok(())
        }
    }

    fn node(path: &str, name: &str, is_dir: bool, parent: Option<&str>, content: &[u8]) -> MockNodeData {
        MockNodeData {
            path: path.to_string(),
            name: name.to_string(),
            is_dir,
            parent: parent.map(str::to_string),
            content: content.to_vec(),
        }
    }

    fn mockfs() -> MockFileSystem {
        MockFileSystem {
            closed: Cell::new(false),
            fsrl_root: MockFsrlRoot,
            ref_manager: MockRefManager,
            nodes: std::rc::Rc::new(vec![
                node("/", "", true, None, b""),
                node("/a.txt", "a.txt", false, Some("/"), b"hello"),
                node("/sub", "sub", true, Some("/"), b""),
                node("/sub/b.txt", "b.txt", false, Some("/sub"), b"world"),
            ]),
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn is_static_defaults_to_true() {
        assert!(mockfs().is_static());
    }

    #[test]
    fn file_count_defaults_to_negative_one() {
        assert_eq!(mockfs().get_file_count(), -1);
    }

    #[test]
    fn lookup_finds_root_and_children() {
        let fs = mockfs();
        let root = fs.lookup(None).unwrap().expect("root should exist");
        assert!(root.is_directory());

        let a = fs.lookup(Some("/a.txt")).unwrap().expect("a.txt should exist");
        assert_eq!(a.get_name(), "a.txt");
        assert!(!a.is_directory());

        assert!(fs.lookup(Some("/nope")).unwrap().is_none());
    }

    #[test]
    fn lookup_with_comparator_falls_back_to_lookup() {
        let fs = mockfs();
        let cmp: &dyn Fn(&str, &str) -> Ordering = &|a, b| a.cmp(b);
        let a = fs
            .lookup_with_comparator(Some("/a.txt"), Some(cmp))
            .unwrap()
            .expect("a.txt should exist");
        assert_eq!(a.get_name(), "a.txt");
    }

    #[test]
    fn root_dir_delegates_to_lookup_none() {
        let fs = mockfs();
        let root = fs.get_root_dir().expect("root should exist");
        assert_eq!(root.get_path(), "/");
    }

    #[test]
    fn get_listing_returns_children_of_root() {
        let fs = mockfs();
        let mut names: Vec<String> =
            fs.get_listing(None).unwrap().iter().map(|f| f.get_name().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "sub"]);
    }

    #[test]
    fn get_listing_returns_children_of_subdirectory() {
        let fs = mockfs();
        let sub = fs.lookup(Some("/sub")).unwrap().unwrap();
        let listing = fs.get_listing(Some(sub.as_ref())).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "b.txt");
    }

    #[test]
    fn get_byte_provider_reads_file_bytes() {
        let fs = mockfs();
        let monitor = crate::util::task::DummyMonitor;
        let file = fs.lookup(Some("/a.txt")).unwrap().unwrap();
        let mut bp = fs
            .get_byte_provider(file.as_ref(), &monitor)
            .unwrap()
            .expect("a.txt should have data");
        let len = bp.length().unwrap();
        assert_eq!(bp.read_bytes(0, len as usize).unwrap(), b"hello");
    }

    #[test]
    fn get_byte_provider_returns_none_for_directory() {
        let fs = mockfs();
        let monitor = crate::util::task::DummyMonitor;
        let root = fs.get_root_dir().unwrap();
        assert!(fs.get_byte_provider(root.as_ref(), &monitor).unwrap().is_none());
    }

    #[test]
    fn get_input_stream_reads_full_contents() {
        let fs = mockfs();
        let monitor = crate::util::task::DummyMonitor;
        let file = fs.lookup(Some("/sub/b.txt")).unwrap().unwrap();
        let bytes = fs
            .get_input_stream(file.as_ref(), &monitor)
            .unwrap()
            .expect("b.txt should have data");
        assert_eq!(bytes, b"world");
    }

    #[test]
    fn get_file_type_defaults_from_is_directory_when_attrs_empty() {
        let fs = mockfs();
        let monitor = crate::util::task::DummyMonitor;
        let file = fs.lookup(Some("/a.txt")).unwrap().unwrap();
        assert_eq!(fs.get_file_type(file.as_ref(), &monitor), FileType::File);

        let dir = fs.lookup(Some("/sub")).unwrap().unwrap();
        assert_eq!(fs.get_file_type(dir.as_ref(), &monitor), FileType::Directory);
    }

    #[test]
    fn resolve_symlinks_default_returns_none() {
        let fs = mockfs();
        let file = fs.lookup(Some("/a.txt")).unwrap().unwrap();
        assert!(fs.resolve_symlinks(file.as_ref()).unwrap().is_none());
    }

    #[test]
    fn files_iterates_leaf_files_depth_first_alphabetically() {
        let fs = mockfs();
        let names: Vec<String> = fs
            .files()
            .unwrap()
            .map(|r| r.unwrap().get_name().to_string())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn files_with_filter_excludes_non_matching_leaves() {
        let fs = mockfs();
        let filter: Box<dyn Fn(&dyn GFile<MockFsMarker, MockFsrl>) -> bool> =
            Box::new(|f| f.get_name() == "b.txt");
        let names: Vec<String> = fs
            .files_with(None, Some(filter))
            .unwrap()
            .map(|r| r.unwrap().get_name().to_string())
            .collect();
        assert_eq!(names, vec!["b.txt"]);
    }

    #[test]
    fn close_marks_filesystem_closed() {
        let mut fs = mockfs();
        assert!(!fs.is_closed());
        fs.close().unwrap();
        assert!(fs.is_closed());
    }

    #[test]
    fn boxed_dyn_g_file_system_is_accepted() {
        let fs: Box<dyn GFileSystem<MockFsMarker, MockFsrl, MockFsrlRoot, MockRefManager>> =
            Box::new(mockfs());
        assert_eq!(fs.get_name(), "mockfs");
        assert_eq!(fs.get_type(), "mock");
    }
}
