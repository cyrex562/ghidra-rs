use std::any::Any;
use std::cmp::Ordering;
use std::io;
use std::rc::Rc;

use thiserror::Error;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::file_system_ref_manager::FileSystemRefManager;
use super::fileinfo::file_attribute_type::FileAttributeType;
use super::fileinfo::file_attributes::{FileAttributeValue, FileAttributes};
use super::fileinfo::file_type::FileType;
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::g_file_hash_provider::GFileHashProvider;
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

impl From<GFileSystemError> for io::Error {
    /// Collapses a [`GFileSystemError`] into an [`io::Error`], mapping cancellation to
    /// [`io::ErrorKind::Interrupted`] (Java callers that only declare `IOException` see a
    /// cancellation the same way).
    fn from(e: GFileSystemError) -> io::Error {
        match e {
            GFileSystemError::Io(e) => e,
            GFileSystemError::Cancelled(c) => io::Error::new(io::ErrorKind::Interrupted, c),
        }
    }
}

/// A filesystem that contains files, mirroring `ghidra.formats.gfilesystem.GFileSystem`.
///
/// This is the trait filesystem implementations write. Its files are typed:
/// [`Fs`](GFileSystem::Fs) is the handle type the implementation's [`GFile`]s carry (the Java
/// `GFileImpl.fileSystem` back-reference, see [`GFile`]). Because that type differs between
/// implementations, code that must hold *any* filesystem -- the
/// [`FileSystemService`](super::file_system_service::FileSystemService), its instance cache,
/// [`FileSystemRef`](super::file_system_ref::FileSystemRef)s -- uses the object-safe
/// [`AnyGFileSystem`] view instead, which every `GFileSystem` gets through a blanket impl.
///
/// Filesystems are shared (Java hands out one instance through many
/// [`FileSystemRef`](super::file_system_ref::FileSystemRef)s), so they are held as
/// [`FsHandle`] (`Rc<dyn AnyGFileSystem>`) and every method, including
/// [`close`](GFileSystem::close), takes `&self`: an implementation keeps its mutable state
/// (open/closed, index) behind its own interior mutability.
pub trait GFileSystem: 'static {
    /// The filesystem handle type carried by this filesystem's [`GFile`]s.
    type Fs: 'static;

    /// File system volume name -- typically the name of the container file or an internally
    /// stored 'volume' name.
    fn get_name(&self) -> String;

    /// The short (`[a-z0-9]+`) type string of this filesystem.
    ///
    /// Java's default implementation derives this by reflecting on the `FileSystemInfo`
    /// annotation attached to the implementing class; Rust has no such reflection, so
    /// implementors supply it directly (typically from their
    /// [`FileSystemInfo`](super::annotations::file_system_info::FileSystemInfo) constant).
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
    fn get_ref_manager(&self) -> &FileSystemRefManager;

    /// Number of files in the filesystem, if known, otherwise `-1`.
    fn get_file_count(&self) -> i32 {
        -1
    }

    /// Retrieves a file by its full path and filename, using this filesystem's default name
    /// comparison logic. `None` or `"/"` retrieves the root directory. Returns `Ok(None)` if not
    /// found.
    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<Self::Fs>>>>;

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
    ) -> io::Result<Option<Box<dyn GFile<Self::Fs>>>> {
        self.lookup(path)
    }

    /// The file system's root directory, or `None` if the lookup fails.
    fn get_root_dir(&self) -> Option<Box<dyn GFile<Self::Fs>>> {
        self.lookup(None).ok().flatten()
    }

    /// A [`ByteProvider`] over the contents of `file`, or `None` if the file has no data.
    fn get_byte_provider(
        &self,
        file: &dyn GFile<Self::Fs>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError>;

    /// A stream over `file`'s contents, or `None` if the file has no data.
    ///
    /// Mirrors the Java default, which wraps the
    /// [`get_byte_provider`](GFileSystem::get_byte_provider) result in a stream that closes the
    /// provider when done; here the provider's own input stream owns everything it needs.
    fn get_input_stream(
        &self,
        file: &dyn GFile<Self::Fs>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn io::Read>>, GFileSystemError> {
        let Some(bp) = self.get_byte_provider(file, monitor)? else {
            return Ok(None);
        };
        Ok(Some(bp.get_input_stream(0)?))
    }

    /// Files residing in `directory` (`None` means the filesystem root).
    fn get_listing(
        &self,
        directory: Option<&dyn GFile<Self::Fs>>,
    ) -> io::Result<Vec<Box<dyn GFile<Self::Fs>>>>;

    /// Attribute values for `file`. Implementors are not required to add FSRL, NAME, or PATH
    /// values unless non-standard.
    fn get_file_attributes(
        &self,
        file: &dyn GFile<Self::Fs>,
        monitor: &dyn TaskMonitor,
    ) -> FileAttributes;

    /// Converts `file` into its symlink destination, or `None` if not a symlink or the
    /// destination is invalid.
    ///
    /// This default always returns `None`, matching Java's default (for which "not a symlink"
    /// and "invalid symlink destination" are indistinguishable at this default level).
    fn resolve_symlinks(
        &self,
        _file: &dyn GFile<Self::Fs>,
    ) -> io::Result<Option<Box<dyn GFile<Self::Fs>>>> {
        Ok(None)
    }

    /// The [`FileType`] of `file`.
    fn get_file_type(&self, file: &dyn GFile<Self::Fs>, monitor: &dyn TaskMonitor) -> FileType {
        match self.get_file_attributes(file, monitor).get(FileAttributeType::FileTypeAttr) {
            Some(FileAttributeValue::FileType(t)) => *t,
            _ => {
                if file.is_directory() {
                    FileType::Directory
                } else {
                    FileType::File
                }
            }
        }
    }

    /// Closes the filesystem, releasing any resources it holds.
    ///
    /// Implementations notify their ref manager first
    /// ([`FileSystemRefManager::on_close`]), as every Java implementation does.
    fn close(&self) -> io::Result<()>;

    /// This filesystem as a [`GFileHashProvider`], if it is one.
    ///
    /// Stands in for Java's `fs instanceof GFileHashProvider` checks; the default is `None`.
    fn as_hash_provider(&self) -> Option<&dyn GFileHashProvider<Self::Fs>> {
        None
    }

    /// Iterates depth-first over all files in this filesystem, starting at the root.
    fn files(&self) -> io::Result<GFileSystemIterator<Self::Fs>> {
        self.files_with(None, None)
    }

    /// Iterates depth-first over the files in this filesystem, optionally starting at `dir`
    /// (defaulting to the root) and optionally filtering leaf files with `filter`.
    fn files_with(
        &self,
        dir: Option<Box<dyn GFile<Self::Fs>>>,
        filter: Option<Box<dyn Fn(&dyn GFile<Self::Fs>) -> bool>>,
    ) -> io::Result<GFileSystemIterator<Self::Fs>> {
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

/// A shared handle to a mounted filesystem of any implementation.
pub type FsHandle = Rc<dyn AnyGFileSystem>;

/// The type-erased view of a [`GFile`] handed across the [`AnyGFileSystem`] boundary.
///
/// Every `Box<dyn GFile<FS>>` is one; [`as_any`](AnyGFile::as_any) recovers the typed file
/// (`downcast_ref::<Box<dyn GFile<FS>>>()`) for code that knows the filesystem's handle type.
pub trait AnyGFile {
    /// The FSRL of this file. Mirrors `GFile.getFSRL()`.
    fn get_fsrl(&self) -> &Fsrl;
    /// The path of this file within its filesystem. Mirrors `GFile.getPath()`.
    fn get_path(&self) -> &str;
    /// The name of this file. Mirrors `GFile.getName()`.
    fn get_name(&self) -> &str;
    /// Whether this is a directory. Mirrors `GFile.isDirectory()`.
    fn is_directory(&self) -> bool;
    /// The length of the file, or `-1` if unknown. Mirrors `GFile.getLength()`.
    fn get_length(&self) -> i64;
    /// The typed file, for downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl<FS: 'static> AnyGFile for Box<dyn GFile<FS>> {
    fn get_fsrl(&self) -> &Fsrl {
        (**self).get_fsrl()
    }
    fn get_path(&self) -> &str {
        (**self).get_path()
    }
    fn get_name(&self) -> &str {
        (**self).get_name()
    }
    fn is_directory(&self) -> bool {
        (**self).is_directory()
    }
    fn get_length(&self) -> i64 {
        (**self).get_length()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// An erased file, as returned by [`AnyGFileSystem`] lookups and listings.
pub type DynGFile = Box<dyn AnyGFile>;

/// The object-safe view of a [`GFileSystem`] that code holding *any* filesystem uses.
///
/// Implemented for every [`GFileSystem`] by a blanket impl; there is nothing to implement by
/// hand. File arguments must be files this same filesystem handed out (Java has the same
/// expectation); passing a file from another filesystem is an
/// [`io::ErrorKind::InvalidInput`] error.
pub trait AnyGFileSystem {
    /// See [`GFileSystem::get_name`].
    fn get_name(&self) -> String;
    /// See [`GFileSystem::get_type`].
    fn get_type(&self) -> String;
    /// See [`GFileSystem::get_description`].
    fn get_description(&self) -> String;
    /// See [`GFileSystem::get_fsrl`].
    fn get_fsrl(&self) -> &FsrlRoot;
    /// See [`GFileSystem::is_closed`].
    fn is_closed(&self) -> bool;
    /// See [`GFileSystem::is_static`].
    fn is_static(&self) -> bool;
    /// See [`GFileSystem::get_ref_manager`].
    fn get_ref_manager(&self) -> &FileSystemRefManager;
    /// See [`GFileSystem::get_file_count`].
    fn get_file_count(&self) -> i32;
    /// See [`GFileSystem::lookup`].
    fn lookup(&self, path: Option<&str>) -> io::Result<Option<DynGFile>>;
    /// See [`GFileSystem::get_listing`].
    fn get_listing(&self, directory: Option<&dyn AnyGFile>) -> io::Result<Vec<DynGFile>>;
    /// See [`GFileSystem::get_byte_provider`].
    fn get_byte_provider(
        &self,
        file: &dyn AnyGFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError>;
    /// See [`GFileSystem::get_file_attributes`].
    fn get_file_attributes(
        &self,
        file: &dyn AnyGFile,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<FileAttributes>;
    /// `Some(hash result)` if this filesystem is a [`GFileHashProvider`], else `None`.
    fn get_md5_hash(
        &self,
        file: &dyn AnyGFile,
        required: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Result<Option<String>, GFileSystemError>>;
    /// See [`GFileSystem::close`].
    fn close(&self) -> io::Result<()>;
    /// The concrete filesystem, for downcasting (Java's `Class.cast` in
    /// `mountSpecificFileSystem`).
    fn as_any(&self) -> &dyn Any;
    /// The shared concrete filesystem, for `Rc::downcast`.
    fn into_any_rc(self: Rc<Self>) -> Rc<dyn Any>;
}

fn typed_file<'a, FS: 'static>(file: &'a dyn AnyGFile) -> io::Result<&'a dyn GFile<FS>> {
    file.as_any()
        .downcast_ref::<Box<dyn GFile<FS>>>()
        .map(|b| b.as_ref())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} does not belong to this filesystem", file.get_fsrl()),
            )
        })
}

fn erase<FS: 'static>(file: Box<dyn GFile<FS>>) -> DynGFile {
    Box::new(file)
}

impl<T: GFileSystem> AnyGFileSystem for T {
    fn get_name(&self) -> String {
        GFileSystem::get_name(self)
    }
    fn get_type(&self) -> String {
        GFileSystem::get_type(self)
    }
    fn get_description(&self) -> String {
        GFileSystem::get_description(self)
    }
    fn get_fsrl(&self) -> &FsrlRoot {
        GFileSystem::get_fsrl(self)
    }
    fn is_closed(&self) -> bool {
        GFileSystem::is_closed(self)
    }
    fn is_static(&self) -> bool {
        GFileSystem::is_static(self)
    }
    fn get_ref_manager(&self) -> &FileSystemRefManager {
        GFileSystem::get_ref_manager(self)
    }
    fn get_file_count(&self) -> i32 {
        GFileSystem::get_file_count(self)
    }
    fn lookup(&self, path: Option<&str>) -> io::Result<Option<DynGFile>> {
        Ok(GFileSystem::lookup(self, path)?.map(erase))
    }
    fn get_listing(&self, directory: Option<&dyn AnyGFile>) -> io::Result<Vec<DynGFile>> {
        let dir = directory.map(typed_file::<T::Fs>).transpose()?;
        Ok(GFileSystem::get_listing(self, dir)?.into_iter().map(erase).collect())
    }
    fn get_byte_provider(
        &self,
        file: &dyn AnyGFile,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        GFileSystem::get_byte_provider(self, typed_file::<T::Fs>(file)?, monitor)
    }
    fn get_file_attributes(
        &self,
        file: &dyn AnyGFile,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<FileAttributes> {
        Ok(GFileSystem::get_file_attributes(self, typed_file::<T::Fs>(file)?, monitor))
    }
    fn get_md5_hash(
        &self,
        file: &dyn AnyGFile,
        required: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Result<Option<String>, GFileSystemError>> {
        let hp = self.as_hash_provider()?;
        Some(match typed_file::<T::Fs>(file) {
            Ok(f) => hp.get_md5_hash(f, required, monitor),
            Err(e) => Err(e.into()),
        })
    }
    fn close(&self) -> io::Result<()> {
        GFileSystem::close(self)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any_rc(self: Rc<Self>) -> Rc<dyn Any> {
        self
    }
}

impl std::fmt::Display for dyn AnyGFileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_fsrl())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ByteProvider, FileAttributeType, FileAttributeValue, FileAttributes, FileSystemRefManager,
        FileType, FsrlRoot, GFile, GFileSystem, GFileSystemError, Ordering, TaskMonitor,
    };
    use std::io;
    use super::super::fsrl::Fsrl;
    use std::cell::Cell;

    // ── Mock seam types ─────────────────────────────────────────────────────


    // ── Mock GFile ────────────────────────────────────────────────────────────
    //
    // `FS` (the GFile type parameter) is deliberately a bare marker unrelated to
    // `MockFileSystem` below, demonstrating the decoupling documented on `GFileSystem`.

    struct MockFsMarker;

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
        fsrl: Fsrl,
        // Shared with the owning `MockFileSystem` so `GFile::get_listing` (used internally by
        // `GFileSystemIterator`) can find children without a back-reference to the filesystem.
        all_nodes: std::rc::Rc<Vec<MockNodeData>>,
    }

    impl MockFile {
        fn new(node: MockNodeData, all_nodes: std::rc::Rc<Vec<MockNodeData>>) -> Self {
            let fsrl = FsrlRoot::make_root("mock").with_path_md5(Some(&node.path), None);
            MockFile { node, fsrl, all_nodes }
        }
    }

    impl GFile<MockFsMarker> for MockFile {
        fn get_filesystem(&self) -> &MockFsMarker {
            &MockFsMarker
        }

        fn get_fsrl(&self) -> &Fsrl {
            &self.fsrl
        }

        fn get_parent_file(&self) -> Option<&dyn GFile<MockFsMarker>> {
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

        fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<MockFsMarker>>>> {
            Ok(self
                .all_nodes
                .iter()
                .filter(|n| n.parent.as_deref() == Some(self.node.path.as_str()))
                .map(|n| -> Box<dyn GFile<MockFsMarker>> {
                    Box::new(MockFile::new(n.clone(), self.all_nodes.clone()))
                })
                .collect())
        }
    }

    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    // ── Mock GFileSystem ─────────────────────────────────────────────────────

    struct MockFileSystem {
        closed: Cell<bool>,
        fsrl_root: FsrlRoot,
        ref_manager: FileSystemRefManager,
        nodes: std::rc::Rc<Vec<MockNodeData>>,
    }

    impl GFileSystem for MockFileSystem {
        type Fs = MockFsMarker;

        fn get_name(&self) -> String {
            "mockfs".to_string()
        }

        fn get_type(&self) -> String {
            "mock".to_string()
        }

        fn get_description(&self) -> String {
            "Mock filesystem".to_string()
        }

        fn get_fsrl(&self) -> &FsrlRoot {
            &self.fsrl_root
        }

        fn is_closed(&self) -> bool {
            self.closed.get()
        }

        fn get_ref_manager(&self) -> &FileSystemRefManager {
            &self.ref_manager
        }

        fn lookup(
            &self,
            path: Option<&str>,
        ) -> io::Result<Option<Box<dyn GFile<MockFsMarker>>>> {
            let key = path.unwrap_or("/");
            Ok(self.nodes.iter().find(|n| n.path == key).map(|n| {
                let boxed: Box<dyn GFile<MockFsMarker>> =
                    Box::new(MockFile::new(n.clone(), self.nodes.clone()));
                boxed
            }))
        }

        fn get_byte_provider(
            &self,
            file: &dyn GFile<MockFsMarker>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
            let node = self.nodes.iter().find(|n| n.path == file.get_path());
            match node {
                Some(n) if !n.is_dir => Ok(Some(Box::new(ByteArrayProvider::new(n.content.clone())))),
                _ => Ok(None),
            }
        }

        fn get_listing(
            &self,
            directory: Option<&dyn GFile<MockFsMarker>>,
        ) -> io::Result<Vec<Box<dyn GFile<MockFsMarker>>>> {
            let parent_path = directory
                .map(|d| d.get_path().to_string())
                .unwrap_or_else(|| "/".to_string());
            Ok(self
                .nodes
                .iter()
                .filter(|n| n.parent.as_deref() == Some(parent_path.as_str()))
                .map(|n| -> Box<dyn GFile<MockFsMarker>> {
                    Box::new(MockFile::new(n.clone(), self.nodes.clone()))
                })
                .collect())
        }

        fn get_file_attributes(
            &self,
            file: &dyn GFile<MockFsMarker>,
            _monitor: &dyn TaskMonitor,
        ) -> FileAttributes {
            // "/sub/b.txt" records an explicit FILE_TYPE_ATTR that overrides the
            // directory-flag fallback in the default `get_file_type`.
            if file.get_path() == "/sub/b.txt" {
                FileAttributes::of([(
                    FileAttributeType::FileTypeAttr,
                    Some(FileAttributeValue::FileType(FileType::SymbolicLink)),
                )])
            } else {
                FileAttributes::new()
            }
        }

        fn close(&self) -> io::Result<()> {
            let _ = self.ref_manager.on_close(self);
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
            fsrl_root: FsrlRoot::make_root("mock"),
            ref_manager: FileSystemRefManager::new(),
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
        let bp = fs
            .get_byte_provider(file.as_ref(), &monitor)
            .unwrap()
            .expect("a.txt should have data");
        let len = bp.length();
        assert_eq!(bp.read_bytes(0, len).unwrap(), b"hello");
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
        let mut stream = fs
            .get_input_stream(file.as_ref(), &monitor)
            .unwrap()
            .expect("b.txt should have data");
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut stream, &mut bytes).unwrap();
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
    fn get_file_type_prefers_explicit_file_type_attribute() {
        let fs = mockfs();
        let monitor = crate::util::task::DummyMonitor;
        let file = fs.lookup(Some("/sub/b.txt")).unwrap().unwrap();
        assert_eq!(fs.get_file_type(file.as_ref(), &monitor), FileType::SymbolicLink);
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
        let filter: Box<dyn Fn(&dyn GFile<MockFsMarker>) -> bool> =
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
        let fs = mockfs();
        assert!(!fs.is_closed());
        fs.close().unwrap();
        assert!(fs.is_closed());
    }

    #[test]
    fn boxed_dyn_g_file_system_is_accepted() {
        let fs: Box<dyn GFileSystem<Fs = MockFsMarker>> = Box::new(mockfs());
        assert_eq!(fs.get_name(), "mockfs");
        assert_eq!(fs.get_type(), "mock");
    }

    #[test]
    fn erased_view_round_trips_files() {
        use super::{AnyGFileSystem, FsHandle};
        let fs: FsHandle = std::rc::Rc::new(mockfs());
        let monitor = crate::util::task::DummyMonitor;
        let file = fs.lookup(Some("/a.txt")).unwrap().unwrap();
        assert_eq!(file.get_path(), "/a.txt");
        let bp = fs.get_byte_provider(&*file, &monitor).unwrap().unwrap();
        assert_eq!(bp.read_bytes(0, 5).unwrap(), b"hello");
        let root = fs.lookup(None).unwrap().unwrap();
        let mut names: Vec<String> =
            fs.get_listing(Some(&*root)).unwrap().iter().map(|f| f.get_name().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "sub"]);
        assert!(fs.get_md5_hash(&*file, true, &monitor).is_none());
        assert!(AnyGFileSystem::as_any(&*fs).downcast_ref::<MockFileSystem>().is_some());
        fs.close().unwrap();
        assert!(fs.is_closed());
        assert!(fs.get_ref_manager().is_closed());
    }
}
