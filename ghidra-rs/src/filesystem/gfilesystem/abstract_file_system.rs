//! Port of `ghidra.formats.gfilesystem.AbstractFileSystem`.
//!
//! Default implementation of the base functionality of a container filesystem whose files are
//! tracked in a [`FileSystemIndexHelper`].
//!
//! The Java abstract class declares no abstract methods of its own (the remaining
//! `GFileSystem` methods -- `getByteProvider`, `close`, `isClosed`, ... -- are left to each
//! subclass). It is therefore ported, like
//! [`AbstractSinglePayloadFileSystemBase`](super::abstract_single_payload_file_system::AbstractSinglePayloadFileSystemBase),
//! as a shared-state struct, [`AbstractFileSystemBase`], that each concrete filesystem embeds.
//!
//! Two Java fields are not modeled, following that same precedent:
//! - `refManager`: this port has no concrete `FileSystemRefManager` yet (see
//!   [`super::file_system_ref_manager`]); subclasses only call `refManager.onClose()`, which
//!   notifies listeners.
//! - `fsService`: there is no concrete `FileSystemService` yet (see
//!   [`super::file_system_service`]); a subclass that needs one holds it itself.
//!
//! Java's `GFileImpl` keeps a back-reference to its owning filesystem, so `GFile.getListing()`
//! can call `fs.getListing(this)`. The files handed out here instead carry an
//! [`AbstractFsHandle`] (the filesystem's identity and FSRL root) and cannot reach the index
//! that lists them without a reference cycle; [`GFile::get_listing`] on them therefore returns
//! an [`io::ErrorKind::Unsupported`] error, and listings are obtained through
//! [`AbstractFileSystemBase::get_listing`].

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::rc::Rc;

use super::file_system_index_helper::{FileSystemIndexHelper, NameComparator};
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::g_file_impl::{FsGetListing, GFileImpl, HasFsrlRoot};

/// The filesystem identity stored inside each [`AbstractFsGFile`].
///
/// Stands in for the Java `GFileImpl.fileSystem` back-reference. Two handles are equal only if
/// they are clones of the same handle, matching Java's identity comparison of the owning
/// filesystem in `GFileImpl.equals`.
#[derive(Clone)]
pub struct AbstractFsHandle(Rc<FsrlRoot>);

impl AbstractFsHandle {
    /// The FSRL root of the owning filesystem.
    pub fn fsrl_root(&self) -> &FsrlRoot {
        &self.0
    }
}

impl PartialEq for AbstractFsHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for AbstractFsHandle {}

impl Hash for AbstractFsHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Rc::as_ptr(&self.0), state);
    }
}

impl fmt::Debug for AbstractFsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AbstractFsHandle({})", self.0)
    }
}

impl HasFsrlRoot<Fsrl> for AbstractFsHandle {
    fn root_fsrl(&self) -> &Fsrl {
        self.0.as_fsrl()
    }
}

impl FsGetListing<AbstractFsHandle, Fsrl> for AbstractFsHandle {
    /// Always an [`io::ErrorKind::Unsupported`] error; see the module docs.
    fn fs_get_listing(
        &self,
        file: &dyn GFile<AbstractFsHandle, Fsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<AbstractFsHandle, Fsrl>>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "GFile.getListing() for {} must go through its filesystem's get_listing",
                file.get_path()
            ),
        ))
    }
}

/// The concrete [`GFile`] type an [`AbstractFileSystemBase`] hands out.
pub type AbstractFsGFile = GFileImpl<AbstractFsHandle, Fsrl>;

/// The index type an [`AbstractFileSystemBase`] keeps, with per-file metadata `M`.
pub type AbstractFsIndex<M> = FileSystemIndexHelper<AbstractFsHandle, Fsrl, M>;

/// Shared state and behaviour of a container filesystem.
///
/// Mirrors `ghidra.formats.gfilesystem.AbstractFileSystem<METADATATYPE>`.
pub struct AbstractFileSystemBase<M> {
    fs_fsrl: FsrlRoot,
    fs_index: AbstractFsIndex<M>,
    filename_comparator: Option<fn(&str, &str) -> Ordering>,
}

impl<M> AbstractFileSystemBase<M> {
    /// Initializes the fields for the filesystem `fs_fsrl`, creating an empty index.
    ///
    /// Mirrors `AbstractFileSystem(FSRLRoot, FileSystemService)`; see the module docs for the
    /// service parameter.
    pub fn new(fs_fsrl: FsrlRoot) -> Self {
        let handle = AbstractFsHandle(Rc::new(fs_fsrl.clone()));
        let fs_index = FileSystemIndexHelper::from_fsrl_root(handle, &fs_fsrl);
        AbstractFileSystemBase { fs_fsrl, fs_index, filename_comparator: None }
    }

    /// Sets the comparator [`lookup`](Self::lookup) uses to match file names.
    ///
    /// Stands in for overriding the protected `getFilenameComparator()`.
    pub fn with_filename_comparator(mut self, comparator: fn(&str, &str) -> Ordering) -> Self {
        self.filename_comparator = Some(comparator);
        self
    }

    /// The comparator used by [`lookup`](Self::lookup); `None` means exact matching.
    /// Mirrors `getFilenameComparator()`.
    pub fn get_filename_comparator(&self) -> Option<fn(&str, &str) -> Ordering> {
        self.filename_comparator
    }

    /// The filesystem's volume name: the name of its container file. Mirrors `getName()`.
    pub fn get_name(&self) -> String {
        self.fs_fsrl.container().and_then(Fsrl::name).unwrap_or_default()
    }

    /// This filesystem's FSRL root. Mirrors `getFSRL()`.
    pub fn get_fsrl(&self) -> &FsrlRoot {
        &self.fs_fsrl
    }

    /// The file index (Java's protected `fsIndex`).
    pub fn fs_index(&self) -> &AbstractFsIndex<M> {
        &self.fs_index
    }

    /// Mutable access to the file index (Java's protected `fsIndex`).
    pub fn fs_index_mut(&mut self) -> &mut AbstractFsIndex<M> {
        &mut self.fs_index
    }

    /// Looks up `path` from the root using the
    /// [filename comparator](Self::get_filename_comparator). Mirrors `lookup(String)`.
    pub fn lookup(&self, path: Option<&str>) -> Option<&AbstractFsGFile> {
        let comparator = self.filename_comparator;
        let name_comp: NameComparator<'_> =
            comparator.as_ref().map(|c| c as &dyn Fn(&str, &str) -> Ordering);
        self.fs_index.lookup_with(None, path, name_comp)
    }

    /// Looks up `path` from the root comparing names with `name_comp` (`None`: exact).
    /// Mirrors `lookup(String, Comparator<String>)`.
    pub fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: NameComparator<'_>,
    ) -> Option<&AbstractFsGFile> {
        self.fs_index.lookup_with(None, path, name_comp)
    }

    /// The root directory. Mirrors `getRootDir()`.
    pub fn get_root_dir(&self) -> &AbstractFsGFile {
        self.fs_index.get_root_dir()
    }

    /// The files in `directory` (`None` means the root directory). Mirrors
    /// `getListing(GFile)`.
    pub fn get_listing(
        &self,
        directory: Option<&dyn GFile<AbstractFsHandle, Fsrl>>,
    ) -> Vec<&AbstractFsGFile> {
        self.fs_index.get_listing(directory)
    }

    /// Number of files in the index. Mirrors `getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        self.fs_index.get_file_count()
    }

    /// The target of `file` if it is a symlink, else `file`. Mirrors
    /// `resolveSymlinks(GFile)`.
    ///
    /// # Errors
    /// If `file` is unknown or symlinks are nested too deeply.
    pub fn resolve_symlinks(
        &self,
        file: &dyn GFile<AbstractFsHandle, Fsrl>,
    ) -> io::Result<Option<&AbstractFsGFile>> {
        self.fs_index.resolve_symlinks(file)
    }
}

/// Mirrors `toString()`, which returns `getName()`.
impl<M> fmt::Display for AbstractFileSystemBase<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.get_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::file_system_index_helper::copy_file;

    fn fs() -> AbstractFileSystemBase<u32> {
        let root = Fsrl::from_string("file:///tmp/libfoo.a").unwrap().make_nested("coff");
        AbstractFileSystemBase::new(root)
    }

    #[test]
    fn name_fsrl_and_display() {
        let fs = fs();
        assert_eq!(fs.get_name(), "libfoo.a");
        assert_eq!(fs.to_string(), "libfoo.a");
        assert_eq!(fs.get_fsrl().to_string(), "file:///tmp/libfoo.a|coff://");
        assert_eq!(fs.get_root_dir().get_fsrl().to_string(), "file:///tmp/libfoo.a|coff:///");
        assert_eq!(fs.get_file_count(), 1);
    }

    #[test]
    fn index_backed_lookup_and_listing() {
        let mut fs = fs();
        fs.fs_index_mut().store_file("dir/a.obj", -1, false, 10, 1);
        fs.fs_index_mut().store_file("b.obj", -1, false, 20, 2);
        assert_eq!(fs.get_file_count(), 4);
        let names: Vec<&str> = fs.get_listing(None).iter().map(|f| f.get_name()).collect();
        assert_eq!(names, ["dir", "b.obj"]);
        let a = fs.lookup(Some("/dir/a.obj")).unwrap();
        assert_eq!(a.get_fsrl().to_string(), "file:///tmp/libfoo.a|coff:///dir/a.obj");
        assert_eq!(fs.fs_index().get_metadata(a), Some(&1));
        assert!(fs.lookup(Some("/DIR/A.OBJ")).is_none());
        let ci: &dyn Fn(&str, &str) -> Ordering =
            &|x, y| x.to_lowercase().cmp(&y.to_lowercase());
        assert!(fs.lookup_with_comparator(Some("/DIR/A.OBJ"), Some(ci)).is_some());
    }

    #[test]
    fn filename_comparator_applies_to_lookup() {
        let mut fs = fs().with_filename_comparator(|x, y| x.to_lowercase().cmp(&y.to_lowercase()));
        assert!(fs.get_filename_comparator().is_some());
        fs.fs_index_mut().store_file("Readme.TXT", -1, false, 1, 0);
        assert_eq!(fs.lookup(Some("readme.txt")).unwrap().get_name(), "Readme.TXT");
    }

    #[test]
    fn resolve_symlinks_delegates() {
        let mut fs = fs();
        fs.fs_index_mut().store_file("target", -1, false, 1, 0);
        let link = copy_file(fs.fs_index_mut().store_symlink("link", -1, "target", 0, None));
        assert_eq!(fs.resolve_symlinks(&link).unwrap().unwrap().get_name(), "target");
    }

    #[test]
    fn gfile_listing_is_unsupported_and_handles_are_per_filesystem() {
        let a = fs();
        let b = fs();
        let err = a.get_root_dir().get_listing().err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_ne!(a.get_root_dir().get_filesystem(), b.get_root_dir().get_filesystem());
        assert!(a.get_listing(Some(b.get_root_dir())).is_empty());
    }
}
