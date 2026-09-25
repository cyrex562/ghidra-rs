//! Port of `ghidra.formats.gfilesystem.SingleFileSystemIndexHelper`.
//!
//! A helper for filesystems that only ever hold a single "payload" file: it owns a synthetic
//! root directory plus the one payload file inside it, and answers the listing / lookup /
//! attribute queries a `GFileSystem` needs.
//!
//! Java's `GFileImpl` holds a back-reference to its owning `GFileSystem`. As with the other
//! filesystems in this crate (`SevenZipFileSystem`, `DyldCacheFileSystem`), the files handed
//! out here are [`GFileImpl`]s parameterized with a small cloneable
//! [`SinglePayloadFsHandle`] instead, which carries exactly what a file needs from its
//! filesystem (the root FSRL for path derivation, and enough to answer `getListing()`).

use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::rc::Rc;

use super::fileinfo::file_attributes::FileAttributes;
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::g_file_impl::{FsGetListing, GFileImpl, HasFsrlRoot};

/// The concrete [`GFile`] type a [`SingleFileSystemIndexHelper`] hands out.
pub type SinglePayloadGFile = GFileImpl<SinglePayloadFsHandle, Fsrl>;

struct HandleState {
    fs_fsrl: FsrlRoot,
    root_fsrl: Fsrl,
    payload_fsrl: Fsrl,
    payload_length: i64,
    closed: Cell<bool>,
}

/// The filesystem identity stored inside each [`SinglePayloadGFile`].
///
/// Stands in for the Java `GFileImpl.fileSystem` back-reference. Two handles are equal only if
/// they are clones of the same handle, matching Java's identity comparison of the owning
/// filesystem in `GFileImpl.equals`.
#[derive(Clone)]
pub struct SinglePayloadFsHandle(Rc<HandleState>);

impl SinglePayloadFsHandle {
    fn root_file(&self) -> SinglePayloadGFile {
        GFileImpl::from_fsrl(self.clone(), None, self.0.root_fsrl.clone(), true, -1)
    }

    fn payload_file(&self) -> SinglePayloadGFile {
        GFileImpl::from_fsrl(
            self.clone(),
            Some(Box::new(self.root_file())),
            self.0.payload_fsrl.clone(),
            false,
            self.0.payload_length,
        )
    }

    fn is_root(&self, file: &dyn GFile<SinglePayloadFsHandle, Fsrl>) -> bool {
        file.get_filesystem() == self
            && file.is_directory()
            && Some(file.get_path()) == self.0.root_fsrl.path()
    }

    fn listing_of(
        &self,
        directory: Option<&dyn GFile<SinglePayloadFsHandle, Fsrl>>,
    ) -> io::Result<bool> {
        if self.0.closed.get() {
            return Err(io::Error::other("Invalid state, index already closed"));
        }
        Ok(directory.is_none_or(|d| self.is_root(d)))
    }
}

impl PartialEq for SinglePayloadFsHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SinglePayloadFsHandle {}

impl Hash for SinglePayloadFsHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Rc::as_ptr(&self.0), state);
    }
}

impl fmt::Debug for SinglePayloadFsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SinglePayloadFsHandle({})", self.0.fs_fsrl)
    }
}

impl HasFsrlRoot<Fsrl> for SinglePayloadFsHandle {
    fn root_fsrl(&self) -> &Fsrl {
        self.0.fs_fsrl.as_fsrl()
    }
}

impl FsGetListing<SinglePayloadFsHandle, Fsrl> for SinglePayloadFsHandle {
    fn fs_get_listing(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle, Fsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<SinglePayloadFsHandle, Fsrl>>>> {
        Ok(if self.listing_of(Some(file))? {
            vec![Box::new(self.payload_file())]
        } else {
            Vec::new()
        })
    }
}

/// `GFileImpl.equals` for a file this helper created versus an arbitrary [`GFile`]: same
/// owning filesystem, same path, same directory flag.
fn same_file(a: &SinglePayloadGFile, b: &dyn GFile<SinglePayloadFsHandle, Fsrl>) -> bool {
    a.get_filesystem() == b.get_filesystem()
        && a.get_path() == b.get_path()
        && a.is_directory() == b.is_directory()
}

/// A helper class used by `GFileSystem` implementations that have a single file.
///
/// Mirrors `ghidra.formats.gfilesystem.SingleFileSystemIndexHelper`.
pub struct SingleFileSystemIndexHelper {
    handle: SinglePayloadFsHandle,
    root_dir: SinglePayloadGFile,
    payload_file: Option<SinglePayloadGFile>,
    payload_attrs: Option<FileAttributes>,
}

impl SingleFileSystemIndexHelper {
    /// Creates a new instance. A "root" directory file is auto-created for the filesystem,
    /// holding a single payload file named `payload_filename`.
    ///
    /// Mirrors `SingleFileSystemIndexHelper(GFileSystem, FSRLRoot, String, long, String)`. The
    /// Java `fs` parameter only serves as the owner of the created files; here that owner is
    /// the [`SinglePayloadFsHandle`] this constructor creates.
    pub fn new(
        fs_fsrl: &FsrlRoot,
        payload_filename: &str,
        length: i64,
        payload_md5: Option<&str>,
    ) -> Self {
        let root_fsrl = fs_fsrl.with_path("/");
        let payload_fsrl = root_fsrl.append_path(payload_filename).with_md5(payload_md5);
        let handle = SinglePayloadFsHandle(Rc::new(HandleState {
            fs_fsrl: fs_fsrl.clone(),
            root_fsrl,
            payload_fsrl,
            payload_length: length,
            closed: Cell::new(false),
        }));
        let root_dir = handle.root_file();
        let payload_file = Some(handle.payload_file());
        SingleFileSystemIndexHelper { handle, root_dir, payload_file, payload_attrs: None }
    }

    /// Clears the data held by this object. Mirrors `clear()`.
    pub fn clear(&mut self) {
        self.payload_file = None;
        self.handle.0.closed.set(true);
    }

    /// `true` if `file` is the payload file. Mirrors `isPayloadFile(GFile)`; always `false`
    /// once [`clear`](Self::clear)ed.
    pub fn is_payload_file(&self, file: &dyn GFile<SinglePayloadFsHandle, Fsrl>) -> bool {
        self.payload_file.as_ref().is_some_and(|p| same_file(p, file))
    }

    /// `true` if this object has been [`clear`](Self::clear)ed. Mirrors `isClosed()`.
    pub fn is_closed(&self) -> bool {
        self.payload_file.is_none()
    }

    /// The payload file, i.e. the main file of this filesystem; `None` once cleared.
    /// Mirrors `getPayloadFile()`.
    pub fn get_payload_file(&self) -> Option<&SinglePayloadGFile> {
        self.payload_file.as_ref()
    }

    /// The root directory's FSRL. Mirrors `getRootDirFSRL()`.
    pub fn get_root_dir_fsrl(&self) -> &Fsrl {
        self.root_dir.get_fsrl()
    }

    /// The root directory. Mirrors `getRootDir()`.
    pub fn get_root_dir(&self) -> &SinglePayloadGFile {
        &self.root_dir
    }

    /// Number of files in this index, always 1. Mirrors `getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        1
    }

    /// The files in `directory` (`None` means the root directory): the payload file for the
    /// root, nothing for anything else.
    ///
    /// Mirrors `getListing(GFile)`.
    ///
    /// # Errors
    /// If this index has already been cleared.
    pub fn get_listing(
        &self,
        directory: Option<&dyn GFile<SinglePayloadFsHandle, Fsrl>>,
    ) -> io::Result<Vec<&SinglePayloadGFile>> {
        let is_root = self.handle.listing_of(directory)?;
        Ok(match (&self.payload_file, is_root) {
            (Some(p), true) => vec![p],
            _ => Vec::new(),
        })
    }

    /// Looks up `path` from the root: `None` or `"/"` is the root directory, the payload
    /// file's path (or bare name) is the payload file, anything else is `None`.
    ///
    /// Mirrors `lookup(String)`.
    pub fn lookup(&self, path: Option<&str>) -> Option<&SinglePayloadGFile> {
        self.lookup_with(None, path, None)
    }

    /// Looks up `path` relative to `base_dir` (which must be the root directory, if given),
    /// comparing names with `name_comp` (default: exact, case-sensitive comparison).
    ///
    /// The payload file matches either its FSRL path (`"/payloadname"`) or just its name, for
    /// compatibility with existing data holding malformed FSRLs without a leading slash.
    ///
    /// Mirrors `lookup(GFile, String, Comparator<String>)`.
    pub fn lookup_with(
        &self,
        base_dir: Option<&dyn GFile<SinglePayloadFsHandle, Fsrl>>,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> Option<&SinglePayloadGFile> {
        if base_dir.is_some_and(|b| !same_file(&self.root_dir, b)) {
            return None;
        }
        let path = match path {
            None | Some("/") => return Some(&self.root_dir),
            Some(p) => p,
        };
        let payload = self.payload_file.as_ref()?;
        let cmp = |a: &str, b: &str| match name_comp {
            Some(f) => f(a, b),
            None => a.cmp(b),
        };
        let fsrl = payload.get_fsrl();
        let matches = |candidate: Option<&str>| {
            candidate.is_some_and(|c| cmp(path, c) == Ordering::Equal)
        };
        (matches(fsrl.path()) || matches(fsrl.name().as_deref())).then_some(payload)
    }

    /// Sets the attributes reported for the payload file. Mirrors
    /// `setPayloadFileAttributes(FileAttributes)`.
    pub fn set_payload_file_attributes(&mut self, attrs: FileAttributes) {
        self.payload_attrs = Some(attrs);
    }

    /// The payload file's attributes for the payload file, otherwise
    /// [`FileAttributes::empty`]. Mirrors `getFileAttributes(GFile)`.
    pub fn get_file_attributes(
        &self,
        file: &dyn GFile<SinglePayloadFsHandle, Fsrl>,
    ) -> &FileAttributes {
        match &self.payload_attrs {
            Some(attrs) if self.is_payload_file(file) => attrs,
            _ => FileAttributes::empty(),
        }
    }
}

impl fmt::Display for SingleFileSystemIndexHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SingleFileSystemIndexHelper for {}", self.handle.0.fs_fsrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;

    fn fs_root() -> FsrlRoot {
        Fsrl::from_string("file:///tmp/container.gz").unwrap().make_nested("gzip")
    }

    fn helper() -> SingleFileSystemIndexHelper {
        SingleFileSystemIndexHelper::new(&fs_root(), "payload.bin", 1234, Some("0123abcd"))
    }

    #[test]
    fn root_and_payload_fsrls() {
        let h = helper();
        assert_eq!(h.get_root_dir_fsrl().to_string(), "file:///tmp/container.gz|gzip:///");
        assert!(h.get_root_dir().is_directory());
        let p = h.get_payload_file().unwrap();
        assert_eq!(p.get_name(), "payload.bin");
        assert_eq!(p.get_path(), "/payload.bin");
        assert_eq!(p.get_length(), 1234);
        assert!(!p.is_directory());
        assert_eq!(p.get_fsrl().md5(), Some("0123abcd"));
        assert_eq!(p.get_parent_file().unwrap().get_path(), "/");
        assert_eq!(h.get_file_count(), 1);
    }

    #[test]
    fn listing_of_root_is_payload_only() {
        let h = helper();
        let names: Vec<&str> = h.get_listing(None).unwrap().iter().map(|f| f.get_name()).collect();
        assert_eq!(names, ["payload.bin"]);
        let via_root = h.get_listing(Some(h.get_root_dir())).unwrap();
        assert_eq!(via_root.len(), 1);
        let payload = h.get_payload_file().unwrap();
        assert!(h.get_listing(Some(payload)).unwrap().is_empty());
    }

    #[test]
    fn gfile_get_listing_delegates_to_handle() {
        let h = helper();
        let listing = h.get_root_dir().get_listing().unwrap();
        assert_eq!(listing.len(), 1);
        assert!(h.is_payload_file(listing[0].as_ref()));
        assert!(h.get_payload_file().unwrap().get_listing().unwrap().is_empty());
    }

    #[test]
    fn lookup_root_and_payload_by_path_or_name() {
        let h = helper();
        assert!(h.lookup(None).unwrap().is_directory());
        assert!(h.lookup(Some("/")).unwrap().is_directory());
        assert_eq!(h.lookup(Some("/payload.bin")).unwrap().get_name(), "payload.bin");
        assert_eq!(h.lookup(Some("payload.bin")).unwrap().get_name(), "payload.bin");
        assert!(h.lookup(Some("/PAYLOAD.BIN")).is_none());
        assert!(h.lookup(Some("/other")).is_none());
    }

    #[test]
    fn lookup_with_comparator_and_base_dir() {
        let h = helper();
        let ci: &dyn Fn(&str, &str) -> Ordering =
            &|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase());
        assert!(h.lookup_with(None, Some("/PAYLOAD.BIN"), Some(ci)).is_some());
        assert!(h.lookup_with(Some(h.get_root_dir()), Some("payload.bin"), None).is_some());
        let payload = h.get_payload_file().unwrap();
        assert!(h.lookup_with(Some(payload), Some("payload.bin"), None).is_none());
    }

    #[test]
    fn files_from_another_helper_are_not_payload() {
        let a = helper();
        let b = helper();
        assert!(a.is_payload_file(a.get_payload_file().unwrap()));
        assert!(!a.is_payload_file(b.get_payload_file().unwrap()));
        assert!(!a.is_payload_file(a.get_root_dir()));
    }

    #[test]
    fn attributes_only_for_payload() {
        let mut h = helper();
        let payload = h.get_payload_file().unwrap();
        assert!(h.get_file_attributes(payload).get_attributes().is_empty());
        h.set_payload_file_attributes(FileAttributes::of([(
            FileAttributeType::SizeAttr,
            Some(1234i64.into()),
        )]));
        let payload = h.get_payload_file().unwrap();
        assert_eq!(h.get_file_attributes(payload).get_long(FileAttributeType::SizeAttr, -1), 1234);
        assert!(h.get_file_attributes(h.get_root_dir()).get_attributes().is_empty());
    }

    #[test]
    fn clear_closes_index() {
        let mut h = helper();
        let root_listing_before = h.get_root_dir().get_listing().unwrap().len();
        assert_eq!(root_listing_before, 1);
        h.clear();
        assert!(h.is_closed());
        assert!(h.get_payload_file().is_none());
        assert!(h.get_listing(None).is_err());
        assert!(h.get_root_dir().get_listing().is_err());
        assert!(h.lookup(Some("/payload.bin")).is_none());
        assert!(h.lookup(Some("/")).is_some());
    }

    #[test]
    fn display_names_filesystem() {
        assert_eq!(
            helper().to_string(),
            "SingleFileSystemIndexHelper for file:///tmp/container.gz|gzip://"
        );
    }
}
