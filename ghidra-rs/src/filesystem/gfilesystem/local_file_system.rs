//! Port of `ghidra.formats.gfilesystem.LocalFileSystem`.
//!
//! A [`GFileSystem`] over the host computer's own filesystem, the root that every other
//! filesystem FSRL eventually bottoms out at (`file:///...`).
//!
//! Distinct from the unrelated `ghidra.framework.store.local.LocalFileSystem`
//! ([`crate::framework::store::local::local_file_system`]).
//!
//! The files it hands out carry a [`LocalFsHandle`]: since a local directory can be listed
//! straight from the host filesystem, [`GFile::get_listing`] on them works directly (no index
//! back-reference is needed). Java's `ReferenceMap` fingerprint->MD5 cache (soft values) is
//! kept as an ordinary map.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::UNIX_EPOCH;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::file_byte_provider::{AccessMode, FileByteProvider};
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use super::annotations::file_system_info::FileSystemInfo;
use super::file_system_ref_manager::FileSystemRefManager;
use super::fileinfo::file_attribute_type::FileAttributeType;
use super::fileinfo::file_attributes::{FileAttributeValue, FileAttributes};
use super::fileinfo::file_type::FileType;
use super::fs_utilities;
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::g_file_hash_provider::GFileHashProvider;
use super::g_file_impl::{FsGetListing, GFileImpl, HasFsrlRoot};
use super::g_file_system::{GFileSystem, GFileSystemError};

/// The identity carried by every [`GFile`] a [`LocalFileSystem`] hands out (Java's
/// `GFileImpl.fileSystem` back-reference). Two handles are equal only if they belong to the
/// same filesystem instance.
#[derive(Clone)]
pub struct LocalFsHandle(Rc<FsrlRoot>);

impl PartialEq for LocalFsHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for LocalFsHandle {}

impl Hash for LocalFsHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Rc::as_ptr(&self.0), state);
    }
}

impl fmt::Debug for LocalFsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalFsHandle({})", self.0)
    }
}

impl HasFsrlRoot for LocalFsHandle {
    fn root_fsrl(&self) -> &Fsrl {
        self.0.as_fsrl()
    }
}

impl FsGetListing<LocalFsHandle> for LocalFsHandle {
    fn fs_get_listing(
        &self,
        file: &dyn GFile<LocalFsHandle>,
    ) -> io::Result<Vec<Box<dyn GFile<LocalFsHandle>>>> {
        Ok(list_dir(self, file))
    }
}

/// The concrete [`GFile`] type a [`LocalFileSystem`] hands out.
pub type LocalGFile = GFileImpl<LocalFsHandle>;

#[derive(Clone, PartialEq, Eq, Hash)]
struct FileFingerprintRec {
    path: String,
    timestamp: i64,
    length: u64,
}

/// A [`GFileSystem`] implementation giving access to the user's operating system's
/// filesystem.
///
/// Mirrors `ghidra.formats.gfilesystem.LocalFileSystem`.
pub struct LocalFileSystem {
    fs_fsrl: FsrlRoot,
    handle: LocalFsHandle,
    ref_manager: FileSystemRefManager,
    file_fingerprint_to_md5_map: RefCell<HashMap<FileFingerprintRec, String>>,
}

fn last_modified_millis(p: &Path) -> i64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn file_length(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

fn local_fsrl(handle: &LocalFsHandle, f: &Path) -> Fsrl {
    let mut abs_path = absolute(f).to_string_lossy().into_owned();
    if cfg!(windows) {
        abs_path = abs_path.replace('\\', "/");
    }
    let fsrl_path = fs_utilities::append_path(&[Some("/"), Some(&abs_path)])
        .unwrap_or_else(|| "/".to_string());
    handle.0.with_path_md5(Some(&fsrl_path), None)
}

/// `f` and its ancestors, most specific first: `/a/b` -> `[/a/b, /a, /]`.
fn get_file_path_parts(f: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut cur = Some(f);
    while let Some(p) = cur {
        results.push(p.to_path_buf());
        cur = p.parent();
    }
    results
}

fn root_dir(handle: &LocalFsHandle) -> LocalGFile {
    GFileImpl::from_fsrl(handle.clone(), None, handle.0.with_path_md5(Some("/"), None), true, -1)
}

fn get_gfile(handle: &LocalFsHandle, f: &Path) -> LocalGFile {
    let parts = get_file_path_parts(f);
    let mut current = root_dir(handle);
    // parts ends with the root element ("/"), which `current` already is (non-Windows).
    let start = if cfg!(windows) { parts.len() as isize - 1 } else { parts.len() as isize - 2 };
    let mut i = start;
    while i >= 0 {
        let part = &parts[i as usize];
        let child_fsrl = local_fsrl(handle, part);
        current = GFileImpl::from_fsrl(
            handle.clone(),
            Some(Box::new(current)),
            child_fsrl,
            part.is_dir(),
            file_length(part) as i64,
        );
        i -= 1;
    }
    current
}

fn list_dir(handle: &LocalFsHandle, directory: &dyn GFile<LocalFsHandle>) -> Vec<Box<dyn GFile<LocalFsHandle>>> {
    let local_dir = PathBuf::from(directory.get_path());
    if !local_dir.is_dir() || fs_utilities::is_symlink(&local_dir) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(&local_dir) else {
        return Vec::new();
    };
    let mut results: Vec<Box<dyn GFile<LocalFsHandle>>> = Vec::new();
    for entry in entries.flatten() {
        let f = entry.path();
        if f.is_file() || f.is_dir() || fs_utilities::is_symlink(&f) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let new_file_fsrl = directory.get_fsrl().append_path(&name);
            // Java passes `directory` itself as the parent; GFile parents are owned here, so
            // an equivalent parent chain is rebuilt from the directory's path.
            let parent = get_gfile(handle, &local_dir);
            results.push(Box::new(GFileImpl::from_fsrl(
                handle.clone(),
                Some(Box::new(parent)),
                new_file_fsrl,
                f.is_dir(),
                file_length(&f) as i64,
            )));
        }
    }
    results
}

fn update_case_insensitive_file_path(f: PathBuf) -> io::Result<PathBuf> {
    // On Windows, the canonical path carries the on-disk case of each element.
    if cfg!(windows) {
        std::fs::canonicalize(&f)
    } else {
        Ok(f)
    }
}

fn find_in_dir(
    dir: &Path,
    name: &str,
    name_comp: &dyn Fn(&str, &str) -> Ordering,
) -> io::Result<Option<PathBuf>> {
    let exact = dir.join(name);
    if exact.exists() {
        // Skip listing the whole directory if the exact match agrees with the comparator.
        let exact = update_case_insensitive_file_path(exact)?;
        let exact_name = exact.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name_comp(&exact_name, name) == Ordering::Equal {
            return Ok(Some(exact));
        }
    }
    // A case-insensitive comparator could match several files: return an exact match if
    // there is one, otherwise the first candidate in sorted order (stable across runs).
    let mut candidates = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let found = entry.file_name().to_string_lossy().into_owned();
            if name_comp(name, &found) == Ordering::Equal {
                if name == found {
                    return Ok(Some(entry.path()));
                }
                candidates.push(entry.path());
            }
        }
    }
    candidates.sort();
    Ok(candidates.into_iter().next())
}

impl LocalFileSystem {
    /// The filesystem type string, `"file"`. Mirrors `LocalFileSystem.FSTYPE`.
    pub const FSTYPE: &'static str = "file";

    /// `@FileSystemInfo(type = "file", description = "Local filesystem", factory =
    /// GFileSystemFactoryIgnore.class)`.
    pub const INFO: FileSystemInfo = FileSystemInfo::with(Self::FSTYPE, "Local filesystem", 0);

    /// Creates a new filesystem rooted at `file://`. Mirrors `makeGlobalRootFS()`.
    pub fn make_global_root_fs() -> Self {
        Self::new(FsrlRoot::make_root(Self::FSTYPE))
    }

    fn new(fsrl: FsrlRoot) -> Self {
        LocalFileSystem {
            handle: LocalFsHandle(Rc::new(fsrl.clone())),
            fs_fsrl: fsrl,
            ref_manager: FileSystemRefManager::new(),
            file_fingerprint_to_md5_map: RefCell::new(HashMap::new()),
        }
    }

    /// Returns `true` if `fsrl` is located on this filesystem. Mirrors `isSameFS(FSRL)`.
    pub fn is_same_fs(&self, fsrl: &Fsrl) -> bool {
        self.fs_fsrl == fsrl.fs()
    }

    /// Returns `true` if `fsrl` is a local directory. Mirrors `isLocalSubdir(FSRL)`.
    pub fn is_local_subdir(&self, fsrl: &Fsrl) -> bool {
        self.is_same_fs(fsrl) && Path::new(fsrl.path().unwrap_or("")).is_dir()
    }

    /// The local file `fsrl` names. Mirrors `getLocalFile(FSRL)`.
    ///
    /// # Errors
    /// If `fsrl` is not a local-filesystem FSRL.
    pub fn get_local_file(&self, fsrl: &Fsrl) -> io::Result<PathBuf> {
        if !self.is_same_fs(fsrl) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("FSRL does not specify local file: {fsrl}"),
            ));
        }
        Ok(PathBuf::from(fsrl.path().unwrap_or("")))
    }

    /// The FSRL of the local file `f`. Mirrors `getLocalFSRL(File)`.
    pub fn get_local_fsrl(&self, f: &Path) -> Fsrl {
        local_fsrl(&self.handle, f)
    }

    /// A [`GFile`] for the local file `f`, with its parent chain. Mirrors `getGFile(File)`.
    pub fn get_gfile(&self, f: &Path) -> LocalGFile {
        get_gfile(&self.handle, f)
    }

    /// The attributes of the local file `f`. Mirrors `getFileAttributes(File)`.
    pub fn get_local_file_attributes(&self, f: &Path) -> FileAttributes {
        let file_type = fs_utilities::get_file_type(f);
        let symlink_dest =
            if file_type == FileType::SymbolicLink { fs_utilities::read_symlink(f) } else { None };
        let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut attrs = FileAttributes::of([
            (FileAttributeType::NameAttr, Some(FileAttributeValue::Str(name))),
            (FileAttributeType::FileTypeAttr, Some(FileAttributeValue::FileType(file_type))),
            (FileAttributeType::SizeAttr, Some(FileAttributeValue::Long(file_length(f) as i64))),
            (FileAttributeType::ModifiedDateAttr, Some(FileAttributeValue::Date(last_modified_millis(f)))),
        ]);
        if let Some(dest) = symlink_dest {
            attrs.add(FileAttributeType::SymlinkDestAttr, Some(FileAttributeValue::Str(dest)));
        }
        attrs
    }

    /// A [`FileByteProvider`] over the local file `fsrl` names. Mirrors
    /// `getByteProvider(FSRL, TaskMonitor)`.
    ///
    /// # Errors
    /// If `fsrl` is not local or the file cannot be opened.
    pub fn get_byte_provider_for_fsrl(&self, fsrl: &Fsrl) -> io::Result<FileByteProvider> {
        let f = self.get_local_file(fsrl)?;
        FileByteProvider::new(&f, Some(fsrl.clone()), AccessMode::Read)
    }

    /// The MD5 of the local file `fsrl` names, cached by (path, timestamp, length). Returns
    /// `None` if not a file, or if not cached and not `required`. Mirrors
    /// `getMD5Hash(FSRL, boolean, TaskMonitor)`.
    ///
    /// # Errors
    /// If `fsrl` is not local, or hashing fails or is cancelled.
    pub fn get_md5_hash_for_fsrl(
        &self,
        fsrl: &Fsrl,
        required: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<String>, GFileSystemError> {
        let f = self.get_local_file(fsrl)?;
        if !f.is_file() {
            return Ok(None);
        }
        let rec = FileFingerprintRec {
            path: f.to_string_lossy().into_owned(),
            timestamp: last_modified_millis(&f),
            length: file_length(&f),
        };
        let cached = self.file_fingerprint_to_md5_map.borrow().get(&rec).cloned();
        if cached.is_none() && required {
            let md5 = fs_utilities::get_file_md5(&f, monitor)?;
            self.file_fingerprint_to_md5_map.borrow_mut().insert(rec, md5.clone());
            return Ok(Some(md5));
        }
        Ok(cached)
    }

    /// Looks up `path` (relative to `base_dir`, or absolute) on the local filesystem,
    /// optionally matching each path element with `name_comp`. Mirrors
    /// `lookupFile(File, String, Comparator)`.
    pub fn lookup_file(
        base_dir: Option<&Path>,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> Option<PathBuf> {
        let path = path.unwrap_or("/");
        let mut f = match base_dir {
            Some(b) => b.join(path),
            None => PathBuf::from(path),
        };
        if !f.is_absolute() {
            Msg::debug(
                "LocalFileSystem",
                &format!("Non-absolute path encountered in LocalFileSystem lookup: {path}"),
            );
            f = absolute(&f);
        }
        let result = (|| -> io::Result<Option<PathBuf>> {
            match name_comp {
                Some(cmp) if f.parent().is_some() => {
                    // Look each element up in its parent's listing; "." and ".." elements are
                    // never found this way, which avoids path traversal.
                    let mut parts = get_file_path_parts(&f);
                    let mut i = parts.len() as isize - 2;
                    while i >= 0 {
                        let idx = i as usize;
                        let parent_dir = parts[idx + 1].clone();
                        let name = parts[idx]
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        match find_in_dir(&parent_dir, &name, cmp)? {
                            Some(found) => parts[idx] = found,
                            None => return Ok(None),
                        }
                        i -= 1;
                    }
                    Ok(Some(parts.swap_remove(0)))
                }
                _ => {
                    let f = update_case_insensitive_file_path(f.clone())?;
                    Ok((fs_utilities::is_symlink(&f) || f.exists()).then_some(f))
                }
            }
        })();
        result.unwrap_or_else(|e| {
            Msg::warn("LocalFileSystem", &format!("Error resolving path: {path}: {e}"));
            None
        })
    }
}

impl GFileSystem for LocalFileSystem {
    type Fs = LocalFsHandle;

    fn get_name(&self) -> String {
        "Root Filesystem".to_string()
    }

    fn get_type(&self) -> String {
        Self::INFO.fs_type.to_string()
    }

    fn get_description(&self) -> String {
        Self::INFO.description.to_string()
    }

    fn get_fsrl(&self) -> &FsrlRoot {
        &self.fs_fsrl
    }

    fn is_closed(&self) -> bool {
        false
    }

    fn is_static(&self) -> bool {
        false
    }

    fn get_ref_manager(&self) -> &FileSystemRefManager {
        &self.ref_manager
    }

    fn lookup(&self, path: Option<&str>) -> io::Result<Option<Box<dyn GFile<LocalFsHandle>>>> {
        self.lookup_with_comparator(path, None)
    }

    fn lookup_with_comparator(
        &self,
        path: Option<&str>,
        name_comp: Option<&dyn Fn(&str, &str) -> Ordering>,
    ) -> io::Result<Option<Box<dyn GFile<LocalFsHandle>>>> {
        if path.is_none() || path == Some("/") {
            return Ok(Some(Box::new(root_dir(&self.handle))));
        }
        Ok(Self::lookup_file(None, path, name_comp)
            .map(|f| Box::new(self.get_gfile(&f)) as Box<dyn GFile<LocalFsHandle>>))
    }

    fn get_byte_provider(
        &self,
        file: &dyn GFile<LocalFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
        Ok(Some(Box::new(self.get_byte_provider_for_fsrl(file.get_fsrl())?)))
    }

    fn get_input_stream(
        &self,
        file: &dyn GFile<LocalFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn io::Read>>, GFileSystemError> {
        let f = self.get_local_file(file.get_fsrl())?;
        Ok(Some(Box::new(std::fs::File::open(f)?)))
    }

    fn get_listing(
        &self,
        directory: Option<&dyn GFile<LocalFsHandle>>,
    ) -> io::Result<Vec<Box<dyn GFile<LocalFsHandle>>>> {
        match directory {
            Some(d) => Ok(list_dir(&self.handle, d)),
            None => Ok(list_dir(&self.handle, &root_dir(&self.handle))),
        }
    }

    fn get_file_attributes(
        &self,
        file: &dyn GFile<LocalFsHandle>,
        _monitor: &dyn TaskMonitor,
    ) -> FileAttributes {
        self.get_local_file_attributes(Path::new(file.get_path()))
    }

    fn get_file_type(&self, file: &dyn GFile<LocalFsHandle>, _monitor: &dyn TaskMonitor) -> FileType {
        fs_utilities::get_file_type(Path::new(file.get_path()))
    }

    fn resolve_symlinks(
        &self,
        file: &dyn GFile<LocalFsHandle>,
    ) -> io::Result<Option<Box<dyn GFile<LocalFsHandle>>>> {
        let f = self.get_local_file(file.get_fsrl())?;
        let canonical = std::fs::canonicalize(&f)?;
        // Java returns `file` itself when already canonical; GFiles are owned here, so an
        // equivalent file is rebuilt.
        Ok(Some(Box::new(self.get_gfile(&canonical))))
    }

    /// Does nothing, like Java: the local filesystem is never closed.
    fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn as_hash_provider(&self) -> Option<&dyn GFileHashProvider<LocalFsHandle>> {
        Some(self)
    }
}

impl GFileHashProvider<LocalFsHandle> for LocalFileSystem {
    fn get_md5_hash(
        &self,
        file: &dyn GFile<LocalFsHandle>,
        required: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<String>, GFileSystemError> {
        self.get_md5_hash_for_fsrl(file.get_fsrl(), required, monitor)
    }
}

impl fmt::Display for LocalFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Local file system {}", self.fs_fsrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn local_fsrl_round_trips_to_local_file() {
        let lfs = LocalFileSystem::make_global_root_fs();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"abc").unwrap();
        let fsrl = lfs.get_local_fsrl(&f);
        assert_eq!(fsrl.to_string(), format!("file://{}", f.display()));
        assert!(lfs.is_same_fs(&fsrl));
        assert_eq!(lfs.get_local_file(&fsrl).unwrap(), f);
        let other = Fsrl::from_string("file:///x.zip|zip:///y").unwrap();
        assert!(!lfs.is_same_fs(&other));
        assert!(lfs.get_local_file(&other).is_err());
    }

    #[test]
    fn lookup_listing_and_bytes() {
        let lfs = LocalFileSystem::make_global_root_fs();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let d = GFileSystem::lookup(&lfs, dir.path().to_str()).unwrap().unwrap();
        assert!(d.is_directory());
        assert_eq!(d.get_parent_file().unwrap().get_path(), dir.path().parent().unwrap().to_str().unwrap());
        let mut names: Vec<String> =
            GFileSystem::get_listing(&lfs, Some(d.as_ref())).unwrap().iter().map(|f| f.get_name().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["sub", "x.txt"]);
        // GFile::get_listing works directly on local files.
        assert_eq!(d.get_listing().unwrap().len(), 2);

        let x = GFileSystem::lookup(&lfs, dir.path().join("x.txt").to_str()).unwrap().unwrap();
        assert_eq!(x.get_length(), 5);
        let bp = GFileSystem::get_byte_provider(&lfs, x.as_ref(), &DummyMonitor).unwrap().unwrap();
        assert_eq!(bp.read_bytes(0, 5).unwrap(), b"hello");
        assert_eq!(bp.get_fsrl(), Some(x.get_fsrl()));
        assert!(GFileSystem::lookup(&lfs, dir.path().join("nope").to_str()).unwrap().is_none());
        assert!(GFileSystem::lookup(&lfs, None).unwrap().unwrap().is_directory());
    }

    #[test]
    fn lookup_with_case_insensitive_comparator() {
        let lfs = LocalFileSystem::make_global_root_fs();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Mixed.TXT"), b"1").unwrap();
        let cmp = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
        let found = lfs
            .lookup_with_comparator(dir.path().join("mixed.txt").to_str(), Some(&cmp))
            .unwrap()
            .unwrap();
        assert_eq!(found.get_name(), "Mixed.TXT");
    }

    #[test]
    fn attributes_and_md5_hash() {
        let lfs = LocalFileSystem::make_global_root_fs();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("h.txt");
        std::fs::write(&f, b"hello").unwrap();
        let attrs = lfs.get_local_file_attributes(&f);
        assert_eq!(attrs.get(FileAttributeType::SizeAttr), Some(&FileAttributeValue::Long(5)));
        assert_eq!(
            attrs.get(FileAttributeType::FileTypeAttr),
            Some(&FileAttributeValue::FileType(FileType::File))
        );
        let fsrl = lfs.get_local_fsrl(&f);
        assert_eq!(lfs.get_md5_hash_for_fsrl(&fsrl, false, &DummyMonitor).unwrap(), None);
        assert_eq!(
            lfs.get_md5_hash_for_fsrl(&fsrl, true, &DummyMonitor).unwrap().as_deref(),
            Some("5d41402abc4b2a76b9719d911017c592")
        );
        // Now cached: available without `required`.
        assert!(lfs.get_md5_hash_for_fsrl(&fsrl, false, &DummyMonitor).unwrap().is_some());
        let dir_fsrl = lfs.get_local_fsrl(dir.path());
        assert_eq!(lfs.get_md5_hash_for_fsrl(&dir_fsrl, true, &DummyMonitor).unwrap(), None);
    }

    #[test]
    fn root_fs_is_never_closed_and_not_static() {
        let lfs = LocalFileSystem::make_global_root_fs();
        assert!(!GFileSystem::is_closed(&lfs));
        assert!(!GFileSystem::is_static(&lfs));
        assert_eq!(GFileSystem::get_name(&lfs), "Root Filesystem");
        assert_eq!(lfs.get_fsrl().to_string(), "file://");
    }
}
