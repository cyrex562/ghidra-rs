//! Port of `ghidra.formats.gfilesystem.FileSystemIndexHelper`.
//!
//! A helper used by `GFileSystem` implementations to track mappings between [`GFileImpl`]
//! instances and the container filesystem's native file objects ("metadata"), maintaining a
//! directory tree with path lookups, symlink resolution and per-directory filename
//! "unique-ifying" (a `"[nnn]"` suffix is added to a file's name if it is not unique in its
//! directory).
//!
//! # Rust shape
//!
//! Java keys its three maps by `GFile` object (whose equality is owning filesystem + path +
//! directory flag). Here every file's data lives in an arena (`Vec`) and the maps hold arena
//! indices, keyed by `(path, is_directory)`; a queried [`GFile`] only resolves if its owning
//! filesystem equals this index's filesystem, preserving Java's `GFileImpl.equals` semantics.
//!
//! The index is generic over the filesystem handle `FS` its files carry (see [`GFileImpl`]);
//! file locators are the real [`Fsrl`]. Java's `synchronized` methods become `&self` /
//! `&mut self` borrows.

use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::io;

use crate::util::msg::Msg;

use super::fs_utilities::split_path;
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file::GFile;
use super::g_file_impl::{FsGetListing, GFileImpl, HasFsrlRoot};

/// Mirrors `FileSystemIndexHelper.MAX_SYMLINK_RECURSE_DEPTH`.
const MAX_SYMLINK_RECURSE_DEPTH: usize = 10;

/// Arena index of the root directory.
const ROOT: usize = 0;

/// Optional filename comparator, mirroring Java's nullable `Comparator<String>` (`None` means
/// exact matching).
pub type NameComparator<'a> = Option<&'a dyn Fn(&str, &str) -> Ordering>;

/// Map key standing in for Java's `GFile` hash key within one filesystem.
type FileKey = (String, bool);

/// Mirrors the nested `FileSystemIndexHelper.FileData` class.
struct FileData<FS, M> {
    file: GFileImpl<FS>,
    metadata: Option<M>,
    file_index: i64,
    symlink_path: Option<String>,
}

/// One directory's contents: name -> arena index, plus insertion order so listings are
/// deterministic (Java's `HashMap` iteration order is unspecified).
#[derive(Default)]
struct DirListing {
    by_name: HashMap<String, usize>,
    order: Vec<String>,
}

impl DirListing {
    fn insert(&mut self, name: String, idx: usize) {
        if self.by_name.insert(name.clone(), idx).is_none() {
            self.order.push(name);
        }
    }
}

fn key_of<FS>(file: &dyn GFile<FS>) -> FileKey {
    (file.get_path().to_owned(), file.is_directory())
}

/// Deep-copies `file` (and its parent chain) into an owned [`GFileImpl`] that compares equal
/// to it, standing in for Java sharing the same `GFile` reference (e.g. to keep a file while
/// the index that handed it out is mutated).
pub fn copy_file<FS>(file: &dyn GFile<FS>) -> GFileImpl<FS>
where
    FS: Clone + HasFsrlRoot + FsGetListing<FS> + 'static,
{
    let parent = file
        .get_parent_file()
        .map(|p| Box::new(copy_file(p)) as Box<dyn GFile<FS>>);
    GFileImpl::from_fsrl(
        file.get_filesystem().clone(),
        parent,
        file.get_fsrl().clone(),
        file.is_directory(),
        file.get_length(),
    )
}

/// Tracks the [`GFileImpl`]s of a container filesystem and the native metadata (`M`) of each.
///
/// Mirrors `ghidra.formats.gfilesystem.FileSystemIndexHelper<METADATATYPE>`.
pub struct FileSystemIndexHelper<FS, M> {
    filesystem: FS,
    /// Arena of every file ever stored; index [`ROOT`] is the root directory. Entries are
    /// never removed individually (only by [`clear`](Self::clear)).
    files: Vec<FileData<FS, M>>,
    file_to_entry: HashMap<FileKey, usize>,
    file_index_to_entry: HashMap<i64, usize>,
    directory_to_listing: HashMap<FileKey, DirListing>,
    /// Set by [`clear`](Self::clear), which takes `&self` so a shared filesystem can close its
    /// index. While set, the index behaves as if its maps were empty; the storage itself is
    /// released by the next mutation (or when the index is dropped).
    cleared: Cell<bool>,
}

impl<FS, M> FileSystemIndexHelper<FS, M>
where
    FS: Clone + PartialEq + HasFsrlRoot + FsGetListing<FS> + 'static,
{
    /// Creates an index for the filesystem `fs` whose FSRL root is `fs_fsrl`; the root
    /// directory is `fs_fsrl.withPath("/")`.
    ///
    /// Mirrors `FileSystemIndexHelper(GFileSystem, FSRLRoot)`.
    pub fn from_fsrl_root(fs: FS, fs_fsrl: &FsrlRoot) -> Self {
        Self::new(fs, fs_fsrl.with_path("/"))
    }
}

impl<FS, M> FileSystemIndexHelper<FS, M>
where
    FS: Clone + PartialEq + HasFsrlRoot + FsGetListing<FS> + 'static,
{
    /// Creates an index for `filesystem`, auto-creating a root directory with the FSRL
    /// `root_dir_fsrl` (Java passes `fsFSRL.withPath("/")`).
    ///
    /// Mirrors `FileSystemIndexHelper(GFileSystem, FSRLRoot)`; see also
    /// [`from_fsrl_root`](Self::from_fsrl_root), which derives `root_dir_fsrl` from the root.
    pub fn new(filesystem: FS, root_dir_fsrl: Fsrl) -> Self {
        let root_file = GFileImpl::from_fsrl(filesystem.clone(), None, root_dir_fsrl, true, -1);
        let root_key = key_of(&root_file);
        let mut helper = FileSystemIndexHelper {
            filesystem,
            files: vec![FileData { file: root_file, metadata: None, file_index: -1, symlink_path: None }],
            file_to_entry: HashMap::new(),
            file_index_to_entry: HashMap::new(),
            directory_to_listing: HashMap::new(),
            cleared: Cell::new(false),
        };
        helper.file_to_entry.insert(root_key.clone(), ROOT);
        helper.directory_to_listing.insert(root_key, DirListing::default());
        helper
    }

    /// The root directory. Mirrors `getRootDir()`.
    pub fn get_root_dir(&self) -> &GFileImpl<FS> {
        &self.files[ROOT].file
    }

    /// Removes all file info from this index (the root directory object itself is kept, but
    /// is no longer indexed). Mirrors `clear()`.
    ///
    /// Takes `&self` (Java's method is `synchronized`) so a filesystem shared through
    /// [`FsHandle`](super::g_file_system::FsHandle)s can clear its index from
    /// [`GFileSystem::close`](super::g_file_system::GFileSystem::close). The index reads as empty
    /// from then on; storing new files first discards the old ones.
    pub fn clear(&self) {
        self.cleared.set(true);
    }

    /// `true` once [`clear`](Self::clear)ed (and not since refilled).
    pub fn is_cleared(&self) -> bool {
        self.cleared.get()
    }

    /// Physically discards the contents of a [`clear`](Self::clear)ed index before a
    /// mutation, so the index then behaves exactly like Java's emptied maps.
    fn purge_if_cleared(&mut self) {
        if self.cleared.replace(false) {
            self.file_to_entry.clear();
            self.directory_to_listing.clear();
            self.file_index_to_entry.clear();
            self.files.truncate(1);
        }
    }

    /// Number of files in this index, including the root directory and any directories that
    /// were auto-created. Mirrors `getFileCount()`.
    pub fn get_file_count(&self) -> i32 {
        if self.cleared.get() {
            return 0;
        }
        self.file_to_entry.len() as i32
    }

    /// The indexed entry for `file`, if `file` belongs to this filesystem and is indexed.
    fn entry_of(&self, file: &dyn GFile<FS>) -> Option<usize> {
        if file.get_filesystem() != &self.filesystem || self.cleared.get() {
            return None;
        }
        self.file_to_entry.get(&key_of(file)).copied()
    }

    /// Mirrors the private `getFileData(GFile)`: `None` is the root directory.
    fn get_file_data(&self, file: Option<&dyn GFile<FS>>) -> io::Result<usize> {
        match file {
            None => Ok(ROOT),
            Some(f) => self
                .entry_of(f)
                .ok_or_else(|| io::Error::other(format!("Unknown file: {}", f.get_path()))),
        }
    }

    /// Mirrors the private `getParentFileData(FileData)`.
    fn get_parent_file_data(&self, idx: usize) -> Option<usize> {
        self.files[idx].file.get_parent_file().and_then(|p| self.entry_of(p))
    }

    /// The metadata associated with `file`, or `None` if not found (or none was stored).
    /// Mirrors `getMetadata(GFile)`.
    pub fn get_metadata(&self, file: &dyn GFile<FS>) -> Option<&M> {
        self.entry_of(file).and_then(|i| self.files[i].metadata.as_ref())
    }

    /// Sets the metadata associated with `file`. Mirrors `setMetadata(GFile, METADATATYPE)`.
    ///
    /// # Errors
    /// If `file` is not in this index.
    pub fn set_metadata(&mut self, file: &dyn GFile<FS>, metadata: M) -> io::Result<()> {
        self.purge_if_cleared();
        let idx = self.get_file_data(Some(file))?;
        self.files[idx].metadata = Some(metadata);
        Ok(())
    }

    /// The file stored with the filesystem-specific index `file_index`, or `None`.
    /// Mirrors `getFileByIndex(long)`.
    pub fn get_file_by_index(&self, file_index: i64) -> Option<&GFileImpl<FS>> {
        if self.cleared.get() {
            return None;
        }
        self.file_index_to_entry.get(&file_index).map(|&i| &self.files[i].file)
    }

    /// The files that have been added to `directory` (`None` means the root directory), in
    /// insertion order; empty if unknown. Mirrors `getListing(GFile)`.
    pub fn get_listing(
        &self,
        directory: Option<&dyn GFile<FS>>,
    ) -> Vec<&GFileImpl<FS>> {
        if self.cleared.get() {
            return Vec::new();
        }
        let key = match directory {
            None => key_of(&self.files[ROOT].file),
            Some(d) if d.get_filesystem() == &self.filesystem => key_of(d),
            Some(_) => return Vec::new(),
        };
        self.directory_to_listing
            .get(&key)
            .map(|l| l.order.iter().map(|n| &self.files[l.by_name[n]].file).collect())
            .unwrap_or_default()
    }

    /// The file at `path` (exact name matching), or `None`. Mirrors `lookup(String)`.
    pub fn lookup(&self, path: &str) -> Option<&GFileImpl<FS>> {
        self.lookup_with(None, Some(path), None)
    }

    /// The file at `path` relative to `base_dir` (default: root), comparing names with
    /// `name_comp` (default: exact), or `None`.
    ///
    /// Mirrors `lookup(GFile, String, Comparator<String>)`.
    pub fn lookup_with(
        &self,
        base_dir: Option<&dyn GFile<FS>>,
        path: Option<&str>,
        name_comp: NameComparator<'_>,
    ) -> Option<&GFileImpl<FS>> {
        // Java: an unknown base dir throws IOException, which is swallowed into null.
        let base = self.get_file_data(base_dir).ok()?;
        let parts = split_path(path);
        self.lookup_idx(Some(base), &parts, None, name_comp).map(|i| &self.files[i].file)
    }

    /// Read-only form of the protected `lookup(FileData, String[], int, boolean, Comparator)`
    /// (`createIfMissing == false`).
    fn lookup_idx(
        &self,
        base: Option<usize>,
        nameparts: &[String],
        maxpart: Option<usize>,
        name_comp: NameComparator<'_>,
    ) -> Option<usize> {
        let maxpart = maxpart.unwrap_or(nameparts.len());
        let mut current = Some(base.unwrap_or(ROOT));
        for name in nameparts.iter().take(maxpart) {
            let Some(cur) = current else { break };
            if name.is_empty() {
                continue;
            }
            current = self.lookup_file_in_dir(&key_of(&self.files[cur].file), name, name_comp);
        }
        current
    }

    /// Mirrors the protected `lookupParent(String[], Comparator)`: walks all but the last
    /// element of `nameparts` from the root, creating missing directories.
    fn lookup_parent(&mut self, nameparts: &[String]) -> usize {
        let mut current = ROOT;
        for name in nameparts.iter().take(nameparts.len() - 1) {
            if name.is_empty() {
                continue;
            }
            let dir_key = key_of(&self.files[current].file);
            self.directory_to_listing.entry(dir_key.clone()).or_default();
            current = match self.lookup_file_in_dir(&dir_key, name, None) {
                Some(next) => next,
                None => self.do_store_missing_dir(name, current),
            };
        }
        current
    }

    /// Mirrors the protected `lookupFileInDir(Map, String, Comparator)`.
    fn lookup_file_in_dir(
        &self,
        dir_key: &FileKey,
        filename: &str,
        name_comp: NameComparator<'_>,
    ) -> Option<usize> {
        if self.cleared.get() {
            return None;
        }
        let dir = self.directory_to_listing.get(dir_key)?;
        let Some(cmp) = name_comp else {
            return dir.by_name.get(filename).copied();
        };
        let mut candidates = Vec::new();
        for &idx in dir.by_name.values() {
            let name = self.files[idx].file.get_name();
            if cmp(filename, name) == Ordering::Equal {
                if name == filename {
                    return Some(idx);
                }
                candidates.push(idx);
            }
        }
        candidates.into_iter().min_by(|&a, &b| {
            self.files[a].file.get_name().cmp(self.files[b].file.get_name())
        })
    }

    /// Mirrors the protected `resolveSymlinkPath(FileData, String, int, StringBuilder,
    /// Comparator)`.
    fn resolve_symlink_path(
        &self,
        base: Option<usize>,
        path: &str,
        depth: usize,
        debug: &mut String,
        name_comp: NameComparator<'_>,
    ) -> io::Result<Option<usize>> {
        if depth > MAX_SYMLINK_RECURSE_DEPTH {
            return Err(io::Error::other(format!("Too many symlinks: {debug}, {path}")));
        }
        debug.push('[');
        let mut current = Some(base.unwrap_or(ROOT));
        for (i, name) in split_path(Some(path)).iter().enumerate() {
            let Some(cur) = current else { break };
            if i != 0 {
                debug.push(',');
            }
            debug.push_str(name);
            if i == 0 && name.is_empty() {
                // leading '/' was present in the path, it overrides the current location
                current = Some(ROOT);
                continue;
            }
            if name.is_empty() || name == "." {
                continue;
            }
            if name == ".." {
                current = self.get_parent_file_data(cur);
                continue;
            }
            let mut next =
                self.lookup_file_in_dir(&key_of(&self.files[cur].file), name, name_comp);
            if let Some(n) = next {
                if let Some(target) = &self.files[n].symlink_path {
                    next = self.resolve_symlink_path(Some(cur), target, depth + 1, debug, name_comp)?;
                }
            }
            current = next;
        }
        debug.push(']');
        Ok(current)
    }

    /// If `file` is a symlink, the file it targets; otherwise `file` itself. `None` if the
    /// symlink path was invalid or reached outside the bounds of this filesystem.
    ///
    /// Mirrors `resolveSymlinks(GFile)`.
    ///
    /// # Errors
    /// If `file` is not in this index, or symlinks are nested too deeply.
    pub fn resolve_symlinks(
        &self,
        file: &dyn GFile<FS>,
    ) -> io::Result<Option<&GFileImpl<FS>>> {
        let mut fd = Some(self.get_file_data(Some(file))?);
        if let Some(target) = fd.and_then(|i| self.files[i].symlink_path.as_deref()) {
            let parent = self.get_parent_file_data(fd.unwrap_or(ROOT));
            fd = self.resolve_symlink_path(parent, target, 0, &mut String::new(), None)?;
        }
        Ok(fd.map(|i| &self.files[i].file))
    }

    /// The symlink destination of `file` (`None` means the root directory), or `None` if it is
    /// not a symlink or not indexed. Mirrors `getSymlinkPath(GFile)`.
    pub fn get_symlink_path(&self, file: Option<&dyn GFile<FS>>) -> Option<&str> {
        let idx = match file {
            None => Some(ROOT),
            Some(f) => self.entry_of(f),
        };
        idx.and_then(|i| self.files[i].symlink_path.as_deref())
    }

    /// Creates and stores a file entry at `path` (back slashes are normalized to forward
    /// slashes); missing parent directories are auto-created. A file name that is not unique
    /// in its directory gets a `"[nnn]"` suffix, where `nnn` is its file index.
    ///
    /// `file_index` is the filesystem-specific unique index of the file, or -1 to use the
    /// current file count; `length` is -1 if unknown.
    ///
    /// Mirrors `storeFile(String, long, boolean, long, METADATATYPE)`.
    pub fn store_file(
        &mut self,
        path: &str,
        file_index: i64,
        is_directory: bool,
        length: i64,
        metadata: impl Into<Option<M>>,
    ) -> &GFileImpl<FS> {
        self.purge_if_cleared();
        let nameparts = split_path(Some(path));
        let Some(lastpart) = nameparts.last() else {
            return &self.files[ROOT].file;
        };
        let lastpart = lastpart.clone();
        let parent = self.lookup_parent(&nameparts);
        let parent_copy = copy_file(&self.files[parent].file);
        let idx = self.do_store_file(
            &lastpart,
            parent_copy,
            file_index,
            is_directory,
            length,
            None,
            metadata.into(),
        );
        &self.files[idx].file
    }

    /// Creates and stores a file entry named `filename` in the directory `parent` (`None`
    /// means the root directory).
    ///
    /// Mirrors `storeFileWithParent(String, GFile, long, boolean, long, METADATATYPE)`.
    pub fn store_file_with_parent(
        &mut self,
        filename: &str,
        parent: Option<&dyn GFile<FS>>,
        file_index: i64,
        is_directory: bool,
        length: i64,
        metadata: impl Into<Option<M>>,
    ) -> &GFileImpl<FS> {
        self.purge_if_cleared();
        let parent_copy = copy_file(parent.unwrap_or(&self.files[ROOT].file));
        let idx = self.do_store_file(
            filename,
            parent_copy,
            file_index,
            is_directory,
            length,
            None,
            metadata.into(),
        );
        &self.files[idx].file
    }

    /// Creates and stores a symlink entry at `path` pointing to `symlink_path`. A `length` of
    /// 0 is replaced by the (UTF-16) length of `symlink_path`. An empty path is rejected with
    /// a warning and the root directory is returned.
    ///
    /// Mirrors `storeSymlink(String, long, String, long, METADATATYPE)`.
    pub fn store_symlink(
        &mut self,
        path: &str,
        file_index: i64,
        symlink_path: &str,
        length: i64,
        metadata: impl Into<Option<M>>,
    ) -> &GFileImpl<FS> {
        self.purge_if_cleared();
        let nameparts = split_path(Some(path));
        let Some(lastpart) = nameparts.last() else {
            Msg::warn(
                "FileSystemIndexHelper",
                &format!("Unable to create invalid symlink file [{path}] -> [{symlink_path}]"),
            );
            return &self.files[ROOT].file;
        };
        let lastpart = lastpart.clone();
        let length = symlink_length(length, symlink_path);
        let parent = self.lookup_parent(&nameparts);
        let parent_copy = copy_file(&self.files[parent].file);
        let idx = self.do_store_file(
            &lastpart,
            parent_copy,
            file_index,
            false,
            length,
            Some(symlink_path.to_owned()),
            metadata.into(),
        );
        &self.files[idx].file
    }

    /// Creates and stores a symlink entry named `filename` in the directory `parent` (`None`
    /// means the root directory).
    ///
    /// Mirrors `storeSymlinkWithParent(String, GFile, long, String, long, METADATATYPE)`.
    pub fn store_symlink_with_parent(
        &mut self,
        filename: &str,
        parent: Option<&dyn GFile<FS>>,
        file_index: i64,
        symlink_path: &str,
        length: i64,
        metadata: impl Into<Option<M>>,
    ) -> &GFileImpl<FS> {
        self.purge_if_cleared();
        let length = symlink_length(length, symlink_path);
        let parent_copy = copy_file(parent.unwrap_or(&self.files[ROOT].file));
        let idx = self.do_store_file(
            filename,
            parent_copy,
            file_index,
            false,
            length,
            Some(symlink_path.to_owned()),
            metadata.into(),
        );
        &self.files[idx].file
    }

    /// Mirrors the private `doStoreMissingDir(String, GFile)`.
    fn do_store_missing_dir(&mut self, filename: &str, parent: usize) -> usize {
        let parent_copy = copy_file(&self.files[parent].file);
        let parent_key = key_of(&parent_copy);
        self.directory_to_listing.entry(parent_key.clone()).or_default();
        let file = self.create_new_file(parent_copy, filename, true, -1);
        let key = key_of(&file);
        let idx = self.files.len();
        self.files.push(FileData { file, metadata: None, file_index: -1, symlink_path: None });
        self.file_to_entry.insert(key.clone(), idx);
        if let Some(dir) = self.directory_to_listing.get_mut(&parent_key) {
            dir.insert(filename.to_owned(), idx);
        }
        self.directory_to_listing.entry(key).or_default();
        idx
    }

    /// Mirrors the private `doStoreFile(String, GFile, long, boolean, long, String,
    /// METADATATYPE)`.
    #[allow(clippy::too_many_arguments)]
    fn do_store_file(
        &mut self,
        filename: &str,
        parent: GFileImpl<FS>,
        file_index: i64,
        is_directory: bool,
        length: i64,
        symlink_path: Option<String>,
        metadata: Option<M>,
    ) -> usize {
        let file_num =
            if file_index != -1 { file_index } else { self.file_to_entry.len() as i64 };
        if self.file_index_to_entry.contains_key(&file_num) {
            Msg::warn(
                "FileSystemIndexHelper",
                &format!("Duplicate fileNum {file_num} for file {}/{filename}", parent.get_path()),
            );
        }

        let parent_key = key_of(&parent);
        let dir = self.directory_to_listing.entry(parent_key.clone()).or_default();
        let unique_name = if dir.by_name.contains_key(filename) && !is_directory {
            format!("{filename}[{file_num}]")
        } else {
            filename.to_owned()
        };

        let file = self.create_new_file(parent, &unique_name, is_directory, length);
        let key = key_of(&file);
        let idx = self.files.len();
        self.files.push(FileData { file, metadata, file_index: file_num, symlink_path });
        self.file_to_entry.insert(key.clone(), idx);
        self.file_index_to_entry.insert(file_num, idx);
        if let Some(dir) = self.directory_to_listing.get_mut(&parent_key) {
            dir.insert(unique_name, idx);
        }
        if is_directory {
            // eagerly create the directory listing entry
            self.directory_to_listing.entry(key).or_default();
        }
        idx
    }

    /// Mirrors the protected `createNewFile(GFile, String, boolean, long, METADATATYPE)`.
    fn create_new_file(
        &self,
        parent: GFileImpl<FS>,
        name: &str,
        is_directory: bool,
        size: i64,
    ) -> GFileImpl<FS> {
        let fsrl = parent.get_fsrl().append_path(name);
        GFileImpl::from_fsrl(self.filesystem.clone(), Some(Box::new(parent)), fsrl, is_directory, size)
    }

    /// Replaces the FSRL of a file already in the index. Mirrors `updateFSRL(GFile, FSRL)`.
    pub fn update_fsrl(&mut self, file: &dyn GFile<FS>, new_fsrl: Fsrl) {
        self.purge_if_cleared();
        let parent = file
            .get_parent_file()
            .map(|p| Box::new(copy_file(p)) as Box<dyn GFile<FS>>);
        let new_file = GFileImpl::from_fsrl(
            self.filesystem.clone(),
            parent,
            new_fsrl,
            file.is_directory(),
            file.get_length(),
        );
        let new_key = key_of(&new_file);
        let same_fs = file.get_filesystem() == &self.filesystem;
        let old_key = key_of(file);

        if let Some(idx) = self.entry_of(file) {
            self.file_to_entry.remove(&old_key);
            let file_index = self.files[idx].file_index;
            self.file_index_to_entry.remove(&file_index);
            self.files[idx].file = new_file;
            self.file_to_entry.insert(new_key.clone(), idx);
            if file_index != -1 {
                self.file_index_to_entry.insert(file_index, idx);
            }
        }

        if same_fs {
            if let Some(listing) = self.directory_to_listing.remove(&old_key) {
                self.directory_to_listing.insert(new_key, listing);
            }
        }
    }
}

/// `length != 0 ? length : symlinkPath.length()` (Java string length is in UTF-16 units).
fn symlink_length(length: i64, symlink_path: &str) -> i64 {
    if length != 0 { length } else { symlink_path.encode_utf16().count() as i64 }
}

impl<FS: fmt::Debug, M> fmt::Display for FileSystemIndexHelper<FS, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileSystemIndexHelper for {:?}", self.filesystem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// Minimal filesystem identity: equal only to its own clones (like Java object identity).
    #[derive(Clone, Debug)]
    struct TestFs(Rc<FsrlRoot>);

    impl PartialEq for TestFs {
        fn eq(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.0, &other.0)
        }
    }

    impl HasFsrlRoot for TestFs {
        fn root_fsrl(&self) -> &Fsrl {
            self.0.as_fsrl()
        }
    }

    impl FsGetListing<TestFs> for TestFs {
        fn fs_get_listing(
            &self,
            _file: &dyn GFile<TestFs>,
        ) -> io::Result<Vec<Box<dyn GFile<TestFs>>>> {
            Ok(Vec::new())
        }
    }

    type Helper = FileSystemIndexHelper<TestFs, String>;

    fn fs_root() -> FsrlRoot {
        Fsrl::from_string("file:///tmp/a.zip").unwrap().make_nested("zip")
    }

    fn helper() -> Helper {
        let root = fs_root();
        Helper::from_fsrl_root(TestFs(Rc::new(root.clone())), &root)
    }

    fn names(files: Vec<&GFileImpl<TestFs>>) -> Vec<String> {
        files.iter().map(|f| f.get_name().to_owned()).collect()
    }

    #[test]
    fn root_dir_and_initial_count() {
        let h = helper();
        let root = h.get_root_dir();
        assert!(root.is_directory());
        assert_eq!(root.get_path(), "/");
        assert_eq!(root.get_fsrl().to_string(), "file:///tmp/a.zip|zip:///");
        assert_eq!(h.get_file_count(), 1);
        assert!(h.get_listing(None).is_empty());
    }

    #[test]
    fn store_file_creates_missing_parent_dirs() {
        let mut h = helper();
        let f = h.store_file("dir1\\sub/file.txt", 7, false, 100, "meta".to_owned());
        assert_eq!(f.get_path(), "/dir1/sub/file.txt");
        assert_eq!(f.get_fsrl().to_string(), "file:///tmp/a.zip|zip:///dir1/sub/file.txt");
        assert_eq!(f.get_length(), 100);
        assert_eq!(f.get_parent_file().unwrap().get_path(), "/dir1/sub");
        // root + dir1 + sub + file
        assert_eq!(h.get_file_count(), 4);
        assert_eq!(names(h.get_listing(None)), ["dir1"]);
        let dir1 = h.lookup("/dir1").unwrap();
        assert!(dir1.is_directory());
        assert_eq!(h.get_metadata(dir1), None);
        let sub = h.lookup("dir1/sub").unwrap();
        assert_eq!(names(h.get_listing(Some(sub))), ["file.txt"]);
        let f = h.lookup("/dir1//sub/file.txt").unwrap();
        assert_eq!(h.get_metadata(f).map(String::as_str), Some("meta"));
        assert_eq!(h.get_file_by_index(7).unwrap().get_path(), "/dir1/sub/file.txt");
        assert!(h.get_file_by_index(8).is_none());
    }

    #[test]
    fn root_path_store_returns_root() {
        let mut h = helper();
        assert_eq!(h.store_file("/", 1, false, 0, None).get_path(), "/");
        assert_eq!(h.get_file_count(), 1);
    }

    #[test]
    fn duplicate_names_are_uniquified_with_file_index() {
        let mut h = helper();
        h.store_file("a.txt", -1, false, 1, None);
        let dup = h.store_file("a.txt", -1, false, 2, None);
        // second file's auto file index is the file count at the time (root + a.txt)
        assert_eq!(dup.get_name(), "a.txt[2]");
        let dup2 = h.store_file("/a.txt", 42, false, 3, None);
        assert_eq!(dup2.get_name(), "a.txt[42]");
        assert_eq!(names(h.get_listing(None)), ["a.txt", "a.txt[2]", "a.txt[42]"]);
        assert_eq!(h.get_file_by_index(1).unwrap().get_name(), "a.txt");
        // directories are never uniquified
        h.store_file("d", -1, true, -1, None);
        let d2 = h.store_file("d", -1, true, -1, None);
        assert_eq!(d2.get_name(), "d");
    }

    #[test]
    fn lookup_with_comparator_prefers_exact_then_sorted() {
        let mut h = helper();
        h.store_file("B.TXT", -1, false, 1, None);
        h.store_file("b.txt", -1, false, 1, None);
        h.store_file("b.Txt", -1, false, 1, None);
        let ci: &dyn Fn(&str, &str) -> Ordering =
            &|a, b| a.to_lowercase().cmp(&b.to_lowercase());
        assert_eq!(h.lookup_with(None, Some("b.Txt"), Some(ci)).unwrap().get_name(), "b.Txt");
        // no exact match: lexicographically smallest candidate ("B.TXT" < "b.Txt" < "b.txt")
        assert_eq!(h.lookup_with(None, Some("B.txt"), Some(ci)).unwrap().get_name(), "B.TXT");
        assert!(h.lookup("B.txt").is_none());
        assert!(h.lookup_with(None, None, None).unwrap().is_directory());
    }

    #[test]
    fn lookup_relative_to_base_dir_and_unknown_base() {
        let mut h = helper();
        h.store_file("x/y/z", -1, false, 1, None);
        let x = copy_file(h.lookup("x").unwrap());
        assert_eq!(h.lookup_with(Some(&x), Some("y/z"), None).unwrap().get_path(), "/x/y/z");
        let other = helper();
        let foreign = copy_file(other.get_root_dir());
        assert!(h.lookup_with(Some(&foreign), Some("x"), None).is_none());
        assert!(h.get_metadata(&foreign).is_none());
    }

    #[test]
    fn set_metadata_and_unknown_file_error() {
        let mut h = helper();
        let f = copy_file(h.store_file("f", -1, false, 1, "one".to_owned()));
        h.set_metadata(&f, "two".to_owned()).unwrap();
        assert_eq!(h.get_metadata(&f).map(String::as_str), Some("two"));
        let other = helper();
        let err = h.set_metadata(other.get_root_dir(), "x".to_owned()).unwrap_err();
        assert_eq!(err.to_string(), "Unknown file: /");
    }

    #[test]
    fn symlinks_resolve_relative_absolute_and_chained() {
        let mut h = helper();
        h.store_file("bin/real", -1, false, 5, None);
        let rel = copy_file(h.store_symlink("bin/rel", -1, "./real", 0, None));
        assert_eq!(rel.get_length(), 6);
        assert_eq!(h.get_symlink_path(Some(&rel)), Some("./real"));
        assert_eq!(h.resolve_symlinks(&rel).unwrap().unwrap().get_path(), "/bin/real");

        let abs = copy_file(h.store_symlink("lib/abs", -1, "/bin/rel", 3, None));
        assert_eq!(abs.get_length(), 3);
        assert_eq!(h.resolve_symlinks(&abs).unwrap().unwrap().get_path(), "/bin/real");

        let up = copy_file(h.store_symlink("lib/up", -1, "../bin/real", 0, None));
        assert_eq!(h.resolve_symlinks(&up).unwrap().unwrap().get_path(), "/bin/real");

        let outside = copy_file(h.store_symlink("out", -1, "../../x", 0, None));
        assert!(h.resolve_symlinks(&outside).unwrap().is_none());

        let plain = copy_file(h.lookup("bin/real").unwrap());
        assert_eq!(h.resolve_symlinks(&plain).unwrap().unwrap().get_path(), "/bin/real");
        assert_eq!(h.get_symlink_path(Some(&plain)), None);
        assert_eq!(h.get_symlink_path(None), None);
    }

    #[test]
    fn symlink_loop_errors() {
        let mut h = helper();
        let a = copy_file(h.store_symlink("a", -1, "b", 0, None));
        h.store_symlink("b", -1, "a", 0, None);
        let err = h.resolve_symlinks(&a).unwrap_err();
        assert!(err.to_string().starts_with("Too many symlinks: [b[a[b[a"), "{err}");
    }

    #[test]
    fn invalid_symlink_path_returns_root() {
        let mut h = helper();
        assert_eq!(h.store_symlink("/", 1, "x", 0, None).get_path(), "/");
        assert_eq!(h.get_file_count(), 1);
    }

    #[test]
    fn store_with_parent() {
        let mut h = helper();
        let dir = copy_file(h.store_file("d", -1, true, -1, None));
        let f = h.store_file_with_parent("f", Some(&dir), 9, false, 4, None);
        assert_eq!(f.get_path(), "/d/f");
        let s = h.store_symlink_with_parent("s", None, -1, "d/f", 0, None);
        assert_eq!(s.get_path(), "/s");
        assert_eq!(s.get_length(), 3);
        assert_eq!(names(h.get_listing(Some(&dir))), ["f"]);
    }

    #[test]
    fn update_fsrl_rekeys_entry() {
        let mut h = helper();
        let f = copy_file(h.store_file("d/f", 5, false, 4, "m".to_owned()));
        let new_fsrl = f.get_fsrl().with_md5(Some("abcd"));
        h.update_fsrl(&f, new_fsrl);
        let updated = h.get_file_by_index(5).unwrap();
        assert_eq!(updated.get_fsrl().md5(), Some("abcd"));
        assert_eq!(updated.get_parent_file().unwrap().get_path(), "/d");
        let looked_up = copy_file(h.lookup("d/f").unwrap());
        assert_eq!(h.get_metadata(&looked_up).map(String::as_str), Some("m"));
    }

    #[test]
    fn clear_empties_index() {
        let mut h = helper();
        h.store_file("a/b", -1, false, 1, None);
        h.clear();
        assert_eq!(h.get_file_count(), 0);
        assert!(h.get_listing(None).is_empty());
        assert!(h.lookup("a/b").is_none());
        assert!(h.get_file_by_index(2).is_none());
        assert_eq!(h.get_root_dir().get_path(), "/");
    }

    #[test]
    fn clear_through_shared_ref_then_refill_matches_java_emptied_maps() {
        let mut h = helper();
        h.store_file("a/b", 7, false, 1, "meta".to_owned());
        let b = copy_file(h.lookup("a/b").unwrap());
        {
            let shared: &Helper = &h;
            shared.clear();
            assert!(shared.is_cleared());
            assert!(shared.get_metadata(&b).is_none());
            assert!(shared.resolve_symlinks(&b).is_err(), "Unknown file after clear");
            // Java: lookup(null) still answers the (unindexed) root directory.
            assert_eq!(shared.lookup_with(None, None, None).unwrap().get_path(), "/");
        }
        // Java's clear() also dropped the root from the maps, so a refill counts only new files.
        h.store_file("c", -1, false, 1, None);
        assert!(!h.is_cleared());
        assert_eq!(h.get_file_count(), 1);
        assert!(h.lookup("a/b").is_none());
        assert_eq!(names(h.get_listing(None)), ["c"]);
    }

    #[test]
    fn display_names_filesystem() {
        assert!(helper().to_string().starts_with("FileSystemIndexHelper for TestFs("));
    }
}
