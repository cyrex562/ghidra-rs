//! Port of `ghidra.formats.gfilesystem.FileSystemInstanceManager`.
//!
//! The [`FileSystemService`](super::file_system_service::FileSystemService)'s cache of
//! mounted filesystems. It holds one [`FileSystemRef`] of its own per filesystem, so a
//! filesystem whose only remaining ref is the cache's is "unused" and may be closed by
//! [`close_all_unused`](FileSystemInstanceManager::close_all_unused),
//! [`cache_maint`](FileSystemInstanceManager::cache_maint) or
//! [`release_immediate`](FileSystemInstanceManager::release_immediate).
//!
//! Java's manager registers *itself* as a listener on every cached filesystem's ref manager.
//! Here the registered listener is a small object holding a [`Weak`] pointer back to the
//! manager, so the filesystem -> listener -> manager -> filesystem chain is not a strong
//! reference cycle. The cache map sits behind a private [`RefCell`]; no borrow of it is held
//! while a filesystem is closed or a ref is released, since both notify listeners that may
//! re-enter the manager.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::msg::Msg;

use super::file_system_event_listener::FileSystemEventListener;
use super::file_system_ref::FileSystemRef;
use super::file_system_ref_manager::{FileSystemRefManager, FsEventListener};
use super::fsrl::Fsrl;
use super::fsrl_root::FsrlRoot;
use super::g_file_system::{AnyGFileSystem, FsHandle};

/// How long an unused filesystem stays cached before [`cache_maint`] closes it (60 seconds).
///
/// [`cache_maint`]: FileSystemInstanceManager::cache_maint
pub const FILESYSTEM_PURGE_DELAY_MS: i64 = 60 * 1000;

fn current_time_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The listener registered on each cached filesystem's ref manager.
struct InstanceListener(Weak<FileSystemInstanceManager>);

impl FileSystemEventListener<dyn AnyGFileSystem, FileSystemRefManager> for InstanceListener {
    fn on_filesystem_close(&self, fs: &dyn AnyGFileSystem) {
        if let Some(mgr) = self.0.upgrade() {
            mgr.on_filesystem_close(fs);
        }
    }

    fn on_filesystem_ref_change(&self, _fs: &dyn AnyGFileSystem, _ref_manager: &FileSystemRefManager) {
        // Java does nothing here either.
    }
}

/// A cache of mounted filesystems keyed by FSRL root.
///
/// Mirrors the package-private `ghidra.formats.gfilesystem.FileSystemInstanceManager`.
pub struct FileSystemInstanceManager {
    /// `FSRLRoot -> FSCacheInfo`; an `FSCacheInfo` is just the cache's own ref.
    filesystems: RefCell<HashMap<FsrlRoot, FileSystemRef>>,
    root_fs: FsHandle,
    root_fsrl: FsrlRoot,
    listener: Rc<FsEventListener>,
}

impl FileSystemInstanceManager {
    /// Creates the cache; `root_fs` (the local filesystem) is never stored in it but is
    /// answered for directly by [`get_ref`](Self::get_ref). Mirrors
    /// `FileSystemInstanceManager(GFileSystem)`.
    pub fn new(root_fs: FsHandle) -> Rc<Self> {
        Rc::new_cyclic(|weak| FileSystemInstanceManager {
            filesystems: RefCell::new(HashMap::new()),
            root_fsrl: root_fs.get_fsrl().clone(),
            root_fs,
            listener: Rc::new(InstanceListener(weak.clone())),
        })
    }

    /// Forcefully closes all cached filesystems and empties the cache. Mirrors `clear()`.
    pub fn clear(&self) {
        let drained: Vec<(FsrlRoot, FileSystemRef)> = self.filesystems.borrow_mut().drain().collect();
        for (_, fs_ref) in drained {
            let fs = Rc::clone(fs_ref.get_filesystem());
            if !fs.get_ref_manager().can_close(&fs_ref) {
                Msg::warn("FileSystemInstanceManager", &format!("Forcing filesystem closed: {fs}"));
            }
            fs.get_ref_manager().remove_listener(&self.listener);
            if let Err(e) = fs.close() {
                Msg::warn("FileSystemInstanceManager", &format!("Error closing filesystem: {e}"));
            }
            drop(fs_ref);
        }
    }

    /// Closes every cached filesystem that nothing outside the cache references. Mirrors
    /// `closeAllUnused()`.
    pub fn close_all_unused(&self) {
        let recs_to_purge = self.get_unused_fses();
        if !recs_to_purge.is_empty() {
            Msg::info(
                "FileSystemInstanceManager",
                &format!("Removing {} unused filesystems from cache", recs_to_purge.len()),
            );
        }
        for fsrl in recs_to_purge {
            self.release(&fsrl);
        }
    }

    /// The FSRL roots of all cached filesystems. Mirrors `getMountedFilesystems()`.
    pub fn get_mounted_filesystems(&self) -> Vec<FsrlRoot> {
        self.filesystems.borrow().keys().cloned().collect()
    }

    /// Adds `fs` to the cache, taking a ref to it and listening for its close. Mirrors
    /// `add(GFileSystem)`.
    ///
    /// # Errors
    /// If `fs` is already closed.
    pub fn add(&self, fs: &FsHandle) -> Result<(), super::file_system_ref_manager::FileSystemRefManagerError> {
        let fs_ref = fs.get_ref_manager().create(fs)?;
        fs.get_ref_manager().add_listener(Rc::clone(&self.listener));
        let prev = self.filesystems.borrow_mut().insert(fs.get_fsrl().clone(), fs_ref);
        if prev.is_some() {
            Msg::warn(
                "FileSystemInstanceManager",
                &format!("Added second instance of same filesystem!  {}", fs.get_fsrl()),
            );
        }
        drop(prev);
        Ok(())
    }

    /// A new ref to the filesystem at `fsrl` (the root filesystem, or a cached one, matched
    /// exactly or -- when `fsrl` has no MD5 -- by equivalence), or `None`. Mirrors
    /// `getRef(FSRLRoot)`.
    pub fn get_ref(&self, fsrl: &FsrlRoot) -> Option<FileSystemRef> {
        if self.root_fsrl == *fsrl {
            return self.root_fs.get_ref_manager().create(&self.root_fs).ok();
        }
        let fs = {
            let map = self.filesystems.borrow();
            match map.get(fsrl) {
                Some(r) => Some(Rc::clone(r.get_filesystem())),
                None if fsrl.md5().is_none() => map
                    .iter()
                    .find(|(k, _)| k.is_equivalent(fsrl))
                    .map(|(_, r)| Rc::clone(r.get_filesystem())),
                None => None,
            }
        }?;
        fs.get_ref_manager().create(&fs).ok()
    }

    fn find_mounted_at(&self, container_fsrl: &Fsrl) -> Option<FsHandle> {
        let map = self.filesystems.borrow();
        map.iter()
            .filter(|(fs_fsrl, _)| {
                fs_fsrl.container().is_some_and(|c| container_fsrl.is_equivalent(c))
            })
            .map(|(_, r)| Rc::clone(r.get_filesystem()))
            .next()
    }

    /// Returns `true` if a cached filesystem's container is `container_fsrl`. Mirrors
    /// `isFilesystemMountedAt(FSRL)`.
    pub fn is_filesystem_mounted_at(&self, container_fsrl: &Fsrl) -> bool {
        self.find_mounted_at(container_fsrl).is_some()
    }

    /// A new ref to the cached filesystem whose container is `container_fsrl`, or `None`.
    /// Mirrors `getFilesystemRefMountedAt(FSRL)`.
    pub fn get_filesystem_ref_mounted_at(&self, container_fsrl: &Fsrl) -> Option<FileSystemRef> {
        let fs = self.find_mounted_at(container_fsrl)?;
        fs.get_ref_manager().create(&fs).ok()
    }

    /// A cached filesystem was closed by someone other than this cache: forget it. Mirrors
    /// `onFilesystemClose(GFileSystem)`.
    fn on_filesystem_close(&self, fs: &dyn AnyGFileSystem) {
        let removed = self.filesystems.borrow_mut().remove(fs.get_fsrl());
        Msg::warn(
            "FileSystemInstanceManager",
            &format!("Filesystem {} was closed outside of cache", fs.get_fsrl()),
        );
        drop(removed);
    }

    /// Closes cached filesystems that have been unused for longer than
    /// [`FILESYSTEM_PURGE_DELAY_MS`]. Mirrors `cacheMaint()`, which Java's service runs every
    /// ten seconds on a timer.
    pub fn cache_maint(&self) {
        let recs_to_purge = self.get_expired(self.get_unused_fses(), current_time_millis());
        if !recs_to_purge.is_empty() {
            Msg::info(
                "FileSystemInstanceManager",
                &format!("Evicting {} filesystems from cache", recs_to_purge.len()),
            );
        }
        for fsrl in recs_to_purge {
            self.release(&fsrl);
        }
    }

    fn get_expired(&self, recs: Vec<FsrlRoot>, now: i64) -> Vec<FsrlRoot> {
        let cutoff = now - FILESYSTEM_PURGE_DELAY_MS;
        let map = self.filesystems.borrow();
        recs.into_iter()
            .filter(|k| {
                map.get(k).is_some_and(|r| {
                    r.get_filesystem().get_ref_manager().get_last_used_timestamp() < cutoff
                })
            })
            .collect()
    }

    fn get_unused_fses(&self) -> Vec<FsrlRoot> {
        self.filesystems
            .borrow()
            .iter()
            .filter(|(_, r)| r.get_filesystem().get_ref_manager().can_close(r))
            .map(|(k, _)| k.clone())
            .collect()
    }

    fn release(&self, fs_fsrl: &FsrlRoot) {
        let Some(mut fs_ref) = self.filesystems.borrow_mut().remove(fs_fsrl) else {
            return;
        };
        let fs = Rc::clone(fs_ref.get_filesystem());
        fs.get_ref_manager().remove_listener(&self.listener);
        let _ = fs_ref.close();
        match fs.close() {
            Ok(()) => Msg::debug(
                "FileSystemInstanceManager",
                &format!(
                    "Closing unused filesystem [{}]",
                    fs_fsrl.container().map_or("null".to_string(), ToString::to_string)
                ),
            ),
            Err(e) => Msg::error("FileSystemInstanceManager", &format!("Error closing filesystem: {e}")),
        }
    }

    /// Closes `fs_ref`, and if the cache's own ref is then the only one left, closes and
    /// evicts the filesystem. Mirrors `releaseImmediate(FileSystemRef)`.
    pub fn release_immediate(&self, mut fs_ref: FileSystemRef) {
        let fs_fsrl = fs_ref.get_filesystem().get_fsrl().clone();
        let _ = fs_ref.close();
        let can_close = {
            let map = self.filesystems.borrow();
            match map.get(&fs_fsrl) {
                None => {
                    if self.root_fsrl != fs_fsrl {
                        // we don't store root FS refs
                        Msg::warn(
                            "FileSystemInstanceManager",
                            &format!("Unknown file system reference: {fs_fsrl}"),
                        );
                    }
                    return;
                }
                Some(cache_ref) => cache_ref.get_filesystem().get_ref_manager().can_close(cache_ref),
            }
        };
        if can_close {
            self.release(&fs_fsrl);
        }
    }

    #[cfg(test)]
    pub(crate) fn cache_maint_at(&self, now: i64) {
        for fsrl in self.get_expired(self.get_unused_fses(), now) {
            self.release(&fsrl);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::file_system_ref_manager::test_support::EmptyFs;

    fn nested_fs(container: &str, fstype: &str) -> FsHandle {
        let mut fs = EmptyFs::new(fstype);
        fs.fsrl = FsrlRoot::nested_fs(Some(&Fsrl::from_string(container).unwrap()), fstype);
        Rc::new(fs)
    }

    fn root() -> FsHandle {
        Rc::new(EmptyFs::new("file"))
    }

    #[test]
    fn add_get_ref_and_mounted_at() {
        let mgr = FileSystemInstanceManager::new(root());
        let fs = nested_fs("file:///a.gz?MD5=0123456789abcdef0123456789abcdef", "gzip");
        mgr.add(&fs).unwrap();
        assert_eq!(fs.get_ref_manager().ref_count(), 1);
        assert_eq!(mgr.get_mounted_filesystems(), vec![fs.get_fsrl().clone()]);

        let r = mgr.get_ref(fs.get_fsrl()).unwrap();
        assert!(Rc::ptr_eq(r.get_filesystem(), &fs));
        // Equivalence match ignores the MD5.
        let no_md5 = FsrlRoot::nested_fs(Some(&Fsrl::from_string("file:///a.gz").unwrap()), "gzip");
        assert!(mgr.get_ref(&no_md5).is_some());
        assert!(mgr.is_filesystem_mounted_at(&Fsrl::from_string("file:///a.gz").unwrap()));
        assert!(!mgr.is_filesystem_mounted_at(&Fsrl::from_string("file:///b.gz").unwrap()));
        assert!(mgr.get_filesystem_ref_mounted_at(&Fsrl::from_string("file:///a.gz").unwrap()).is_some());
        // The root filesystem is answered for without being cached.
        assert!(mgr.get_ref(&FsrlRoot::make_root("file")).is_some());
    }

    #[test]
    fn close_all_unused_closes_only_unreferenced_filesystems() {
        let mgr = FileSystemInstanceManager::new(root());
        let a = nested_fs("file:///a.gz", "gzip");
        let b = nested_fs("file:///b.gz", "gzip");
        mgr.add(&a).unwrap();
        mgr.add(&b).unwrap();
        let held = mgr.get_ref(b.get_fsrl()).unwrap();
        mgr.close_all_unused();
        assert!(a.is_closed());
        assert!(!b.is_closed());
        assert_eq!(mgr.get_mounted_filesystems(), vec![b.get_fsrl().clone()]);
        drop(held);
        mgr.close_all_unused();
        assert!(b.is_closed());
        assert!(mgr.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn release_immediate_closes_when_last_outside_ref_goes() {
        let mgr = FileSystemInstanceManager::new(root());
        let fs = nested_fs("file:///a.gz", "gzip");
        mgr.add(&fs).unwrap();
        let r1 = mgr.get_ref(fs.get_fsrl()).unwrap();
        let r2 = r1.dup().unwrap();
        mgr.release_immediate(r1);
        assert!(!fs.is_closed());
        mgr.release_immediate(r2);
        assert!(fs.is_closed());
        assert!(mgr.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn closing_outside_the_cache_evicts_it() {
        let mgr = FileSystemInstanceManager::new(root());
        let fs = nested_fs("file:///a.gz", "gzip");
        mgr.add(&fs).unwrap();
        fs.close().unwrap();
        assert!(mgr.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn cache_maint_evicts_only_expired_unused() {
        let mgr = FileSystemInstanceManager::new(root());
        let fs = nested_fs("file:///a.gz", "gzip");
        mgr.add(&fs).unwrap();
        let now = fs.get_ref_manager().get_last_used_timestamp();
        mgr.cache_maint_at(now + 1000);
        assert!(!fs.is_closed());
        mgr.cache_maint_at(now + FILESYSTEM_PURGE_DELAY_MS + 1);
        assert!(fs.is_closed());
    }

    #[test]
    fn clear_forces_everything_closed() {
        let mgr = FileSystemInstanceManager::new(root());
        let fs = nested_fs("file:///a.gz", "gzip");
        mgr.add(&fs).unwrap();
        let _held = mgr.get_ref(fs.get_fsrl()).unwrap();
        mgr.clear();
        assert!(fs.is_closed());
        assert!(mgr.get_mounted_filesystems().is_empty());
    }
}
