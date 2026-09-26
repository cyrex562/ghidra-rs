//! Port of `ghidra.formats.gfilesystem.FileSystemRefManager`.
//!
//! Every filesystem owns one manager; it hands out [`FileSystemRef`]s that pin the filesystem,
//! tracks which of them are still open, and broadcasts ref changes and the filesystem's close
//! to [`FileSystemEventListener`]s.
//!
//! Ownership (CONVENTION_QUEUE verdict for this type: ARENA): Java's manager keeps a
//! back-reference to its filesystem and a list of the ref *objects* it created, compared by
//! identity. Here the manager is the store of ref *IDs* ([`FileSystemRefId`], a `Copy` token
//! each [`FileSystemRef`] carries) and the filesystem is passed in at call time
//! ([`create`](FileSystemRefManager::create) / [`release`](FileSystemRefManager::release) /
//! [`on_close`](FileSystemRefManager::on_close)) instead of being stored, so there is no
//! filesystem <-> manager reference cycle.
//!
//! Filesystems are shared through `&self` (see [`GFileSystem`](super::g_file_system::GFileSystem)),
//! so the manager's bookkeeping sits behind private [`RefCell`]s. Borrows are never held
//! while listeners run -- Java likewise invokes listeners outside its `synchronized` blocks --
//! so a listener may call back into the manager.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::util::msg::Msg;

use super::file_system_event_listener::FileSystemEventListener;
use super::file_system_ref::{FileSystemRef, FileSystemRefId};
use super::g_file_system::{AnyGFileSystem, FsHandle};

/// A listener for a filesystem's ref-change and close events.
pub type FsEventListener = dyn FileSystemEventListener<dyn AnyGFileSystem, FileSystemRefManager>;

/// Failure mode shared by [`FileSystemRefManager`] operations that mirror Java methods that
/// throw `IllegalArgumentException`.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum FileSystemRefManagerError {
    /// The owning filesystem was already closed when [`create`](FileSystemRefManager::create)
    /// was called.
    #[error("File system already closed: {0}")]
    FileSystemAlreadyClosed(String),
    /// [`release`](FileSystemRefManager::release) was called with a ref this manager did not
    /// hand out (or had already released).
    #[error("Tried to remove unknown reference to {0}")]
    UnknownRef(String),
    /// [`on_close`](FileSystemRefManager::on_close) was called on a manager that was already
    /// closed.
    #[error("FileSystemRefManager already closed!")]
    AlreadyClosed,
}

fn current_time_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Creates and releases [`FileSystemRef`]s to one filesystem and broadcasts events to
/// [`FileSystemEventListener`]s.
///
/// Mirrors `ghidra.formats.gfilesystem.FileSystemRefManager`.
pub struct FileSystemRefManager {
    /// Open refs, most recent last; `None` once [`on_close`](Self::on_close)d (Java nulls both
    /// its `fs` and `refs` fields).
    refs: RefCell<Option<Vec<FileSystemRefId>>>,
    next_id: Cell<u64>,
    listeners: RefCell<Vec<Rc<FsEventListener>>>,
    last_used_ts: Cell<i64>,
}

impl Default for FileSystemRefManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystemRefManager {
    /// Creates a new manager. Mirrors `FileSystemRefManager(GFileSystem)`; the filesystem is
    /// supplied to each operation instead of being stored (see the module docs).
    pub fn new() -> Self {
        let mgr = FileSystemRefManager {
            refs: RefCell::new(Some(Vec::new())),
            next_id: Cell::new(0),
            listeners: RefCell::new(Vec::new()),
            last_used_ts: Cell::new(0),
        };
        mgr.touch();
        mgr
    }

    fn touch(&self) {
        self.last_used_ts.set(current_time_millis());
    }

    /// Adds a listener that will be called when the filesystem is closed or when refs change.
    ///
    /// Java's `ListenerSet` here is created with strong references, and so is this list.
    pub fn add_listener(&self, listener: Rc<FsEventListener>) {
        self.listeners.borrow_mut().push(listener);
    }

    /// Removes a previously added listener (compared by identity).
    pub fn remove_listener(&self, listener: &Rc<FsEventListener>) {
        self.listeners.borrow_mut().retain(|l| !Rc::ptr_eq(l, listener));
    }

    fn snapshot_listeners(&self) -> Vec<Rc<FsEventListener>> {
        self.listeners.borrow().clone()
    }

    fn broadcast_ref_change(&self, fs: &(dyn AnyGFileSystem + 'static)) {
        for l in self.snapshot_listeners() {
            l.on_filesystem_ref_change(fs, self);
        }
    }

    /// Creates a new [`FileSystemRef`] pinning `fs` (which must be the filesystem that owns this
    /// manager), broadcasting `on_filesystem_ref_change` to listeners.
    ///
    /// # Errors
    /// [`FileSystemRefManagerError::FileSystemAlreadyClosed`] if `fs` is closed, matching Java's
    /// `IllegalArgumentException`.
    pub fn create(&self, fs: &FsHandle) -> Result<FileSystemRef, FileSystemRefManagerError> {
        if fs.is_closed() {
            return Err(FileSystemRefManagerError::FileSystemAlreadyClosed(fs.to_string()));
        }
        let id = FileSystemRefId(self.next_id.get());
        {
            let mut refs = self.refs.borrow_mut();
            let Some(refs) = refs.as_mut() else {
                return Err(FileSystemRefManagerError::FileSystemAlreadyClosed(fs.to_string()));
            };
            self.next_id.set(id.0 + 1);
            refs.push(id);
        }
        self.touch();
        self.broadcast_ref_change(&**fs);
        Ok(FileSystemRef::new(Rc::clone(fs), id))
    }

    /// Releases a previously created ref, broadcasting `on_filesystem_ref_change` to
    /// listeners. `fs` is the filesystem that owns this manager.
    ///
    /// # Errors
    /// [`FileSystemRefManagerError::UnknownRef`] if `id` is not an open ref of this manager.
    pub fn release(
        &self,
        fs: &(dyn AnyGFileSystem + 'static),
        id: FileSystemRefId,
    ) -> Result<(), FileSystemRefManagerError> {
        let found = {
            let mut refs = self.refs.borrow_mut();
            // Search backwards: the most recently added ref is the most likely to be removed.
            match refs.as_mut().and_then(|r| r.iter().rposition(|tmp| *tmp == id).map(|i| (r, i))) {
                Some((r, i)) => {
                    r.remove(i);
                    true
                }
                None => false,
            }
        };
        if !found {
            return Err(FileSystemRefManagerError::UnknownRef(fs.to_string()));
        }
        self.touch();
        self.broadcast_ref_change(fs);
        Ok(())
    }

    /// Returns `true` if the only ref pinning the filesystem is `callers_ref`.
    pub fn can_close(&self, callers_ref: &FileSystemRef) -> bool {
        match self.refs.borrow().as_ref() {
            Some(refs) => refs.len() == 1 && refs[0] == callers_ref.id(),
            None => false,
        }
    }

    /// The number of currently open refs.
    pub fn ref_count(&self) -> usize {
        self.refs.borrow().as_ref().map_or(0, Vec::len)
    }

    /// Called by the filesystem `fs` before it makes any destructive changes during its close,
    /// to shut this manager down and broadcast `on_filesystem_close` to listeners.
    ///
    /// # Errors
    /// [`FileSystemRefManagerError::AlreadyClosed`] if this manager was already closed.
    pub fn on_close(&self, fs: &(dyn AnyGFileSystem + 'static)) -> Result<(), FileSystemRefManagerError> {
        {
            let mut refs = self.refs.borrow_mut();
            let Some(open) = refs.as_ref() else {
                return Err(FileSystemRefManagerError::AlreadyClosed);
            };
            if !open.is_empty() {
                Msg::warn(
                    "FileSystemRefManager",
                    &format!("Closing filesystem even though it has active handles open: {fs}"),
                );
            }
            *refs = None;
        }
        for l in self.snapshot_listeners() {
            l.on_filesystem_close(fs);
        }
        Ok(())
    }

    /// Returns `true` once [`on_close`](Self::on_close) has run.
    pub fn is_closed(&self) -> bool {
        self.refs.borrow().is_none()
    }

    /// The time (milliseconds since the epoch, like `System.currentTimeMillis()`) this manager
    /// was last touched by a ref change.
    pub fn get_last_used_timestamp(&self) -> i64 {
        self.last_used_ts.get()
    }

    #[cfg(test)]
    pub(crate) fn set_last_used_timestamp_for_test(&self, ts: i64) {
        self.last_used_ts.set(ts);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A minimal real [`GFileSystem`] used by the ref-manager, ref and service tests.

    use std::cell::Cell;
    use std::io;

    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::app::util::bin::byte_provider::ByteProvider;
    use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
    use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
    use crate::filesystem::gfilesystem::g_file::GFile;
    use crate::filesystem::gfilesystem::g_file_system::{GFileSystem, GFileSystemError};
    use crate::util::task::TaskMonitor;

    use super::FileSystemRefManager;

    /// An empty filesystem whose close notifies its ref manager, as real ones do.
    pub struct EmptyFs {
        pub fsrl: FsrlRoot,
        pub ref_manager: FileSystemRefManager,
        pub closed: Cell<bool>,
    }

    impl EmptyFs {
        pub fn new(protocol: &str) -> Self {
            EmptyFs {
                fsrl: FsrlRoot::make_root(protocol),
                ref_manager: FileSystemRefManager::new(),
                closed: Cell::new(false),
            }
        }
    }

    impl GFileSystem for EmptyFs {
        type Fs = ();
        fn get_name(&self) -> String {
            "empty".into()
        }
        fn get_type(&self) -> String {
            "empty".into()
        }
        fn get_description(&self) -> String {
            "Empty".into()
        }
        fn get_fsrl(&self) -> &FsrlRoot {
            &self.fsrl
        }
        fn is_closed(&self) -> bool {
            self.closed.get()
        }
        fn get_ref_manager(&self) -> &FileSystemRefManager {
            &self.ref_manager
        }
        fn lookup(&self, _path: Option<&str>) -> io::Result<Option<Box<dyn GFile<()>>>> {
            Ok(None)
        }
        fn get_byte_provider(
            &self,
            _file: &dyn GFile<()>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn ByteProvider>>, GFileSystemError> {
            Ok(Some(Box::new(ByteArrayProvider::new(Vec::new()))))
        }
        fn get_listing(&self, _d: Option<&dyn GFile<()>>) -> io::Result<Vec<Box<dyn GFile<()>>>> {
            Ok(Vec::new())
        }
        fn get_file_attributes(&self, _f: &dyn GFile<()>, _m: &dyn TaskMonitor) -> FileAttributes {
            FileAttributes::new()
        }
        fn close(&self) -> io::Result<()> {
            let _ = self.ref_manager.on_close(self);
            self.closed.set(true);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::test_support::EmptyFs;
    use super::*;
    use crate::filesystem::gfilesystem::g_file_system::GFileSystem;

    struct Recorder {
        close_calls: Cell<usize>,
        ref_change_calls: Cell<usize>,
    }

    impl FileSystemEventListener<dyn AnyGFileSystem, FileSystemRefManager> for Recorder {
        fn on_filesystem_close(&self, _fs: &dyn AnyGFileSystem) {
            self.close_calls.set(self.close_calls.get() + 1);
        }
        fn on_filesystem_ref_change(&self, _fs: &dyn AnyGFileSystem, _rm: &FileSystemRefManager) {
            self.ref_change_calls.set(self.ref_change_calls.get() + 1);
        }
    }

    fn fs() -> FsHandle {
        Rc::new(EmptyFs::new("empty"))
    }

    fn recorder() -> Rc<Recorder> {
        Rc::new(Recorder { close_calls: Cell::new(0), ref_change_calls: Cell::new(0) })
    }

    #[test]
    fn create_returns_distinct_refs_and_can_close_tracks_sole_ref() {
        let fs = fs();
        let mut r1 = fs.get_ref_manager().create(&fs).unwrap();
        assert!(fs.get_ref_manager().can_close(&r1));
        let mut r2 = r1.dup().unwrap();
        assert_ne!(r1.id(), r2.id());
        assert_eq!(fs.get_ref_manager().ref_count(), 2);
        assert!(!fs.get_ref_manager().can_close(&r1));
        r2.close().unwrap();
        assert!(fs.get_ref_manager().can_close(&r1));
        r1.close().unwrap();
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }

    #[test]
    fn create_fails_when_filesystem_already_closed() {
        let fs = fs();
        fs.close().unwrap();
        let err = fs.get_ref_manager().create(&fs).unwrap_err();
        assert_eq!(err, FileSystemRefManagerError::FileSystemAlreadyClosed("empty://".into()));
    }

    #[test]
    fn release_of_unknown_ref_errors() {
        let fs = fs();
        let mut r = fs.get_ref_manager().create(&fs).unwrap();
        let id = r.id();
        r.close().unwrap();
        let err = fs.get_ref_manager().release(&*fs, id).unwrap_err();
        assert_eq!(err, FileSystemRefManagerError::UnknownRef("empty://".into()));
    }

    #[test]
    fn listeners_see_ref_changes_until_removed_and_close_once() {
        let fs = fs();
        let rec = recorder();
        let l: Rc<FsEventListener> = rec.clone();
        fs.get_ref_manager().add_listener(l.clone());
        let mut r = fs.get_ref_manager().create(&fs).unwrap();
        assert_eq!(rec.ref_change_calls.get(), 1);
        r.close().unwrap();
        assert_eq!(rec.ref_change_calls.get(), 2);
        fs.close().unwrap();
        assert_eq!(rec.close_calls.get(), 1);
        assert!(fs.get_ref_manager().is_closed());
        assert_eq!(
            fs.get_ref_manager().on_close(&*fs).unwrap_err(),
            FileSystemRefManagerError::AlreadyClosed
        );
        fs.get_ref_manager().remove_listener(&l);
        assert_eq!(fs.get_ref_manager().listeners.borrow().len(), 0);
    }

    #[test]
    fn touch_updates_last_used_timestamp() {
        let fs = fs();
        fs.get_ref_manager().set_last_used_timestamp_for_test(5);
        let _r = fs.get_ref_manager().create(&fs).unwrap();
        assert!(fs.get_ref_manager().get_last_used_timestamp() > 5);
    }

    #[test]
    fn typed_access_through_trait() {
        let e = EmptyFs::new("empty");
        assert_eq!(GFileSystem::get_ref_manager(&e).ref_count(), 0);
    }
}
