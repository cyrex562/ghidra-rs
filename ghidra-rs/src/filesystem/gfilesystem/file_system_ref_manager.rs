use std::rc::Rc;

use thiserror::Error;

use crate::filesystem::seam_stubs::{FileSystemRefLike, GFileSystemLike};

use super::file_system_event_listener::FileSystemEventListener;

/// Failure mode shared by [`FileSystemRefManager`] operations that mirror Java methods that
/// throw `IllegalArgumentException`.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum FileSystemRefManagerError {
    /// The owning filesystem was already closed when [`create`](FileSystemRefManager::create)
    /// was called.
    #[error("File system already closed: {0}")]
    FileSystemAlreadyClosed(String),

    /// [`release`](FileSystemRefManager::release) was called with a ref this manager did not
    /// hand out.
    #[error("Tried to remove unknown reference to {0}")]
    UnknownRef(String),

    /// [`on_close`](FileSystemRefManager::on_close) was called on a manager that was already
    /// closed.
    #[error("FileSystemRefManager already closed!")]
    AlreadyClosed,
}

/// A helper that manages creating and releasing filesystem references and broadcasting events
/// to [`FileSystemEventListener`] listeners, mirroring
/// `ghidra.formats.gfilesystem.FileSystemRefManager`.
///
/// This is a cycle cut-point: `GFileSystem` owns a `FileSystemRefManager` (via
/// `getRefManager()`), `FileSystemRefManager` hands out refs that point back at the owning
/// `GFileSystem`, and `FileSystemRef` (also unported) closes the loop by calling back into the
/// manager that created it via `getFilesystem().getRefManager()`. Rust can't express that
/// cycle with concrete structs, so this becomes a trait; `Fs` (the filesystem) and `Ref` (the
/// ref returned by [`create`](FileSystemRefManager::create)) are free type parameters here
/// rather than concrete ported types, exactly like
/// [`GFileSystem`](super::g_file_system::GFileSystem) decouples its own
/// `FS`/`Fsrl`/`FsrlRoot`/`RefManager` parameters instead of tying them to `Self`.
///
/// `Ref` is bounded by [`FileSystemRefLike`], a minimal seam standing in for the unported
/// `FileSystemRef` -- this manager never calls a method on the refs it hands out, only
/// compares their identity (matching Java's `==` comparisons in `release`/`canClose`), so the
/// seam requires nothing but [`PartialEq`].
///
/// `Rm` is the type listeners see as "the ref manager" in
/// [`FileSystemEventListener::on_filesystem_ref_change`]. Like `Fs`, it is intentionally a
/// free parameter rather than `Self` -- tying either to `Self` would make this trait
/// dyn-incompatible, the same reasoning documented on `FileSystemEventListener` itself.
///
/// Java's listeners are weakly referenced and auto-removed once nothing else holds them; this
/// port uses strong [`Rc`] references instead and leaves eviction to
/// [`remove_listener`](FileSystemRefManager::remove_listener), since Rust has no automatic
/// weak-listener bookkeeping equivalent to Java's `ListenerSet`.
pub trait FileSystemRefManager<Fs, Ref, Rm>
where
    Fs: GFileSystemLike,
    Ref: FileSystemRefLike,
{
    /// Adds a listener that will be called when the owning filesystem is
    /// [`on_close`](FileSystemRefManager::on_close)d or when refs change.
    fn add_listener(&mut self, listener: Rc<dyn FileSystemEventListener<Fs, Rm>>);

    /// Removes a previously added listener.
    fn remove_listener(&mut self, listener: &Rc<dyn FileSystemEventListener<Fs, Rm>>);

    /// Creates a new ref pointing at the owning filesystem, broadcasting
    /// `on_filesystem_ref_change` to listeners.
    ///
    /// Returns [`FileSystemRefManagerError::FileSystemAlreadyClosed`] if the owning filesystem
    /// is already closed, matching Java's `IllegalArgumentException`.
    fn create(&mut self) -> Result<Ref, FileSystemRefManagerError>;

    /// Releases a previously created ref, broadcasting `on_filesystem_ref_change` to
    /// listeners.
    ///
    /// Returns [`FileSystemRefManagerError::UnknownRef`] if `r` was not handed out by this
    /// manager, matching Java's `IllegalArgumentException`.
    fn release(&mut self, r: Ref) -> Result<(), FileSystemRefManagerError>;

    /// Returns `true` if the only ref pinning the owning filesystem is `callers_ref`.
    fn can_close(&self, callers_ref: &Ref) -> bool;

    /// Called before any destructive changes are made to the owning filesystem, to gracefully
    /// shut down this manager and broadcast `on_filesystem_close` to listeners.
    ///
    /// Returns [`FileSystemRefManagerError::AlreadyClosed`] if this manager was already closed.
    fn on_close(&mut self) -> Result<(), FileSystemRefManagerError>;

    /// The timestamp (implementor-defined units, mirroring `System.currentTimeMillis()`) this
    /// manager was last touched by a ref change.
    fn get_last_used_timestamp(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // ── Mock seam types ─────────────────────────────────────────────────────

    struct MockFs {
        closed: Cell<bool>,
        name: &'static str,
    }
    impl GFileSystemLike for MockFs {}

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockRef(u32);
    impl FileSystemRefLike for MockRef {}

    struct Recorder {
        close_calls: Cell<usize>,
        ref_change_calls: Cell<usize>,
    }

    impl FileSystemEventListener<MockFs, MockRefManager> for Recorder {
        fn on_filesystem_close(&self, _fs: &MockFs) {
            self.close_calls.set(self.close_calls.get() + 1);
        }

        fn on_filesystem_ref_change(&self, _fs: &MockFs, _ref_manager: &MockRefManager) {
            self.ref_change_calls.set(self.ref_change_calls.get() + 1);
        }
    }

    // ── Mock FileSystemRefManager ─────────────────────────────────────────────
    //
    // Exercises the real Java behavior: identity-based ref bookkeeping, broadcasting to
    // listeners, and the two IllegalArgumentException-equivalent error paths.

    struct MockRefManager {
        fs: Rc<MockFs>,
        refs: RefCell<Option<Vec<MockRef>>>,
        listeners: RefCell<Vec<Rc<dyn FileSystemEventListener<MockFs, MockRefManager>>>>,
        next_id: Cell<u32>,
        last_used: Cell<i64>,
    }

    impl MockRefManager {
        fn new(fs: Rc<MockFs>) -> Self {
            let mgr = MockRefManager {
                fs,
                refs: RefCell::new(Some(Vec::new())),
                listeners: RefCell::new(Vec::new()),
                next_id: Cell::new(0),
                last_used: Cell::new(0),
            };
            mgr.touch();
            mgr
        }

        fn touch(&self) {
            self.last_used.set(self.last_used.get() + 1);
        }

        fn broadcast_ref_change(&self) {
            for l in self.listeners.borrow().iter() {
                l.on_filesystem_ref_change(&self.fs, self);
            }
        }
    }

    impl FileSystemRefManager<MockFs, MockRef, MockRefManager> for MockRefManager {
        fn add_listener(&mut self, listener: Rc<dyn FileSystemEventListener<MockFs, MockRefManager>>) {
            self.listeners.borrow_mut().push(listener);
        }

        fn remove_listener(&mut self, listener: &Rc<dyn FileSystemEventListener<MockFs, MockRefManager>>) {
            self.listeners.borrow_mut().retain(|l| !Rc::ptr_eq(l, listener));
        }

        fn create(&mut self) -> Result<MockRef, FileSystemRefManagerError> {
            if self.fs.closed.get() {
                return Err(FileSystemRefManagerError::FileSystemAlreadyClosed(
                    self.fs.name.to_string(),
                ));
            }
            let r = MockRef(self.next_id.get());
            self.next_id.set(self.next_id.get() + 1);
            self.refs
                .borrow_mut()
                .as_mut()
                .expect("manager not yet closed")
                .push(r.clone());
            self.touch();
            self.broadcast_ref_change();
            Ok(r)
        }

        fn release(&mut self, r: MockRef) -> Result<(), FileSystemRefManagerError> {
            let found = {
                let mut refs = self.refs.borrow_mut();
                let refs = refs.as_mut().expect("manager not yet closed");
                match refs.iter().rposition(|tmp| *tmp == r) {
                    Some(i) => {
                        refs.remove(i);
                        true
                    }
                    None => false,
                }
            };
            if !found {
                return Err(FileSystemRefManagerError::UnknownRef(self.fs.name.to_string()));
            }
            self.touch();
            self.broadcast_ref_change();
            Ok(())
        }

        fn can_close(&self, callers_ref: &MockRef) -> bool {
            let refs = self.refs.borrow();
            let refs = refs.as_ref().expect("manager not yet closed");
            refs.len() == 1 && refs[0] == *callers_ref
        }

        fn on_close(&mut self) -> Result<(), FileSystemRefManagerError> {
            if self.refs.borrow().is_none() {
                return Err(FileSystemRefManagerError::AlreadyClosed);
            }
            *self.refs.borrow_mut() = None;
            for l in self.listeners.borrow().iter() {
                l.on_filesystem_close(&self.fs);
            }
            Ok(())
        }

        fn get_last_used_timestamp(&self) -> i64 {
            self.last_used.get()
        }
    }

    fn mgr() -> (Rc<MockFs>, MockRefManager) {
        let fs = Rc::new(MockFs { closed: Cell::new(false), name: "mockfs" });
        let m = MockRefManager::new(fs.clone());
        (fs, m)
    }

    fn recorder() -> Rc<Recorder> {
        Rc::new(Recorder { close_calls: Cell::new(0), ref_change_calls: Cell::new(0) })
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn create_returns_distinct_refs_and_bumps_timestamp() {
        let (_fs, mut m) = mgr();
        let before = m.get_last_used_timestamp();
        let r1 = m.create().unwrap();
        let r2 = m.create().unwrap();
        assert_ne!(r1, r2);
        assert!(m.get_last_used_timestamp() > before);
    }

    #[test]
    fn create_fails_when_filesystem_already_closed() {
        let (fs, mut m) = mgr();
        fs.closed.set(true);
        let err = m.create().unwrap_err();
        assert_eq!(err, FileSystemRefManagerError::FileSystemAlreadyClosed("mockfs".to_string()));
    }

    #[test]
    fn can_close_true_only_when_sole_ref_matches() {
        let (_fs, mut m) = mgr();
        let r1 = m.create().unwrap();
        assert!(m.can_close(&r1));

        let r2 = m.create().unwrap();
        assert!(!m.can_close(&r1));
        assert!(!m.can_close(&r2));

        m.release(r2).unwrap();
        assert!(m.can_close(&r1));
    }

    #[test]
    fn release_removes_ref_and_errors_on_unknown_ref() {
        let (_fs, mut m) = mgr();
        let r1 = m.create().unwrap();
        m.release(r1.clone()).unwrap();

        // Releasing the same ref again is now "unknown".
        let err = m.release(r1).unwrap_err();
        assert_eq!(err, FileSystemRefManagerError::UnknownRef("mockfs".to_string()));
    }

    #[test]
    fn add_and_remove_listener_gate_ref_change_broadcasts() {
        let (_fs, mut m) = mgr();
        let rec = recorder();
        let listener: Rc<dyn FileSystemEventListener<MockFs, MockRefManager>> = rec.clone();
        m.add_listener(listener.clone());

        let r1 = m.create().unwrap();
        assert_eq!(rec.ref_change_calls.get(), 1);

        m.remove_listener(&listener);
        m.release(r1).unwrap();
        assert_eq!(rec.ref_change_calls.get(), 1, "listener removed, should not fire again");
    }

    #[test]
    fn on_close_broadcasts_and_rejects_double_close() {
        let (_fs, mut m) = mgr();
        let rec = recorder();
        let listener: Rc<dyn FileSystemEventListener<MockFs, MockRefManager>> = rec.clone();
        m.add_listener(listener);

        m.on_close().unwrap();
        assert_eq!(rec.close_calls.get(), 1);

        let err = m.on_close().unwrap_err();
        assert_eq!(err, FileSystemRefManagerError::AlreadyClosed);
    }

    #[test]
    fn boxed_dyn_ref_manager_is_accepted() {
        let (_fs, m) = mgr();
        let mut boxed: Box<dyn FileSystemRefManager<MockFs, MockRef, MockRefManager>> = Box::new(m);
        let r = boxed.create().unwrap();
        assert!(boxed.can_close(&r));
    }
}
