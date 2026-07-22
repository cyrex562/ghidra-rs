use crate::filesystem::seam_stubs::GFileSystemLike;

/// A handle to a [`GFileSystem`](super::g_file_system::GFileSystem) which allows tracking the
/// current users of the filesystem, mirroring `ghidra.formats.gfilesystem.FileSystemRef`.
///
/// Instances must be [`close`](FileSystemRef::close)d when not needed anymore, and should not
/// be shared across threads.
///
/// This is a cycle cut-point: Java's `FileSystemRef` is created by and closes back through a
/// `FileSystemRefManager`, which in turn hands out refs for a `GFileSystem`, which owns the
/// `FileSystemRefManager` -- a three-way cycle. Rust can't express that with concrete structs,
/// so `FileSystemRef` becomes a trait, exactly like
/// [`FileSystemRefManager`](super::file_system_ref_manager::FileSystemRefManager) already did
/// for its own side of the cycle.
///
/// `Fs` is bounded only by the minimal [`GFileSystemLike`] marker (see
/// `crate::filesystem::seam_stubs`) -- this trait's contract never calls a method on the
/// filesystem it points to, it only hands the reference back to callers via
/// [`get_filesystem`](FileSystemRef::get_filesystem). Implementors are free to hold their own
/// concrete handle to a ref manager (e.g. an `Rc<RefCell<...>>`) to actually implement
/// [`dup`](FileSystemRef::dup)/[`close`](FileSystemRef::close); the trait only declares the
/// public shape, matching how the Java class's `dup()`/`close()` bodies reach into a
/// `FileSystemRefManager` that this trait does not itself need to know about.
///
/// [`dup`](FileSystemRef::dup) returns `Box<dyn FileSystemRef<Fs>>` rather than `Self`, keeping
/// this trait object-safe.
///
/// Java's `finalize()` (which warns via `Msg.warn` if a ref was garbage-collected while still
/// open) and `toString()` (which delegates to the filesystem's FSRL) have no port here: both
/// require a live `FSRL`/`Msg` collaborator tied to a *specific* implementation's fields, not a
/// generic contract over `Fs`, and Rust has no GC-finalizer equivalent to trigger the warning
/// non-deterministically in the first place. Implementors that want the same "warn if dropped
/// unclosed" behavior can do so in their own `Drop` impl using
/// [`crate::util::msg::Msg::warn`].
pub trait FileSystemRef<Fs>
where
    Fs: GFileSystemLike,
{
    /// Creates a duplicate ref pointing at the same filesystem.
    fn dup(&self) -> Box<dyn FileSystemRef<Fs>>;

    /// The filesystem this ref points to.
    fn get_filesystem(&self) -> &Fs;

    /// Closes this reference, releasing it from the owning ref manager.
    fn close(&mut self);

    /// Returns `true` if this ref was [`close`](FileSystemRef::close)d.
    fn is_closed(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    // ── Mock seam types ─────────────────────────────────────────────────────

    struct MockFs {
        name: &'static str,
    }
    impl GFileSystemLike for MockFs {}

    // ── Mock FileSystemRef ─────────────────────────────────────────────────
    //
    // Simulates a real implementation's private link back to a ref manager (here, just a
    // shared open-ref counter) instead of routing through `Fs`, exercising the decoupling
    // documented on the trait: `dup`/`close` do real bookkeeping without `Fs` exposing any
    // manager-shaped methods.

    struct MockRef {
        fs: Rc<MockFs>,
        open_refs: Rc<Cell<usize>>,
        closed: bool,
    }

    impl MockRef {
        fn new(fs: Rc<MockFs>, open_refs: Rc<Cell<usize>>) -> Self {
            open_refs.set(open_refs.get() + 1);
            MockRef { fs, open_refs, closed: false }
        }
    }

    impl FileSystemRef<MockFs> for MockRef {
        fn dup(&self) -> Box<dyn FileSystemRef<MockFs>> {
            Box::new(MockRef::new(self.fs.clone(), self.open_refs.clone()))
        }

        fn get_filesystem(&self) -> &MockFs {
            &self.fs
        }

        fn close(&mut self) {
            if !self.closed {
                self.open_refs.set(self.open_refs.get() - 1);
                self.closed = true;
            }
        }

        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    fn setup() -> (Rc<MockFs>, Rc<Cell<usize>>) {
        (Rc::new(MockFs { name: "mockfs" }), Rc::new(Cell::new(0)))
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn get_filesystem_returns_owning_fs() {
        let (fs, counter) = setup();
        let r = MockRef::new(fs.clone(), counter);
        assert_eq!(r.get_filesystem().name, "mockfs");
    }

    #[test]
    fn new_ref_starts_open() {
        let (fs, counter) = setup();
        let r = MockRef::new(fs, counter.clone());
        assert!(!r.is_closed());
        assert_eq!(counter.get(), 1);
    }

    #[test]
    fn dup_creates_independent_ref_sharing_open_count() {
        let (fs, counter) = setup();
        let r1 = MockRef::new(fs, counter.clone());
        let r2 = r1.dup();
        assert_eq!(counter.get(), 2);
        assert!(!r2.is_closed());
    }

    #[test]
    fn close_marks_closed_and_decrements_open_count() {
        let (fs, counter) = setup();
        let mut r = MockRef::new(fs, counter.clone());
        r.close();
        assert!(r.is_closed());
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn close_is_idempotent() {
        let (fs, counter) = setup();
        let mut r = MockRef::new(fs, counter.clone());
        r.close();
        r.close();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn closing_one_dup_does_not_close_the_other() {
        let (fs, counter) = setup();
        let mut r1 = MockRef::new(fs, counter.clone());
        let mut r2 = r1.dup();
        r1.close();
        assert!(r1.is_closed());
        assert!(!r2.is_closed());
        assert_eq!(counter.get(), 1);
        r2.close();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn boxed_dyn_file_system_ref_is_accepted() {
        let (fs, counter) = setup();
        let mut boxed: Box<dyn FileSystemRef<MockFs>> = Box::new(MockRef::new(fs, counter.clone()));
        assert!(!boxed.is_closed());
        boxed.close();
        assert!(boxed.is_closed());
        assert_eq!(counter.get(), 0);
    }
}
