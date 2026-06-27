/// Events broadcast when a GFileSystem is closed or has a FileSystemRef change.
///
/// Implementors register with a `FileSystemRefManager` to receive lifecycle notifications.
/// The two type parameters `FS` and `RM` represent the filesystem and ref-manager types
/// respectively; they will be instantiated with the concrete Rust ports of `GFileSystem`
/// and `FileSystemRefManager` once those classes are ported.
pub trait FileSystemEventListener<FS, RM> {
    /// Called by a GFileSystem before any destructive changes are made to the filesystem
    /// instance during [`close`](GFileSystem::close).
    ///
    /// `fs` — the filesystem that is about to be closed.
    fn on_filesystem_close(&self, fs: &FS);

    /// Called by a `FileSystemRefManager` when a new `FileSystemRef` is created or released.
    ///
    /// `fs` — the filesystem being updated.
    /// `ref_manager` — the manager tracking the modified filesystem.
    fn on_filesystem_ref_change(&self, fs: &FS, ref_manager: &RM);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFs {
        pub name: &'static str,
    }

    struct MockRefManager {
        pub ref_count: usize,
    }

    struct Recorder {
        pub close_calls: std::cell::Cell<usize>,
        pub ref_change_calls: std::cell::Cell<usize>,
    }

    impl<FS, RM> FileSystemEventListener<FS, RM> for Recorder {
        fn on_filesystem_close(&self, _fs: &FS) {
            self.close_calls.set(self.close_calls.get() + 1);
        }

        fn on_filesystem_ref_change(&self, _fs: &FS, _ref_manager: &RM) {
            self.ref_change_calls.set(self.ref_change_calls.get() + 1);
        }
    }

    fn recorder() -> Recorder {
        Recorder {
            close_calls: std::cell::Cell::new(0),
            ref_change_calls: std::cell::Cell::new(0),
        }
    }

    #[test]
    fn on_filesystem_close_is_called() {
        let r = recorder();
        let fs = MockFs { name: "test" };
        FileSystemEventListener::<MockFs, MockRefManager>::on_filesystem_close(&r, &fs);
        assert_eq!(r.close_calls.get(), 1);
        assert_eq!(r.ref_change_calls.get(), 0);
    }

    #[test]
    fn on_filesystem_ref_change_is_called() {
        let r = recorder();
        let fs = MockFs { name: "test" };
        let rm = MockRefManager { ref_count: 2 };
        r.on_filesystem_ref_change(&fs, &rm);
        assert_eq!(r.close_calls.get(), 0);
        assert_eq!(r.ref_change_calls.get(), 1);
    }

    #[test]
    fn multiple_calls_accumulate() {
        let r = recorder();
        let fs = MockFs { name: "test" };
        let rm = MockRefManager { ref_count: 1 };
        FileSystemEventListener::<MockFs, MockRefManager>::on_filesystem_close(&r, &fs);
        FileSystemEventListener::<MockFs, MockRefManager>::on_filesystem_close(&r, &fs);
        r.on_filesystem_ref_change(&fs, &rm);
        assert_eq!(r.close_calls.get(), 2);
        assert_eq!(r.ref_change_calls.get(), 1);
    }

    #[test]
    fn independent_listeners_do_not_share_state() {
        let r1 = recorder();
        let r2 = recorder();
        let fs = MockFs { name: "test" };
        FileSystemEventListener::<MockFs, MockRefManager>::on_filesystem_close(&r1, &fs);
        assert_eq!(r1.close_calls.get(), 1);
        assert_eq!(r2.close_calls.get(), 0);
    }
}
