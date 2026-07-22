use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::util::task::TaskMonitor;

/// [`GFileSystem`](super::g_file_system::GFileSystem) add-on trait that provides MD5 hashing
/// for files located within the filesystem.
///
/// Mirrors `ghidra.formats.gfilesystem.GFileHashProvider`. Implementing filesystems (e.g. the
/// Rust port of `LocalFileSystem`) implement both `GFileSystem` and this trait; callers probe
/// for support with a downcast rather than Java's `instanceof`.
///
/// `FS` and `Fsrl` are the same free type parameters used by [`GFile`] -- the concrete
/// filesystem and FSRL types -- kept as trait-level generics (rather than tied to `Self`) so
/// this trait stays object-safe.
pub trait GFileHashProvider<FS, Fsrl> {
    /// Returns the MD5 hash of the specified file.
    ///
    /// # Arguments
    /// * `file` - the file to hash
    /// * `required` - if `true`, the hash will always be returned, even if it has to be
    ///   calculated. If `false`, the hash is only returned if easily available.
    /// * `monitor` - monitor for cancellation
    fn get_md5_hash(
        &self,
        file: &dyn GFile<FS, Fsrl>,
        required: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, GFileSystemError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockFs;
    struct MockFsrl;

    struct MockFile {
        path: String,
        name: String,
    }

    impl GFile<MockFs, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFs {
            unimplemented!()
        }
        fn get_fsrl(&self) -> &MockFsrl {
            unimplemented!()
        }
        fn get_parent_file(&self) -> Option<&dyn GFile<MockFs, MockFsrl>> {
            None
        }
        fn get_path(&self) -> &str {
            &self.path
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn is_directory(&self) -> bool {
            false
        }
        fn get_length(&self) -> i64 {
            42
        }
        fn get_listing(&self) -> std::io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            Ok(vec![])
        }
    }

    /// Hash provider that only returns a hash when `required` is true, mimicking a filesystem
    /// backend that has to do real work (e.g. a full file read) to compute one on demand.
    struct LazyHashProvider {
        computed: AtomicBool,
    }

    impl GFileHashProvider<MockFs, MockFsrl> for LazyHashProvider {
        fn get_md5_hash(
            &self,
            file: &dyn GFile<MockFs, MockFsrl>,
            required: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<String, GFileSystemError> {
            monitor.check_cancelled()?;
            if !required {
                return Ok(String::new());
            }
            self.computed.store(true, Ordering::SeqCst);
            Ok(format!("md5:{}", file.get_name()))
        }
    }

    struct DummyMonitor {
        cancelled: bool,
    }

    impl TaskMonitor for DummyMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.cancelled {
                Err(CancelledException::default())
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn required_hash_is_computed() {
        let provider = LazyHashProvider { computed: AtomicBool::new(false) };
        let file = MockFile { path: "/a.txt".into(), name: "a.txt".into() };
        let monitor = DummyMonitor { cancelled: false };

        let hash = provider.get_md5_hash(&file, true, &monitor).unwrap();

        assert_eq!(hash, "md5:a.txt");
        assert!(provider.computed.load(Ordering::SeqCst));
    }

    #[test]
    fn optional_hash_skips_computation() {
        let provider = LazyHashProvider { computed: AtomicBool::new(false) };
        let file = MockFile { path: "/b.txt".into(), name: "b.txt".into() };
        let monitor = DummyMonitor { cancelled: false };

        let hash = provider.get_md5_hash(&file, false, &monitor).unwrap();

        assert_eq!(hash, "");
        assert!(!provider.computed.load(Ordering::SeqCst));
    }

    #[test]
    fn cancelled_monitor_short_circuits() {
        let provider = LazyHashProvider { computed: AtomicBool::new(false) };
        let file = MockFile { path: "/c.txt".into(), name: "c.txt".into() };
        let monitor = DummyMonitor { cancelled: true };

        let err = provider.get_md5_hash(&file, true, &monitor).unwrap_err();

        assert!(matches!(err, GFileSystemError::Cancelled(_)));
        assert!(!provider.computed.load(Ordering::SeqCst));
    }

    #[test]
    fn hash_provider_as_trait_object() {
        let provider: Box<dyn GFileHashProvider<MockFs, MockFsrl>> =
            Box::new(LazyHashProvider { computed: AtomicBool::new(false) });
        let file = MockFile { path: "/d.txt".into(), name: "d.txt".into() };
        let monitor = DummyMonitor { cancelled: false };

        let hash = provider.get_md5_hash(&file, true, &monitor).unwrap();

        assert_eq!(hash, "md5:d.txt");
    }
}
