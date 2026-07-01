use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to track if the file system is undergoing a long-running synchronization operation.
///
/// This class is a workaround to avoid rewriting the complicated file system locking logic.
/// Mirrors `ghidra.framework.store.FileSystemSynchronizer`.
pub struct FileSystemSynchronizer;

static IS_SYNCHRONIZING: AtomicBool = AtomicBool::new(false);

impl FileSystemSynchronizer {
    /// Sets whether the synchronization operation is running.
    pub fn set_synchronizing(is_syncing: bool) {
        IS_SYNCHRONIZING.store(is_syncing, Ordering::Relaxed);
    }

    /// Returns true if the underlying file system is going through a long-running
    /// synchronization operation while holding the filesystem lock.
    ///
    /// Calling this method allows clients in the UI thread to avoid calling methods
    /// that require a file system lock, which would cause the UI to freeze during
    /// the synchronization operation.
    pub fn is_synchronizing() -> bool {
        IS_SYNCHRONIZING.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn initial_state_not_synchronizing() {
        FileSystemSynchronizer::set_synchronizing(false);
        assert!(!FileSystemSynchronizer::is_synchronizing());
    }

    #[test]
    fn set_synchronizing_true() {
        FileSystemSynchronizer::set_synchronizing(true);
        assert!(FileSystemSynchronizer::is_synchronizing());
    }

    #[test]
    fn set_synchronizing_false() {
        FileSystemSynchronizer::set_synchronizing(true);
        FileSystemSynchronizer::set_synchronizing(false);
        assert!(!FileSystemSynchronizer::is_synchronizing());
    }

    #[test]
    fn toggle_synchronizing_state() {
        FileSystemSynchronizer::set_synchronizing(false);
        assert!(!FileSystemSynchronizer::is_synchronizing());

        FileSystemSynchronizer::set_synchronizing(true);
        assert!(FileSystemSynchronizer::is_synchronizing());

        FileSystemSynchronizer::set_synchronizing(false);
        assert!(!FileSystemSynchronizer::is_synchronizing());
    }

    #[test]
    fn concurrent_reads_during_synchronization() {
        FileSystemSynchronizer::set_synchronizing(true);

        let handles: Vec<_> = (0..5)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..10 {
                        let is_syncing = FileSystemSynchronizer::is_synchronizing();
                        assert!(is_syncing);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        FileSystemSynchronizer::set_synchronizing(false);
    }

    #[test]
    fn concurrent_reads_not_synchronizing() {
        FileSystemSynchronizer::set_synchronizing(false);

        let handles: Vec<_> = (0..5)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..10 {
                        let is_syncing = FileSystemSynchronizer::is_synchronizing();
                        assert!(!is_syncing);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn concurrent_reads_with_state_changes() {
        let counter = Arc::new(std::sync::Mutex::new(0));

        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..20 {
                FileSystemSynchronizer::set_synchronizing(!FileSystemSynchronizer::is_synchronizing());
                let mut c = counter_clone.lock().unwrap();
                *c += 1;
            }
        });

        for _ in 0..50 {
            let _ = FileSystemSynchronizer::is_synchronizing();
        }

        handle.join().unwrap();

        let changes = counter.lock().unwrap();
        assert!(*changes > 0);
    }
}
