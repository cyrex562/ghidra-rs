use std::path::Path;
use std::sync::{Mutex, OnceLock};

use super::channel_locker::ChannelLocker;
use super::file_channel_lock::FileChannelLock;
use super::file_locker::FileLocker;

/// Factory for creating file lockers that adapt to available locking mechanisms.
///
/// Mirrors `generic.util.LockFactory` from Ghidra. Determines whether the system
/// supports channel locking and returns the appropriate locker type.
pub enum Locker {
    FileLocker(FileLocker),
    ChannelLocker(ChannelLocker),
}

impl Locker {
    /// Acquire the lock. Behavior depends on the locker type.
    pub fn lock(&mut self) -> bool {
        match self {
            Locker::FileLocker(fl) => fl.lock(),
            Locker::ChannelLocker(cl) => cl.lock(),
        }
    }

    /// Returns `true` if this instance currently holds the lock.
    pub fn is_locked(&self) -> bool {
        match self {
            Locker::FileLocker(fl) => fl.is_locked(),
            Locker::ChannelLocker(cl) => cl.is_locked(),
        }
    }

    /// Release the lock and delete the lock file if we are the owner.
    pub fn release(&mut self) {
        match self {
            Locker::FileLocker(fl) => fl.release(),
            Locker::ChannelLocker(cl) => cl.release(),
        }
    }

    /// Returns `true` if the existing lock was created by a plain `FileLocker`.
    pub fn can_force_lock(&self) -> bool {
        match self {
            Locker::FileLocker(fl) => fl.can_force_lock(),
            Locker::ChannelLocker(cl) => cl.can_force_lock(),
        }
    }

    /// Overwrite the existing lock file (only if it is a plain `FileLocker` lock).
    pub fn force_lock(&mut self) -> bool {
        match self {
            Locker::FileLocker(fl) => fl.force_lock(),
            Locker::ChannelLocker(cl) => cl.force_lock(),
        }
    }

    /// Return an HTML fragment describing the existing lock file's properties.
    pub fn get_existing_lock_file_information(&self) -> String {
        match self {
            Locker::FileLocker(fl) => fl.get_existing_lock_file_information(),
            Locker::ChannelLocker(cl) => cl.get_existing_lock_file_information(),
        }
    }
}

impl std::fmt::Display for Locker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Locker::FileLocker(fl) => std::fmt::Display::fmt(fl, f),
            Locker::ChannelLocker(cl) => std::fmt::Display::fmt(cl, f),
        }
    }
}

/// Create a file locker appropriate for the given file.
///
/// If the parent directory supports channel locking, returns a `ChannelLocker`;
/// otherwise returns a plain `FileLocker`.
///
/// # Arguments
///
/// * `lock_file` - The path to the lock file.
///
/// # Returns
///
/// A `Locker` that is either a `FileLocker` or `ChannelLocker` depending on
/// whether channel locking is supported.
pub fn create_file_locker(lock_file: &Path) -> Locker {
    if let Some(parent) = lock_file.parent() {
        if supports_channel_locking(parent) {
            return Locker::ChannelLocker(ChannelLocker::new(lock_file));
        }
    }
    Locker::FileLocker(FileLocker::new(lock_file))
}

static CHANNEL_LOCKING_SUPPORT: OnceLock<Mutex<Option<bool>>> = OnceLock::new();

/// Test whether the given directory supports channel locking.
///
/// This performs a crude locking test by attempting to create a temporary
/// lock file and acquire a channel lock on it. The result is cached across
/// multiple calls (mirrors the Java `supportsChannelLocking` static field).
fn supports_channel_locking(test_dir: &Path) -> bool {
    let support = CHANNEL_LOCKING_SUPPORT.get_or_init(|| Mutex::new(None));
    let mut cached = support.lock().unwrap();

    if let Some(result) = *cached {
        return result;
    }

    let test_file = create_test_file(test_dir);
    let mut channel_lock = FileChannelLock::new(&test_file);
    let can_lock = channel_lock.lock();
    channel_lock.release();

    *cached = Some(can_lock);
    can_lock
}

fn create_test_file(directory: &Path) -> std::path::PathBuf {
    directory.join(".ghidra.test.lock~")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn create_file_locker_returns_locker() {
        let path = tmp_path("ghidra_lf_t1.lock");
        let _ = fs::remove_file(&path);

        let locker = create_file_locker(&path);
        match locker {
            Locker::FileLocker(_) | Locker::ChannelLocker(_) => {
                // Either is acceptable
            }
        }
    }

    #[test]
    fn locker_can_lock_and_unlock() {
        let path = tmp_path("ghidra_lf_t2.lock");
        let _ = fs::remove_file(&path);

        let mut locker = create_file_locker(&path);
        assert!(locker.lock());
        assert!(locker.is_locked());
        locker.release();
        assert!(!locker.is_locked());
    }

    #[test]
    fn locker_display_works() {
        let path = tmp_path("ghidra_lf_t3.lock");
        let _ = fs::remove_file(&path);

        let locker = create_file_locker(&path);
        let text = format!("{}", locker);
        assert!(!text.is_empty());
    }

    #[test]
    fn locker_get_existing_lock_file_information_works_on_no_lock() {
        let path = tmp_path("ghidra_lf_t4.lock");
        let _ = fs::remove_file(&path);

        let locker = create_file_locker(&path);
        let info = locker.get_existing_lock_file_information();
        assert!(info.contains("no properties") || info.contains("<table"));
    }

    #[test]
    fn second_locker_cannot_lock_over_first() {
        let path = tmp_path("ghidra_lf_t5.lock");
        let tilde = std::path::PathBuf::from(format!("{}~", path.display()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&tilde);

        let mut first = create_file_locker(&path);
        assert!(first.lock());

        let mut second = create_file_locker(&path);
        assert!(!second.lock());

        first.release();
    }

    #[test]
    fn can_force_lock_returns_false_initially() {
        let path = tmp_path("ghidra_lf_t6.lock");
        let _ = fs::remove_file(&path);

        let locker = create_file_locker(&path);
        assert!(!locker.can_force_lock());
    }
}
