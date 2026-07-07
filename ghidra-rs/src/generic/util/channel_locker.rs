use std::path::Path;

use super::file_locker::FileLocker;

/// Lock file guarded by both a properties file and an exclusive OS-level file
/// channel lock, allowing a stale lock left behind by a crashed process to be
/// detected and reclaimed by a later `lock()` call.
///
/// Mirrors `generic.util.ChannelLocker` from Ghidra, which subclasses `FileLocker`
/// and overrides its lock-type, `lock()`, `createLockFile()`, and `release()`
/// behavior. Rust has no subclassing, so this type composes over [`FileLocker`],
/// which encodes the channel-locking behavior internally.
pub struct ChannelLocker {
    inner: FileLocker,
}

impl ChannelLocker {
    /// Create a `ChannelLocker` for the given path.
    ///
    /// If a lock file already exists its properties are loaded immediately.
    pub fn new(lock_file: &Path) -> Self {
        ChannelLocker {
            inner: FileLocker::new_channel_locker(lock_file),
        }
    }

    /// Acquire the lock. Succeeds when there is no conflicting lock (or the
    /// existing lock is a stale channel lock) and the OS-level channel lock
    /// can also be acquired.
    pub fn lock(&mut self) -> bool {
        self.inner.lock()
    }

    /// Returns `true` if this instance currently holds the lock.
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// Release the channel lock and the lock file if we are the owner.
    pub fn release(&mut self) {
        self.inner.release()
    }

    /// Returns `true` if the existing lock was created by a plain `FileLocker`
    /// (meaning it can be safely force-replaced).
    pub fn can_force_lock(&self) -> bool {
        self.inner.can_force_lock()
    }

    /// Overwrite the existing lock file (only if it is a plain `FileLocker` lock)
    /// and acquire a fresh channel lock.
    pub fn force_lock(&mut self) -> bool {
        self.inner.force_lock()
    }

    /// Return an HTML fragment describing the existing lock file's properties,
    /// or a plain-text message when no properties are present.
    pub fn get_existing_lock_file_information(&self) -> String {
        self.inner.get_existing_lock_file_information()
    }
}

impl std::fmt::Display for ChannelLocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn lock_creates_file_and_returns_true() {
        let path = tmp_path("ghidra_cl_t1.lock");
        let tilde = PathBuf::from(format!("{}~", path.display()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&tilde);

        let mut locker = ChannelLocker::new(&path);
        assert!(locker.lock());
        assert!(path.exists());
        assert!(tilde.exists());
        assert!(locker.is_locked());

        locker.release();
        assert!(!path.exists());
        assert!(!tilde.exists());
    }

    #[test]
    fn lock_type_is_channel_lock() {
        let path = tmp_path("ghidra_cl_t2.lock");
        let _ = fs::remove_file(&path);

        let locker = ChannelLocker::new(&path);
        assert_eq!(locker.inner.lock_type(), "Channel Lock");
    }

    #[test]
    fn second_locker_fails_while_first_holds_channel_lock() {
        let path = tmp_path("ghidra_cl_t3.lock");
        let tilde = PathBuf::from(format!("{}~", path.display()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&tilde);

        let mut first = ChannelLocker::new(&path);
        assert!(first.lock());

        // Second locker sees the on-disk "Channel Lock" properties file, and the
        // underlying OS lock is still held, so it must fail to acquire.
        let mut second = ChannelLocker::new(&path);
        assert!(!second.lock());

        first.release();
    }

    #[test]
    fn lock_succeeds_over_stale_channel_lock_file() {
        // Simulate a crashed process: the properties file exists (so existing
        // lock type is "Channel Lock"), but the OS-level channel lock is free.
        let path = tmp_path("ghidra_cl_t4.lock");
        let tilde = PathBuf::from(format!("{}~", path.display()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&tilde);

        {
            let mut stale = ChannelLocker::new(&path);
            assert!(stale.lock());
            // Drop without releasing: leaves the properties file and OS lock
            // behind, but dropping FileChannelLock releases the OS-level flock.
        }

        let mut recovered = ChannelLocker::new(&path);
        assert!(recovered.lock(), "should reclaim a stale channel lock");
        recovered.release();
    }

    #[test]
    fn release_without_lock_is_safe() {
        let path = tmp_path("ghidra_cl_t5.lock");
        let _ = fs::remove_file(&path);

        let mut locker = ChannelLocker::new(&path);
        locker.release();
        locker.release();
    }

    #[test]
    fn cannot_lock_over_plain_file_lock() {
        let path = tmp_path("ghidra_cl_t6.lock");
        let _ = fs::remove_file(&path);

        let mut plain = FileLocker::new(&path);
        assert!(plain.lock());

        let mut channel = ChannelLocker::new(&path);
        assert!(!channel.lock(), "channel locker must not override a plain file lock");

        plain.release();
    }

    #[test]
    fn display_uses_channel_locker_name() {
        let path = tmp_path("ghidra_cl_t7.lock");
        let _ = fs::remove_file(&path);

        let locker = ChannelLocker::new(&path);
        let text = format!("{}", locker);
        assert!(text.starts_with("ChannelLocker"), "got: {}", text);
    }
}
