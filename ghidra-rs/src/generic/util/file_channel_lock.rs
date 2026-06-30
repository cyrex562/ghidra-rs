use std::fs::{File, OpenOptions};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Acquires and holds an exclusive OS-level advisory lock on a file.
///
/// Mirrors `generic.util.FileChannelLock` from Ghidra. The lock file path
/// is derived by appending `~` to the absolute path of the supplied file.
/// The lock file is deleted on release **only** when the lock was successfully
/// acquired, so a caller that failed to lock will not remove a live peer's
/// lock file.
pub struct FileChannelLock {
    lock_file: PathBuf,
    file: Option<File>,
    is_locked: bool,
}

impl FileChannelLock {
    /// Create a `FileChannelLock` whose underlying file is `lock_file` with
    /// `~` appended to its absolute path.
    pub fn new(lock_file: &std::path::Path) -> Self {
        let abs = if lock_file.is_absolute() {
            lock_file.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(lock_file)
        };
        let mut s = abs.into_os_string();
        s.push("~");
        FileChannelLock {
            lock_file: PathBuf::from(s),
            file: None,
            is_locked: false,
        }
    }

    /// Try to acquire an exclusive lock. Returns `true` on success, `false`
    /// if the file is already locked or any I/O error occurs.
    pub fn lock(&mut self) -> bool {
        match self.try_acquire() {
            Ok(true) => {
                self.is_locked = true;
                true
            }
            _ => {
                self.release();
                false
            }
        }
    }

    /// Release the lock and delete the lock file (only if the lock was held).
    pub fn release(&mut self) {
        #[cfg(unix)]
        if self.is_locked {
            if let Some(ref f) = self.file {
                unsafe {
                    libc::flock(f.as_raw_fd(), libc::LOCK_UN);
                }
            }
        }
        self.file = None;
        if self.is_locked {
            let _ = std::fs::remove_file(&self.lock_file);
            self.is_locked = false;
        }
    }

    #[cfg(unix)]
    fn try_acquire(&mut self) -> std::io::Result<bool> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.lock_file)?;
        let fd = file.as_raw_fd();
        self.file = Some(file);
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(err)
        }
    }

    #[cfg(not(unix))]
    fn try_acquire(&mut self) -> std::io::Result<bool> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.lock_file)?;
        self.file = Some(file);
        Ok(true)
    }
}

impl Drop for FileChannelLock {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    fn tilde(base: &PathBuf) -> PathBuf {
        PathBuf::from(format!("{}~", base.display()))
    }

    #[test]
    fn lock_returns_true_and_creates_tilde_file() {
        let base = tmp_path("ghidra_fcl_t1.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        let mut fcl = FileChannelLock::new(&base);
        assert!(fcl.lock());
        assert!(t.exists());
        fcl.release();
    }

    #[test]
    fn release_deletes_tilde_file_when_locked() {
        let base = tmp_path("ghidra_fcl_t2.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        let mut fcl = FileChannelLock::new(&base);
        assert!(fcl.lock());
        fcl.release();
        assert!(!t.exists());
    }

    #[test]
    fn tilde_suffix_reflects_lock_file_path() {
        let base = tmp_path("ghidra_fcl_t3.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        let mut fcl = FileChannelLock::new(&base);
        assert!(fcl.lock());
        // lock_file must be the base path with ~ appended
        assert!(t.exists(), "expected lock file at {}", t.display());
        fcl.release();
    }

    #[test]
    fn lock_after_release_succeeds_again() {
        let base = tmp_path("ghidra_fcl_t4.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        let mut fcl = FileChannelLock::new(&base);
        assert!(fcl.lock());
        fcl.release();
        assert!(!t.exists());
        assert!(fcl.lock());
        fcl.release();
        assert!(!t.exists());
    }

    #[test]
    fn drop_releases_and_deletes_lock_file() {
        let base = tmp_path("ghidra_fcl_t5.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        {
            let mut fcl = FileChannelLock::new(&base);
            assert!(fcl.lock());
            assert!(t.exists());
        }
        assert!(!t.exists());
    }

    #[test]
    fn release_without_lock_is_safe() {
        let base = tmp_path("ghidra_fcl_t6.lock");
        let mut fcl = FileChannelLock::new(&base);
        // never locked — release must not panic or delete anything unexpected
        fcl.release();
        fcl.release();
    }

    #[cfg(unix)]
    #[test]
    fn second_lock_attempt_returns_false_while_first_held() {
        let base = tmp_path("ghidra_fcl_t7.lock");
        let t = tilde(&base);
        let _ = std::fs::remove_file(&t);

        let mut fcl1 = FileChannelLock::new(&base);
        let mut fcl2 = FileChannelLock::new(&base);

        assert!(fcl1.lock(), "first lock should succeed");
        // Linux flock: independent open-file-descriptions from the same process
        // conflict, so the second non-blocking attempt must fail.
        assert!(!fcl2.lock(), "second lock on held file should fail");
        // lock file must not be deleted when the second attempt fails
        assert!(t.exists(), "lock file should still exist while first lock is held");

        fcl1.release();
    }
}
