use std::path::PathBuf;

use crate::framework::model::ProjectLocator;
use crate::framework::seam_stubs::ProjectLockLike;
use crate::generic::util::lock_factory::{create_file_locker, Locker};

/// A simple delegate for creating and using locks in Ghidra.
///
/// Port of `ghidra.framework.data.ProjectLock`. The Java class is package-private and holds a
/// `FileLocker` (created via `LockFactory.createFileLocker`); Rust has no subclassing, so this
/// composes over [`Locker`] the same way [`Locker`] itself composes over `FileLocker`/
/// `ChannelLocker`.
pub struct ProjectLock {
    #[allow(dead_code)]
    lock_file: PathBuf,
    locker: Locker,
}

impl ProjectLock {
    /// Create a new `ProjectLock` for the project identified by `project_locator`, mirroring
    /// `ProjectLock(ProjectLocator)`. Determines the appropriate locker type via
    /// `LockFactory.createFileLocker` (ported as [`create_file_locker`]).
    pub fn new(project_locator: &dyn ProjectLocator) -> Self {
        let lock_file = project_locator.get_project_lock_file();
        let locker = create_file_locker(&lock_file);
        ProjectLock { lock_file, locker }
    }

    /// Acquire the lock, mirroring `ProjectLock.lock()`.
    pub fn lock(&mut self) -> bool {
        self.locker.lock()
    }

    /// Forcibly overwrite an existing lock, mirroring `ProjectLock.forceLock()`.
    pub fn force_lock(&mut self) -> bool {
        self.locker.force_lock()
    }

    /// Determine whether the existing lock can be forced, mirroring `ProjectLock.canForceLock()`.
    pub fn can_force_lock(&self) -> bool {
        self.locker.can_force_lock()
    }

    /// Release the lock, mirroring `ProjectLock.release()`.
    pub fn release(&mut self) {
        self.locker.release()
    }

    /// Determine if this instance currently holds the lock, mirroring `ProjectLock.isLocked()`.
    pub fn is_locked(&self) -> bool {
        self.locker.is_locked()
    }

    /// Return an HTML fragment describing the existing lock file's properties, mirroring
    /// `ProjectLock.getExistingLockFileInformation()`.
    pub fn get_existing_lock_file_information(&self) -> String {
        self.locker.get_existing_lock_file_information()
    }
}

impl ProjectLockLike for ProjectLock {
    fn is_locked(&self) -> bool {
        ProjectLock::is_locked(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Minimal `ProjectLocator` that reports a fixed location/name so
    /// `get_project_lock_file()` (the default-method logic in the `ProjectLocator` trait) points
    /// at a scratch path we control.
    struct TestLocator {
        location: String,
        name: String,
    }

    impl ProjectLocator for TestLocator {
        fn get_location(&self) -> String {
            self.location.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    fn locator_for(dir: &Path, name: &str) -> TestLocator {
        TestLocator {
            location: dir.display().to_string(),
            name: name.to_string(),
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ghidra_project_lock_t_{tag}"));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn lock_and_release_round_trip() {
        let dir = scratch_dir("rt");
        let locator = locator_for(&dir, "roundtrip");
        let lock_path = locator.get_project_lock_file();
        let _ = fs::remove_file(&lock_path);

        let mut lock = ProjectLock::new(&locator);
        assert!(!lock.is_locked());
        assert!(lock.lock());
        assert!(lock.is_locked());

        lock.release();
        assert!(!lock.is_locked());

        let _ = fs::remove_file(&lock_path);
    }

    #[test]
    fn second_lock_on_same_project_fails() {
        let dir = scratch_dir("dup");
        let locator = locator_for(&dir, "duplicate");
        let lock_path = locator.get_project_lock_file();
        let _ = fs::remove_file(&lock_path);

        let mut first = ProjectLock::new(&locator);
        assert!(first.lock());

        let mut second = ProjectLock::new(&locator);
        assert!(!second.lock());
        assert!(!second.is_locked());

        first.release();
        let _ = fs::remove_file(&lock_path);
    }

    #[test]
    fn can_force_lock_reflects_existing_lock_kind() {
        let dir = scratch_dir("force");
        let locator = locator_for(&dir, "forceable");
        let lock_path = locator.get_project_lock_file();
        let _ = fs::remove_file(&lock_path);

        let mut first = ProjectLock::new(&locator);
        assert!(first.lock());

        let second = ProjectLock::new(&locator);
        // Whether an existing lock can be forced depends on the locker kind
        // (channel-lock-capable filesystems refuse forcing); just exercise the call end to end.
        let _ = second.can_force_lock();

        first.release();
        let _ = fs::remove_file(&lock_path);
    }

    #[test]
    fn get_existing_lock_file_information_on_fresh_path() {
        let dir = scratch_dir("info");
        let locator = locator_for(&dir, "info");
        let lock_path = locator.get_project_lock_file();
        let _ = fs::remove_file(&lock_path);

        let lock = ProjectLock::new(&locator);
        let info = lock.get_existing_lock_file_information();
        assert!(!info.is_empty());
    }

    #[test]
    fn project_lock_like_trait_delegates_to_is_locked() {
        let dir = scratch_dir("trait");
        let locator = locator_for(&dir, "trait");
        let lock_path = locator.get_project_lock_file();
        let _ = fs::remove_file(&lock_path);

        let mut lock = ProjectLock::new(&locator);
        assert!(lock.lock());

        let as_trait: &dyn ProjectLockLike = &lock;
        assert!(as_trait.is_locked());

        lock.release();
        let _ = fs::remove_file(&lock_path);
    }
}
