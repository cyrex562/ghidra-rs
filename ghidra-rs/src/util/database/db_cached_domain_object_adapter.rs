//! Port of `ghidra.util.database.DBCachedDomainObjectAdapter`: a domain object that can use
//! `DBCachedObjectStoreFactory`.
//!
//! Technically, this only introduces a read-write lock to the domain object. The
//! `DBCachedObjectStoreFactory` and related require this read-write lock. Sadly, this idea
//! didn't pan out, and that read-write lock is just a degenerate wrapper of the Ghidra
//! [`Lock`], which is not a read-write lock. This class may disappear.
//!
//! The Java source also declares a package-private `SwingAwareReadWriteLock` nested class (a
//! `ReentrantReadWriteLock` subclass that logs a warning when it blocks the Swing thread for too
//! long). It is never actually assigned to this class's `lock` field, nor referenced anywhere
//! else in the codebase -- dead code even in the original -- so it is not ported here.

use crate::framework::seam_stubs::DBDomainObjectSupport;
use crate::util::lock_hold::Lock;

/// A domain object that can use `DBCachedObjectStoreFactory`.
///
/// Port of `ghidra.util.database.DBCachedDomainObjectAdapter`.
pub trait DBCachedDomainObjectAdapter: DBDomainObjectSupport {
    /// Get the "read-write" lock, mirroring `getReadWriteLock()`.
    fn get_read_write_lock(&self) -> &dyn Lock;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::data::DomainObjectAdapterDB;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::db::DBHandle;
    use crate::framework::model::DomainObject;
    use crate::util::lock_hold::LockHold;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingLock {
        locks: AtomicUsize,
        unlocks: AtomicUsize,
    }

    impl CountingLock {
        fn new() -> Self {
            Self {
                locks: AtomicUsize::new(0),
                unlocks: AtomicUsize::new(0),
            }
        }
    }

    impl Lock for CountingLock {
        fn lock(&self) {
            self.locks.fetch_add(1, Ordering::SeqCst);
        }

        fn unlock(&self) {
            self.unlocks.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockCachedDomainObject {
        dbh: DBHandle,
        lock: CountingLock,
        initialized: bool,
    }

    impl MockCachedDomainObject {
        fn new() -> Self {
            Self {
                dbh: DBHandle::new().unwrap(),
                lock: CountingLock::new(),
                initialized: false,
            }
        }
    }

    impl DomainObject for MockCachedDomainObject {}

    impl ErrorHandler for MockCachedDomainObject {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl DomainObjectAdapterDB for MockCachedDomainObject {
        fn get_db_handle(&self) -> &DBHandle {
            &self.dbh
        }
    }

    impl DBDomainObjectSupport for MockCachedDomainObject {
        fn init(&mut self) -> std::io::Result<()> {
            self.initialized = true;
            Ok(())
        }
    }

    impl DBCachedDomainObjectAdapter for MockCachedDomainObject {
        fn get_read_write_lock(&self) -> &dyn Lock {
            &self.lock
        }
    }

    #[test]
    fn read_write_lock_is_usable_through_trait_object() {
        let mut obj = MockCachedDomainObject::new();
        obj.init().unwrap();
        assert!(obj.initialized);

        let dyn_obj: &dyn DBCachedDomainObjectAdapter = &obj;
        {
            let _hold = LockHold::lock(dyn_obj.get_read_write_lock());
            assert_eq!(obj.lock.locks.load(Ordering::SeqCst), 1);
            assert_eq!(obj.lock.unlocks.load(Ordering::SeqCst), 0);
        }
        assert_eq!(obj.lock.locks.load(Ordering::SeqCst), 1);
        assert_eq!(obj.lock.unlocks.load(Ordering::SeqCst), 1);
    }
}
