use std::sync::{Arc, Mutex};

use crate::framework::model::{DomainObject, DomainObjectLockedException};

/// A hold on the lock for a domain object, obtained via [`DomainObjectLockHold::lock`] or
/// [`DomainObjectLockHold::force_lock`].
///
/// This is designed for use as a Rust RAII guard to ensure the timely release of the lock
/// even in exceptional conditions, as in:
///
/// ```ignore
/// let hold = DomainObjectLockHold::lock(&object, "Demonstration")?;
/// // Do stuff while holding the lock
/// drop(hold); // or let it drop out of scope
/// ```
///
/// Port of `ghidra.util.database.DomainObjectLockHold`.
pub struct DomainObjectLockHold {
    object: Arc<Mutex<dyn DomainObject>>,
}

impl DomainObjectLockHold {
    /// Wrapper for [`DomainObject::lock`].
    ///
    /// # Arguments
    /// * `object` - the domain object to lock
    /// * `reason` - reason for the lock
    ///
    /// # Returns
    /// The hold, which should be stored in a variable to keep it alive while the lock is needed.
    /// When the hold is dropped, the lock is released.
    ///
    /// # Errors
    /// Returns `DomainObjectLockedException` if the lock could not be obtained.
    pub fn lock(
        object: Arc<Mutex<dyn DomainObject>>,
        reason: &str,
    ) -> Result<Self, DomainObjectLockedException> {
        {
            let mut obj = object
                .lock()
                .map_err(|_| DomainObjectLockedException::new("lock poisoned"))?;
            if !obj.lock(reason) {
                return Err(DomainObjectLockedException::new("Could not get lock"));
            }
        }
        Ok(Self { object })
    }

    /// Wrapper for [`DomainObject::force_lock`].
    ///
    /// # Arguments
    /// * `object` - the domain object to lock
    /// * `rollback` - whether to rollback the current transaction
    /// * `reason` - reason for the lock
    ///
    /// # Returns
    /// The hold, which should be stored in a variable to keep it alive while the lock is needed.
    /// When the hold is dropped, the lock is released.
    pub fn force_lock(
        object: Arc<Mutex<dyn DomainObject>>,
        rollback: bool,
        reason: &str,
    ) -> Self {
        {
            let mut obj = object.lock().expect("lock poisoned");
            obj.force_lock(rollback, reason);
        }
        Self { object }
    }
}

impl Drop for DomainObjectLockHold {
    fn drop(&mut self) {
        if let Ok(mut obj) = self.object.lock() {
            obj.unlock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::Path;

    use crate::framework::model::{SaveError, DomainObjectConsumer, DomainFile};
    use crate::framework::seam_stubs::{
        DomainObjectFileListener, DomainObjectListener, Options, TransactionListener,
    };
    use crate::framework::model::event_queue_id::EventQueueID;
    use crate::program::seam_stubs::Transaction;
    use crate::util::task::TaskMonitor;

    struct MockDomainObject {
        lock_count: RefCell<usize>,
        unlock_count: RefCell<usize>,
        can_lock_result: bool,
        lock_result: bool,
    }

    impl MockDomainObject {
        fn new() -> Self {
            Self {
                lock_count: RefCell::new(0),
                unlock_count: RefCell::new(0),
                can_lock_result: true,
                lock_result: true,
            }
        }

        fn with_lock_result(mut self, result: bool) -> Self {
            self.lock_result = result;
            self
        }

        fn lock_count(&self) -> usize {
            *self.lock_count.borrow()
        }

        fn unlock_count(&self) -> usize {
            *self.unlock_count.borrow()
        }
    }

    impl DomainObject for MockDomainObject {
        fn can_lock(&self) -> bool {
            self.can_lock_result
        }

        fn lock(&mut self, _reason: &str) -> bool {
            *self.lock_count.borrow_mut() += 1;
            self.lock_result
        }

        fn force_lock(&mut self, _rollback: bool, _reason: &str) {
            *self.lock_count.borrow_mut() += 1;
        }

        fn unlock(&mut self) {
            *self.unlock_count.borrow_mut() += 1;
        }
    }

    #[test]
    fn lock_grants_lock_and_returns_hold() {
        let mock = MockDomainObject::new();
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        let hold = DomainObjectLockHold::lock(Arc::clone(&object), "test").unwrap();
        let obj = object.lock().unwrap();
        assert_eq!(obj.lock_count(), 1);
        drop(obj);
        drop(hold);
    }

    #[test]
    fn lock_fails_if_cannot_acquire() {
        let mock = Box::new(MockDomainObject::new().with_lock_result(false));
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        let result = DomainObjectLockHold::lock(Arc::clone(&object), "test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "Domain object is locked by Could not get lock");
    }

    #[test]
    fn lock_is_released_on_drop() {
        let mock = MockDomainObject::new();
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        {
            let _hold = DomainObjectLockHold::lock(Arc::clone(&object), "test").unwrap();
            let obj = object.lock().unwrap();
            assert_eq!(obj.lock_count(), 1);
            assert_eq!(obj.unlock_count(), 0);
            drop(obj);
        }

        let obj = object.lock().unwrap();
        assert_eq!(obj.unlock_count(), 1);
    }

    #[test]
    fn force_lock_always_succeeds() {
        let mock = Box::new(MockDomainObject::new().with_lock_result(false));
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        let hold = DomainObjectLockHold::force_lock(Arc::clone(&object), false, "test");
        let obj = object.lock().unwrap();
        assert_eq!(obj.lock_count(), 1);
        drop(obj);
        drop(hold);
    }

    #[test]
    fn force_lock_is_released_on_drop() {
        let mock = MockDomainObject::new();
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        {
            let _hold = DomainObjectLockHold::force_lock(Arc::clone(&object), false, "test");
            let obj = object.lock().unwrap();
            assert_eq!(obj.lock_count(), 1);
            assert_eq!(obj.unlock_count(), 0);
            drop(obj);
        }

        let obj = object.lock().unwrap();
        assert_eq!(obj.unlock_count(), 1);
    }

    #[test]
    fn force_lock_with_rollback_true() {
        let mock = MockDomainObject::new();
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        let _hold = DomainObjectLockHold::force_lock(Arc::clone(&object), true, "test");
    }

    #[test]
    fn multiple_holds_on_same_object() {
        let mock = MockDomainObject::new();
        let object = Arc::new(Mutex::new(mock as Box<dyn DomainObject>));

        {
            let _h1 = DomainObjectLockHold::lock(Arc::clone(&object), "first").unwrap();
            {
                let _h2 = DomainObjectLockHold::lock(Arc::clone(&object), "second").unwrap();
            }
        }
    }
}
