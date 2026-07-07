/// Acquire/release contract of `java.util.concurrent.locks.Lock`.
///
/// Implementors must ensure that every `lock()` call is paired with exactly one `unlock()`.
pub trait Lock {
    /// Acquires the lock, blocking until it is available.
    fn lock(&self);
    /// Releases the lock.
    fn unlock(&self);
}

/// RAII guard that acquires a [`Lock`] on construction and releases it on drop.
///
/// Use [`LockHold::lock`] to acquire; the lock is automatically released when this guard
/// drops — the Rust equivalent of Java's `try-with-resources` pattern.
///
/// Port of `ghidra.util.LockHold`.
pub struct LockHold<'a, L: Lock + ?Sized> {
    lock: &'a L,
}

impl<'a, L: Lock + ?Sized> LockHold<'a, L> {
    /// Acquires `lock` and returns a guard that releases it when dropped.
    pub fn lock(lock: &'a L) -> Self {
        lock.lock();
        Self { lock }
    }
}

impl<'a, L: Lock + ?Sized> Drop for LockHold<'a, L> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        fn lock_count(&self) -> usize {
            self.locks.load(Ordering::SeqCst)
        }

        fn unlock_count(&self) -> usize {
            self.unlocks.load(Ordering::SeqCst)
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

    #[test]
    fn lock_is_acquired_on_construction() {
        let l = CountingLock::new();
        let _hold = LockHold::lock(&l);
        assert_eq!(l.lock_count(), 1);
        assert_eq!(l.unlock_count(), 0);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let l = CountingLock::new();
        {
            let _hold = LockHold::lock(&l);
        }
        assert_eq!(l.lock_count(), 1);
        assert_eq!(l.unlock_count(), 1);
    }

    #[test]
    fn multiple_holds_are_independent() {
        let l = CountingLock::new();
        {
            let _h1 = LockHold::lock(&l);
            {
                let _h2 = LockHold::lock(&l);
            }
            assert_eq!(l.lock_count(), 2);
            assert_eq!(l.unlock_count(), 1);
        }
        assert_eq!(l.lock_count(), 2);
        assert_eq!(l.unlock_count(), 2);
    }

    #[test]
    fn lock_released_on_panic_unwind() {
        let l = std::sync::Arc::new(CountingLock::new());
        let l2 = l.clone();
        let _ = std::panic::catch_unwind(move || {
            let _hold = LockHold::lock(l2.as_ref());
            panic!("intentional");
        });
        assert_eq!(l.lock_count(), 1);
        assert_eq!(l.unlock_count(), 1);
    }

    #[test]
    fn dyn_lock_dispatch() {
        let l = CountingLock::new();
        let lock_ref: &dyn Lock = &l;
        {
            let _hold = LockHold::lock(lock_ref);
        }
        assert_eq!(l.lock_count(), 1);
        assert_eq!(l.unlock_count(), 1);
    }
}
