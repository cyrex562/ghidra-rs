use std::sync::Arc;

use crate::util::lock_hold::{Lock, LockHold};

use super::synchronized_spliterator::Spliterator;

/// Wraps a [`Spliterator`] in one that synchronizes all operations on a given [`Lock`].
///
/// Unlike [`SynchronizedSpliterator`][super::synchronized_spliterator::SynchronizedSpliterator],
/// which synchronizes on an intrinsic monitor, this variant acquires an explicit `Lock` via
/// [`LockHold`] for each operation and releases it before returning -- mirroring Java's
/// `try (LockHold hold = LockHold.lock(lock)) { ... }` pattern. Element processing by the
/// caller of `try_advance` occurs outside the lock, matching the Java semantics.
///
/// Multiple `DBSynchronizedSpliterator`s produced by [`try_split`][Self::try_split] share the
/// same `Arc<dyn Lock>`, matching the Java behavior where split halves synchronize on the same
/// `Lock` instance as the parent.
///
/// Port of `ghidra.util.database.DBSynchronizedSpliterator`.
pub struct DBSynchronizedSpliterator<S> {
    inner: S,
    lock: Arc<dyn Lock>,
}

impl<S: Spliterator> DBSynchronizedSpliterator<S> {
    /// Creates a `DBSynchronizedSpliterator` wrapping `inner`, synchronizing on `lock`.
    ///
    /// Mirrors the Java constructor `DBSynchronizedSpliterator(Spliterator<T>, Lock)`.
    pub fn new(inner: S, lock: Arc<dyn Lock>) -> Self {
        Self { inner, lock }
    }
}

impl<S: Spliterator> Spliterator for DBSynchronizedSpliterator<S> {
    type Item = S::Item;

    /// Advances to the next element under the lock and returns it, or `None` if exhausted.
    ///
    /// The lock is released before the element is returned to the caller, so any work done
    /// with the element happens outside the critical section.
    fn try_advance(&mut self) -> Option<S::Item> {
        let item = {
            let _hold = LockHold::lock(self.lock.as_ref());
            self.inner.try_advance()
        };
        item
    }

    /// Splits off a portion of this spliterator, wrapping the result in a new
    /// `DBSynchronizedSpliterator` that shares the same lock.
    fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = S::Item>>> {
        let new_split = {
            let _hold = LockHold::lock(self.lock.as_ref());
            self.inner.try_split()
        }?;
        Some(Box::new(DBSynchronizedSpliterator {
            inner: new_split,
            lock: Arc::clone(&self.lock),
        }))
    }

    fn estimate_size(&self) -> u64 {
        let _hold = LockHold::lock(self.lock.as_ref());
        self.inner.estimate_size()
    }

    fn characteristics(&self) -> u32 {
        let _hold = LockHold::lock(self.lock.as_ref());
        self.inner.characteristics()
    }
}

impl<S: Spliterator> Iterator for DBSynchronizedSpliterator<S> {
    type Item = S::Item;

    fn next(&mut self) -> Option<S::Item> {
        Spliterator::try_advance(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::synchronized_spliterator::characteristics;
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

    struct VecSpliterator<T> {
        data: Vec<T>,
        pos: usize,
    }

    impl<T: Clone + 'static> VecSpliterator<T> {
        fn new(data: Vec<T>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl<T: Clone + 'static> Spliterator for VecSpliterator<T> {
        type Item = T;

        fn try_advance(&mut self) -> Option<T> {
            if self.pos < self.data.len() {
                let item = self.data[self.pos].clone();
                self.pos += 1;
                Some(item)
            } else {
                None
            }
        }

        fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = T>>> {
            let remaining = self.data.len() - self.pos;
            if remaining < 2 {
                return None;
            }
            let mid = self.pos + remaining / 2;
            let left = VecSpliterator {
                data: self.data[self.pos..mid].to_vec(),
                pos: 0,
            };
            self.pos = mid;
            Some(Box::new(left))
        }

        fn estimate_size(&self) -> u64 {
            (self.data.len() - self.pos) as u64
        }

        fn characteristics(&self) -> u32 {
            characteristics::ORDERED | characteristics::SIZED | characteristics::SUBSIZED
        }
    }

    fn make(data: Vec<i32>) -> DBSynchronizedSpliterator<VecSpliterator<i32>> {
        DBSynchronizedSpliterator::new(VecSpliterator::new(data), Arc::new(CountingLock::new()))
    }

    #[test]
    fn advances_elements_in_order() {
        let mut s = make(vec![1, 2, 3]);
        assert_eq!(s.try_advance(), Some(1));
        assert_eq!(s.try_advance(), Some(2));
        assert_eq!(s.try_advance(), Some(3));
        assert_eq!(s.try_advance(), None);
    }

    #[test]
    fn returns_none_when_empty() {
        let mut s = make(vec![]);
        assert_eq!(s.try_advance(), None);
    }

    #[test]
    fn iterator_trait_yields_same_sequence() {
        let s = make(vec![10, 20, 30]);
        let collected: Vec<i32> = s.collect();
        assert_eq!(collected, vec![10, 20, 30]);
    }

    #[test]
    fn estimate_size_decreases_as_consumed() {
        let mut s = make(vec![1, 2, 3]);
        assert_eq!(s.estimate_size(), 3);
        s.try_advance();
        assert_eq!(s.estimate_size(), 2);
        s.try_advance();
        assert_eq!(s.estimate_size(), 1);
        s.try_advance();
        assert_eq!(s.estimate_size(), 0);
    }

    #[test]
    fn characteristics_forwarded_from_inner() {
        let s = make(vec![1]);
        let expected =
            characteristics::ORDERED | characteristics::SIZED | characteristics::SUBSIZED;
        assert_eq!(s.characteristics(), expected);
    }

    #[test]
    fn try_split_divides_elements() {
        let mut s = make(vec![1, 2, 3, 4]);
        let mut split = s.try_split().unwrap();
        // VecSpliterator splits at midpoint: split gets [1,2], original gets [3,4]
        assert_eq!(split.try_advance(), Some(1));
        assert_eq!(split.try_advance(), Some(2));
        assert_eq!(split.try_advance(), None);
        assert_eq!(s.try_advance(), Some(3));
        assert_eq!(s.try_advance(), Some(4));
        assert_eq!(s.try_advance(), None);
    }

    #[test]
    fn try_split_none_when_too_small() {
        let mut s = make(vec![42]);
        assert!(s.try_split().is_none());
    }

    #[test]
    fn try_split_none_on_empty() {
        let mut s = make(vec![]);
        assert!(s.try_split().is_none());
    }

    #[test]
    fn split_shares_same_lock() {
        let lock: Arc<dyn Lock> = Arc::new(CountingLock::new());
        let mut s =
            DBSynchronizedSpliterator::new(VecSpliterator::new(vec![1, 2, 3, 4]), Arc::clone(&lock));
        let _split = s.try_split().unwrap();
        assert_eq!(Arc::strong_count(&lock), 3); // lock + s.lock + split.lock
    }

    #[test]
    fn lock_is_released_before_item_returned() {
        let counting = Arc::new(CountingLock::new());
        let lock: Arc<dyn Lock> = counting.clone();
        let mut s = DBSynchronizedSpliterator::new(VecSpliterator::new(vec![99]), lock);
        let item = s.try_advance();
        assert_eq!(item, Some(99));
        assert_eq!(counting.locks.load(Ordering::SeqCst), 1);
        assert_eq!(counting.unlocks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lock_acquired_for_each_operation() {
        let counting = Arc::new(CountingLock::new());
        let lock: Arc<dyn Lock> = counting.clone();
        let mut s = DBSynchronizedSpliterator::new(VecSpliterator::new(vec![1, 2]), lock);
        s.try_advance();
        s.estimate_size();
        s.characteristics();
        assert_eq!(counting.locks.load(Ordering::SeqCst), 3);
        assert_eq!(counting.unlocks.load(Ordering::SeqCst), 3);
    }
}
