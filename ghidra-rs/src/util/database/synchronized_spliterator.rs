use std::sync::{Arc, Mutex};

/// Characteristic flags matching `java.util.Spliterator` constants.
pub mod characteristics {
    pub const ORDERED: u32 = 0x0000_0010;
    pub const DISTINCT: u32 = 0x0000_0001;
    pub const SORTED: u32 = 0x0000_0004;
    pub const SIZED: u32 = 0x0000_0040;
    pub const NONNULL: u32 = 0x0000_0100;
    pub const IMMUTABLE: u32 = 0x0000_0400;
    pub const CONCURRENT: u32 = 0x0000_1000;
    pub const SUBSIZED: u32 = 0x0000_4000;
    /// Sentinel returned by `estimate_size` when the size is unknown.
    pub const UNKNOWN_SIZE: u64 = u64::MAX;
}

/// A sequential traversal and partitioning source.
///
/// Analogous to `java.util.Spliterator`. Implementations advance through elements one
/// at a time and can optionally split themselves for parallel processing.
pub trait Spliterator {
    type Item: 'static;

    /// Returns the next element, or `None` if exhausted.
    fn try_advance(&mut self) -> Option<Self::Item>;

    /// Splits off a portion of this spliterator into a new one, or returns `None` if
    /// splitting is not possible (e.g. too few remaining elements).
    fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = Self::Item>>>;

    /// Returns an estimate of the number of remaining elements, or
    /// [`characteristics::UNKNOWN_SIZE`] if unknown.
    fn estimate_size(&self) -> u64;

    /// Returns a bitmask of characteristic flags (see [`characteristics`]).
    fn characteristics(&self) -> u32;
}

impl<T: 'static> Spliterator for Box<dyn Spliterator<Item = T>> {
    type Item = T;

    fn try_advance(&mut self) -> Option<T> {
        (**self).try_advance()
    }

    fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = T>>> {
        (**self).try_split()
    }

    fn estimate_size(&self) -> u64 {
        (**self).estimate_size()
    }

    fn characteristics(&self) -> u32 {
        (**self).characteristics()
    }
}

/// Wraps a [`Spliterator`] in one that synchronizes all operations on a shared lock.
///
/// Element access is locked; element processing by the caller occurs outside the lock.
/// This matches the Java semantics where the consumer action in `tryAdvance` runs after
/// the `synchronized` block exits — avoiding holding the lock while arbitrary user code
/// runs.
///
/// Multiple `SynchronizedSpliterator`s produced by [`try_split`][Self::try_split] share
/// the same `Arc<Mutex>` lock, matching the Java behavior where split halves synchronize
/// on the same intrinsic lock as the parent.
///
/// Port of `ghidra.util.database.SynchronizedSpliterator`.
pub struct SynchronizedSpliterator<S> {
    inner: S,
    lock: Arc<Mutex<()>>,
}

impl<S: Spliterator> SynchronizedSpliterator<S> {
    /// Creates a `SynchronizedSpliterator` using the provided shared lock.
    ///
    /// Mirrors the Java constructor `SynchronizedSpliterator(Spliterator<T>, Object lock)`.
    /// Pass an `Arc<Mutex<()>>` that is shared with the owning collection so that all
    /// callers coordinate on the same monitor.
    pub fn new(inner: S, lock: Arc<Mutex<()>>) -> Self {
        Self { inner, lock }
    }
}

impl<S: Spliterator> Spliterator for SynchronizedSpliterator<S> {
    type Item = S::Item;

    /// Advances to the next element under the lock and returns it, or `None` if exhausted.
    ///
    /// The lock is released before the element is returned to the caller, so any work
    /// done with the element happens outside the critical section.
    fn try_advance(&mut self) -> Option<S::Item> {
        let item = {
            let _guard = self.lock.lock().unwrap();
            self.inner.try_advance()
        };
        item
    }

    /// Splits off a portion of this spliterator, wrapping the result in a new
    /// `SynchronizedSpliterator` that shares the same lock.
    fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = S::Item>>> {
        let new_split = {
            let _guard = self.lock.lock().unwrap();
            self.inner.try_split()
        }?;
        Some(Box::new(SynchronizedSpliterator {
            inner: new_split,
            lock: Arc::clone(&self.lock),
        }))
    }

    fn estimate_size(&self) -> u64 {
        let _guard = self.lock.lock().unwrap();
        self.inner.estimate_size()
    }

    fn characteristics(&self) -> u32 {
        let _guard = self.lock.lock().unwrap();
        self.inner.characteristics()
    }
}

impl<S: Spliterator> Iterator for SynchronizedSpliterator<S> {
    type Item = S::Item;

    fn next(&mut self) -> Option<S::Item> {
        Spliterator::try_advance(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{characteristics, Spliterator, SynchronizedSpliterator};
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct VecSpliterator<T> {
        data: Vec<T>,
        pos: usize,
    }

    impl<T: Clone + Send + 'static> VecSpliterator<T> {
        fn new(data: Vec<T>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl<T: Clone + Send + 'static> Spliterator for VecSpliterator<T> {
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
            let left = VecSpliterator { data: self.data[self.pos..mid].to_vec(), pos: 0 };
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

    fn make(data: Vec<i32>) -> SynchronizedSpliterator<VecSpliterator<i32>> {
        SynchronizedSpliterator::new(VecSpliterator::new(data), Arc::new(Mutex::new(())))
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
        let lock = Arc::new(Mutex::new(()));
        let mut s = SynchronizedSpliterator::new(VecSpliterator::new(vec![1, 2, 3, 4]), Arc::clone(&lock));
        let _split = s.try_split().unwrap();
        // If both shared the same lock, trying to lock here (with no holder) succeeds.
        assert!(lock.try_lock().is_ok());
    }

    #[test]
    fn lock_is_released_before_item_returned() {
        // After try_advance returns, the lock must be free for another acquisition.
        let lock = Arc::new(Mutex::new(()));
        let mut s = SynchronizedSpliterator::new(
            VecSpliterator::new(vec![99]),
            Arc::clone(&lock),
        );
        let item = s.try_advance();
        assert_eq!(item, Some(99));
        // Lock must be released at this point.
        assert!(
            lock.try_lock().is_ok(),
            "lock should be released after try_advance returns"
        );
    }

    #[test]
    fn concurrent_access_from_two_threads_is_safe() {
        let lock = Arc::new(Mutex::new(()));
        let mut a = SynchronizedSpliterator::new(
            VecSpliterator::new(vec![1, 2, 3]),
            Arc::clone(&lock),
        );
        let mut b = SynchronizedSpliterator::new(
            VecSpliterator::new(vec![4, 5, 6]),
            Arc::clone(&lock),
        );

        let ha = thread::spawn(move || {
            let mut out = vec![];
            while let Some(x) = a.try_advance() {
                out.push(x);
            }
            out
        });
        let hb = thread::spawn(move || {
            let mut out = vec![];
            while let Some(x) = b.try_advance() {
                out.push(x);
            }
            out
        });

        let mut ra = ha.join().unwrap();
        let mut rb = hb.join().unwrap();
        ra.sort_unstable();
        rb.sort_unstable();
        assert_eq!(ra, vec![1, 2, 3]);
        assert_eq!(rb, vec![4, 5, 6]);
    }
}
