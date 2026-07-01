use std::sync::Arc;
use std::sync::RwLock;

/// A trait for iterators that support removal of the current element.
///
/// This trait mirrors `java.util.Iterator` and provides the core iterator contract
/// with mutable access methods.
pub trait RemovableIterator<T> {
    /// Returns `true` if there is a next element.
    fn has_next(&mut self) -> bool;
    /// Returns the next element.
    fn next(&mut self) -> T;
    /// Removes the current element (optional operation).
    fn remove(&mut self);
}

/// A thread-safe wrapper around an iterator that synchronizes access using a read-write lock.
///
/// Read operations (`has_next`, `next`) acquire the read lock, while the destructive
/// operation (`remove`) acquires the write lock. This mirrors the Java semantics of
/// `ghidra.util.database.DBSynchronizedIterator`, which wraps a `java.util.Iterator`
/// and a `ReadWriteLock`.
///
/// # Example
///
/// ```ignore
/// let lock = Arc::new(RwLock::new(()));
/// let mut wrapped = VecIterator::new(vec![1, 2, 3]);
/// let mut iter = DBSynchronizedIterator::new(Box::new(wrapped), lock);
/// while iter.has_next() {
///     let item = iter.next();
///     // ...
/// }
/// ```
pub struct DBSynchronizedIterator<T> {
    iterator: Box<dyn RemovableIterator<T>>,
    lock: Arc<RwLock<()>>,
}

impl<T> DBSynchronizedIterator<T> {
    /// Creates a new `DBSynchronizedIterator` wrapping an iterator and protecting it with a lock.
    ///
    /// # Arguments
    ///
    /// * `iterator` - The wrapped iterator to synchronize
    /// * `lock` - The read-write lock controlling access
    pub fn new(iterator: Box<dyn RemovableIterator<T>>, lock: Arc<RwLock<()>>) -> Self {
        Self { iterator, lock }
    }

    /// Returns `true` if there is a next element.
    ///
    /// This operation acquires the read lock.
    pub fn has_next(&mut self) -> bool {
        let _guard = self.lock.read().unwrap();
        self.iterator.has_next()
    }

    /// Returns the next element.
    ///
    /// This operation acquires the read lock.
    pub fn next(&mut self) -> T {
        let _guard = self.lock.read().unwrap();
        self.iterator.next()
    }

    /// Removes the current element.
    ///
    /// This operation acquires the write lock and is only called if the underlying
    /// iterator supports removal.
    pub fn remove(&mut self) {
        let _guard = self.lock.write().unwrap();
        self.iterator.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestIterator {
        items: Vec<i32>,
        pos: usize,
        remove_count: Arc<AtomicUsize>,
    }

    impl TestIterator {
        fn new(items: Vec<i32>) -> (Self, Arc<AtomicUsize>) {
            let remove_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    items,
                    pos: 0,
                    remove_count: remove_count.clone(),
                },
                remove_count,
            )
        }
    }

    impl RemovableIterator<i32> for TestIterator {
        fn has_next(&mut self) -> bool {
            self.pos < self.items.len()
        }

        fn next(&mut self) -> i32 {
            let item = self.items[self.pos];
            self.pos += 1;
            item
        }

        fn remove(&mut self) {
            self.remove_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn has_next_with_elements() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![1, 2, 3]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        assert!(iter.has_next());
    }

    #[test]
    fn has_next_empty() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        assert!(!iter.has_next());
    }

    #[test]
    fn has_next_exhausted() {
        let lock = Arc::new(RwLock::new(()));
        let (mut inner, _) = TestIterator::new(vec![1]);
        inner.next();
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        assert!(!iter.has_next());
    }

    #[test]
    fn next_returns_elements() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![1, 2, 3]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        assert_eq!(iter.next(), 1);
        assert_eq!(iter.next(), 2);
        assert_eq!(iter.next(), 3);
    }

    #[test]
    fn iteration_sequence() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![5, 10, 15]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        assert!(iter.has_next());
        assert_eq!(iter.next(), 5);
        assert!(iter.has_next());
        assert_eq!(iter.next(), 10);
        assert!(iter.has_next());
        assert_eq!(iter.next(), 15);
        assert!(!iter.has_next());
    }

    #[test]
    fn remove_increments_counter() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, remove_count) = TestIterator::new(vec![10, 20, 30]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock);

        iter.next();
        iter.remove();
        iter.next();
        iter.remove();

        assert_eq!(remove_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn lock_acquired_during_has_next() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![1]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock.clone());

        iter.has_next();

        let acquired = lock.try_write().is_ok();
        assert!(acquired, "write lock should be acquirable after has_next returns");
    }

    #[test]
    fn lock_acquired_during_next() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, _) = TestIterator::new(vec![1, 2]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock.clone());

        iter.next();

        let acquired = lock.try_write().is_ok();
        assert!(acquired, "write lock should be acquirable after next returns");
    }

    #[test]
    fn lock_acquired_during_remove() {
        let lock = Arc::new(RwLock::new(()));
        let (inner, remove_count) = TestIterator::new(vec![1]);
        let mut iter = DBSynchronizedIterator::new(Box::new(inner), lock.clone());

        iter.next();
        iter.remove();

        assert_eq!(remove_count.load(Ordering::SeqCst), 1);
        let acquired = lock.try_write().is_ok();
        assert!(acquired, "write lock should be acquirable after remove returns");
    }
}
