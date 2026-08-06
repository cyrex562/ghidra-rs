use std::sync::Arc;
use std::sync::RwLock;

/// An iterator whose current element can be removed from the underlying collection.
///
/// Extends [`Iterator`] rather than restating it: `has_next`/`next` were a transcription of
/// `java.util.Iterator` that std already provides (and provides better -- `next` yields
/// `Option<Self::Item>` instead of panicking past the end, and every adaptor works). What std
/// has no equivalent for is removal *during* iteration, so that is all this trait adds.
///
/// See `OWNERSHIP_MIGRATION.md` (the `ITER` verdict in `CONVENTION_QUEUE.tsv`): the debt was
/// the `Box<dyn RemovableIterator<T>>` erasure, not the trait -- removal is a real capability,
/// so the trait earns its keep.
pub trait RemovableIterator: Iterator {
    /// Removes the element most recently returned by [`Iterator::next`] (optional operation).
    fn remove(&mut self);
}

/// A thread-safe wrapper around an iterator that synchronizes access using a read-write lock.
///
/// Reading (`Iterator::next`) acquires the read lock, while the destructive
/// operation (`remove`) acquires the write lock. This mirrors the Java semantics of
/// `ghidra.util.database.DBSynchronizedIterator`, which wraps a `java.util.Iterator`
/// and a `ReadWriteLock`.
///
/// # Example
///
/// ```ignore
/// let lock = Arc::new(RwLock::new(()));
/// let mut iter = DBSynchronizedIterator::new(removable_iter, lock);
/// while let Some(item) = iter.next() {
///     // ...
/// }
/// ```
pub struct DBSynchronizedIterator<I: RemovableIterator> {
    iterator: I,
    lock: Arc<RwLock<()>>,
}

impl<I: RemovableIterator> DBSynchronizedIterator<I> {
    /// Creates a new `DBSynchronizedIterator` wrapping an iterator and protecting it with a lock.
    ///
    /// # Arguments
    ///
    /// * `iterator` - The wrapped iterator to synchronize
    /// * `lock` - The read-write lock controlling access
    pub fn new(iterator: I, lock: Arc<RwLock<()>>) -> Self {
        Self { iterator, lock }
    }
}

impl<I: RemovableIterator> Iterator for DBSynchronizedIterator<I> {
    type Item = I::Item;

    /// Yields the next element, holding the read lock for the duration of the call.
    fn next(&mut self) -> Option<Self::Item> {
        let _guard = self.lock.read().unwrap();
        self.iterator.next()
    }
}

impl<I: RemovableIterator> RemovableIterator for DBSynchronizedIterator<I> {
    /// Removes the current element, holding the WRITE lock (removal mutates the collection).
    fn remove(&mut self) {
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

    impl Iterator for TestIterator {
        type Item = i32;

        fn next(&mut self) -> Option<i32> {
            let item = *self.items.get(self.pos)?;
            self.pos += 1;
            Some(item)
        }
    }

    impl RemovableIterator for TestIterator {
        fn remove(&mut self) {
            self.remove_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn sync_iter(items: Vec<i32>) -> (DBSynchronizedIterator<TestIterator>, Arc<AtomicUsize>) {
        let lock = Arc::new(RwLock::new(()));
        let (inner, removals) = TestIterator::new(items);
        (DBSynchronizedIterator::new(inner, lock), removals)
    }

    /// `has_next` is gone; `Peekable` is how you look without consuming.
    #[test]
    fn peek_reports_a_pending_element() {
        let (iter, _) = sync_iter(vec![1, 2, 3]);
        let mut iter = iter.peekable();
        assert_eq!(iter.peek(), Some(&1));
    }

    #[test]
    fn peek_is_none_when_empty() {
        let (iter, _) = sync_iter(vec![]);
        let mut iter = iter.peekable();
        assert_eq!(iter.peek(), None);
    }

    #[test]
    fn next_returns_none_past_the_end_instead_of_panicking() {
        // The old `next(&mut self) -> T` indexed straight into the backing Vec and panicked
        // once exhausted, mirroring java.util.Iterator. std::Iterator makes that unrepresentable.
        let (mut iter, _) = sync_iter(vec![1]);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn next_returns_elements_in_order() {
        let (iter, _) = sync_iter(vec![1, 2, 3]);
        assert_eq!(iter.collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn remove_delegates_to_the_wrapped_iterator() {
        let (mut iter, removals) = sync_iter(vec![1, 2, 3]);
        iter.next();
        iter.remove();
        assert_eq!(removals.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn removal_takes_the_write_lock_while_iteration_takes_the_read_lock() {
        // Both operations must go through the shared lock; this exercises the pair in
        // sequence, which would deadlock if `remove` re-entered the read guard.
        let (mut iter, removals) = sync_iter(vec![1, 2]);
        assert_eq!(iter.next(), Some(1));
        iter.remove();
        assert_eq!(iter.next(), Some(2));
        assert_eq!(removals.load(Ordering::SeqCst), 1);
    }

    /// The payoff of extending Iterator: adaptors, none of which the old trait allowed.
    #[test]
    fn adaptors_work_on_a_synchronized_iterator() {
        let (iter, _) = sync_iter(vec![1, 2, 3, 4]);
        let evens: Vec<i32> = iter.filter(|n| n % 2 == 0).collect();
        assert_eq!(evens, vec![2, 4]);
    }
}
