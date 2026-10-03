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

/// `DBSynchronizedIterator` (Java: `ghidra.util.database.DBSynchronizedIterator`) is
/// deliberately absent.
///
/// The Java class wraps an iterator plus the database's `ReadWriteLock`, taking the read lock
/// around `hasNext`/`next` and the write lock around `remove`. Translated literally it became
/// a struct holding `Arc<RwLock<()>>` -- a lock over `()`, i.e. over no data at all -- while
/// owning its delegate iterator by value. It therefore protected nothing that `&self`/`&mut
/// self` did not already protect, and could not be used the way its name suggests: sharing it
/// across threads requires `Arc<..>`, at which point `remove(&mut self)` is unreachable.
///
/// The Rust equivalent of "a synchronized view of a collection" is to put the collection
/// itself behind the lock -- `Arc<RwLock<C>>` -- and iterate while holding a guard. That gives
/// real mutual exclusion over real data, which the wrapper never did.
///
/// A lock belongs in a ported type only when it coordinates something the type does not own
/// (an external resource, or state shared with another holder of the same lock). When that
/// case arrives, use the crate's [`Lock`](crate::util::lock_hold::Lock) abstraction, as
/// [`DBSynchronizedSpliterator`](super::db_synchronized_spliterator::DBSynchronizedSpliterator)
/// does, rather than an ad-hoc `Mutex<()>`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct TestIterator {
        items: Vec<i32>,
        pos: usize,
        remove_count: Arc<AtomicUsize>,
    }

    impl TestIterator {
        fn new(items: Vec<i32>) -> (Self, Arc<AtomicUsize>) {
            let remove_count = Arc::new(AtomicUsize::new(0));
            (
                Self { items, pos: 0, remove_count: remove_count.clone() },
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
            self.pos -= 1;
            self.items.remove(self.pos);
        }
    }

    #[test]
    fn next_returns_none_past_the_end_instead_of_panicking() {
        // The old `fn next(&mut self) -> T` indexed straight into the backing Vec and panicked
        // once exhausted, mirroring java.util.Iterator. Option makes that unrepresentable.
        let (mut iter, _) = TestIterator::new(vec![1]);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn peek_replaces_has_next() {
        let (iter, _) = TestIterator::new(vec![1, 2]);
        let mut iter = iter.peekable();
        assert_eq!(iter.peek(), Some(&1));
        iter.next();
        iter.next();
        assert_eq!(iter.peek(), None);
    }

    #[test]
    fn remove_drops_the_element_last_returned() {
        let (mut iter, removals) = TestIterator::new(vec![1, 2, 3]);
        assert_eq!(iter.next(), Some(1));
        iter.remove();
        assert_eq!(removals.load(Ordering::SeqCst), 1);
        // removal rewinds onto the shifted element, so iteration continues from 2
        assert_eq!(iter.collect::<Vec<_>>(), vec![2, 3]);
    }

    /// The payoff of extending Iterator: adaptors, none of which the old trait allowed.
    #[test]
    fn adaptors_work_on_a_removable_iterator() {
        let (iter, _) = TestIterator::new(vec![1, 2, 3, 4]);
        assert_eq!(iter.filter(|n| n % 2 == 0).collect::<Vec<_>>(), vec![2, 4]);
    }
}
