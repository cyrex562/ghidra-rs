use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

use crate::util::database::synchronized_spliterator::{characteristics, Spliterator, SynchronizedSpliterator};
use crate::util::database::DBSynchronizedSpliterator;
use crate::util::lock_hold::Lock;
use crate::util::merge_sorting_spliterator::MergeSortingIterator;

/// Adapts an [`Iterator`] to the [`Spliterator`] trait so it can be wrapped by
/// [`SynchronizedSpliterator`] or [`DBSynchronizedSpliterator`].
///
/// Unlike a true spliterator, this adapter never splits -- matching the fact that an
/// arbitrary Java `Stream`'s spliterator is not guaranteed to be splittable either.
struct IterSpliterator<I> {
    inner: I,
}

impl<I: Iterator> Spliterator for IterSpliterator<I>
where
    I: 'static,
    I::Item: 'static,
{
    type Item = I::Item;

    fn try_advance(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn try_split(&mut self) -> Option<Box<dyn Spliterator<Item = Self::Item>>> {
        None
    }

    fn estimate_size(&self) -> u64 {
        let (lower, upper) = self.inner.size_hint();
        match upper {
            Some(upper) if upper == lower => lower as u64,
            _ => characteristics::UNKNOWN_SIZE,
        }
    }

    fn characteristics(&self) -> u32 {
        0
    }
}

/// Utilities for working with streams (Rust [`Iterator`]s).
///
/// Port of `ghidra.util.StreamUtils`.
pub struct StreamUtils;

impl StreamUtils {
    /// Merges sorted streams into a single sorted stream.
    ///
    /// Each stream in `streams` must already be sorted according to `comparator`. If
    /// exactly one stream is given, it is returned unchanged rather than wrapped.
    pub fn merge<T, I, C>(streams: Vec<I>, comparator: C) -> Box<dyn Iterator<Item = T>>
    where
        T: 'static,
        I: Iterator<Item = T> + 'static,
        C: Fn(&T, &T) -> Ordering + 'static,
    {
        if streams.len() == 1 {
            let mut streams = streams;
            return Box::new(streams.pop().unwrap());
        }
        Box::new(MergeSortingIterator::new(streams, comparator))
    }

    /// Adapts a stream into an iterable.
    ///
    /// Rust iterators already implement [`IntoIterator`], so this is the identity
    /// function; it exists only to mirror the Java API.
    pub fn iter<T>(stream: impl Iterator<Item = T>) -> impl Iterator<Item = T> {
        stream
    }

    /// Wraps the given stream into a stream synchronized on the given lock.
    ///
    /// **NOTE:** This makes no guarantees regarding the consistency or visit order if the
    /// underlying resource is modified between elements being visited. It merely prevents
    /// the stream client from accessing the underlying resource concurrently. For such
    /// guarantees, the client may need to acquire the lock for its whole use of the stream.
    pub fn sync<T, I>(lock: Arc<Mutex<()>>, stream: I) -> impl Iterator<Item = T>
    where
        T: 'static,
        I: Iterator<Item = T> + 'static,
    {
        SynchronizedSpliterator::new(IterSpliterator { inner: stream }, lock)
    }

    /// Wraps the given stream into a stream synchronized on the given lock.
    ///
    /// **NOTE:** This makes no guarantees regarding the consistency or visit order if the
    /// underlying resource is modified between elements being visited. It merely prevents
    /// the stream client from accessing the underlying resource concurrently. For such
    /// guarantees, the client may need to acquire the lock for its whole use of the stream.
    pub fn lock<T, I>(lock: Arc<dyn Lock>, stream: I) -> impl Iterator<Item = T>
    where
        T: 'static,
        I: Iterator<Item = T> + 'static,
    {
        DBSynchronizedSpliterator::new(IterSpliterator { inner: stream }, lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn cmp_i32(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    #[test]
    fn merge_two_sorted_streams() {
        let result: Vec<i32> = StreamUtils::merge(
            vec![vec![1, 3, 5].into_iter(), vec![2, 4, 6].into_iter()],
            cmp_i32,
        )
        .collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn merge_single_stream_returned_directly() {
        let result: Vec<i32> =
            StreamUtils::merge(vec![vec![7, 8, 9].into_iter()], cmp_i32).collect();
        assert_eq!(result, vec![7, 8, 9]);
    }

    #[test]
    fn merge_no_streams_is_empty() {
        let result: Vec<i32> = StreamUtils::merge(Vec::<std::vec::IntoIter<i32>>::new(), cmp_i32).collect();
        assert_eq!(result, Vec::<i32>::new());
    }

    #[test]
    fn iter_is_identity() {
        let result: Vec<i32> = StreamUtils::iter(vec![1, 2, 3].into_iter()).collect();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn sync_yields_same_elements() {
        let lock = Arc::new(Mutex::new(()));
        let result: Vec<i32> = StreamUtils::sync(lock, vec![1, 2, 3].into_iter()).collect();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn sync_serializes_concurrent_access() {
        use std::thread;

        let lock = Arc::new(Mutex::new(()));
        let mut a = StreamUtils::sync(Arc::clone(&lock), vec![1, 2, 3].into_iter());
        let mut b = StreamUtils::sync(lock, vec![4, 5, 6].into_iter());

        let ha = thread::spawn(move || a.by_ref().collect::<Vec<_>>());
        let hb = thread::spawn(move || b.by_ref().collect::<Vec<_>>());

        let mut ra = ha.join().unwrap();
        let mut rb = hb.join().unwrap();
        ra.sort_unstable();
        rb.sort_unstable();
        assert_eq!(ra, vec![1, 2, 3]);
        assert_eq!(rb, vec![4, 5, 6]);
    }

    struct CountingLock {
        locks: AtomicUsize,
        unlocks: AtomicUsize,
    }

    impl CountingLock {
        fn new() -> Self {
            Self { locks: AtomicUsize::new(0), unlocks: AtomicUsize::new(0) }
        }
    }

    impl Lock for CountingLock {
        fn lock(&self) {
            self.locks.fetch_add(1, AtomicOrdering::SeqCst);
        }

        fn unlock(&self) {
            self.unlocks.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    #[test]
    fn lock_yields_same_elements() {
        let lock: Arc<dyn Lock> = Arc::new(CountingLock::new());
        let result: Vec<i32> = StreamUtils::lock(lock, vec![1, 2, 3].into_iter()).collect();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn lock_acquires_and_releases_for_each_element() {
        let counting = Arc::new(CountingLock::new());
        let lock: Arc<dyn Lock> = counting.clone();
        let result: Vec<i32> = StreamUtils::lock(lock, vec![1, 2].into_iter()).collect();
        assert_eq!(result, vec![1, 2]);
        // One lock/unlock per try_advance call, including the final exhausting call.
        assert_eq!(counting.locks.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(counting.unlocks.load(AtomicOrdering::SeqCst), 3);
    }
}
