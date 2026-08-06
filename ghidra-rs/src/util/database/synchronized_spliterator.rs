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

/// `SynchronizedSpliterator` (Java: `ghidra.util.database.SynchronizedSpliterator`) is
/// deliberately absent.
///
/// The Java class wraps a spliterator and runs every operation inside `synchronized (lock)` on
/// a caller-supplied intrinsic monitor, with splits sharing that monitor. Ported literally it
/// became a struct holding `Arc<Mutex<()>>` -- a lock over no data -- around an inner
/// spliterator it owns by value, so it serialized callers without protecting anything the
/// borrow checker did not already protect. Its `try_split` hands out *disjoint* owned halves,
/// so even the split case shares no state to guard.
///
/// A caller that genuinely needs to serialize access to a resource should hold that lock
/// itself for the duration of its use of the stream (which the Java doc already recommended
/// for any consistency guarantee), or put the resource behind the lock -- see the "Ported Java
/// locks" convention in `OWNERSHIP_MIGRATION.md`.
///
/// [`DBSynchronizedSpliterator`](super::db_synchronized_spliterator::DBSynchronizedSpliterator)
/// is unaffected: it takes `Arc<dyn Lock>`, the crate's real lock abstraction, whose
/// acquire/release contract is pinned by its own tests.

#[cfg(test)]
mod tests {
    use super::{characteristics, Spliterator};

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

    fn make(data: Vec<i32>) -> VecSpliterator<i32> {
        VecSpliterator::new(data)
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
    fn estimate_size_decreases_as_consumed() {
        let mut s = make(vec![1, 2, 3]);
        assert_eq!(s.estimate_size(), 3);
        s.try_advance();
        assert_eq!(s.estimate_size(), 2);
    }

    #[test]
    fn characteristics_are_forwarded() {
        let s = make(vec![1, 2]);
        assert_eq!(
            s.characteristics(),
            characteristics::ORDERED | characteristics::SIZED | characteristics::SUBSIZED
        );
    }

    #[test]
    fn try_split_divides_elements() {
        let mut s = make(vec![1, 2, 3, 4]);
        let mut left = s.try_split().expect("splittable");
        let mut got_left = vec![];
        while let Some(x) = left.try_advance() {
            got_left.push(x);
        }
        let mut got_right = vec![];
        while let Some(x) = s.try_advance() {
            got_right.push(x);
        }
        assert_eq!(got_left, vec![1, 2]);
        assert_eq!(got_right, vec![3, 4]);
    }

    #[test]
    fn try_split_none_when_too_small() {
        let mut s = make(vec![1]);
        assert!(s.try_split().is_none());
    }

    #[test]
    fn try_split_none_on_empty() {
        let mut s = make(vec![]);
        assert!(s.try_split().is_none());
    }

    /// The splits own disjoint halves -- the fact that made the removed wrapper's shared
    /// `Mutex<()>` guard nothing: there is no shared state for a lock to protect.
    ///
    /// Note this cannot be demonstrated across threads: `try_split` returns
    /// `Box<dyn Spliterator<Item = T>>` with no `Send` bound, so a split cannot be moved to
    /// another thread at all. The parallel decomposition that `java.util.Spliterator` exists
    /// for is therefore not expressible in this port as it stands -- which is a further reason
    /// the synchronization wrapper protected nothing: nothing could run in parallel.
    #[test]
    fn splits_own_disjoint_halves() {
        let mut s = make(vec![1, 2, 3, 4]);
        let mut left = s.try_split().expect("splittable");

        let mut got_left = vec![];
        while let Some(x) = left.try_advance() {
            got_left.push(x);
        }
        let mut got_right = vec![];
        while let Some(x) = s.try_advance() {
            got_right.push(x);
        }

        assert_eq!(got_left, vec![1, 2]);
        assert_eq!(got_right, vec![3, 4]);
    }
}
