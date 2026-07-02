use std::cmp::Ordering;

use super::peekable_iterator::PeekableIterator;

/// An iterator that merges one or more sorted [`PeekableIterator`]s into a single
/// sorted stream.
///
/// Each source iterator must already yield items in sorted order (ascending, unless
/// `forward` is `false`). Items are compared either by their natural [`Ord`] via
/// [`MultiIterator::with_ord`], or by a supplied comparator via [`MultiIterator::new`].
///
/// Duplicate items across iterators are preserved: this class performs no de-duplication,
/// matching the Java original.
///
/// Mirrors `generic.util.MultiIterator` from Ghidra. The Java class implements
/// `java.util.Iterator<T>`, throwing `AssertException` from `next()` when called past
/// exhaustion and `UnsupportedOperationException` from `remove()`; the idiomatic Rust
/// equivalent implements [`Iterator`], returning `None` on exhaustion and omitting
/// `remove` (the standard [`Iterator`] trait has no such method).
pub struct MultiIterator<T> {
    iterators: Vec<Box<dyn PeekableIterator<Item = T>>>,
    comparator: Box<dyn Fn(&T, &T) -> Ordering>,
}

impl<T: 'static> MultiIterator<T> {
    /// Creates a `MultiIterator` from iterators whose items are not naturally
    /// comparable (i.e. do not implement [`Ord`]), using `comparator` to find the
    /// next item.
    ///
    /// `forward` is `true` if the source iterators yield items in ascending order,
    /// `false` if descending.
    ///
    /// Mirrors the Java constructor `MultiIterator(List<PeekableIterator<T>>,
    /// Comparator<T>, boolean)`.
    pub fn new<C>(
        iterators: Vec<Box<dyn PeekableIterator<Item = T>>>,
        comparator: C,
        forward: bool,
    ) -> Self
    where
        C: Fn(&T, &T) -> Ordering + 'static,
    {
        let comparator: Box<dyn Fn(&T, &T) -> Ordering> = if forward {
            Box::new(comparator)
        } else {
            Box::new(move |a: &T, b: &T| comparator(a, b).reverse())
        };
        Self { iterators, comparator }
    }

    /// Creates a `MultiIterator` from iterators whose items are naturally comparable.
    ///
    /// `forward` is `true` if the source iterators yield items in ascending order,
    /// `false` if descending.
    ///
    /// Mirrors the Java constructor `MultiIterator(List<PeekableIterator<T>>, boolean)`,
    /// which uses an internal `TComparator` delegating to `Comparable.compareTo`.
    pub fn with_ord(iterators: Vec<Box<dyn PeekableIterator<Item = T>>>, forward: bool) -> Self
    where
        T: Ord,
    {
        Self::new(iterators, |a: &T, b: &T| a.cmp(b), forward)
    }

    /// Compares the peeked items of the iterators at `i` and `j`, both of which must
    /// currently have a peekable item.
    fn compare_peeked(&mut self, i: usize, j: usize) -> Ordering {
        let (lo, hi) = if i < j { (i, j) } else { (j, i) };
        let (left, right) = self.iterators.split_at_mut(hi);
        let lo_item = left[lo]
            .peek()
            .expect("compare_peeked requires a peeked item");
        let hi_item = right[0]
            .peek()
            .expect("compare_peeked requires a peeked item");
        if i < j {
            (self.comparator)(lo_item, hi_item)
        } else {
            (self.comparator)(hi_item, lo_item)
        }
    }
}

impl<T: 'static> Iterator for MultiIterator<T> {
    type Item = T;

    /// Returns the next item in sorted order across all source iterators, advancing
    /// only the iterator that produced it, or `None` once every source iterator is
    /// exhausted.
    ///
    /// When multiple iterators peek an equal item, the first (by index) is advanced,
    /// matching the Java original's tie-breaking behavior.
    fn next(&mut self) -> Option<T> {
        let mut lowest: Option<usize> = None;
        for i in 0..self.iterators.len() {
            if self.iterators[i].peek().is_none() {
                continue;
            }
            lowest = match lowest {
                None => Some(i),
                Some(best) => {
                    if self.compare_peeked(best, i) == Ordering::Greater {
                        Some(i)
                    } else {
                        Some(best)
                    }
                }
            };
        }

        let lowest = lowest?;
        self.iterators[lowest].next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(v: Vec<i32>) -> Box<dyn PeekableIterator<Item = i32>> {
        Box::new(v.into_iter().peekable())
    }

    #[test]
    fn merges_two_sorted_iterators() {
        let mi = MultiIterator::with_ord(vec![boxed(vec![1, 3, 5]), boxed(vec![2, 4, 6])], true);
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn merges_three_sorted_iterators() {
        let mi = MultiIterator::with_ord(
            vec![boxed(vec![1, 4]), boxed(vec![2, 5]), boxed(vec![3, 6])],
            true,
        );
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn preserves_duplicate_items() {
        let mi = MultiIterator::with_ord(vec![boxed(vec![1, 2, 2]), boxed(vec![2, 3])], true);
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 2, 2, 2, 3]);
    }

    #[test]
    fn ties_advance_earliest_iterator_first() {
        // Both iterators peek `1` first; the earlier index (0) must be the one advanced,
        // which is only observable because it leaves iterator 0 with `10` remaining
        // while iterator 1 still has `1`.
        let mi = MultiIterator::with_ord(vec![boxed(vec![1, 10]), boxed(vec![1])], true);
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 1, 10]);
    }

    #[test]
    fn empty_iterators_are_skipped() {
        let mi = MultiIterator::with_ord(vec![boxed(vec![]), boxed(vec![1, 2]), boxed(vec![])], true);
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 2]);
    }

    #[test]
    fn no_iterators_yields_nothing() {
        let mi: MultiIterator<i32> = MultiIterator::with_ord(vec![], true);
        let result: Vec<i32> = mi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn all_empty_iterators_yield_nothing() {
        let mi = MultiIterator::with_ord(vec![boxed(vec![]), boxed(vec![])], true);
        let result: Vec<i32> = mi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn reverse_order_with_natural_ord() {
        let mi = MultiIterator::with_ord(
            vec![boxed(vec![5, 3, 1]), boxed(vec![6, 4, 2])],
            false,
        );
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn custom_comparator_forward() {
        // Compare by absolute distance from 10, both streams sorted accordingly.
        let mi = MultiIterator::new(
            vec![boxed(vec![10, 9, 7]), boxed(vec![11, 13])],
            |a: &i32, b: &i32| (a - 10).abs().cmp(&(b - 10).abs()),
            true,
        );
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![10, 9, 11, 7, 13]);
    }

    #[test]
    fn custom_comparator_reversed() {
        let mi = MultiIterator::new(
            vec![boxed(vec![1, 2, 3])],
            |a: &i32, b: &i32| a.cmp(b),
            false,
        );
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn iterator_is_fused_after_exhaustion() {
        let mut mi = MultiIterator::with_ord(vec![boxed(vec![1])], true);
        assert_eq!(mi.next(), Some(1));
        assert_eq!(mi.next(), None);
        assert_eq!(mi.next(), None);
    }

    #[test]
    fn single_iterator_passthrough() {
        let mi = MultiIterator::with_ord(vec![boxed(vec![3, 1, 4, 1, 5])], true);
        let result: Vec<i32> = mi.collect();
        assert_eq!(result, vec![3, 1, 4, 1, 5]);
    }
}
