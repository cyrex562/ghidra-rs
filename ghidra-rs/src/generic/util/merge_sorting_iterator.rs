use std::cmp::Ordering;

use super::peekable_iterator::PeekableIterator;

/// One source iterator being merged, together with its buffered ("peeked") next value.
///
/// Java's `MergeSortingIterator` stores its sources in a `PriorityQueue<PeekableIterator<? extends
/// T>>` ordered by `PeekableIterator::peek`, which lets the JVM re-heapify in `O(log n)` whenever
/// an iterator's peeked value changes. [`PeekableIterator::peek`] in this crate takes `&mut self`
/// (see `peekable_iterator.rs`), so two entries' peeked values can't be borrowed simultaneously to
/// feed a heap comparator without aliasing. Buffering the peeked value here as a plain owned `T`
/// sidesteps that: comparisons only ever need shared (`&self`) access to already-buffered values,
/// at the cost of a linear scan per `next()`/`peek()` call instead of a logarithmic one. For a
/// utility class with no documented hot-path use (its own javadoc says the labeled-merge variant
/// exists mainly for tests), that trade is a non-issue.
struct BufferedIter<T> {
    it: Box<dyn Iterator<Item = T>>,
    buffered: Option<T>,
}

impl<T> BufferedIter<T> {
    /// Wraps `it`, priming the buffer with its first value. Returns `None` if `it` is already
    /// empty, mirroring the constructor's `if (it.hasNext()) { queue.add(...) }` guard -- an
    /// iterator that starts empty is never tracked at all.
    fn new(mut it: Box<dyn Iterator<Item = T>>) -> Option<Self> {
        let first = it.next()?;
        Some(Self {
            it,
            buffered: Some(first),
        })
    }

    fn has_value(&self) -> bool {
        self.buffered.is_some()
    }

    /// Takes the buffered value and refills the buffer from the underlying iterator.
    fn advance(&mut self) -> T {
        let value = self
            .buffered
            .take()
            .expect("advance() called on an exhausted BufferedIter");
        self.buffered = self.it.next();
        value
    }
}

/// An iterator which merges sorted iterators according to a comparator.
///
/// Port of `generic.util.MergeSortingIterator<T>`.
///
/// Ties (two sources whose buffered values compare equal) are broken deterministically in favor
/// of whichever source was registered first. Java's `PriorityQueue` gives no such guarantee --
/// tie order there depends on heap layout/insertion history -- so this is a (harmless, since the
/// values are equal under the comparator) behavioral narrowing rather than a preserved quirk.
pub struct MergeSortingIterator<T> {
    comparator: Box<dyn Fn(&T, &T) -> Ordering>,
    entries: Vec<BufferedIter<T>>,
}

impl<T> MergeSortingIterator<T> {
    /// Construct a merge sorting iterator.
    ///
    /// `iterators` is a collection of iterators to merge; `comparator` defines how the input and
    /// output iterators are sorted. Each source iterator must already yield values in
    /// `comparator` order.
    ///
    /// Port of `MergeSortingIterator(Iterable<? extends Iterator<? extends T>>, Comparator<?
    /// super T>)`.
    pub fn new<I, C>(iterators: I, comparator: C) -> Self
    where
        I: IntoIterator<Item = Box<dyn Iterator<Item = T>>>,
        C: Fn(&T, &T) -> Ordering + 'static,
    {
        let entries = iterators.into_iter().filter_map(BufferedIter::new).collect();
        Self {
            comparator: Box::new(comparator),
            entries,
        }
    }

    /// Index of the entry whose buffered value sorts first, or `None` if every source is
    /// exhausted.
    fn min_index(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.has_value() {
                continue;
            }
            best = match best {
                None => Some(i),
                Some(b) => {
                    let ord = (self.comparator)(
                        entry.buffered.as_ref().unwrap(),
                        self.entries[b].buffered.as_ref().unwrap(),
                    );
                    if ord == Ordering::Less {
                        Some(i)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        best
    }
}

impl<T> Iterator for MergeSortingIterator<T> {
    type Item = T;

    /// Port of `MergeSortingIterator.next()`.
    fn next(&mut self) -> Option<T> {
        let idx = self.min_index()?;
        let value = self.entries[idx].advance();
        if !self.entries[idx].has_value() {
            self.entries.remove(idx);
        }
        Some(value)
    }
}

impl<T> PeekableIterator for MergeSortingIterator<T> {
    /// Port of `MergeSortingIterator.peek()`.
    ///
    /// Java's implementation is `queue.peek().peek()`: `PriorityQueue.peek()` returns `null`
    /// (not an exception) when the queue is empty, so calling `.peek()` on that `null` actually
    /// throws `NullPointerException` at runtime -- not the `NoSuchElementException` the method
    /// signature advertises. This port doesn't reproduce that crash: like every other
    /// `PeekableIterator` implementor in this crate (see `peekable_iterator.rs`), an exhausted
    /// iterator's `peek()` returns `None` rather than panicking.
    fn peek(&mut self) -> Option<&T> {
        let idx = self.min_index()?;
        self.entries[idx].buffered.as_ref()
    }
}

/// Construct a merge-sorting iterator which generates labeled values.
///
/// The map of iterators is a map of `(label, iterator)` pairs to be merged. Each iterator must
/// return values sorted by `comparator`. The combined iterator yields `(label, value)` pairs in
/// sorted-by-value order, with the label identifying which source iterator produced the value.
///
/// Port of `MergeSortingIterator.withLabels(Map<L, ? extends Iterator<? extends T>>,
/// Comparator<T>)`. Java's `LabeledIterator` reuses a single mutable `Entry` object per source,
/// writing the label once and overwriting only the `value` field on every `next()`/`peek()` call
/// -- an aliasing trick unavailable in Rust, where each emitted `(L, T)` pair must be a fresh,
/// independently owned value. Hence the `L: Clone` bound below: the label is cloned once per item
/// emitted from its source, rather than reused by reference.
pub fn with_labels<L, T, C>(
    iter_map: Vec<(L, Box<dyn Iterator<Item = T>>)>,
    comparator: C,
) -> MergeSortingIterator<(L, T)>
where
    L: Clone + 'static,
    T: 'static,
    C: Fn(&T, &T) -> Ordering + 'static,
{
    let iterators: Vec<Box<dyn Iterator<Item = (L, T)>>> = iter_map
        .into_iter()
        .map(|(label, it)| -> Box<dyn Iterator<Item = (L, T)>> {
            Box::new(it.map(move |value| (label.clone(), value)))
        })
        .collect();

    MergeSortingIterator::new(iterators, move |a: &(L, T), b: &(L, T)| comparator(&a.1, &b.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(v: Vec<i32>) -> Box<dyn Iterator<Item = i32>> {
        Box::new(v.into_iter())
    }

    #[test]
    fn merges_two_sorted_sources_in_order() {
        let mut it = MergeSortingIterator::new(
            vec![boxed(vec![1, 3, 5]), boxed(vec![2, 4, 6])],
            |a: &i32, b: &i32| a.cmp(b),
        );
        let merged: Vec<i32> = it.by_ref().collect();
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn empty_source_iterators_are_skipped() {
        let mut it = MergeSortingIterator::new(
            vec![boxed(vec![]), boxed(vec![1, 2]), boxed(vec![])],
            |a: &i32, b: &i32| a.cmp(b),
        );
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(2));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn no_sources_yields_nothing() {
        let mut it: MergeSortingIterator<i32> =
            MergeSortingIterator::new(Vec::new(), |a: &i32, b: &i32| a.cmp(b));
        assert_eq!(it.next(), None);
        assert_eq!(PeekableIterator::peek(&mut it), None);
    }

    #[test]
    fn peek_does_not_advance() {
        let mut it = MergeSortingIterator::new(vec![boxed(vec![10, 20])], |a: &i32, b: &i32| a.cmp(b));
        assert_eq!(PeekableIterator::peek(&mut it), Some(&10));
        assert_eq!(PeekableIterator::peek(&mut it), Some(&10));
        assert_eq!(it.next(), Some(10));
        assert_eq!(PeekableIterator::peek(&mut it), Some(&20));
    }

    #[test]
    fn peek_on_exhausted_iterator_is_none() {
        let mut it = MergeSortingIterator::new(vec![boxed(vec![1])], |a: &i32, b: &i32| a.cmp(b));
        assert_eq!(it.next(), Some(1));
        assert_eq!(PeekableIterator::peek(&mut it), None);
    }

    #[test]
    fn reverse_comparator_merges_descending_sources() {
        let mut it = MergeSortingIterator::new(
            vec![boxed(vec![5, 3, 1]), boxed(vec![6, 4, 2])],
            |a: &i32, b: &i32| b.cmp(a),
        );
        let merged: Vec<i32> = it.by_ref().collect();
        assert_eq!(merged, vec![6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn with_labels_tags_each_value_with_its_source() {
        let map: Vec<(&str, Box<dyn Iterator<Item = i32>>)> =
            vec![("a", boxed(vec![1, 4])), ("b", boxed(vec![2, 3]))];
        let merged: Vec<(&str, i32)> = with_labels(map, |x: &i32, y: &i32| x.cmp(y)).collect();
        assert_eq!(merged, vec![("a", 1), ("b", 2), ("b", 3), ("a", 4)]);
    }

    #[test]
    fn with_labels_on_single_source_reuses_its_label_for_every_value() {
        let map: Vec<(String, Box<dyn Iterator<Item = i32>>)> =
            vec![("only".to_string(), boxed(vec![1, 2, 3]))];
        let merged: Vec<(String, i32)> = with_labels(map, |x: &i32, y: &i32| x.cmp(y)).collect();
        assert_eq!(
            merged,
            vec![
                ("only".to_string(), 1),
                ("only".to_string(), 2),
                ("only".to_string(), 3),
            ]
        );
    }

    #[test]
    fn ties_break_toward_earlier_registered_source() {
        // Both sources yield an initial `1`; per the doc comment above, the first-registered
        // source (index 0) should win the tie deterministically.
        let map: Vec<(&str, Box<dyn Iterator<Item = i32>>)> =
            vec![("first", boxed(vec![1])), ("second", boxed(vec![1]))];
        let merged: Vec<(&str, i32)> = with_labels(map, |x: &i32, y: &i32| x.cmp(y)).collect();
        assert_eq!(merged[0], ("first", 1));
    }
}
