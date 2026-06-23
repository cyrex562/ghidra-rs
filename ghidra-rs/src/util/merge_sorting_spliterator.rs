use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;

struct HeapEntry<T> {
    value: T,
    iter: Box<dyn Iterator<Item = T>>,
    comparator: Arc<dyn Fn(&T, &T) -> Ordering>,
}

impl<T> PartialEq for HeapEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        (self.comparator)(&self.value, &other.value) == Ordering::Equal
    }
}

impl<T> Eq for HeapEntry<T> {}

impl<T> PartialOrd for HeapEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for HeapEntry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so BinaryHeap (max-heap) behaves as a min-heap.
        (self.comparator)(&other.value, &self.value)
    }
}

/// An iterator that merges multiple sorted iterators into a single sorted output.
///
/// Given `n` iterators each sorted by `comparator`, yields all elements in globally
/// sorted order. Uses a min-heap for O(log n) per element.
///
/// Port of `ghidra.util.MergeSortingSpliterator`.
pub struct MergeSortingIterator<T> {
    comparator: Arc<dyn Fn(&T, &T) -> Ordering>,
    queue: BinaryHeap<HeapEntry<T>>,
}

impl<T> MergeSortingIterator<T> {
    /// Creates a new `MergeSortingIterator` from sorted iterators and a comparator.
    ///
    /// Each iterator in `iterators` must already be sorted according to `comparator`.
    /// Empty iterators are silently skipped.
    pub fn new<I, C>(iterators: impl IntoIterator<Item = I>, comparator: C) -> Self
    where
        I: Iterator<Item = T> + 'static,
        C: Fn(&T, &T) -> Ordering + 'static,
    {
        let comparator: Arc<dyn Fn(&T, &T) -> Ordering> = Arc::new(comparator);
        let mut queue = BinaryHeap::new();
        for iter in iterators {
            let mut iter: Box<dyn Iterator<Item = T>> = Box::new(iter);
            if let Some(value) = iter.next() {
                queue.push(HeapEntry {
                    value,
                    iter,
                    comparator: Arc::clone(&comparator),
                });
            }
        }
        Self { comparator, queue }
    }

    /// Returns the comparator used to order elements.
    pub fn comparator(&self) -> &dyn Fn(&T, &T) -> Ordering {
        &*self.comparator
    }
}

impl<T> Iterator for MergeSortingIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        let HeapEntry { value, mut iter, comparator } = self.queue.pop()?;
        if let Some(next) = iter.next() {
            self.queue.push(HeapEntry { value: next, iter, comparator });
        }
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Each queue entry holds one buffered element plus the iterator's remaining elements.
        let buffered = self.queue.len();
        let mut lower = buffered;
        let mut upper: Option<usize> = Some(buffered);
        for entry in &self.queue {
            let (l, u) = entry.iter.size_hint();
            lower = lower.saturating_add(l);
            upper = upper.and_then(|ub| u.and_then(|eu| ub.checked_add(eu)));
        }
        (lower, upper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp_i32(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    fn merge(iters: Vec<Vec<i32>>) -> Vec<i32> {
        MergeSortingIterator::new(iters.into_iter().map(|v| v.into_iter()), cmp_i32).collect()
    }

    #[test]
    fn merges_two_sorted_lists() {
        assert_eq!(merge(vec![vec![1, 3, 5], vec![2, 4, 6]]), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn merges_three_sorted_lists() {
        assert_eq!(
            merge(vec![vec![1, 4], vec![2, 5], vec![3, 6]]),
            vec![1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn handles_empty_iterators() {
        assert_eq!(merge(vec![vec![], vec![1, 2], vec![]]), vec![1, 2]);
    }

    #[test]
    fn handles_all_empty_iterators() {
        assert_eq!(merge(vec![vec![], vec![]]), Vec::<i32>::new());
    }

    #[test]
    fn handles_no_iterators() {
        assert_eq!(merge(vec![]), Vec::<i32>::new());
    }

    #[test]
    fn handles_single_iterator() {
        assert_eq!(merge(vec![vec![3, 1, 4, 1, 5]]), vec![3, 1, 4, 1, 5]);
    }

    #[test]
    fn handles_duplicate_elements() {
        assert_eq!(
            merge(vec![vec![1, 2, 2], vec![2, 3]]),
            vec![1, 2, 2, 2, 3]
        );
    }

    #[test]
    fn handles_unequal_length_lists() {
        assert_eq!(merge(vec![vec![1], vec![2, 3, 4, 5]]), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn size_hint_reflects_total_elements() {
        let iter = MergeSortingIterator::new(
            vec![vec![1, 2, 3], vec![4, 5]].into_iter().map(|v| v.into_iter()),
            cmp_i32,
        );
        let (lower, upper) = iter.size_hint();
        // Two buffered + (2 remaining in first + 1 remaining in second)
        assert_eq!(lower, 5);
        assert_eq!(upper, Some(5));
    }

    #[test]
    fn size_hint_decreases_as_elements_consumed() {
        let mut iter = MergeSortingIterator::new(
            vec![vec![1, 2], vec![3, 4]].into_iter().map(|v| v.into_iter()),
            cmp_i32,
        );
        assert_eq!(iter.size_hint().0, 4);
        iter.next();
        assert_eq!(iter.size_hint().0, 3);
        iter.next();
        assert_eq!(iter.size_hint().0, 2);
    }

    #[test]
    fn custom_reverse_comparator() {
        let result: Vec<i32> = MergeSortingIterator::new(
            vec![vec![5, 3, 1], vec![6, 4, 2]].into_iter().map(|v| v.into_iter()),
            |a: &i32, b: &i32| b.cmp(a),
        )
        .collect();
        assert_eq!(result, vec![6, 5, 4, 3, 2, 1]);
    }
}
