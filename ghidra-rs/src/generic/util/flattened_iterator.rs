/// An iterator that flattens an outer iterator by applying a factory function to each element.
///
/// Given an "outer" iterator and a mapping from its elements to "inner" iterators, this is a
/// flattened iterator over elements from the inner iterators. The factory may return [`None`]
/// to skip an outer element (equivalent to returning `null` in Java).
///
/// Mirrors `generic.util.FlattenedIterator` from Ghidra.
pub struct FlattenedIterator<Outer, InnerIter, Factory>
where
    Outer: Iterator,
    InnerIter: Iterator,
    Factory: FnMut(Outer::Item) -> Option<InnerIter>,
{
    outer: Outer,
    inner_factory: Factory,
    inner: Option<InnerIter>,
}

impl<Outer, InnerIter, Factory> FlattenedIterator<Outer, InnerIter, Factory>
where
    Outer: Iterator,
    InnerIter: Iterator,
    Factory: FnMut(Outer::Item) -> Option<InnerIter>,
{
    /// Creates a flattened iterator.
    ///
    /// Iterates over each element of `outer` and applies `inner_factory` to produce an inner
    /// iterator. The returned iterator yields elements from the inner iterators as if
    /// concatenated — a flat-map over iterators. The factory may return [`None`] to skip an
    /// outer element.
    pub fn new(outer: Outer, inner_factory: Factory) -> Self {
        Self {
            outer,
            inner_factory,
            inner: None,
        }
    }
}

impl<Outer, InnerIter, Factory> Iterator for FlattenedIterator<Outer, InnerIter, Factory>
where
    Outer: Iterator,
    InnerIter: Iterator,
    Factory: FnMut(Outer::Item) -> Option<InnerIter>,
{
    type Item = InnerIter::Item;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut inner) = self.inner {
                if let Some(item) = inner.next() {
                    return Some(item);
                }
            }
            self.inner = None;
            let mut advanced = false;
            while let Some(outer_item) = self.outer.next() {
                if let Some(candidate) = (self.inner_factory)(outer_item) {
                    self.inner = Some(candidate);
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_flattening() {
        let outer = vec![vec![1, 2], vec![3, 4], vec![5]];
        let fi = FlattenedIterator::new(outer.into_iter(), |v| Some(v.into_iter()));
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn factory_returning_none_skips_outer_element() {
        let outer = vec![1u32, 2, 3, 4];
        let fi = FlattenedIterator::new(outer.into_iter(), |n| {
            if n % 2 == 0 {
                Some(vec![n * 10, n * 10 + 1].into_iter())
            } else {
                None
            }
        });
        let result: Vec<u32> = fi.collect();
        assert_eq!(result, vec![20, 21, 40, 41]);
    }

    #[test]
    fn empty_outer_iterator() {
        let outer: Vec<Vec<i32>> = vec![];
        let fi = FlattenedIterator::new(outer.into_iter(), |v| Some(v.into_iter()));
        let result: Vec<i32> = fi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn empty_inner_iterators_are_skipped() {
        let outer = vec![vec![], vec![1, 2], vec![], vec![3]];
        let fi = FlattenedIterator::new(outer.into_iter(), |v| Some(v.into_iter()));
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn all_factory_calls_return_none() {
        let outer = vec![1, 2, 3];
        let fi = FlattenedIterator::new(outer.into_iter(), |_| {
            None::<std::vec::IntoIter<i32>>
        });
        let result: Vec<i32> = fi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn single_outer_element() {
        let outer = vec![vec![42]];
        let fi = FlattenedIterator::new(outer.into_iter(), |v| Some(v.into_iter()));
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn mixed_none_and_some_factories() {
        let outer = vec!["skip", "keep", "skip", "keep"];
        let fi = FlattenedIterator::new(outer.into_iter(), |s| {
            if s == "keep" {
                Some(vec![s].into_iter())
            } else {
                None
            }
        });
        let result: Vec<&str> = fi.collect();
        assert_eq!(result, vec!["keep", "keep"]);
    }

    #[test]
    fn inner_iterators_of_varying_lengths() {
        let outer = vec![1usize, 2, 3];
        let fi = FlattenedIterator::new(outer.into_iter(), |n| {
            Some((0..n).collect::<Vec<_>>().into_iter())
        });
        let result: Vec<usize> = fi.collect();
        assert_eq!(result, vec![0, 0, 1, 0, 1, 2]);
    }

    #[test]
    fn empty_outer_never_invokes_factory() {
        let outer: Vec<i32> = vec![];
        let fi = FlattenedIterator::new(outer.into_iter(), |_| -> Option<std::vec::IntoIter<i32>> {
            panic!("factory should not be called for an empty outer iterator")
        });
        let result: Vec<i32> = fi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn first_empty_second_singleton() {
        let outer = vec![0, 1];
        let fi = FlattenedIterator::new(outer.into_iter(), |n| {
            Some(if n == 0 { vec![] } else { vec!["Test"] }.into_iter())
        });
        let result: Vec<&str> = fi.collect();
        assert_eq!(result, vec!["Test"]);
    }

    #[test]
    fn repeated_peek_calls_do_not_advance_state() {
        let outer = vec![0, 1];
        let mut fi = FlattenedIterator::new(outer.into_iter(), |n| {
            Some(if n == 0 { vec!["T1", "T2"] } else { vec!["T3", "T4"] }.into_iter())
        })
        .peekable();

        assert_eq!(fi.peek(), Some(&"T1"));
        assert_eq!(fi.peek(), Some(&"T1"));
        assert_eq!(fi.next(), Some("T1"));
        assert_eq!(fi.peek(), Some(&"T2"));
        assert_eq!(fi.next(), Some("T2"));
        assert_eq!(fi.peek(), Some(&"T3"));
        assert_eq!(fi.next(), Some("T3"));
        assert_eq!(fi.peek(), Some(&"T4"));
        assert_eq!(fi.next(), Some("T4"));
        assert_eq!(fi.peek(), None);
    }

    #[test]
    fn sequential_next_calls_without_peeking() {
        let outer = vec![0, 1];
        let mut fi = FlattenedIterator::new(outer.into_iter(), |n| {
            Some(if n == 0 { vec!["T1", "T2"] } else { vec!["T3", "T4"] }.into_iter())
        });
        assert_eq!(fi.next(), Some("T1"));
        assert_eq!(fi.next(), Some("T2"));
        assert_eq!(fi.next(), Some("T3"));
        assert_eq!(fi.next(), Some("T4"));
        assert_eq!(fi.next(), None);
        assert_eq!(fi.next(), None);
    }
}
