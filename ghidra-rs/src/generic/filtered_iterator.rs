/// An iterator adapter that yields only elements matching a predicate.
///
/// Mirrors `generic.FilteredIterator` from Ghidra. The Java class implements both
/// `Iterator<T>` and `Iterable<T>` (returning `this` from `iterator()`); here
/// [`FilteredIterator`] implements [`Iterator`] and [`IntoIterator`] (returning
/// `self`), which is the idiomatic Rust equivalent.
pub struct FilteredIterator<I, F>
where
    I: Iterator,
    F: FnMut(&I::Item) -> bool,
{
    iter: I,
    filter: F,
}

impl<I, F> FilteredIterator<I, F>
where
    I: Iterator,
    F: FnMut(&I::Item) -> bool,
{
    /// Wraps `iter`, yielding only items for which `filter` returns `true`.
    pub fn new(iter: I, filter: F) -> Self {
        Self { iter, filter }
    }
}

impl<I, F> Iterator for FilteredIterator<I, F>
where
    I: Iterator,
    F: FnMut(&I::Item) -> bool,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.find(|item| (self.filter)(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filters_even_numbers() {
        let v = vec![1, 2, 3, 4, 5, 6];
        let fi = FilteredIterator::new(v.into_iter(), |x| x % 2 == 0);
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![2, 4, 6]);
    }

    #[test]
    fn test_filters_odd_numbers() {
        let v = vec![1, 2, 3, 4, 5];
        let fi = FilteredIterator::new(v.into_iter(), |x| x % 2 != 0);
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![1, 3, 5]);
    }

    #[test]
    fn test_all_filtered_out() {
        let v = vec![1, 3, 5];
        let fi = FilteredIterator::new(v.into_iter(), |x| x % 2 == 0);
        let result: Vec<i32> = fi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn test_none_filtered_out() {
        let v = vec![2, 4, 6];
        let fi = FilteredIterator::new(v.into_iter(), |x| x % 2 == 0);
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![2, 4, 6]);
    }

    #[test]
    fn test_empty_source_iterator() {
        let v: Vec<i32> = vec![];
        let fi = FilteredIterator::new(v.into_iter(), |_| true);
        let result: Vec<i32> = fi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn test_into_iterator() {
        let v = vec![1, 2, 3, 4];
        let fi = FilteredIterator::new(v.into_iter(), |x| *x > 2);
        let mut sum = 0;
        for x in fi {
            sum += x;
        }
        assert_eq!(sum, 7);
    }

    #[test]
    fn test_single_matching_element() {
        let v = vec![1, 2, 3];
        let fi = FilteredIterator::new(v.into_iter(), |x| *x == 2);
        let result: Vec<i32> = fi.collect();
        assert_eq!(result, vec![2]);
    }

    #[test]
    fn test_filter_strings() {
        let v = vec!["alpha", "beta", "gamma", "delta"];
        let fi = FilteredIterator::new(v.into_iter(), |s| s.starts_with('a') || s.starts_with('g'));
        let result: Vec<&str> = fi.collect();
        assert_eq!(result, vec!["alpha", "gamma"]);
    }
}
