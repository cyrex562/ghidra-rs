use std::collections::HashSet;
use std::hash::Hash;

/// A read-only collection backed by a lazy iterator factory.
///
/// Each accessor invokes the factory to produce a fresh iterator; no elements are stored.
/// Mutating operations (`add`, `remove`, etc.) are not supported.
///
/// Port of `ghidra.util.LazyCollection`.
pub struct LazyCollection<T> {
    factory: Box<dyn Fn() -> Box<dyn Iterator<Item = T>>>,
}

impl<T> LazyCollection<T> {
    /// Creates a `LazyCollection` backed by `factory`.
    ///
    /// `factory` is called once per operation; results are not cached.
    pub fn new<F, I>(factory: F) -> Self
    where
        F: Fn() -> I + 'static,
        I: Iterator<Item = T> + 'static,
    {
        Self {
            factory: Box::new(move || Box::new(factory())),
        }
    }

    fn make_iter(&self) -> Box<dyn Iterator<Item = T>> {
        (self.factory)()
    }

    /// Returns the number of elements by exhausting the iterator.
    pub fn len(&self) -> usize {
        self.make_iter().count()
    }

    /// Returns `true` if the collection yields no elements.
    pub fn is_empty(&self) -> bool {
        self.make_iter().next().is_none()
    }

    /// Returns an iterator over the elements.
    pub fn iter(&self) -> Box<dyn Iterator<Item = T>> {
        self.make_iter()
    }

    /// Returns `true` if the collection contains `item`.
    pub fn contains(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.make_iter().any(|e| &e == item)
    }

    /// Returns `true` if the collection contains every element in `items`.
    ///
    /// Short-circuits once all required elements have been matched. Returns `true` when
    /// `items` is empty, matching `Collection.containsAll` semantics.
    pub fn contains_all<'a>(&self, items: impl IntoIterator<Item = &'a T>) -> bool
    where
        T: Eq + Hash + 'a,
    {
        let mut remains: HashSet<&'a T> = items.into_iter().collect();
        if remains.is_empty() {
            return true;
        }
        for e in self.make_iter() {
            remains.remove(&e);
            if remains.is_empty() {
                return true;
            }
        }
        false
    }
}

impl<T: 'static> IntoIterator for LazyCollection<T> {
    type Item = T;
    type IntoIter = Box<dyn Iterator<Item = T>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.factory)()
    }
}

impl<'c, T: 'c> IntoIterator for &'c LazyCollection<T> {
    type Item = T;
    type IntoIter = Box<dyn Iterator<Item = T> + 'c>;

    fn into_iter(self) -> Self::IntoIter {
        (self.factory)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_range(start: i32, end: i32) -> LazyCollection<i32> {
        LazyCollection::new(move || start..end)
    }

    #[test]
    fn len_counts_elements() {
        assert_eq!(make_range(1, 6).len(), 5);
    }

    #[test]
    fn len_empty_range() {
        assert_eq!(make_range(0, 0).len(), 0);
    }

    #[test]
    fn is_empty_true_for_empty_range() {
        assert!(make_range(5, 5).is_empty());
    }

    #[test]
    fn is_empty_false_for_nonempty_range() {
        assert!(!make_range(0, 3).is_empty());
    }

    #[test]
    fn iter_yields_all_elements() {
        let values: Vec<i32> = make_range(1, 4).iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn iter_can_be_called_multiple_times() {
        let c = make_range(0, 3);
        let first: Vec<_> = c.iter().collect();
        let second: Vec<_> = c.iter().collect();
        assert_eq!(first, second);
    }

    #[test]
    fn contains_finds_present_element() {
        assert!(make_range(0, 5).contains(&3));
    }

    #[test]
    fn contains_returns_false_for_absent_element() {
        assert!(!make_range(0, 5).contains(&10));
    }

    #[test]
    fn contains_all_returns_true_when_all_present() {
        assert!(make_range(0, 10).contains_all([1, 3, 7].iter()));
    }

    #[test]
    fn contains_all_returns_false_when_some_missing() {
        assert!(!make_range(0, 5).contains_all([1, 3, 10].iter()));
    }

    #[test]
    fn contains_all_empty_items_returns_true() {
        assert!(make_range(0, 5).contains_all(std::iter::empty::<&i32>()));
    }

    #[test]
    fn contains_all_on_empty_collection_returns_false_for_nonempty_items() {
        assert!(!make_range(0, 0).contains_all([1].iter()));
    }

    #[test]
    fn into_iter_consumes_collection() {
        let values: Vec<i32> = make_range(1, 4).into_iter().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn for_loop_over_reference() {
        let c = make_range(0, 3);
        let mut sum = 0;
        for v in &c {
            sum += v;
        }
        assert_eq!(sum, 3); // 0+1+2
    }

    #[test]
    fn factory_called_per_operation() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let c: LazyCollection<i32> = LazyCollection::new(move || {
            cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            0..3
        });
        let _ = c.len();
        let _ = c.is_empty();
        let _ = c.iter().count();
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}
