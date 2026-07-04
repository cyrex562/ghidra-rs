use std::collections::HashSet;
use std::hash::Hash;

use crate::util::task::{CancellableIterator, TaskMonitor};

/// A collection of utility functions that avoid unsafe casts of collections, mirroring
/// Ghidra's `util.CollectionUtils`.
///
/// Many of the original Java overloads existed only to work around type erasure (separate
/// methods for arrays, `Collection`, `Iterator`, and `Iterable`, plus checked-cast helpers).
/// Rust's `IntoIterator` and static generics collapse most of those into a single function,
/// and the checked-cast helpers (`asList(List, Class)`, `asCollection(Collection, Class)`,
/// `isAllSameType`) have no equivalent since a `Vec<T>` is already guaranteed homogeneous.
///
/// Port of `util.CollectionUtils`.
pub struct CollectionUtils;

impl CollectionUtils {
    /// Turns the given items into a `HashSet`.
    ///
    /// Accepts anything iterable (arrays, `Vec`, `HashSet`, iterators), replacing the
    /// Java overloads for varargs, `Collection`, `Iterator`, and `Iterable`.
    pub fn as_set<T, I>(items: I) -> HashSet<T>
    where
        T: Eq + Hash,
        I: IntoIterator<Item = T>,
    {
        items.into_iter().collect()
    }

    /// Turns the given items into a `Vec`.
    ///
    /// Accepts anything iterable, replacing the Java overloads for varargs, `List`,
    /// `Collection`, `Iterable`, and `Iterator`.
    pub fn as_list<T, I>(items: I) -> Vec<T>
    where
        I: IntoIterator<Item = T>,
    {
        items.into_iter().collect()
    }

    /// Returns `value` if present, otherwise the type's default.
    ///
    /// Mirrors `nonNull(Collection)` and `asCollection(Collection)`, which return an empty
    /// collection instead of `null`; `Option::None` is Rust's equivalent of Java `null` here.
    pub fn non_null<T: Default>(value: Option<T>) -> T {
        value.unwrap_or_default()
    }

    /// Returns `true` if `t` equals one of `possibles`.
    pub fn is_one_of<T: PartialEq>(t: &T, possibles: &[T]) -> bool {
        possibles.iter().any(|possible| possible == t)
    }

    /// Returns `true` if every item is `None`. An empty input is considered all-`None`.
    ///
    /// Mirrors `isAllNull(Object...)` / `isAllNull(Collection)`; `Option` stands in for
    /// Java's nullable element type.
    pub fn is_all_none<T, I>(items: I) -> bool
    where
        I: IntoIterator<Item = Option<T>>,
    {
        items.into_iter().all(|t| t.is_none())
    }

    /// Returns `true` if `items` is absent or empty.
    ///
    /// Mirrors `isBlank(Collection)` / `isBlank(T...)`; `None` stands in for Java's null
    /// array/collection reference.
    pub fn is_blank<T>(items: Option<&[T]>) -> bool {
        items.map_or(true, |s| s.is_empty())
    }

    /// Wraps a single item as a one-element iterable.
    pub fn as_iterable_once<T>(t: T) -> std::iter::Once<T> {
        std::iter::once(t)
    }

    /// Combines multiple iterables into a single pass-through iterator, without copying
    /// their elements into a new collection.
    ///
    /// Replaces both `asIterable(Iterable...)` and `asStream(Iterable...)`, which are
    /// distinct in Java but identical in Rust since `Iterator` already serves as both.
    pub fn combine_iterables<T: 'static>(
        iterables: Vec<Box<dyn Iterator<Item = T>>>,
    ) -> Box<dyn Iterator<Item = T>> {
        Box::new(iterables.into_iter().flatten())
    }

    /// Combines multiple iterables into a single iterator that stops once `monitor` reports
    /// cancellation.
    ///
    /// Port of `asCancellableIterable(TaskMonitor, Iterable...)`.
    pub fn combine_cancellable_iterables<T: 'static>(
        monitor: Box<dyn TaskMonitor>,
        iterables: Vec<Box<dyn Iterator<Item = T>>>,
    ) -> CancellableIterator<T> {
        CancellableIterator::new(Self::combine_iterables(iterables), monitor)
    }

    /// Returns an element from `iterable`; `None` if it is empty.
    ///
    /// Mirrors `any(Collection)` / `any(Iterable)`.
    pub fn any<T, I: IntoIterator<Item = T>>(iterable: I) -> Option<T> {
        iterable.into_iter().next()
    }

    /// Returns the only element in `items`; `None` if it is empty or has more than one
    /// element.
    pub fn get<T, I>(items: I) -> Option<T>
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut it = items.into_iter();
        if it.len() != 1 {
            return None;
        }
        it.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockTaskMonitor {
        cancelled: Arc<AtomicBool>,
    }

    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }

    // --- as_set ---

    #[test]
    fn as_set_from_array() {
        let set = CollectionUtils::as_set([1, 2, 2, 3]);
        assert_eq!(set, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn as_set_from_empty_vec() {
        let set: HashSet<i32> = CollectionUtils::as_set(Vec::new());
        assert!(set.is_empty());
    }

    #[test]
    fn as_set_from_iterator() {
        let set = CollectionUtils::as_set(vec![1, 2, 3].into_iter().filter(|n| *n > 1));
        assert_eq!(set, HashSet::from([2, 3]));
    }

    // --- as_list ---

    #[test]
    fn as_list_from_array() {
        let list = CollectionUtils::as_list([1, 2, 3]);
        assert_eq!(list, vec![1, 2, 3]);
    }

    #[test]
    fn as_list_from_empty() {
        let list: Vec<i32> = CollectionUtils::as_list(Vec::new());
        assert!(list.is_empty());
    }

    #[test]
    fn as_list_from_set() {
        let set = HashSet::from([42]);
        let list = CollectionUtils::as_list(set);
        assert_eq!(list, vec![42]);
    }

    #[test]
    fn as_list_from_iterator() {
        let list = CollectionUtils::as_list(vec![1, 2, 3].into_iter());
        assert_eq!(list, vec![1, 2, 3]);
    }

    // --- non_null ---

    #[test]
    fn non_null_returns_value_when_present() {
        let value: Vec<i32> = CollectionUtils::non_null(Some(vec![1, 2]));
        assert_eq!(value, vec![1, 2]);
    }

    #[test]
    fn non_null_returns_default_when_absent() {
        let value: Vec<i32> = CollectionUtils::non_null(None);
        assert!(value.is_empty());
    }

    // --- is_one_of ---

    #[test]
    fn is_one_of_matches() {
        assert!(CollectionUtils::is_one_of(&2, &[1, 2, 3]));
    }

    #[test]
    fn is_one_of_no_match() {
        assert!(!CollectionUtils::is_one_of(&9, &[1, 2, 3]));
    }

    #[test]
    fn is_one_of_empty_possibles() {
        let possibles: [i32; 0] = [];
        assert!(!CollectionUtils::is_one_of(&1, &possibles));
    }

    // --- is_all_none ---

    #[test]
    fn is_all_none_true_for_all_none() {
        let items: Vec<Option<i32>> = vec![None, None];
        assert!(CollectionUtils::is_all_none(items));
    }

    #[test]
    fn is_all_none_false_when_one_present() {
        let items: Vec<Option<i32>> = vec![None, Some(1)];
        assert!(!CollectionUtils::is_all_none(items));
    }

    #[test]
    fn is_all_none_true_for_empty() {
        let items: Vec<Option<i32>> = vec![];
        assert!(CollectionUtils::is_all_none(items));
    }

    // --- is_blank ---

    #[test]
    fn is_blank_true_for_none() {
        assert!(CollectionUtils::is_blank::<i32>(None));
    }

    #[test]
    fn is_blank_true_for_empty_slice() {
        let items: [i32; 0] = [];
        assert!(CollectionUtils::is_blank(Some(&items[..])));
    }

    #[test]
    fn is_blank_false_for_non_empty_slice() {
        let items = [1, 2];
        assert!(!CollectionUtils::is_blank(Some(&items[..])));
    }

    // --- as_iterable_once ---

    #[test]
    fn as_iterable_once_yields_single_item() {
        let items: Vec<i32> = CollectionUtils::as_iterable_once(7).collect();
        assert_eq!(items, vec![7]);
    }

    // --- combine_iterables ---

    #[test]
    fn combine_iterables_concatenates_in_order() {
        let a: Box<dyn Iterator<Item = i32>> = Box::new(vec![1, 2].into_iter());
        let b: Box<dyn Iterator<Item = i32>> = Box::new(vec![3, 4].into_iter());
        let combined: Vec<i32> = CollectionUtils::combine_iterables(vec![a, b]).collect();
        assert_eq!(combined, vec![1, 2, 3, 4]);
    }

    #[test]
    fn combine_iterables_empty_input_yields_empty() {
        let combined: Vec<i32> = CollectionUtils::combine_iterables(vec![]).collect();
        assert!(combined.is_empty());
    }

    #[test]
    fn combine_iterables_skips_an_empty_iterable_in_the_middle() {
        let a: Box<dyn Iterator<Item = i32>> = Box::new(vec![1, 2].into_iter());
        let b: Box<dyn Iterator<Item = i32>> = Box::new(vec![3].into_iter());
        let empty: Box<dyn Iterator<Item = i32>> = Box::new(Vec::new().into_iter());
        let d: Box<dyn Iterator<Item = i32>> = Box::new(vec![4].into_iter());
        let combined: Vec<i32> = CollectionUtils::combine_iterables(vec![a, b, empty, d]).collect();
        assert_eq!(combined, vec![1, 2, 3, 4]);
    }

    // --- combine_cancellable_iterables ---

    #[test]
    fn combine_cancellable_iterables_stops_on_cancellation() {
        let a: Box<dyn Iterator<Item = i32>> = Box::new(vec![1, 2].into_iter());
        let b: Box<dyn Iterator<Item = i32>> = Box::new(vec![3, 4].into_iter());
        let cancelled = Arc::new(AtomicBool::new(false));
        let monitor: Box<dyn TaskMonitor> = Box::new(MockTaskMonitor { cancelled: cancelled.clone() });

        let mut iter = CollectionUtils::combine_cancellable_iterables(monitor, vec![a, b]);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        cancelled.store(true, Ordering::SeqCst);
        assert_eq!(iter.next(), None);
    }

    // --- any ---

    #[test]
    fn any_returns_first_element() {
        assert_eq!(CollectionUtils::any(vec![5, 6, 7]), Some(5));
    }

    #[test]
    fn any_returns_none_for_empty() {
        let empty: Vec<i32> = vec![];
        assert_eq!(CollectionUtils::any(empty), None);
    }

    // --- get ---

    #[test]
    fn get_returns_single_element() {
        assert_eq!(CollectionUtils::get(vec![42]), Some(42));
    }

    #[test]
    fn get_returns_none_for_empty() {
        let empty: Vec<i32> = vec![];
        assert_eq!(CollectionUtils::get(empty), None);
    }

    #[test]
    fn get_returns_none_for_multiple_elements() {
        assert_eq!(CollectionUtils::get(vec![1, 2]), None);
    }
}
