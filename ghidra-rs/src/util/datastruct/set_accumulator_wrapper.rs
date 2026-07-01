use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::Accumulator;

/// A wrapper around an accumulator that only passes unique items to the wrapped accumulator.
///
/// This accumulator maintains an internal concurrent set to track which items have been seen.
/// Only items that have not been added before will be forwarded to the wrapped accumulator.
///
/// Port of `ghidra.util.datastruct.SetAccumulatorWrapper`.
pub struct SetAccumulatorWrapper<T: Eq + std::hash::Hash + Clone, A: Accumulator<T>> {
    set: Arc<Mutex<HashSet<T>>>,
    accumulator: A,
}

impl<T: Eq + std::hash::Hash + Clone, A: Accumulator<T>> SetAccumulatorWrapper<T, A> {
    /// Creates a new set accumulator wrapper that will only pass unique items to the given accumulator.
    pub fn new(accumulator: A) -> Self {
        Self {
            set: Arc::new(Mutex::new(HashSet::new())),
            accumulator,
        }
    }

    /// Returns the internal set used by this wrapper.
    /// This should only be called when data loading is finished.
    pub fn as_set(&self) -> HashSet<T>
    where
        T: Clone,
    {
        self.set.lock().unwrap().clone()
    }
}

impl<T: Eq + std::hash::Hash + Clone, A: Accumulator<T>> Accumulator<T> for SetAccumulatorWrapper<T, A> {
    fn add(&mut self, item: T) {
        let mut set = self.set.lock().unwrap();
        if set.insert(item.clone()) {
            drop(set);
            self.accumulator.add(item);
        }
    }

    fn add_all(&mut self, iter: impl IntoIterator<Item = T>) {
        for item in iter {
            self.add(item);
        }
    }

    fn get_progress(&self) -> usize {
        self.set.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAccumulator<T> {
        items: Vec<T>,
    }

    impl<T> TestAccumulator<T> {
        fn new() -> Self {
            Self { items: Vec::new() }
        }
    }

    impl<T> Accumulator<T> for TestAccumulator<T> {
        fn add(&mut self, item: T) {
            self.items.push(item);
        }

        fn get_progress(&self) -> usize {
            self.items.len()
        }
    }

    #[test]
    fn new_wrapper_is_empty() {
        let inner = TestAccumulator::<i32>::new();
        let wrapper = SetAccumulatorWrapper::new(inner);
        assert_eq!(wrapper.get_progress(), 0);
    }

    #[test]
    fn add_single_item_forwards_to_accumulator() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add(42);
        assert_eq!(wrapper.get_progress(), 1);
        assert_eq!(wrapper.accumulator.get_progress(), 1);
        assert_eq!(wrapper.accumulator.items, vec![42]);
    }

    #[test]
    fn add_duplicate_does_not_forward() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add(42);
        wrapper.add(42);
        assert_eq!(wrapper.get_progress(), 1);
        assert_eq!(wrapper.accumulator.get_progress(), 1);
        assert_eq!(wrapper.accumulator.items, vec![42]);
    }

    #[test]
    fn add_multiple_unique_items() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add(1);
        wrapper.add(2);
        wrapper.add(3);
        assert_eq!(wrapper.get_progress(), 3);
        assert_eq!(wrapper.accumulator.get_progress(), 3);
        assert_eq!(wrapper.accumulator.items, vec![1, 2, 3]);
    }

    #[test]
    fn add_mixed_unique_and_duplicate_items() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add(1);
        wrapper.add(2);
        wrapper.add(1);
        wrapper.add(3);
        wrapper.add(2);
        assert_eq!(wrapper.get_progress(), 3);
        assert_eq!(wrapper.accumulator.get_progress(), 3);
        assert_eq!(wrapper.accumulator.items, vec![1, 2, 3]);
    }

    #[test]
    fn add_all_with_unique_items() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add_all(vec![10, 20, 30]);
        assert_eq!(wrapper.get_progress(), 3);
        assert_eq!(wrapper.accumulator.get_progress(), 3);
        assert_eq!(wrapper.accumulator.items, vec![10, 20, 30]);
    }

    #[test]
    fn add_all_with_duplicates() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add_all(vec![1, 2, 2, 3, 3, 3]);
        assert_eq!(wrapper.get_progress(), 3);
        assert_eq!(wrapper.accumulator.get_progress(), 3);
        assert_eq!(wrapper.accumulator.items, vec![1, 2, 3]);
    }

    #[test]
    fn add_all_empty_does_nothing() {
        let inner = TestAccumulator::<i32>::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add_all(std::iter::empty());
        assert_eq!(wrapper.get_progress(), 0);
        assert_eq!(wrapper.accumulator.get_progress(), 0);
    }

    #[test]
    fn add_all_does_not_duplicate_across_calls() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add_all(vec![1, 2, 3]);
        wrapper.add_all(vec![2, 3, 4]);
        assert_eq!(wrapper.get_progress(), 4);
        assert_eq!(wrapper.accumulator.get_progress(), 4);
        assert_eq!(wrapper.accumulator.items, vec![1, 2, 3, 4]);
    }

    #[test]
    fn as_set_returns_internal_set() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add_all(vec![1, 2, 3]);
        let set = wrapper.as_set();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
    }

    #[test]
    fn progress_equals_set_size() {
        let inner = TestAccumulator::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        assert_eq!(wrapper.get_progress(), 0);
        wrapper.add(1);
        assert_eq!(wrapper.get_progress(), 1);
        wrapper.add(1);
        assert_eq!(wrapper.get_progress(), 1);
        wrapper.add(2);
        assert_eq!(wrapper.get_progress(), 2);
    }

    #[test]
    fn with_string_items() {
        let inner = TestAccumulator::<String>::new();
        let mut wrapper = SetAccumulatorWrapper::new(inner);
        wrapper.add("hello".to_string());
        wrapper.add("world".to_string());
        wrapper.add("hello".to_string());
        assert_eq!(wrapper.get_progress(), 2);
        assert_eq!(wrapper.accumulator.get_progress(), 2);
    }
}
