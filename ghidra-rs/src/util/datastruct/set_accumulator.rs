use super::Accumulator;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::fmt;

/// An accumulator backed by a thread-safe set.
///
/// This struct has methods to retrieve the data once all loading has finished.
/// API uses of the accumulator are inherently multi-threaded. The internal set
/// is synchronized so that data in the accumulator will be visible to client threads.
///
/// Port of `ghidra.util.datastruct.SetAccumulator`.
pub struct SetAccumulator<T: Eq + std::hash::Hash> {
    set: Arc<Mutex<HashSet<T>>>,
}

impl<T: Eq + std::hash::Hash> SetAccumulator<T> {
    /// Creates a new empty set accumulator.
    pub fn new() -> Self {
        Self {
            set: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Returns `true` if the set contains the given item.
    pub fn contains(&self, item: &T) -> bool {
        self.set.lock().unwrap().contains(item)
    }

    /// Returns a clone of all items currently in the accumulator.
    pub fn get(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.set.lock().unwrap().iter().cloned().collect()
    }

    /// Returns a clone of all items currently in the accumulator as a HashSet.
    /// Alias for getting the underlying set.
    pub fn as_set(&self) -> HashSet<T>
    where
        T: Clone,
    {
        self.set.lock().unwrap().clone()
    }

    /// Returns the number of items in the accumulator.
    pub fn size(&self) -> usize {
        self.set.lock().unwrap().len()
    }

    /// Returns an iterator over the items in the accumulator.
    pub fn iter(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.set.lock().unwrap().iter().cloned().collect()
    }
}

impl<T: Eq + std::hash::Hash> Default for SetAccumulator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Eq + std::hash::Hash> Clone for SetAccumulator<T> {
    fn clone(&self) -> Self {
        Self {
            set: Arc::clone(&self.set),
        }
    }
}

impl<T: Eq + std::hash::Hash> Accumulator<T> for SetAccumulator<T> {
    fn add(&mut self, item: T) {
        self.set.lock().unwrap().insert(item);
    }

    fn add_all(&mut self, iter: impl IntoIterator<Item = T>) {
        let mut set = self.set.lock().unwrap();
        for item in iter {
            set.insert(item);
        }
    }

    fn get_progress(&self) -> usize {
        self.set.lock().unwrap().len()
    }
}

impl<T: Eq + std::hash::Hash> IntoIterator for SetAccumulator<T>
where
    T: Clone,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let guard = self.set.lock().unwrap();
        guard.iter().cloned().collect::<Vec<_>>().into_iter()
    }
}

impl<'a, T: Eq + std::hash::Hash> IntoIterator for &'a SetAccumulator<T>
where
    T: Clone,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.set.lock().unwrap().iter().cloned().collect::<Vec<_>>().into_iter()
    }
}

impl<T: Eq + std::hash::Hash + fmt::Display> fmt::Display for SetAccumulator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = self.set.lock().unwrap();
        write!(f, "{{")?;
        let mut first = true;
        for item in set.iter() {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{}", item)?;
            first = false;
        }
        write!(f, "}}")
    }
}

impl<T: Eq + std::hash::Hash + fmt::Debug> fmt::Debug for SetAccumulator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = self.set.lock().unwrap();
        f.debug_struct("SetAccumulator")
            .field("set", &*set)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator_is_empty() {
        let acc: SetAccumulator<i32> = SetAccumulator::new();
        assert_eq!(acc.size(), 0);
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn add_single_item_increments_size() {
        let mut acc = SetAccumulator::new();
        acc.add(42);
        assert_eq!(acc.size(), 1);
        assert_eq!(acc.get_progress(), 1);
    }

    #[test]
    fn add_multiple_items() {
        let mut acc = SetAccumulator::new();
        acc.add(1);
        acc.add(2);
        acc.add(3);
        assert_eq!(acc.size(), 3);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn add_duplicate_item_does_not_increase_size() {
        let mut acc = SetAccumulator::new();
        acc.add(42);
        assert_eq!(acc.size(), 1);
        acc.add(42);
        assert_eq!(acc.size(), 1);
    }

    #[test]
    fn add_all_with_vec() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![10, 20, 30]);
        assert_eq!(acc.size(), 3);
        let items = acc.get();
        assert_eq!(items.len(), 3);
        assert!(items.contains(&10));
        assert!(items.contains(&20));
        assert!(items.contains(&30));
    }

    #[test]
    fn add_all_with_duplicates_deduplicates() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![1, 2, 2, 3, 3, 3]);
        assert_eq!(acc.size(), 3);
    }

    #[test]
    fn add_all_with_iterator() {
        let mut acc = SetAccumulator::new();
        acc.add_all([1, 2, 3].iter().copied());
        assert_eq!(acc.size(), 3);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn add_all_empty_does_nothing() {
        let mut acc: SetAccumulator<i32> = SetAccumulator::new();
        acc.add_all(std::iter::empty());
        assert_eq!(acc.size(), 0);
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn contains_returns_true_for_present_item() {
        let mut acc = SetAccumulator::new();
        acc.add(42);
        assert!(acc.contains(&42));
    }

    #[test]
    fn contains_returns_false_for_missing_item() {
        let mut acc = SetAccumulator::new();
        acc.add(42);
        assert!(!acc.contains(&99));
    }

    #[test]
    fn get_returns_copy_of_items() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![1, 2, 3]);
        let items = acc.get();
        assert_eq!(items.len(), 3);
        assert!(items.contains(&1));
        assert!(items.contains(&2));
        assert!(items.contains(&3));
    }

    #[test]
    fn as_set_returns_copy_of_items() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![10, 20, 30]);
        let set = acc.as_set();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert!(set.contains(&30));
    }

    #[test]
    fn into_iter_iterates_all_items() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![1, 2, 3]);
        let collected: Vec<_> = acc.into_iter().collect();
        assert_eq!(collected.len(), 3);
        assert!(collected.contains(&1));
        assert!(collected.contains(&2));
        assert!(collected.contains(&3));
    }

    #[test]
    fn ref_iter_iterates_items_by_reference() {
        let mut acc = SetAccumulator::new();
        acc.add_all(vec![5, 10, 15]);
        let collected: Vec<_> = (&acc).into_iter().collect();
        assert_eq!(collected.len(), 3);
        assert!(collected.contains(&5));
        assert!(collected.contains(&10));
        assert!(collected.contains(&15));
    }

    #[test]
    fn clone_shares_underlying_set() {
        let mut acc1 = SetAccumulator::new();
        acc1.add(42);
        let acc2 = acc1.clone();
        assert_eq!(acc2.size(), 1);
        assert!(acc2.contains(&42));
    }

    #[test]
    fn clone_shares_future_additions() {
        let mut acc1 = SetAccumulator::new();
        acc1.add(1);
        let acc2 = acc1.clone();
        acc1.add(2);
        assert_eq!(acc2.size(), 2);
        assert!(acc2.contains(&1));
        assert!(acc2.contains(&2));
    }

    #[test]
    fn add_and_add_all_mixed() {
        let mut acc = SetAccumulator::new();
        acc.add(1);
        acc.add_all(vec![2, 3]);
        acc.add(4);
        assert_eq!(acc.size(), 4);
        let items = acc.get();
        assert_eq!(items.len(), 4);
        assert!(items.contains(&1));
        assert!(items.contains(&2));
        assert!(items.contains(&3));
        assert!(items.contains(&4));
    }

    #[test]
    fn get_progress_after_operations() {
        let mut acc: SetAccumulator<String> = SetAccumulator::new();
        assert_eq!(acc.get_progress(), 0);
        acc.add("hello".to_string());
        assert_eq!(acc.get_progress(), 1);
        acc.add_all(vec!["world".to_string(), "rust".to_string()]);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn display_empty_set() {
        let acc: SetAccumulator<i32> = SetAccumulator::new();
        assert_eq!(acc.to_string(), "{}");
    }

    #[test]
    fn display_with_items() {
        let mut acc = SetAccumulator::new();
        acc.add(1);
        acc.add(2);
        acc.add(3);
        let s = acc.to_string();
        assert!(s.contains("1"));
        assert!(s.contains("2"));
        assert!(s.contains("3"));
        assert!(s.starts_with("{"));
        assert!(s.ends_with("}"));
    }
}
