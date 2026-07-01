use super::Accumulator;
use std::sync::{Arc, Mutex};
use std::fmt;

/// An accumulator backed by a thread-safe list.
///
/// This struct has methods to retrieve the data once all loading has finished.
/// API uses of the accumulator are inherently multi-threaded. The internal list
/// is synchronized so that data in the accumulator will be visible to client threads.
///
/// Port of `ghidra.util.datastruct.ListAccumulator`.
pub struct ListAccumulator<T> {
    list: Arc<Mutex<Vec<T>>>,
}

impl<T> ListAccumulator<T> {
    /// Creates a new empty list accumulator.
    pub fn new() -> Self {
        Self {
            list: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns `true` if the list contains the given item.
    pub fn contains(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.list.lock().unwrap().contains(item)
    }

    /// Returns a clone of all items currently in the accumulator.
    pub fn get(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.list.lock().unwrap().clone()
    }

    /// Returns a clone of all items currently in the accumulator.
    /// Alias for [`get`](ListAccumulator::get).
    pub fn as_list(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.list.lock().unwrap().clone()
    }

    /// Returns the number of items in the accumulator.
    pub fn size(&self) -> usize {
        self.list.lock().unwrap().len()
    }

    /// Returns an iterator over the items in the accumulator.
    pub fn iter(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.list.lock().unwrap().clone()
    }
}

impl<T> Default for ListAccumulator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ListAccumulator<T> {
    fn clone(&self) -> Self {
        Self {
            list: Arc::clone(&self.list),
        }
    }
}

impl<T> Accumulator<T> for ListAccumulator<T> {
    fn add(&mut self, item: T) {
        self.list.lock().unwrap().push(item);
    }

    fn add_all(&mut self, iter: impl IntoIterator<Item = T>) {
        let mut list = self.list.lock().unwrap();
        for item in iter {
            list.push(item);
        }
    }

    fn get_progress(&self) -> usize {
        self.list.lock().unwrap().len()
    }
}

impl<T> IntoIterator for ListAccumulator<T>
where
    T: Clone,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let guard = self.list.lock().unwrap();
        guard.clone().into_iter()
    }
}

impl<'a, T> IntoIterator for &'a ListAccumulator<T>
where
    T: Clone,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.lock().unwrap().clone().into_iter()
    }
}

impl<T: fmt::Display> fmt::Display for ListAccumulator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = self.list.lock().unwrap();
        write!(f, "[")?;
        for (i, item) in list.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", item)?;
        }
        write!(f, "]")
    }
}

impl<T: fmt::Debug> fmt::Debug for ListAccumulator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = self.list.lock().unwrap();
        f.debug_struct("ListAccumulator")
            .field("list", &*list)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator_is_empty() {
        let acc: ListAccumulator<i32> = ListAccumulator::new();
        assert_eq!(acc.size(), 0);
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn add_single_item_increments_size() {
        let mut acc = ListAccumulator::new();
        acc.add(42);
        assert_eq!(acc.size(), 1);
        assert_eq!(acc.get_progress(), 1);
    }

    #[test]
    fn add_multiple_items() {
        let mut acc = ListAccumulator::new();
        acc.add(1);
        acc.add(2);
        acc.add(3);
        assert_eq!(acc.size(), 3);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn add_all_with_vec() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![10, 20, 30]);
        assert_eq!(acc.size(), 3);
        assert_eq!(acc.get(), vec![10, 20, 30]);
    }

    #[test]
    fn add_all_with_iterator() {
        let mut acc = ListAccumulator::new();
        acc.add_all([1, 2, 3].iter().copied());
        assert_eq!(acc.size(), 3);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn add_all_empty_does_nothing() {
        let mut acc: ListAccumulator<i32> = ListAccumulator::new();
        acc.add_all(std::iter::empty());
        assert_eq!(acc.size(), 0);
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn contains_returns_true_for_present_item() {
        let mut acc = ListAccumulator::new();
        acc.add(42);
        assert!(acc.contains(&42));
    }

    #[test]
    fn contains_returns_false_for_missing_item() {
        let mut acc = ListAccumulator::new();
        acc.add(42);
        assert!(!acc.contains(&99));
    }

    #[test]
    fn get_returns_copy_of_items() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![1, 2, 3]);
        let items = acc.get();
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn as_list_returns_copy_of_items() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![10, 20, 30]);
        let list = acc.as_list();
        assert_eq!(list, vec![10, 20, 30]);
    }

    #[test]
    fn into_iter_iterates_all_items() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![1, 2, 3]);
        let collected: Vec<_> = acc.into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn ref_iter_iterates_items_by_reference() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![5, 10, 15]);
        let collected: Vec<_> = (&acc).into_iter().collect();
        assert_eq!(collected, vec![5, 10, 15]);
    }

    #[test]
    fn clone_shares_underlying_list() {
        let mut acc1 = ListAccumulator::new();
        acc1.add(42);
        let acc2 = acc1.clone();
        assert_eq!(acc2.size(), 1);
        assert_eq!(acc2.get(), vec![42]);
    }

    #[test]
    fn clone_shares_future_additions() {
        let mut acc1 = ListAccumulator::new();
        acc1.add(1);
        let acc2 = acc1.clone();
        acc1.add(2);
        assert_eq!(acc2.size(), 2);
        assert_eq!(acc2.get(), vec![1, 2]);
    }

    #[test]
    fn add_and_add_all_mixed() {
        let mut acc = ListAccumulator::new();
        acc.add(1);
        acc.add_all(vec![2, 3]);
        acc.add(4);
        assert_eq!(acc.size(), 4);
        assert_eq!(acc.get(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn get_progress_after_operations() {
        let mut acc: ListAccumulator<String> = ListAccumulator::new();
        assert_eq!(acc.get_progress(), 0);
        acc.add("hello".to_string());
        assert_eq!(acc.get_progress(), 1);
        acc.add_all(vec!["world".to_string(), "rust".to_string()]);
        assert_eq!(acc.get_progress(), 3);
    }

    #[test]
    fn display_empty_list() {
        let acc: ListAccumulator<i32> = ListAccumulator::new();
        assert_eq!(acc.to_string(), "[]");
    }

    #[test]
    fn display_with_items() {
        let mut acc = ListAccumulator::new();
        acc.add_all(vec![1, 2, 3]);
        assert_eq!(acc.to_string(), "[1, 2, 3]");
    }
}
