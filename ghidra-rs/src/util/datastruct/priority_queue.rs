use std::collections::{BTreeMap, VecDeque};

/// Priority queue where objects are ordered by an integer priority value.
///
/// The object with the **lowest** priority number is retrieved via
/// [`get_first`](PriorityQueue::get_first) / [`remove_first`](PriorityQueue::remove_first);
/// the object with the **highest** priority number is retrieved via
/// [`get_last`](PriorityQueue::get_last) / [`remove_last`](PriorityQueue::remove_last).
/// When multiple objects share a priority, insertion order is preserved (FIFO within each tier).
///
/// Port of `ghidra.util.datastruct.PriorityQueue`.
pub struct PriorityQueue<T> {
    size: usize,
    tree: BTreeMap<i32, VecDeque<T>>,
}

impl<T> PriorityQueue<T> {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self {
            size: 0,
            tree: BTreeMap::new(),
        }
    }

    /// Adds `obj` to the queue with the given `priority`.
    pub fn add(&mut self, obj: T, priority: i32) {
        self.tree.entry(priority).or_default().push_back(obj);
        self.size += 1;
    }

    /// Returns the number of objects in the queue.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns `true` if the queue contains no objects.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns a reference to the object with the lowest priority number.
    ///
    /// When multiple objects share the lowest priority, the one inserted first is returned.
    /// Returns `None` if the queue is empty.
    pub fn get_first(&self) -> Option<&T> {
        self.tree.values().next()?.front()
    }

    /// Returns the lowest priority number present in the queue, or `None` if empty.
    pub fn get_first_priority(&self) -> Option<i32> {
        self.tree.keys().next().copied()
    }

    /// Returns a reference to the object with the highest priority number.
    ///
    /// When multiple objects share the highest priority, the one inserted last is returned.
    /// Returns `None` if the queue is empty.
    pub fn get_last(&self) -> Option<&T> {
        self.tree.values().next_back()?.back()
    }

    /// Returns the highest priority number present in the queue, or `None` if empty.
    pub fn get_last_priority(&self) -> Option<i32> {
        self.tree.keys().next_back().copied()
    }

    /// Removes and returns the object with the lowest priority number.
    ///
    /// When multiple objects share the lowest priority, the one inserted first is removed.
    /// Returns `None` if the queue is empty.
    pub fn remove_first(&mut self) -> Option<T> {
        let key = *self.tree.keys().next()?;
        let list = self.tree.get_mut(&key)?;
        let item = list.pop_front()?;
        if list.is_empty() {
            self.tree.remove(&key);
        }
        self.size -= 1;
        Some(item)
    }

    /// Removes and returns the object with the highest priority number.
    ///
    /// When multiple objects share the highest priority, the one inserted last is removed.
    /// Returns `None` if the queue is empty.
    pub fn remove_last(&mut self) -> Option<T> {
        let key = *self.tree.keys().next_back()?;
        let list = self.tree.get_mut(&key)?;
        let item = list.pop_back()?;
        if list.is_empty() {
            self.tree.remove(&key);
        }
        self.size -= 1;
        Some(item)
    }

    /// Removes all objects from the queue.
    pub fn clear(&mut self) {
        self.size = 0;
        self.tree.clear();
    }
}

impl<T> Default for PriorityQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_returns_none() {
        let q: PriorityQueue<i32> = PriorityQueue::new();
        assert!(q.get_first().is_none());
        assert!(q.get_last().is_none());
        assert!(q.get_first_priority().is_none());
        assert!(q.get_last_priority().is_none());
    }

    #[test]
    fn remove_first_from_empty_returns_none() {
        let mut q: PriorityQueue<i32> = PriorityQueue::new();
        assert!(q.remove_first().is_none());
    }

    #[test]
    fn remove_last_from_empty_returns_none() {
        let mut q: PriorityQueue<i32> = PriorityQueue::new();
        assert!(q.remove_last().is_none());
    }

    #[test]
    fn size_and_is_empty() {
        let mut q = PriorityQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.size(), 0);
        q.add("a", 5);
        assert!(!q.is_empty());
        assert_eq!(q.size(), 1);
        q.add("b", 3);
        assert_eq!(q.size(), 2);
    }

    #[test]
    fn get_first_returns_lowest_priority() {
        let mut q = PriorityQueue::new();
        q.add("high", 10);
        q.add("low", 1);
        q.add("mid", 5);
        assert_eq!(q.get_first(), Some(&"low"));
        assert_eq!(q.get_first_priority(), Some(1));
    }

    #[test]
    fn get_last_returns_highest_priority() {
        let mut q = PriorityQueue::new();
        q.add("low", 1);
        q.add("high", 10);
        q.add("mid", 5);
        assert_eq!(q.get_last(), Some(&"high"));
        assert_eq!(q.get_last_priority(), Some(10));
    }

    #[test]
    fn same_priority_fifo_order_get_first() {
        let mut q = PriorityQueue::new();
        q.add("first", 3);
        q.add("second", 3);
        q.add("third", 3);
        assert_eq!(q.get_first(), Some(&"first"));
    }

    #[test]
    fn same_priority_lifo_order_get_last() {
        let mut q = PriorityQueue::new();
        q.add("first", 3);
        q.add("second", 3);
        q.add("third", 3);
        assert_eq!(q.get_last(), Some(&"third"));
    }

    #[test]
    fn remove_first_dequeues_in_priority_then_insertion_order() {
        let mut q = PriorityQueue::new();
        q.add("b1", 2);
        q.add("a1", 1);
        q.add("a2", 1);
        q.add("b2", 2);
        assert_eq!(q.remove_first(), Some("a1"));
        assert_eq!(q.remove_first(), Some("a2"));
        assert_eq!(q.remove_first(), Some("b1"));
        assert_eq!(q.remove_first(), Some("b2"));
        assert!(q.remove_first().is_none());
    }

    #[test]
    fn remove_last_dequeues_in_reverse_priority_then_reverse_insertion_order() {
        let mut q = PriorityQueue::new();
        q.add("a", 1);
        q.add("b1", 2);
        q.add("b2", 2);
        assert_eq!(q.remove_last(), Some("b2"));
        assert_eq!(q.remove_last(), Some("b1"));
        assert_eq!(q.remove_last(), Some("a"));
        assert!(q.remove_last().is_none());
    }

    #[test]
    fn remove_first_cleans_up_empty_priority_bucket() {
        let mut q = PriorityQueue::new();
        q.add("only", 7);
        q.remove_first();
        assert!(q.is_empty());
        assert!(q.get_first_priority().is_none());
    }

    #[test]
    fn size_decrements_on_remove() {
        let mut q = PriorityQueue::new();
        q.add(1, 5);
        q.add(2, 5);
        assert_eq!(q.size(), 2);
        q.remove_first();
        assert_eq!(q.size(), 1);
        q.remove_last();
        assert_eq!(q.size(), 0);
    }

    #[test]
    fn clear_resets_queue() {
        let mut q = PriorityQueue::new();
        q.add("x", 1);
        q.add("y", 2);
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.size(), 0);
        assert!(q.get_first().is_none());
        assert!(q.get_last().is_none());
    }

    #[test]
    fn negative_priorities_ordered_correctly() {
        let mut q = PriorityQueue::new();
        q.add("neg", -5);
        q.add("pos", 5);
        q.add("zero", 0);
        assert_eq!(q.get_first_priority(), Some(-5));
        assert_eq!(q.get_last_priority(), Some(5));
        assert_eq!(q.remove_first(), Some("neg"));
        assert_eq!(q.remove_last(), Some("pos"));
    }

    #[test]
    fn default_creates_empty_queue() {
        let q: PriorityQueue<u8> = PriorityQueue::default();
        assert!(q.is_empty());
    }
}
