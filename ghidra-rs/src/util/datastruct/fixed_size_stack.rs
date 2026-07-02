use super::Stack;
use std::fmt;

/// A fixed-size stack that automatically removes the oldest (deepest) item
/// when the maximum size is exceeded.
///
/// When the stack size exceeds `max_size`, the element at index 0 (the oldest/deepest)
/// is automatically removed during push or add operations.
///
/// Port of `ghidra.util.datastruct.FixedSizeStack`.
#[derive(Debug)]
pub struct FixedSizeStack<T> {
    stack: Stack<T>,
    max_size: usize,
}

impl<T> FixedSizeStack<T> {
    /// Creates a fixed-size stack with the specified maximum size.
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum size of the stack; oldest items are removed when exceeded
    pub fn new(max_size: usize) -> Self {
        Self {
            stack: Stack::new(),
            max_size,
        }
    }

    /// Creates a fixed-size stack with the specified maximum size and pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum size of the stack
    /// * `initial_capacity` - Initial capacity for internal storage
    pub fn with_capacity(max_size: usize, initial_capacity: usize) -> Self {
        Self {
            stack: Stack::with_capacity(initial_capacity),
            max_size,
        }
    }

    /// Returns the maximum size of this stack.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Sets the maximum size of this stack.
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }

    /// Returns `true` if the stack contains no elements.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Returns a reference to the top element without removing it, or `None` if the stack is empty.
    pub fn peek(&self) -> Option<&T> {
        self.stack.peek()
    }

    /// Removes and returns the top element, or `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<T> {
        self.stack.pop()
    }

    /// Pushes `item` onto the top of the stack.
    ///
    /// If the stack size exceeds `max_size` after this operation, the oldest element
    /// is automatically removed.
    pub fn push(&mut self, item: T) {
        if self.stack.size() > self.max_size {
            self.remove(0);
        }
        self.stack.push(item);
    }

    /// Returns the number of elements in the stack.
    pub fn size(&self) -> usize {
        self.stack.size()
    }

    /// Returns a reference to the element at `depth`.
    ///
    /// `depth` 0 is the bottom (oldest); `size() - 1` is the top (newest).
    ///
    /// Panics if `depth >= size()`.
    pub fn get(&self, depth: usize) -> &T {
        self.stack.get(depth)
    }

    /// Adds an item to the top of the stack; equivalent to [`push`](FixedSizeStack::push).
    ///
    /// If the stack size exceeds `max_size` after this operation, the oldest element
    /// is automatically removed.
    pub fn add(&mut self, item: T) {
        if self.stack.size() > self.max_size {
            self.remove(0);
        }
        self.stack.add(item);
    }

    /// Removes and returns the element at the specified index.
    ///
    /// `index` 0 is the bottom (oldest); higher indices are towards the top.
    ///
    /// Panics if `index >= size()`.
    pub fn remove(&mut self, index: usize) -> T {
        let size = self.stack.size();
        assert!(index < size, "index out of bounds");

        let mut items = Vec::new();

        for _ in index..size {
            if let Some(item) = self.stack.pop() {
                items.push(item);
            }
        }

        items.reverse();
        let removed = items.remove(0);

        for item in items {
            self.stack.push(item);
        }

        removed
    }

    /// Removes all elements from the stack.
    pub fn clear(&mut self) {
        self.stack.clear();
    }

    /// Returns an iterator over the stack elements from bottom to top.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.stack.iter()
    }
}

impl<T: PartialEq> FixedSizeStack<T> {
    /// Returns the index of the first occurrence of `item`, or `None` if not found.
    ///
    /// Index 0 indicates the bottom (oldest element) of the stack.
    pub fn search(&self, item: &T) -> Option<usize> {
        self.stack.search(item)
    }
}

impl<T> Default for FixedSizeStack<T> {
    fn default() -> Self {
        Self::new(usize::MAX)
    }
}

impl<T: Clone> Clone for FixedSizeStack<T> {
    fn clone(&self) -> Self {
        Self {
            stack: self.stack.clone(),
            max_size: self.max_size,
        }
    }
}

impl<T: PartialEq> PartialEq for FixedSizeStack<T> {
    fn eq(&self, other: &Self) -> bool {
        self.stack == other.stack && self.max_size == other.max_size
    }
}

impl<T: Eq> Eq for FixedSizeStack<T> {}

impl<T: std::hash::Hash> std::hash::Hash for FixedSizeStack<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.stack.hash(state);
        self.max_size.hash(state);
    }
}

impl<T: fmt::Display> fmt::Display for FixedSizeStack<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.stack)
    }
}

impl<'a, T> IntoIterator for &'a FixedSizeStack<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.stack.iter()
    }
}

impl<T> IntoIterator for FixedSizeStack<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.stack.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty_stack() {
        let stack: FixedSizeStack<i32> = FixedSizeStack::new(3);
        assert!(stack.is_empty());
        assert_eq!(stack.size(), 0);
        assert_eq!(stack.max_size(), 3);
    }

    #[test]
    fn with_capacity_creates_empty() {
        let stack: FixedSizeStack<i32> = FixedSizeStack::with_capacity(3, 10);
        assert!(stack.is_empty());
        assert_eq!(stack.size(), 0);
        assert_eq!(stack.max_size(), 3);
    }

    #[test]
    fn push_within_max_size() {
        let mut stack = FixedSizeStack::new(3);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        assert_eq!(stack.size(), 3);
        assert_eq!(stack.peek(), Some(&3));
    }

    #[test]
    fn push_exceeding_max_size_removes_oldest() {
        let mut stack = FixedSizeStack::new(3);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        stack.push(4);
        assert_eq!(stack.size(), 4);
        assert_eq!(stack.get(0), &2);
        assert_eq!(stack.get(3), &4);
    }

    #[test]
    fn add_within_max_size() {
        let mut stack = FixedSizeStack::new(3);
        stack.add(1);
        stack.add(2);
        stack.add(3);
        assert_eq!(stack.size(), 3);
        assert_eq!(stack.peek(), Some(&3));
    }

    #[test]
    fn add_exceeding_max_size_removes_oldest() {
        let mut stack = FixedSizeStack::new(3);
        stack.add(1);
        stack.add(2);
        stack.add(3);
        stack.add(4);
        assert_eq!(stack.size(), 4);
        assert_eq!(stack.get(0), &2);
        assert_eq!(stack.get(3), &4);
    }

    #[test]
    fn pop_returns_lifo_order() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(10);
        stack.push(20);
        assert_eq!(stack.pop(), Some(20));
        assert_eq!(stack.pop(), Some(10));
        assert_eq!(stack.pop(), None);
    }

    #[test]
    fn get_by_depth() {
        let mut stack = FixedSizeStack::new(5);
        stack.push('a');
        stack.push('b');
        stack.push('c');
        assert_eq!(stack.get(0), &'a');
        assert_eq!(stack.get(1), &'b');
        assert_eq!(stack.get(2), &'c');
    }

    #[test]
    fn search_returns_index() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(10);
        stack.push(20);
        stack.push(30);
        assert_eq!(stack.search(&10), Some(0));
        assert_eq!(stack.search(&20), Some(1));
        assert_eq!(stack.search(&30), Some(2));
        assert_eq!(stack.search(&99), None);
    }

    #[test]
    fn clear_empties_stack() {
        let mut stack = FixedSizeStack::new(3);
        stack.push(1);
        stack.push(2);
        stack.clear();
        assert!(stack.is_empty());
        assert_eq!(stack.size(), 0);
    }

    #[test]
    fn peek_on_empty_returns_none() {
        let stack: FixedSizeStack<i32> = FixedSizeStack::new(3);
        assert_eq!(stack.peek(), None);
    }

    #[test]
    fn set_max_size() {
        let mut stack = FixedSizeStack::new(3);
        stack.push(1);
        stack.push(2);
        stack.set_max_size(5);
        assert_eq!(stack.max_size(), 5);
    }

    #[test]
    fn remove_at_index() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        let removed = stack.remove(1);
        assert_eq!(removed, 2);
        assert_eq!(stack.size(), 2);
        assert_eq!(stack.get(0), &1);
        assert_eq!(stack.get(1), &3);
    }

    #[test]
    fn multiple_pushes_with_max_size_two() {
        let mut stack = FixedSizeStack::new(2);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        assert_eq!(stack.size(), 3);
        assert_eq!(stack.get(0), &2);
        assert_eq!(stack.get(1), &3);
    }

    #[test]
    fn iter_bottom_to_top() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        let v: Vec<i32> = stack.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn clone_produces_equal_stack() {
        let mut orig = FixedSizeStack::new(3);
        orig.push(1);
        orig.push(2);
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn equality_checks_both_stack_and_max_size() {
        let mut a = FixedSizeStack::new(3);
        a.push(1);
        let mut b = FixedSizeStack::new(3);
        b.push(1);
        assert_eq!(a, b);

        let mut c = FixedSizeStack::new(5);
        c.push(1);
        assert_ne!(a, c);
    }

    #[test]
    fn display_format() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(1);
        stack.push(2);
        stack.push(3);
        assert_eq!(format!("{stack}"), "[1, 2, 3]");
    }

    #[test]
    fn into_iter_owned() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(1);
        stack.push(2);
        let v: Vec<i32> = stack.into_iter().collect();
        assert_eq!(v, vec![1, 2]);
    }

    #[test]
    fn into_iter_ref() {
        let mut stack = FixedSizeStack::new(5);
        stack.push(1);
        stack.push(2);
        let v: Vec<i32> = (&stack).into_iter().copied().collect();
        assert_eq!(v, vec![1, 2]);
    }
}
