use std::fmt;

/// Last-in-first-out (LIFO) stack backed by a [`Vec`].
///
/// Iterating via [`iter`](Stack::iter) or `IntoIterator` traverses elements
/// from the **bottom** to the **top** of the stack.
///
/// Port of `ghidra.util.datastruct.Stack`.
pub struct Stack<T> {
    list: Vec<T>,
}

impl<T> Stack<T> {
    /// Creates an empty stack.
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Creates an empty stack pre-allocated for `initial_capacity` elements.
    pub fn with_capacity(initial_capacity: usize) -> Self {
        Self {
            list: Vec::with_capacity(initial_capacity),
        }
    }

    /// Returns `true` if the stack contains no elements.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Returns a reference to the top element without removing it, or `None` if the stack is empty.
    pub fn peek(&self) -> Option<&T> {
        self.list.last()
    }

    /// Removes and returns the top element, or `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<T> {
        self.list.pop()
    }

    /// Pushes `item` onto the top of the stack.
    pub fn push(&mut self, item: T) {
        self.list.push(item);
    }

    /// Returns the number of elements in the stack.
    pub fn size(&self) -> usize {
        self.list.len()
    }

    /// Returns a reference to the element at `depth`.
    ///
    /// `depth` 0 is the bottom; `size() - 1` is the top.
    ///
    /// Panics if `depth >= size()`.
    pub fn get(&self, depth: usize) -> &T {
        &self.list[depth]
    }

    /// Pushes `item` onto the top of the stack; equivalent to [`push`](Stack::push).
    pub fn add(&mut self, item: T) {
        self.list.push(item);
    }

    /// Removes all elements from the stack.
    pub fn clear(&mut self) {
        self.list.clear();
    }

    /// Returns an iterator over the stack elements from bottom to top.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.list.iter()
    }
}

impl<T: PartialEq> Stack<T> {
    /// Returns the index of the first occurrence of `item`, or `None` if not found.
    ///
    /// Index 0 indicates the bottom of the stack.
    pub fn search(&self, item: &T) -> Option<usize> {
        self.list.iter().position(|x| x == item)
    }
}

impl<T> Default for Stack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for Stack<T> {
    fn clone(&self) -> Self {
        Self {
            list: self.list.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for Stack<T> {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl<T: Eq> Eq for Stack<T> {}

impl<T: std::hash::Hash> std::hash::Hash for Stack<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.list.hash(state);
    }
}

impl<T: fmt::Display> fmt::Display for Stack<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, item) in self.list.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{item}")?;
        }
        write!(f, "]")
    }
}

impl<'a, T> IntoIterator for &'a Stack<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl<T> IntoIterator for Stack<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stack_is_empty() {
        let s: Stack<i32> = Stack::new();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn with_capacity_creates_empty() {
        let s: Stack<i32> = Stack::with_capacity(16);
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn default_creates_empty() {
        let s: Stack<u8> = Stack::default();
        assert!(s.is_empty());
    }

    #[test]
    fn push_and_peek() {
        let mut s = Stack::new();
        s.push(1);
        s.push(2);
        s.push(3);
        assert_eq!(s.peek(), Some(&3));
        assert_eq!(s.size(), 3);
    }

    #[test]
    fn peek_on_empty_returns_none() {
        let s: Stack<i32> = Stack::new();
        assert_eq!(s.peek(), None);
    }

    #[test]
    fn pop_returns_lifo_order() {
        let mut s = Stack::new();
        s.push(10);
        s.push(20);
        assert_eq!(s.pop(), Some(20));
        assert_eq!(s.pop(), Some(10));
        assert_eq!(s.pop(), None);
    }

    #[test]
    fn get_by_depth() {
        let mut s = Stack::new();
        s.push('a');
        s.push('b');
        s.push('c');
        assert_eq!(s.get(0), &'a');
        assert_eq!(s.get(1), &'b');
        assert_eq!(s.get(2), &'c');
    }

    #[test]
    fn add_is_alias_for_push() {
        let mut s = Stack::new();
        s.add(42);
        assert_eq!(s.peek(), Some(&42));
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn search_returns_index() {
        let mut s = Stack::new();
        s.push(10);
        s.push(20);
        s.push(30);
        assert_eq!(s.search(&10), Some(0));
        assert_eq!(s.search(&20), Some(1));
        assert_eq!(s.search(&30), Some(2));
    }

    #[test]
    fn search_not_found_returns_none() {
        let mut s = Stack::new();
        s.push(1);
        s.push(2);
        assert_eq!(s.search(&99), None);
    }

    #[test]
    fn clear_empties_stack() {
        let mut s = Stack::new();
        s.push(1);
        s.push(2);
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.size(), 0);
        assert_eq!(s.peek(), None);
    }

    #[test]
    fn iter_bottom_to_top() {
        let mut s = Stack::new();
        s.push(1);
        s.push(2);
        s.push(3);
        let v: Vec<i32> = s.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn into_iter_ref_bottom_to_top() {
        let mut s = Stack::new();
        s.push("x");
        s.push("y");
        let v: Vec<&str> = (&s).into_iter().copied().collect();
        assert_eq!(v, vec!["x", "y"]);
    }

    #[test]
    fn into_iter_owned_bottom_to_top() {
        let mut s = Stack::new();
        s.push(1i32);
        s.push(2);
        let v: Vec<i32> = s.into_iter().collect();
        assert_eq!(v, vec![1, 2]);
    }

    #[test]
    fn equality() {
        let mut a: Stack<i32> = Stack::new();
        a.push(1);
        a.push(2);
        let mut b: Stack<i32> = Stack::new();
        b.push(1);
        b.push(2);
        assert_eq!(a, b);
        b.push(3);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_stack() {
        let mut orig = Stack::new();
        orig.push(1);
        orig.push(2);
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn display_matches_java_list_format() {
        let mut s = Stack::new();
        s.push(1);
        s.push(2);
        s.push(3);
        assert_eq!(format!("{s}"), "[1, 2, 3]");
    }

    #[test]
    fn display_empty_stack() {
        let s: Stack<i32> = Stack::new();
        assert_eq!(format!("{s}"), "[]");
    }
}
