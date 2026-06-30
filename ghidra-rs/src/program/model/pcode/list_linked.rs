use std::cell::{Ref, RefCell};

/// Index of the sentinel (terminal) node; always slot 0 in the arena.
const TERMINAL: usize = 0;

struct Node<T> {
    data: Option<T>,
    prev: usize,
    next: usize,
}

struct ListArena<T> {
    nodes: Vec<Node<T>>,
    free: Vec<usize>,
}

impl<T> ListArena<T> {
    fn new() -> Self {
        Self {
            // Slot 0 is the sentinel; it points to itself when the list is empty.
            nodes: vec![Node { data: None, prev: TERMINAL, next: TERMINAL }],
            free: Vec::new(),
        }
    }

    fn alloc(&mut self, data: T, prev: usize, next: usize) -> usize {
        if let Some(idx) = self.free.pop() {
            self.nodes[idx] = Node { data: Some(data), prev, next };
            idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(Node { data: Some(data), prev, next });
            idx
        }
    }

    fn dealloc(&mut self, idx: usize) {
        self.nodes[idx].data = None;
        self.free.push(idx);
    }
}

/// A doubly-linked list with stable cursors.
///
/// Cursors ([`LinkedIter`]) remain valid across insertions and removals of
/// *other* nodes. This mirrors Ghidra's `ListLinked<T>`, whose primary
/// advantage over `java.util.LinkedList` is that existing iterators are not
/// invalidated when the list is modified.
///
/// All mutation methods use interior mutability (`RefCell`). Callers must not
/// hold a live [`Ref`] returned by [`first`][Self::first], [`last`][Self::last],
/// or [`next_val`][Self::next_val] when calling any mutating method, or a
/// runtime panic will occur.
pub struct ListLinked<T> {
    inner: RefCell<ListArena<T>>,
}

/// A cursor into a [`ListLinked`].
///
/// A cursor identifies a specific node in the list by a slot index. It is
/// `Copy`, so cloning is cheap. Cursors that pointed at a removed node become
/// dangling and should not be used after removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkedIter {
    cur: usize,
}

impl<T> ListLinked<T> {
    pub fn new() -> Self {
        Self { inner: RefCell::new(ListArena::new()) }
    }

    /// Add `data` to the end of the list.
    ///
    /// Any existing cursors remain valid. Returns a cursor to the new node.
    pub fn add(&self, data: T) -> LinkedIter {
        let mut a = self.inner.borrow_mut();
        let prev = a.nodes[TERMINAL].prev;
        let idx = a.alloc(data, prev, TERMINAL);
        a.nodes[prev].next = idx;
        a.nodes[TERMINAL].prev = idx;
        LinkedIter { cur: idx }
    }

    /// Insert `data` immediately after the node at `cursor`.
    ///
    /// All other cursors remain valid. Returns a cursor to the new node.
    pub fn insert_after(&self, cursor: &LinkedIter, data: T) -> LinkedIter {
        let mut a = self.inner.borrow_mut();
        let c = cursor.cur;
        let next = a.nodes[c].next;
        let idx = a.alloc(data, c, next);
        a.nodes[next].prev = idx;
        a.nodes[c].next = idx;
        LinkedIter { cur: idx }
    }

    /// Insert `data` immediately before the node at `cursor`.
    ///
    /// All other cursors remain valid. Returns a cursor to the new node.
    pub fn insert_before(&self, cursor: &LinkedIter, data: T) -> LinkedIter {
        let mut a = self.inner.borrow_mut();
        let c = cursor.cur;
        let prev = a.nodes[c].prev;
        let idx = a.alloc(data, prev, c);
        a.nodes[prev].next = idx;
        a.nodes[c].prev = idx;
        LinkedIter { cur: idx }
    }

    /// Remove the node pointed to by `cursor`.
    ///
    /// If `cursor` points to the terminal (e.g. the value returned by
    /// [`iterator`][Self::iterator] before any advancement), this is a no-op.
    /// All cursors that do not point to the removed node remain valid.
    pub fn remove(&self, cursor: &LinkedIter) {
        let mut a = self.inner.borrow_mut();
        let c = cursor.cur;
        if a.nodes[c].data.is_none() {
            return;
        }
        let prev = a.nodes[c].prev;
        let next = a.nodes[c].next;
        a.nodes[prev].next = next;
        a.nodes[next].prev = prev;
        a.dealloc(c);
    }

    /// Returns a cursor positioned before the first element (at the terminal).
    ///
    /// Use together with [`has_next`][Self::has_next] and
    /// [`next_val`][Self::next_val] to walk the list forward.
    pub fn iterator(&self) -> LinkedIter {
        LinkedIter { cur: TERMINAL }
    }

    /// Returns `true` when there is an element after `cursor`'s current position.
    pub fn has_next(&self, cursor: &LinkedIter) -> bool {
        let a = self.inner.borrow();
        a.nodes[a.nodes[cursor.cur].next].data.is_some()
    }

    /// Advances `cursor` to the next element and returns a borrowed reference to it.
    ///
    /// Returns `None` if there is no next element. The returned [`Ref`] holds a
    /// shared borrow of the list; drop it before calling any mutating method.
    pub fn next_val<'a>(&'a self, cursor: &mut LinkedIter) -> Option<Ref<'a, T>> {
        let borrow = self.inner.borrow();
        let next_idx = borrow.nodes[cursor.cur].next;
        if borrow.nodes[next_idx].data.is_none() {
            return None;
        }
        cursor.cur = next_idx;
        Some(Ref::map(borrow, |a| a.nodes[next_idx].data.as_ref().unwrap()))
    }

    /// Returns `true` when the cursor is positioned at a data element
    /// (i.e., it has not yet been stepped backwards past the first element).
    pub fn has_previous(&self, cursor: &LinkedIter) -> bool {
        let a = self.inner.borrow();
        a.nodes[cursor.cur].data.is_some()
    }

    /// Moves `cursor` backwards and returns a borrowed reference to the element
    /// that the cursor was pointing at before the move.
    ///
    /// This matches Java's `LinkedIterator.previous()` semantics: step
    /// backwards, then return the data at where you were. Returns `None` if
    /// `cursor` is at the terminal.
    pub fn previous_val<'a>(&'a self, cursor: &mut LinkedIter) -> Option<Ref<'a, T>> {
        let borrow = self.inner.borrow();
        let was_cur = cursor.cur;
        if borrow.nodes[was_cur].data.is_none() {
            return None;
        }
        cursor.cur = borrow.nodes[was_cur].prev;
        Some(Ref::map(borrow, |a| a.nodes[was_cur].data.as_ref().unwrap()))
    }

    /// Removes the element at `cursor` and moves the cursor to the preceding node.
    ///
    /// This matches Java's `LinkedIterator.remove()`. If `cursor` points to the
    /// terminal, this is a no-op.
    pub fn remove_at(&self, cursor: &mut LinkedIter) {
        let mut a = self.inner.borrow_mut();
        let c = cursor.cur;
        if a.nodes[c].data.is_none() {
            return;
        }
        let prev = a.nodes[c].prev;
        let next = a.nodes[c].next;
        a.nodes[prev].next = next;
        a.nodes[next].prev = prev;
        a.dealloc(c);
        cursor.cur = prev;
    }

    /// Remove all entries from the list.
    pub fn clear(&self) {
        let mut a = self.inner.borrow_mut();
        a.nodes[TERMINAL].next = TERMINAL;
        a.nodes[TERMINAL].prev = TERMINAL;
        a.nodes.truncate(1);
        a.free.clear();
    }

    /// Returns a borrowed reference to the first element, or `None` if empty.
    pub fn first(&self) -> Option<Ref<'_, T>> {
        let borrow = self.inner.borrow();
        let first_idx = borrow.nodes[TERMINAL].next;
        if first_idx == TERMINAL {
            return None;
        }
        Some(Ref::map(borrow, |a| a.nodes[first_idx].data.as_ref().unwrap()))
    }

    /// Returns a borrowed reference to the last element, or `None` if empty.
    pub fn last(&self) -> Option<Ref<'_, T>> {
        let borrow = self.inner.borrow();
        let last_idx = borrow.nodes[TERMINAL].prev;
        if last_idx == TERMINAL {
            return None;
        }
        Some(Ref::map(borrow, |a| a.nodes[last_idx].data.as_ref().unwrap()))
    }
}

impl<T> Default for ListLinked<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect<T: Copy>(list: &ListLinked<T>) -> Vec<T> {
        let mut out = Vec::new();
        let mut cursor = list.iterator();
        while list.has_next(&cursor) {
            let v = list.next_val(&mut cursor).unwrap();
            out.push(*v);
            drop(v);
        }
        out
    }

    #[test]
    fn test_empty_list() {
        let list: ListLinked<i32> = ListLinked::new();
        assert!(list.first().is_none());
        assert!(list.last().is_none());
        let cursor = list.iterator();
        assert!(!list.has_next(&cursor));
    }

    #[test]
    fn test_add_single() {
        let list = ListLinked::new();
        list.add(42i32);
        assert_eq!(*list.first().unwrap(), 42);
        assert_eq!(*list.last().unwrap(), 42);
    }

    #[test]
    fn test_add_multiple_ordering() {
        let list = ListLinked::new();
        list.add(1i32);
        list.add(2);
        list.add(3);
        assert_eq!(*list.first().unwrap(), 1);
        assert_eq!(*list.last().unwrap(), 3);
        assert_eq!(collect(&list), vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_after() {
        let list = ListLinked::new();
        let c1 = list.add(1i32);
        list.add(3);
        list.insert_after(&c1, 2);
        assert_eq!(collect(&list), vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_after_at_terminal_prepends() {
        let list = ListLinked::new();
        list.add(2i32);
        list.add(3);
        let term = list.iterator();
        list.insert_after(&term, 1);
        assert_eq!(collect(&list), vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_before() {
        let list = ListLinked::new();
        list.add(1i32);
        let c3 = list.add(3);
        list.insert_before(&c3, 2);
        assert_eq!(collect(&list), vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_before_terminal_appends() {
        let list = ListLinked::new();
        list.add(1i32);
        list.add(2);
        let term = list.iterator();
        list.insert_before(&term, 3);
        assert_eq!(collect(&list), vec![1, 2, 3]);
    }

    #[test]
    fn test_remove_middle() {
        let list = ListLinked::new();
        list.add(1i32);
        let c2 = list.add(2);
        list.add(3);
        list.remove(&c2);
        assert_eq!(collect(&list), vec![1, 3]);
        assert_eq!(*list.first().unwrap(), 1);
        assert_eq!(*list.last().unwrap(), 3);
    }

    #[test]
    fn test_remove_first() {
        let list = ListLinked::new();
        let c1 = list.add(1i32);
        list.add(2);
        list.remove(&c1);
        assert_eq!(collect(&list), vec![2]);
    }

    #[test]
    fn test_remove_last() {
        let list = ListLinked::new();
        list.add(1i32);
        let c2 = list.add(2);
        list.remove(&c2);
        assert_eq!(collect(&list), vec![1]);
    }

    #[test]
    fn test_remove_terminal_is_noop() {
        let list = ListLinked::new();
        list.add(1i32);
        let term = list.iterator();
        list.remove(&term);
        assert_eq!(collect(&list), vec![1]);
    }

    #[test]
    fn test_remove_at_advances_cursor_backward() {
        let list = ListLinked::new();
        list.add(1i32);
        list.add(2);
        list.add(3);

        let mut cursor = list.iterator();
        drop(list.next_val(&mut cursor).unwrap()); // at 1
        drop(list.next_val(&mut cursor).unwrap()); // at 2
        list.remove_at(&mut cursor); // remove 2, cursor moves to 1
        assert_eq!(collect(&list), vec![1, 3]);
        // cursor is now at node 1; has_next should see node 3
        assert!(list.has_next(&cursor));
    }

    #[test]
    fn test_has_previous_and_previous_val() {
        let list = ListLinked::new();
        list.add(10i32);
        list.add(20);
        let mut cursor = list.iterator();
        assert!(!list.has_previous(&cursor));

        drop(list.next_val(&mut cursor).unwrap()); // advance to 10
        assert!(list.has_previous(&cursor));

        drop(list.next_val(&mut cursor).unwrap()); // advance to 20
        // previous_val moves cursor back to 10, returns 20
        let v = list.previous_val(&mut cursor).unwrap();
        assert_eq!(*v, 20);
        drop(v);
        // cursor is now at node 10
        assert!(list.has_previous(&cursor));
    }

    #[test]
    fn test_previous_val_at_terminal_returns_none() {
        let list = ListLinked::new();
        list.add(1i32);
        let mut cursor = list.iterator();
        assert!(list.previous_val(&mut cursor).is_none());
        assert_eq!(cursor, list.iterator()); // cursor did not move
    }

    #[test]
    fn test_clear() {
        let list = ListLinked::new();
        list.add(1i32);
        list.add(2);
        list.clear();
        assert!(list.first().is_none());
        assert!(list.last().is_none());
        assert!(!list.has_next(&list.iterator()));
    }

    #[test]
    fn test_add_after_clear_reuses_arena() {
        let list = ListLinked::new();
        list.add(1i32);
        list.add(2);
        list.clear();
        list.add(3);
        assert_eq!(collect(&list), vec![3]);
    }

    #[test]
    fn test_cursor_stable_across_other_insertions() {
        let list = ListLinked::new();
        let c1 = list.add(1i32);
        let c3 = list.add(3);
        list.insert_after(&c1, 2);
        // c1 still points to 1, c3 still points to 3
        assert_eq!(list.inner.borrow().nodes[c1.cur].data, Some(1));
        assert_eq!(list.inner.borrow().nodes[c3.cur].data, Some(3));
    }

    #[test]
    fn test_add_returns_cursor_to_new_node() {
        let list = ListLinked::new();
        let c = list.add(99i32);
        assert_eq!(list.inner.borrow().nodes[c.cur].data, Some(99));
    }

    #[test]
    fn test_iterator_default() {
        let list: ListLinked<i32> = ListLinked::default();
        assert!(list.first().is_none());
    }
}
