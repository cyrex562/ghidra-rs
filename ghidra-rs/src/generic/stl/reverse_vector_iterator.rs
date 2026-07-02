use std::fmt;
use std::ptr::NonNull;

use super::iterator_stl::IteratorStl;

/// A random-access iterator that walks a growable vector back-to-front,
/// mirroring `generic.stl.ReverseVectorIterator<T>` from Ghidra.
///
/// Like [`VectorIterator`](super::vector_iterator::VectorIterator) -- whose
/// `data`/`index` fields the Java class reuses via subclassing -- this
/// iterator does not own its backing storage; it holds a non-owning pointer
/// to the vector plus a cursor `index`. The cursor still names a position in
/// the underlying vector, but traversal runs in the opposite direction:
/// `increment` moves the cursor toward index `0`, `decrement` moves it back
/// toward the last element, and the cursor can legitimately sit one before
/// the front of the vector (index `-1`) to represent the reverse-end
/// position -- hence `index` is signed here, unlike `VectorIterator`'s
/// unsigned cursor.
pub struct ReverseVectorIterator<T> {
    pub(super) data: NonNull<Vec<T>>,
    pub(super) index: isize,
}

impl<T> ReverseVectorIterator<T> {
    /// Creates a new reverse iterator positioned at `index` within `data`.
    ///
    /// Mirrors the Java constructor `ReverseVectorIterator(ArrayList<T> data, int index)`.
    /// Callers typically pass `data.len() - 1` (reverse begin) or `-1`
    /// (reverse end), matching `VectorSTL.rbegin()`/`rend()`.
    ///
    /// # Safety
    /// `data` must be valid and non-dangling, and must not be mutated in a way
    /// that violates Rust's aliasing rules, for as long as the returned
    /// iterator -- and any iterator produced from it via [`IteratorStl::copy_iter`]
    /// or [`Clone`] -- is used.
    pub unsafe fn new(data: NonNull<Vec<T>>, index: isize) -> Self {
        Self { data, index }
    }

    /// Returns the element `offset` positions ahead of the cursor in
    /// traversal order (i.e. at underlying index `index - offset`) without
    /// moving the cursor.
    ///
    /// Mirrors `ReverseVectorIterator.get(int offset)`.
    ///
    /// # Panics
    /// Panics if `index - offset` is out of bounds.
    pub fn get_offset(&self, offset: usize) -> &T {
        let data = unsafe { self.data.as_ref() };
        &data[(self.index - offset as isize) as usize]
    }

    /// Returns the current cursor position, which may be `-1` at the
    /// reverse-end position.
    ///
    /// Mirrors `getIndex()`.
    pub fn get_index(&self) -> isize {
        self.index
    }

    /// Removes `count` elements from the backing vector.
    ///
    /// Mirrors `ReverseVectorIterator.delete(int count)` verbatim, including
    /// its upstream quirk: the removed range is `[index - count + 1, count)`
    /// rather than `[index - count + 1, index + 1)`, so the elements
    /// actually removed depend on both the cursor position and `count` in a
    /// way that only matches "delete `count` elements ending at the cursor"
    /// for particular combinations of the two.
    ///
    /// # Panics
    /// Panics if `index < count - 1`, or if the resulting range is invalid.
    pub fn delete(&mut self, count: usize) {
        let count = count as isize;
        if self.index < count - 1 {
            panic!("ReverseVectorIterator delete index out of bounds");
        }
        let data = unsafe { self.data.as_mut() };
        let from = (self.index - count + 1) as usize;
        let to = count as usize;
        data.drain(from..to);
    }

    fn len(&self) -> usize {
        unsafe { self.data.as_ref() }.len()
    }
}

impl<T> Clone for ReverseVectorIterator<T> {
    /// Mirrors `copy()`: the clone shares the same backing vector, it does not
    /// duplicate its contents.
    fn clone(&self) -> Self {
        Self { data: self.data, index: self.index }
    }
}

impl<T> PartialEq for ReverseVectorIterator<T> {
    /// Mirrors `equals(Object)`: two iterators are equal when they reference
    /// the same backing vector and share the same cursor position.
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.index == other.index
    }
}

impl<T> fmt::Debug for ReverseVectorIterator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReverseVectorIterator")
            .field("data", &self.data)
            .field("index", &self.index)
            .finish()
    }
}

impl<T: fmt::Display> fmt::Display for ReverseVectorIterator<T> {
    /// Mirrors the inherited `VectorIterator.toString()`, which
    /// `ReverseVectorIterator` does not override in Java: it indexes `data`
    /// at the raw cursor position, so -- like the Java original -- this
    /// panics rather than printing `null` when the cursor is at the
    /// reverse-end position (`index < 0`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = unsafe { self.data.as_ref() };
        if self.index >= data.len() as isize {
            write!(f, "VectorIterator: [index={} - null]", self.index)
        } else {
            write!(f, "VectorIterator: [index={} - {}]", self.index, data[self.index as usize])
        }
    }
}

impl<T: 'static> IteratorStl<T> for ReverseVectorIterator<T> {
    fn get(&self) -> &T {
        let data = unsafe { self.data.as_ref() };
        &data[self.index as usize]
    }

    fn set(&mut self, value: T) {
        let data = unsafe { self.data.as_mut() };
        let i = self.index as usize;
        data[i] = value;
    }

    fn increment(&mut self) {
        if self.index < 0 {
            panic!("ReverseVectorIterator cannot increment past the end");
        }
        self.index -= 1;
    }

    fn increment_by(&mut self, n: usize) {
        let n = n as isize;
        if self.index - n < -1 {
            panic!("ReverseVectorIterator cannot increment_by past the end");
        }
        self.index -= n;
    }

    fn decrement(&mut self) {
        if self.index == self.len() as isize - 1 {
            panic!("ReverseVectorIterator cannot decrement past the beginning");
        }
        self.index += 1;
    }

    fn decrement_by(&mut self, n: usize) {
        let n = n as isize;
        if self.index + n >= self.len() as isize {
            panic!("ReverseVectorIterator cannot decrement_by past the beginning");
        }
        self.index += n;
    }

    fn is_begin(&self) -> bool {
        self.index == self.len() as isize - 1
    }

    fn is_end(&self) -> bool {
        self.index < 0
    }

    fn insert(&mut self, value: T) {
        let data = unsafe { self.data.as_mut() };
        data.insert(self.index as usize, value);
    }

    fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
        Box::new(self.clone())
    }

    /// Synchronizes this cursor's reverse begin/end position with `other`.
    ///
    /// The Java original inherits `VectorIterator.assign`, which downcasts
    /// `other` and copies its `data`/`index` fields verbatim -- only
    /// meaningful when `other` really is a `VectorIterator` (or subclass).
    /// Rust trait objects cannot be downcast without extra machinery, so
    /// this only synchronizes the begin/end cursor state exposed through the
    /// [`IteratorStl`] interface, using this type's own (reversed) begin/end
    /// positions. Prefer `*self = other.clone()` when both iterators are
    /// statically known to be [`ReverseVectorIterator`].
    fn assign(&mut self, other: &dyn IteratorStl<T>) {
        if other.is_end() {
            self.index = -1;
        } else if other.is_begin() {
            self.index = self.len() as isize - 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_returns_element_at_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        assert_eq!(*it.get(), 30);
    }

    #[test]
    fn test_set_replaces_element() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        it.set(99);
        assert_eq!(*it.get(), 99);
        assert_eq!(v[1], 99);
    }

    #[test]
    fn test_increment_walks_backward_through_vector() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        assert_eq!(*it.get(), 30);
        it.increment();
        assert_eq!(*it.get(), 20);
        it.increment();
        assert_eq!(*it.get(), 10);
    }

    #[test]
    #[should_panic(expected = "cannot increment past the end")]
    fn test_increment_panics_at_end() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, -1) };
        it.increment();
    }

    #[test]
    fn test_increment_by_skips() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        it.increment_by(2);
        assert_eq!(*it.get(), 10);
    }

    #[test]
    #[should_panic(expected = "cannot increment_by past the end")]
    fn test_increment_by_panics_past_end() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        it.increment_by(3);
    }

    #[test]
    fn test_decrement_retreats_toward_last_element() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        it.decrement();
        assert_eq!(*it.get(), 30);
    }

    #[test]
    #[should_panic(expected = "cannot decrement past the beginning")]
    fn test_decrement_panics_at_begin() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        it.decrement();
    }

    #[test]
    fn test_decrement_by_skips_back() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 0) };
        it.decrement_by(2);
        assert_eq!(*it.get(), 30);
    }

    #[test]
    #[should_panic(expected = "cannot decrement_by past the beginning")]
    fn test_decrement_by_panics_past_beginning() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        it.decrement_by(2);
    }

    #[test]
    fn test_is_begin_true_at_rbegin() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        assert!(it.is_begin());
    }

    #[test]
    fn test_is_begin_false_after_increment() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        it.increment();
        assert!(!it.is_begin());
    }

    #[test]
    fn test_is_end_false_within_bounds() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 0) };
        assert!(!it.is_end());
    }

    #[test]
    fn test_is_end_true_at_negative_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, -1) };
        assert!(it.is_end());
    }

    #[test]
    fn test_insert_shifts_elements() {
        let mut v = vec![10, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 0) };
        it.insert(20);
        assert_eq!(*it.get(), 20);
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn test_copy_iter_shares_same_backing_vector() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        let mut copy = it.copy_iter();
        copy.set(99);
        assert_eq!(*it.get(), 99);
    }

    #[test]
    fn test_get_offset_reads_toward_front() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        assert_eq!(*it.get_offset(0), 30);
        assert_eq!(*it.get_offset(1), 20);
        assert_eq!(*it.get_offset(2), 10);
    }

    #[test]
    fn test_get_index_returns_cursor() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        assert_eq!(it.get_index(), 2);
    }

    #[test]
    fn test_get_index_can_be_negative_at_end() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, -1) };
        assert_eq!(it.get_index(), -1);
    }

    #[test]
    fn test_delete_removes_java_computed_range() {
        // Matches the literal Java behavior of `delete(int count)`, which
        // clears `data.subList(index - count + 1, count)`.
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        it.delete(2);
        assert_eq!(v, vec![30]);
    }

    #[test]
    #[should_panic(expected = "delete index out of bounds")]
    fn test_delete_panics_when_index_too_small() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 0) };
        it.delete(3);
    }

    #[test]
    fn test_partial_eq_same_data_and_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let a = unsafe { ReverseVectorIterator::new(ptr, 1) };
        let b = unsafe { ReverseVectorIterator::new(ptr, 1) };
        assert_eq!(a, b);
    }

    #[test]
    fn test_partial_eq_false_for_different_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let a = unsafe { ReverseVectorIterator::new(ptr, 0) };
        let b = unsafe { ReverseVectorIterator::new(ptr, 1) };
        assert_ne!(a, b);
    }

    #[test]
    fn test_display_shows_value() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, 1) };
        assert_eq!(format!("{}", it), "VectorIterator: [index=1 - 20]");
    }

    #[test]
    #[should_panic]
    fn test_display_panics_at_negative_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { ReverseVectorIterator::new(ptr, -1) };
        let _ = format!("{}", it);
    }

    #[test]
    fn test_assign_to_begin() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let begin = unsafe { ReverseVectorIterator::new(ptr, 2) };
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 0) };
        it.assign(&begin);
        assert!(it.is_begin());
    }

    #[test]
    fn test_assign_to_end() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let end = unsafe { ReverseVectorIterator::new(ptr, -1) };
        let mut it = unsafe { ReverseVectorIterator::new(ptr, 2) };
        it.assign(&end);
        assert!(it.is_end());
    }
}
