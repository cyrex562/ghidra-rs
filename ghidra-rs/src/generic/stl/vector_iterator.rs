use std::fmt;
use std::ptr::NonNull;

use super::iterator_stl::IteratorStl;

/// A random-access iterator over a growable vector, mirroring
/// `generic.stl.VectorIterator<T>` from Ghidra.
///
/// Like the Java class -- whose `data` field is a plain `ArrayList<T>`
/// reference shared with the vector's owner -- this iterator does not own its
/// backing storage. It holds a non-owning pointer to the vector plus a cursor
/// `index`, so mutations made through one iterator (or through the vector's
/// owner) are visible to every other iterator over the same vector.
pub struct VectorIterator<T> {
    pub(super) data: NonNull<Vec<T>>,
    pub(super) index: usize,
}

impl<T> VectorIterator<T> {
    /// Creates a new iterator positioned at `index` within `data`.
    ///
    /// Mirrors the Java constructor `VectorIterator(ArrayList<T> data, int index)`.
    ///
    /// # Safety
    /// `data` must be valid and non-dangling, and must not be mutated in a way
    /// that violates Rust's aliasing rules, for as long as the returned
    /// iterator -- and any iterator produced from it via [`IteratorStl::copy_iter`]
    /// or [`Clone`] -- is used.
    pub unsafe fn new(data: NonNull<Vec<T>>, index: usize) -> Self {
        Self { data, index }
    }

    /// Returns the element at `index + offset` without moving the cursor.
    ///
    /// Mirrors `VectorIterator.get(int offset)`.
    ///
    /// # Panics
    /// Panics if `index + offset` is out of bounds.
    pub fn get_offset(&self, offset: usize) -> &T {
        let data = unsafe { self.data.as_ref() };
        &data[self.index + offset]
    }

    /// Returns the current cursor position.
    ///
    /// Mirrors `getIndex()`.
    pub fn get_index(&self) -> usize {
        self.index
    }

    fn len(&self) -> usize {
        unsafe { self.data.as_ref() }.len()
    }
}

impl<T> Clone for VectorIterator<T> {
    /// Mirrors `copy()`: the clone shares the same backing vector, it does not
    /// duplicate its contents.
    fn clone(&self) -> Self {
        Self { data: self.data, index: self.index }
    }
}

impl<T> PartialEq for VectorIterator<T> {
    /// Mirrors `equals(Object)`: two iterators are equal when they reference
    /// the same backing vector and share the same cursor position.
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.index == other.index
    }
}

impl<T> fmt::Debug for VectorIterator<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VectorIterator")
            .field("data", &self.data)
            .field("index", &self.index)
            .finish()
    }
}

impl<T: fmt::Display> fmt::Display for VectorIterator<T> {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = unsafe { self.data.as_ref() };
        match data.get(self.index) {
            Some(value) => write!(f, "VectorIterator: [index={} - {}]", self.index, value),
            None => write!(f, "VectorIterator: [index={} - null]", self.index),
        }
    }
}

impl<T: 'static> IteratorStl<T> for VectorIterator<T> {
    fn get(&self) -> &T {
        let data = unsafe { self.data.as_ref() };
        &data[self.index]
    }

    fn set(&mut self, value: T) {
        let data = unsafe { self.data.as_mut() };
        data[self.index] = value;
    }

    fn increment(&mut self) {
        if self.index >= self.len() {
            panic!("VectorIterator cannot increment past the end");
        }
        self.index += 1;
    }

    fn increment_by(&mut self, n: usize) {
        if self.index + n > self.len() {
            panic!("VectorIterator cannot increment_by past the end");
        }
        self.index += n;
    }

    fn decrement(&mut self) {
        if self.index == 0 {
            panic!("VectorIterator cannot decrement past the beginning");
        }
        self.index -= 1;
    }

    fn decrement_by(&mut self, n: usize) {
        if n > self.index {
            panic!("VectorIterator cannot decrement_by past the beginning");
        }
        self.index -= n;
    }

    fn is_begin(&self) -> bool {
        self.index == 0
    }

    fn is_end(&self) -> bool {
        self.index >= self.len()
    }

    fn insert(&mut self, value: T) {
        let data = unsafe { self.data.as_mut() };
        data.insert(self.index, value);
    }

    fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
        Box::new(self.clone())
    }

    /// Synchronizes this cursor's begin/end position with `other`.
    ///
    /// The Java original downcasts `other` and copies its `data` and `index`
    /// fields verbatim, which only makes sense when `other` is actually a
    /// `VectorIterator` -- otherwise it throws `ClassCastException`. Rust
    /// trait objects cannot be downcast without extra machinery, so this only
    /// synchronizes the begin/end cursor state exposed through the
    /// [`IteratorStl`] interface. Prefer `*self = other.clone()` when both
    /// iterators are statically known to be [`VectorIterator`].
    fn assign(&mut self, other: &dyn IteratorStl<T>) {
        if other.is_end() {
            self.index = self.len();
        } else if other.is_begin() {
            self.index = 0;
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
        let it = unsafe { VectorIterator::new(ptr, 1) };
        assert_eq!(*it.get(), 20);
    }

    #[test]
    fn test_set_replaces_element() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 1) };
        it.set(99);
        assert_eq!(*it.get(), 99);
        assert_eq!(v[1], 99);
    }

    #[test]
    fn test_increment_advances() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 0) };
        it.increment();
        assert_eq!(*it.get(), 20);
    }

    #[test]
    #[should_panic(expected = "cannot increment past the end")]
    fn test_increment_panics_at_end() {
        let mut v = vec![10];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 1) };
        it.increment();
    }

    #[test]
    fn test_increment_by_skips() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 0) };
        it.increment_by(2);
        assert_eq!(*it.get(), 30);
    }

    #[test]
    #[should_panic(expected = "cannot increment_by past the end")]
    fn test_increment_by_panics_past_end() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 1) };
        it.increment_by(3);
    }

    #[test]
    fn test_decrement_retreats() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 2) };
        it.decrement();
        assert_eq!(*it.get(), 20);
    }

    #[test]
    #[should_panic(expected = "cannot decrement past the beginning")]
    fn test_decrement_panics_at_begin() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 0) };
        it.decrement();
    }

    #[test]
    fn test_decrement_by_skips_back() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 2) };
        it.decrement_by(2);
        assert_eq!(*it.get(), 10);
    }

    #[test]
    #[should_panic(expected = "cannot decrement_by past the beginning")]
    fn test_decrement_by_panics_past_beginning() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 1) };
        it.decrement_by(2);
    }

    #[test]
    fn test_is_begin_true_at_start() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 0) };
        assert!(it.is_begin());
    }

    #[test]
    fn test_is_begin_false_after_increment() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 0) };
        it.increment();
        assert!(!it.is_begin());
    }

    #[test]
    fn test_is_end_false_within_bounds() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 2) };
        assert!(!it.is_end());
    }

    #[test]
    fn test_is_end_true_at_len() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 3) };
        assert!(it.is_end());
    }

    #[test]
    fn test_insert_shifts_elements() {
        let mut v = vec![1, 3];
        let ptr = NonNull::from(&mut v);
        let mut it = unsafe { VectorIterator::new(ptr, 1) };
        it.insert(2);
        assert_eq!(*it.get(), 2);
        it.increment();
        assert_eq!(*it.get(), 3);
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_copy_iter_shares_same_backing_vector() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 0) };
        let mut copy = it.copy_iter();
        copy.set(99);
        assert_eq!(*it.get(), 99);
    }

    #[test]
    fn test_get_offset_reads_ahead() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 0) };
        assert_eq!(*it.get_offset(2), 30);
    }

    #[test]
    fn test_get_index_returns_cursor() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 2) };
        assert_eq!(it.get_index(), 2);
    }

    #[test]
    fn test_partial_eq_same_data_and_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let a = unsafe { VectorIterator::new(ptr, 1) };
        let b = unsafe { VectorIterator::new(ptr, 1) };
        assert_eq!(a, b);
    }

    #[test]
    fn test_partial_eq_false_for_different_index() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let a = unsafe { VectorIterator::new(ptr, 0) };
        let b = unsafe { VectorIterator::new(ptr, 1) };
        assert_ne!(a, b);
    }

    #[test]
    fn test_display_shows_value() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 1) };
        assert_eq!(format!("{}", it), "VectorIterator: [index=1 - 20]");
    }

    #[test]
    fn test_display_shows_null_at_end() {
        let mut v = vec![10, 20, 30];
        let ptr = NonNull::from(&mut v);
        let it = unsafe { VectorIterator::new(ptr, 3) };
        assert_eq!(format!("{}", it), "VectorIterator: [index=3 - null]");
    }

    #[test]
    fn test_assign_to_begin() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let begin = unsafe { VectorIterator::new(ptr, 0) };
        let mut it = unsafe { VectorIterator::new(ptr, 2) };
        it.assign(&begin);
        assert!(it.is_begin());
    }

    #[test]
    fn test_assign_to_end() {
        let mut v = vec![1, 2, 3];
        let ptr = NonNull::from(&mut v);
        let end = unsafe { VectorIterator::new(ptr, 3) };
        let mut it = unsafe { VectorIterator::new(ptr, 0) };
        it.assign(&end);
        assert!(it.is_end());
    }
}
