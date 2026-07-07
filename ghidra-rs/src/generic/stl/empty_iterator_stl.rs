use std::marker::PhantomData;

use super::iterator_stl::IteratorStl;

/// An iterator over an always-empty collection.
///
/// Mirrors `generic.stl.EmptyIteratorSTL<T>` from Ghidra. It is simultaneously
/// positioned at both the beginning and the end of its (nonexistent)
/// collection, so every traversal or mutation operation panics -- matching
/// the Java class, whose corresponding methods throw
/// `UnsupportedOperationException` or `IndexOutOfBoundsException`.
#[derive(Debug, Default)]
pub struct EmptyIteratorStl<T> {
    _marker: PhantomData<T>,
}

impl<T> EmptyIteratorStl<T> {
    /// Creates a new empty iterator.
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Mirrors `EmptyIteratorSTL.delete()`.
    ///
    /// # Panics
    ///
    /// Always panics; deletion is not supported.
    pub fn delete(&self) {
        panic!("EmptyIteratorStl does not support delete");
    }

    /// Mirrors `EmptyIteratorSTL.delete(int)`.
    ///
    /// # Panics
    ///
    /// Always panics; deletion is not supported.
    pub fn delete_count(&self, _count: usize) {
        panic!("EmptyIteratorStl does not support delete");
    }

    /// Mirrors `EmptyIteratorSTL.isRBegin()`. Always `true`.
    pub fn is_r_begin(&self) -> bool {
        true
    }

    /// Mirrors `EmptyIteratorSTL.isREnd()`. Always `true`.
    pub fn is_r_end(&self) -> bool {
        true
    }
}

impl<T> Clone for EmptyIteratorStl<T> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<T: 'static> IteratorStl<T> for EmptyIteratorStl<T> {
    /// # Panics
    ///
    /// Always panics; there is no element to return.
    fn get(&self) -> &T {
        panic!("EmptyIteratorStl has no element to get");
    }

    /// # Panics
    ///
    /// Always panics; setting is not supported.
    fn set(&mut self, _value: T) {
        panic!("EmptyIteratorStl does not support set");
    }

    /// # Panics
    ///
    /// Always panics; the iterator is already past the last element.
    fn increment(&mut self) {
        panic!("EmptyIteratorStl cannot increment past the end");
    }

    /// # Panics
    ///
    /// Always panics; advancing by `n` is not supported.
    fn increment_by(&mut self, _n: usize) {
        panic!("EmptyIteratorStl does not support increment_by");
    }

    /// # Panics
    ///
    /// Always panics; the iterator is already before the first element.
    fn decrement(&mut self) {
        panic!("EmptyIteratorStl cannot decrement past the beginning");
    }

    /// # Panics
    ///
    /// Always panics; retreating by `n` is not supported.
    fn decrement_by(&mut self, _n: usize) {
        panic!("EmptyIteratorStl does not support decrement_by");
    }

    fn is_begin(&self) -> bool {
        true
    }

    fn is_end(&self) -> bool {
        true
    }

    /// # Panics
    ///
    /// Always panics; insertion is not supported.
    fn insert(&mut self, _value: T) {
        panic!("EmptyIteratorStl does not support insert");
    }

    fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
        Box::new(Self::new())
    }

    /// # Panics
    ///
    /// Always panics; assignment is not supported.
    fn assign(&mut self, _other: &dyn IteratorStl<T>) {
        panic!("EmptyIteratorStl does not support assign");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_begin_always_true() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        assert!(it.is_begin());
    }

    #[test]
    fn test_is_end_always_true() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        assert!(it.is_end());
    }

    #[test]
    fn test_is_r_begin_always_true() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        assert!(it.is_r_begin());
    }

    #[test]
    fn test_is_r_end_always_true() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        assert!(it.is_r_end());
    }

    #[test]
    fn test_copy_iter_is_also_empty() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        let copy = it.copy_iter();
        assert!(copy.is_begin());
        assert!(copy.is_end());
    }

    #[test]
    #[should_panic(expected = "has no element to get")]
    fn test_get_panics() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.get();
    }

    #[test]
    #[should_panic(expected = "does not support set")]
    fn test_set_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.set(1);
    }

    #[test]
    #[should_panic(expected = "cannot increment past the end")]
    fn test_increment_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.increment();
    }

    #[test]
    #[should_panic(expected = "does not support increment_by")]
    fn test_increment_by_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.increment_by(1);
    }

    #[test]
    #[should_panic(expected = "cannot decrement past the beginning")]
    fn test_decrement_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.decrement();
    }

    #[test]
    #[should_panic(expected = "does not support decrement_by")]
    fn test_decrement_by_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.decrement_by(1);
    }

    #[test]
    #[should_panic(expected = "does not support insert")]
    fn test_insert_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.insert(1);
    }

    #[test]
    #[should_panic(expected = "does not support assign")]
    fn test_assign_panics() {
        let mut it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        let other: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.assign(&other);
    }

    #[test]
    #[should_panic(expected = "does not support delete")]
    fn test_delete_panics() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.delete();
    }

    #[test]
    #[should_panic(expected = "does not support delete")]
    fn test_delete_count_panics() {
        let it: EmptyIteratorStl<i32> = EmptyIteratorStl::new();
        it.delete_count(5);
    }
}
