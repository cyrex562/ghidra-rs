use std::cmp::Ordering;
use std::fmt;
use std::ptr::NonNull;

use super::iterator_stl::IteratorStl;
use super::reverse_vector_iterator::ReverseVectorIterator;
use super::vector_iterator::VectorIterator;

/// A growable, random-access sequence, mirroring `generic.stl.VectorSTL<T>`
/// from Ghidra.
///
/// This is a thin wrapper around [`Vec<T>`] that exposes the STL-flavored API
/// the Java class provides (`push_back`, `begin`/`end`, `lower_bound`, ...)
/// so ports of code written against the Java `VectorSTL` translate directly.
pub struct VectorStl<T> {
    data: Vec<T>,
}

impl<T> VectorStl<T> {
    /// Creates an empty vector.
    ///
    /// Mirrors the Java no-arg constructor.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Creates an empty vector with room for `initial_capacity` elements
    /// before it needs to reallocate.
    ///
    /// Mirrors the Java `VectorSTL(int initialCapacity)` constructor.
    pub fn with_capacity(initial_capacity: usize) -> Self {
        Self { data: Vec::with_capacity(initial_capacity) }
    }

    /// Ensures the vector can hold at least `capacity` elements without
    /// reallocating.
    ///
    /// Mirrors `reserve(int)`.
    pub fn reserve(&mut self, capacity: usize) {
        self.data.reserve(capacity.saturating_sub(self.data.len()));
    }

    /// Returns a forward iterator positioned at the first element.
    ///
    /// Mirrors `begin()`.
    ///
    /// # Safety contract
    /// The returned iterator holds a non-owning pointer into this vector's
    /// storage (see [`VectorIterator`]). Do not move or drop this `VectorStl`,
    /// and take care with concurrent mutation through other handles, while
    /// the returned iterator is in use.
    pub fn begin(&mut self) -> VectorIterator<T> {
        let ptr = NonNull::from(&mut self.data);
        unsafe { VectorIterator::new(ptr, 0) }
    }

    /// Returns a forward iterator positioned one past the last element.
    ///
    /// Mirrors `end()`. See [`VectorStl::begin`] for the safety contract.
    pub fn end(&mut self) -> VectorIterator<T> {
        let len = self.data.len();
        let ptr = NonNull::from(&mut self.data);
        unsafe { VectorIterator::new(ptr, len) }
    }

    /// Returns a reverse iterator positioned at the last element.
    ///
    /// Mirrors `rBegin()`. See [`VectorStl::begin`] for the safety contract.
    pub fn r_begin(&mut self) -> ReverseVectorIterator<T> {
        let index = self.data.len() as isize - 1;
        let ptr = NonNull::from(&mut self.data);
        unsafe { ReverseVectorIterator::new(ptr, index) }
    }

    /// Returns a reverse iterator positioned one before the first element.
    ///
    /// Mirrors `rEnd()`. See [`VectorStl::begin`] for the safety contract.
    pub fn r_end(&mut self) -> ReverseVectorIterator<T> {
        let ptr = NonNull::from(&mut self.data);
        unsafe { ReverseVectorIterator::new(ptr, -1) }
    }

    /// Removes all elements.
    ///
    /// Mirrors `clear()`.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Returns the number of elements.
    ///
    /// Mirrors `size()`.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the vector has no elements.
    ///
    /// Mirrors `empty()`.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the element at `index`.
    ///
    /// Mirrors `get(int)`.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn get(&self, index: usize) -> &T {
        &self.data[index]
    }

    /// Returns a reference to the first element.
    ///
    /// Mirrors `front()`.
    ///
    /// # Panics
    /// Panics if the vector is empty.
    pub fn front(&self) -> &T {
        &self.data[0]
    }

    /// Returns a reference to the last element.
    ///
    /// Mirrors `back()`.
    ///
    /// # Panics
    /// Panics if the vector is empty.
    pub fn back(&self) -> &T {
        &self.data[self.data.len() - 1]
    }

    /// Replaces the last element with `value`.
    ///
    /// Mirrors `setBack(T)`.
    ///
    /// # Panics
    /// Panics if the vector is empty.
    pub fn set_back(&mut self, value: T) {
        let last = self.data.len() - 1;
        self.data[last] = value;
    }

    /// Appends `value` to the end.
    ///
    /// Mirrors `push_back(T)`.
    pub fn push_back(&mut self, value: T) {
        self.data.push(value);
    }

    /// Removes and returns the last element.
    ///
    /// Mirrors `pop_back()`.
    ///
    /// # Panics
    /// Panics if the vector is empty.
    pub fn pop_back(&mut self) -> T {
        self.data.pop().expect("VectorStl::pop_back called on an empty vector")
    }

    /// Inserts `value` at `index`, shifting later elements back.
    ///
    /// Mirrors `insert(int, T)`.
    ///
    /// # Panics
    /// Panics if `index > size()`.
    pub fn insert(&mut self, index: usize, value: T) {
        self.data.insert(index, value);
    }

    /// Inserts `value` at the position named by `pos`, shifting later
    /// elements back.
    ///
    /// Mirrors `insert(IteratorSTL<T>, T)`. The Java original downcasts the
    /// iterator argument to `VectorIterator` at runtime (throwing
    /// `ClassCastException` otherwise); this takes a [`VectorIterator`]
    /// directly instead, since Rust cannot downcast a `dyn IteratorStl` back
    /// to its concrete type.
    ///
    /// # Panics
    /// Panics if `pos`'s index is out of bounds for this vector.
    pub fn insert_at(&mut self, pos: &VectorIterator<T>, value: T) {
        self.data.insert(pos.get_index(), value);
    }

    /// Inserts every element of `list` at the position named by `pos`,
    /// shifting later elements back.
    ///
    /// Mirrors `insert(IteratorSTL<T>, T[])`.
    ///
    /// # Panics
    /// Panics if `pos`'s index is out of bounds for this vector.
    pub fn insert_slice(&mut self, pos: &VectorIterator<T>, list: &[T])
    where
        T: Clone,
    {
        let index = pos.get_index();
        self.data.splice(index..index, list.iter().cloned());
    }

    /// Appends every element of `vector` to the end.
    ///
    /// Mirrors `appendAll(VectorSTL<T>)`.
    pub fn append_all(&mut self, vector: &VectorStl<T>)
    where
        T: Clone,
    {
        self.data.extend(vector.data.iter().cloned());
    }

    /// Inserts every element of `vector` at the position named by `pos`,
    /// shifting later elements back.
    ///
    /// Mirrors `insertAll(IteratorSTL<T>, VectorSTL<T>)`. See
    /// [`VectorStl::insert_at`] for why this takes a [`VectorIterator`]
    /// directly rather than a `dyn IteratorStl`.
    ///
    /// # Panics
    /// Panics if `pos`'s index is out of bounds for this vector.
    pub fn insert_all(&mut self, pos: &VectorIterator<T>, vector: &VectorStl<T>)
    where
        T: Clone,
    {
        let index = pos.get_index();
        self.data.splice(index..index, vector.data.iter().cloned());
    }

    /// Replaces the element at `index` with `value`.
    ///
    /// Mirrors `set(int, T)`.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn set(&mut self, index: usize, value: T) {
        self.data[index] = value;
    }

    /// Replaces the element at the position named by `iter` with `value`.
    ///
    /// Mirrors `set(IteratorSTL<T>, T)`. See [`VectorStl::insert_at`] for why
    /// this takes a [`VectorIterator`] directly rather than a `dyn IteratorStl`.
    ///
    /// # Panics
    /// Panics if `iter`'s index is out of bounds for this vector.
    pub fn set_at(&mut self, iter: &VectorIterator<T>, value: T) {
        self.data[iter.get_index()] = value;
    }

    /// Removes and returns the element at `index`, shifting later elements
    /// forward.
    ///
    /// Mirrors `erase(int)`.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn erase(&mut self, index: usize) -> T {
        self.data.remove(index)
    }

    /// Removes the element at the position named by `iter`, shifting later
    /// elements forward, and returns the removed value.
    ///
    /// Mirrors `erase(IteratorSTL<T>)`. The Java original returns the same
    /// (now-shifted) iterator; since Rust ownership already leaves the
    /// caller holding `iter`, this returns the removed element instead,
    /// which callers cannot otherwise recover.
    ///
    /// # Panics
    /// Panics if `iter`'s index is out of bounds for this vector.
    pub fn erase_at(&mut self, iter: &VectorIterator<T>) -> T {
        self.data.remove(iter.get_index())
    }

    /// Removes the elements in `[start, end)`, shifting later elements
    /// forward.
    ///
    /// Mirrors `erase(IteratorSTL<T>, IteratorSTL<T>)`.
    ///
    /// # Panics
    /// Panics if `end`'s index precedes `start`'s index, or either index is
    /// out of bounds for this vector.
    pub fn erase_range(&mut self, start: &VectorIterator<T>, end: &VectorIterator<T>) {
        let from = start.get_index();
        let to = end.get_index();
        if to < from {
            panic!("end is before start");
        }
        self.data.drain(from..to);
    }

    /// Sorts the vector using `T`'s natural ordering.
    ///
    /// Mirrors `sort()`. The Java original throws `UnsupportedOperationException`
    /// at runtime if `T` is not `Comparable`; here the `Ord` bound enforces
    /// that at compile time instead.
    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.data.sort();
    }

    /// Sorts the vector using `compare`.
    ///
    /// Mirrors `sort(Comparator<T>)`.
    pub fn sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        self.data.sort_by(compare);
    }

    /// Returns an independent copy of this vector.
    ///
    /// Mirrors `copy()`.
    pub fn copy(&self) -> Self
    where
        T: Clone,
    {
        Self { data: self.data.clone() }
    }

    /// Returns an iterator over references to the elements, in order.
    ///
    /// Mirrors `iterator()` (`Iterable<T>`).
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.data.iter()
    }

    /// Grows or shrinks the vector to `size` elements, filling any new slots
    /// with clones of `value`.
    ///
    /// Mirrors `resize(int, T)`.
    pub fn resize(&mut self, size: usize, value: T)
    where
        T: Clone,
    {
        self.data.resize(size, value);
    }

    /// Clears this vector and copies every element of `other_vector` into it.
    ///
    /// Mirrors `assign(VectorSTL<T>)`.
    pub fn assign(&mut self, other_vector: &VectorStl<T>)
    where
        T: Clone,
    {
        self.data.clear();
        self.data.extend(other_vector.data.iter().cloned());
    }

    /// Returns an iterator positioned at the first element whose key,
    /// according to `compare`, is not less than `key`. Assumes the vector is
    /// sorted in ascending order under `compare`.
    ///
    /// Mirrors `lower_bound(T, Comparator<T>)`, including its literal quirk
    /// of using `T`'s equality (not `compare`) when walking back to the
    /// first of a run of equal keys.
    pub fn lower_bound_by<F>(&mut self, key: &T, mut compare: F) -> VectorIterator<T>
    where
        T: PartialEq,
        F: FnMut(&T, &T) -> Ordering,
    {
        let mut i: isize = match self.data.binary_search_by(|probe| compare(probe, key)) {
            Ok(idx) => idx as isize,
            Err(idx) => -(idx as isize) - 1,
        };
        while i > 0 {
            if self.data[(i - 1) as usize] != *key {
                break;
            }
            i -= 1;
        }
        if i < 0 {
            i = -i - 1;
        }
        let ptr = NonNull::from(&mut self.data);
        unsafe { VectorIterator::new(ptr, i as usize) }
    }

    /// Returns an iterator positioned at the first element whose key is not
    /// less than `key`, using `T`'s natural ordering. Assumes the vector is
    /// sorted in ascending order.
    ///
    /// Mirrors `lower_bound(T)`. The Java original throws
    /// `UnsupportedOperationException` at runtime if `T` is not `Comparable`;
    /// here the `Ord` bound enforces that at compile time instead.
    pub fn lower_bound(&mut self, key: &T) -> VectorIterator<T>
    where
        T: Ord,
    {
        self.lower_bound_by(key, |a, b| a.cmp(b))
    }

    /// Returns an iterator positioned at the first element whose key,
    /// according to `compare`, is greater than `key`. Assumes the vector is
    /// sorted in ascending order under `compare`.
    ///
    /// Mirrors `upper_bound(T, Comparator<T>)`.
    pub fn upper_bound_by<F>(&mut self, key: &T, mut compare: F) -> VectorIterator<T>
    where
        T: PartialEq,
        F: FnMut(&T, &T) -> Ordering,
    {
        let i: isize = match self.data.binary_search_by(|probe| compare(probe, key)) {
            Ok(idx) => idx as isize,
            Err(idx) => -(idx as isize) - 1,
        };
        let mut i = if i < 0 { (-i - 1) as usize } else { i as usize };
        while i < self.data.len() {
            if self.data[i] != *key {
                break;
            }
            i += 1;
        }
        let ptr = NonNull::from(&mut self.data);
        unsafe { VectorIterator::new(ptr, i) }
    }

    /// Returns an iterator positioned at the first element whose key is
    /// greater than `key`, using `T`'s natural ordering. Assumes the vector
    /// is sorted in ascending order.
    ///
    /// Mirrors `upper_bound(T)`. The Java original throws
    /// `UnsupportedOperationException` at runtime if `T` is not `Comparable`;
    /// here the `Ord` bound enforces that at compile time instead.
    pub fn upper_bound(&mut self, key: &T) -> VectorIterator<T>
    where
        T: Ord,
    {
        self.upper_bound_by(key, |a, b| a.cmp(b))
    }
}

impl<T: 'static> VectorStl<T> {
    /// Merges the sorted vectors `v1` and `v2` into `destination` (which is
    /// cleared first), ordering elements via `compare`.
    ///
    /// Mirrors the static `merge(VectorSTL<K>, VectorSTL<K>, VectorSTL<K>, Comparator<K>)`.
    pub fn merge_by<F>(
        v1: &mut VectorStl<T>,
        v2: &mut VectorStl<T>,
        destination: &mut VectorStl<T>,
        mut compare: F,
    ) where
        T: Clone,
        F: FnMut(&T, &T) -> Ordering,
    {
        destination.clear();
        destination.reserve(v1.size() + v2.size());
        let mut it1 = v1.begin();
        let mut it2 = v2.begin();
        while !it1.is_end() && !it2.is_end() {
            if compare(it1.get(), it2.get()) != Ordering::Greater {
                destination.push_back(it1.get().clone());
                it1.increment();
            } else {
                destination.push_back(it2.get().clone());
                it2.increment();
            }
        }
        while !it1.is_end() {
            destination.push_back(it1.get().clone());
            it1.increment();
        }
        while !it2.is_end() {
            destination.push_back(it2.get().clone());
            it2.increment();
        }
    }

    /// Merges the sorted vectors `v1` and `v2` into `destination` (which is
    /// cleared first), using `T`'s natural ordering.
    ///
    /// Mirrors the static `merge(VectorSTL<K>, VectorSTL<K>, VectorSTL<K>)`.
    /// The Java original throws `UnsupportedOperationException` at runtime if
    /// `K` is not `Comparable`; here the `Ord` bound enforces that at
    /// compile time instead.
    pub fn merge(v1: &mut VectorStl<T>, v2: &mut VectorStl<T>, destination: &mut VectorStl<T>)
    where
        T: Ord + Clone,
    {
        Self::merge_by(v1, v2, destination, |a, b| a.cmp(b));
    }
}

impl<T> Default for VectorStl<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for VectorStl<T> {
    /// Mirrors the Java copy constructor `VectorSTL(VectorSTL<T> other)`.
    fn clone(&self) -> Self {
        Self { data: self.data.clone() }
    }
}

impl<T: PartialEq> PartialEq for VectorStl<T> {
    /// Mirrors `equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T: fmt::Display> fmt::Display for VectorStl<T> {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, item) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{item}")?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let v: VectorStl<i32> = VectorStl::new();
        assert!(v.is_empty());
        assert_eq!(v.size(), 0);
    }

    #[test]
    fn test_with_capacity_and_value() {
        let v = VectorStl::with_capacity(0);
        let _: VectorStl<i32> = v;

        let mut filled: VectorStl<i32> = VectorStl::new();
        filled.resize(3, 7);
        assert_eq!(filled.size(), 3);
        assert_eq!(*filled.get(0), 7);
        assert_eq!(*filled.get(2), 7);
    }

    #[test]
    fn test_push_back_and_get() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        assert_eq!(v.size(), 3);
        assert_eq!(*v.get(0), 1);
        assert_eq!(*v.get(1), 2);
        assert_eq!(*v.get(2), 3);
    }

    #[test]
    fn test_pop_back_removes_last() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        assert_eq!(v.pop_back(), 2);
        assert_eq!(v.size(), 1);
    }

    #[test]
    #[should_panic]
    fn test_pop_back_panics_when_empty() {
        let mut v: VectorStl<i32> = VectorStl::new();
        v.pop_back();
    }

    #[test]
    fn test_front_and_back() {
        let mut v = VectorStl::new();
        v.push_back(10);
        v.push_back(20);
        v.push_back(30);
        assert_eq!(*v.front(), 10);
        assert_eq!(*v.back(), 30);
    }

    #[test]
    fn test_set_back() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.set_back(99);
        assert_eq!(*v.back(), 99);
    }

    #[test]
    fn test_insert_shifts_elements() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(3);
        v.insert(1, 2);
        assert_eq!(*v.get(0), 1);
        assert_eq!(*v.get(1), 2);
        assert_eq!(*v.get(2), 3);
    }

    #[test]
    fn test_set_replaces_element() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.set(1, 99);
        assert_eq!(*v.get(1), 99);
    }

    #[test]
    fn test_erase_by_index() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        assert_eq!(v.erase(1), 2);
        assert_eq!(v.size(), 2);
        assert_eq!(*v.get(1), 3);
    }

    #[test]
    fn test_clear() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.clear();
        assert!(v.is_empty());
    }

    #[test]
    fn test_begin_end_walks_forward() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        let mut it = v.begin();
        assert_eq!(*it.get(), 1);
        it.increment();
        assert_eq!(*it.get(), 2);
        it.increment();
        assert_eq!(*it.get(), 3);
        it.increment();
        assert!(it.is_end());
    }

    #[test]
    fn test_r_begin_r_end_walks_backward() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        let mut it = v.r_begin();
        assert_eq!(*it.get(), 3);
        it.increment();
        assert_eq!(*it.get(), 2);
        it.increment();
        assert_eq!(*it.get(), 1);
        it.increment();
        assert!(it.is_end());
    }

    #[test]
    fn test_insert_at_iterator_position() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(3);
        let mut pos = v.begin();
        pos.increment();
        v.insert_at(&pos, 2);
        assert_eq!(*v.get(0), 1);
        assert_eq!(*v.get(1), 2);
        assert_eq!(*v.get(2), 3);
    }

    #[test]
    fn test_set_at_iterator_position() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        let it = v.begin();
        v.set_at(&it, 100);
        assert_eq!(*v.get(0), 100);
    }

    #[test]
    fn test_erase_at_removes_and_returns() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        let it = v.begin();
        let removed = v.erase_at(&it);
        assert_eq!(removed, 1);
        assert_eq!(v.size(), 2);
        assert_eq!(*v.get(0), 2);
    }

    #[test]
    fn test_erase_range_removes_slice() {
        let mut v = VectorStl::new();
        for i in 0..5 {
            v.push_back(i);
        }
        let start = v.begin();
        let mut end = v.begin();
        end.increment_by(3);
        v.erase_range(&start, &end);
        assert_eq!(v.size(), 2);
        assert_eq!(*v.get(0), 3);
        assert_eq!(*v.get(1), 4);
    }

    #[test]
    fn test_append_all() {
        let mut a = VectorStl::new();
        a.push_back(1);
        a.push_back(2);
        let mut b = VectorStl::new();
        b.push_back(3);
        b.push_back(4);
        a.append_all(&b);
        assert_eq!(a.size(), 4);
        assert_eq!(*a.get(3), 4);
    }

    #[test]
    fn test_assign_replaces_contents() {
        let mut a = VectorStl::new();
        a.push_back(1);
        let mut b = VectorStl::new();
        b.push_back(2);
        b.push_back(3);
        a.assign(&b);
        assert_eq!(a.size(), 2);
        assert_eq!(*a.get(0), 2);
        assert_eq!(*a.get(1), 3);
    }

    #[test]
    fn test_sort_natural_order() {
        let mut v = VectorStl::new();
        v.push_back(3);
        v.push_back(1);
        v.push_back(2);
        v.sort();
        assert_eq!(*v.get(0), 1);
        assert_eq!(*v.get(1), 2);
        assert_eq!(*v.get(2), 3);
    }

    #[test]
    fn test_sort_by_reverse() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(3);
        v.push_back(2);
        v.sort_by(|a, b| b.cmp(a));
        assert_eq!(*v.get(0), 3);
        assert_eq!(*v.get(1), 2);
        assert_eq!(*v.get(2), 1);
    }

    #[test]
    fn test_copy_is_independent() {
        let mut v = VectorStl::new();
        v.push_back(1);
        let mut copy = v.copy();
        copy.push_back(2);
        assert_eq!(v.size(), 1);
        assert_eq!(copy.size(), 2);
    }

    #[test]
    fn test_clone_is_independent() {
        let mut v = VectorStl::new();
        v.push_back(1);
        let mut cloned = v.clone();
        cloned.push_back(2);
        assert_eq!(v.size(), 1);
        assert_eq!(cloned.size(), 2);
    }

    #[test]
    fn test_partial_eq() {
        let mut a = VectorStl::new();
        a.push_back(1);
        a.push_back(2);
        let mut b = VectorStl::new();
        b.push_back(1);
        b.push_back(2);
        assert_eq!(a, b);
        b.push_back(3);
        assert_ne!(a, b);
    }

    #[test]
    fn test_display() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        assert_eq!(format!("{v}"), "[1, 2, 3]");
    }

    #[test]
    fn test_display_empty() {
        let v: VectorStl<i32> = VectorStl::new();
        assert_eq!(format!("{v}"), "[]");
    }

    #[test]
    fn test_iter_visits_in_order() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        let collected: Vec<i32> = v.iter().copied().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn test_resize_grows_with_clones() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.resize(3, 9);
        assert_eq!(v.size(), 3);
        assert_eq!(*v.get(1), 9);
        assert_eq!(*v.get(2), 9);
    }

    #[test]
    fn test_resize_shrinks() {
        let mut v = VectorStl::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        v.resize(1, 0);
        assert_eq!(v.size(), 1);
        assert_eq!(*v.get(0), 1);
    }

    #[test]
    fn test_lower_bound_finds_equal() {
        let mut v = VectorStl::new();
        for i in [1, 3, 5, 7, 9] {
            v.push_back(i);
        }
        let it = v.lower_bound(&5);
        assert_eq!(*it.get(), 5);
    }

    #[test]
    fn test_lower_bound_finds_first_of_duplicates() {
        let mut v = VectorStl::new();
        for i in [1, 3, 3, 3, 5] {
            v.push_back(i);
        }
        let it = v.lower_bound(&3);
        assert_eq!(it.get_index(), 1);
    }

    #[test]
    fn test_lower_bound_not_found_returns_insertion_point() {
        let mut v = VectorStl::new();
        for i in [1, 3, 5, 7, 9] {
            v.push_back(i);
        }
        let it = v.lower_bound(&4);
        assert_eq!(*it.get(), 5);
    }

    #[test]
    fn test_upper_bound_skips_past_duplicates() {
        let mut v = VectorStl::new();
        for i in [1, 3, 3, 3, 5] {
            v.push_back(i);
        }
        let it = v.upper_bound(&3);
        assert_eq!(*it.get(), 5);
    }

    #[test]
    fn test_upper_bound_at_end() {
        let mut v = VectorStl::new();
        for i in [1, 3, 5] {
            v.push_back(i);
        }
        let it = v.upper_bound(&5);
        assert!(it.is_end());
    }

    #[test]
    fn test_merge_interleaves_sorted_vectors() {
        let mut v1 = VectorStl::new();
        for i in [1, 3, 5] {
            v1.push_back(i);
        }
        let mut v2 = VectorStl::new();
        for i in [2, 4, 6] {
            v2.push_back(i);
        }
        let mut dest = VectorStl::new();
        VectorStl::merge(&mut v1, &mut v2, &mut dest);
        let collected: Vec<i32> = dest.iter().copied().collect();
        assert_eq!(collected, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_merge_by_with_custom_comparator() {
        let mut v1 = VectorStl::new();
        for i in [5, 3, 1] {
            v1.push_back(i);
        }
        let mut v2 = VectorStl::new();
        for i in [6, 4, 2] {
            v2.push_back(i);
        }
        let mut dest = VectorStl::new();
        VectorStl::merge_by(&mut v1, &mut v2, &mut dest, |a, b| b.cmp(a));
        let collected: Vec<i32> = dest.iter().copied().collect();
        assert_eq!(collected, vec![6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_default_is_empty() {
        let v: VectorStl<i32> = VectorStl::default();
        assert!(v.is_empty());
    }
}
