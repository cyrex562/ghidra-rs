use std::cmp::Ordering;

use super::iterator_stl::IteratorStl;

/// Counts the elements from `position` (inclusive) through the end of its
/// collection, without mutating `position` itself.
///
/// Used by trait implementors to translate an opaque [`IteratorStl`] cursor
/// into a positional index (`size - remaining`) using only the cursor's
/// public operations, since a `dyn IteratorStl<T>` cannot be downcast back to
/// a concrete node/index representation.
fn remaining_count<T>(position: &dyn IteratorStl<T>) -> usize {
    let mut cursor = position.copy_iter();
    let mut count = 0usize;
    while !cursor.is_end() {
        cursor.increment();
        count += 1;
    }
    count
}

/// A doubly-linked, sequential list, mirroring `generic.stl.ListSTL<T>` from
/// Ghidra.
///
/// The Java class is built directly on `ListNodeSTL<T>` plus its own private
/// `ListIterator`/`ReverseListIterator` inner classes, which downcast
/// `IteratorSTL<T>` back to the concrete node holder to splice nodes in and
/// out. Neither inner class is ported, and this trait does not require them:
/// traversal uses the already-ported [`IteratorStl`], and positional
/// operations (`insert`, `erase`, `splice`) locate their target purely
/// through the cursor's own `copy_iter`/`is_end`/`increment` operations (see
/// [`remaining_count`]) rather than downcasting to a concrete node type. This
/// lets callers depend on `Box<dyn ListStl<T>>` without pulling in a concrete
/// linked-list implementation, breaking the cycle this port was selected to
/// cut.
///
/// Debug-only members (`toString`, `printDebug`) and the `Object.equals`
/// override are omitted, matching the sibling STL trait ports.
pub trait ListStl<T: 'static> {
    /// Returns the number of elements.
    ///
    /// Mirrors `size()`.
    fn size(&self) -> usize;

    /// Returns `true` if the list has no elements.
    ///
    /// Mirrors `isEmpty()`.
    fn is_empty(&self) -> bool;

    /// Removes all elements.
    ///
    /// Mirrors `clear()`.
    fn clear(&mut self);

    /// Returns a reference to the first element.
    ///
    /// Mirrors `front()`.
    ///
    /// # Panics
    /// Panics if the list is empty.
    fn front(&self) -> &T;

    /// Returns a reference to the last element.
    ///
    /// Mirrors `back()`.
    ///
    /// # Panics
    /// Panics if the list is empty.
    fn back(&self) -> &T;

    /// Appends `value` to the end.
    ///
    /// Mirrors `push_back(T)`.
    fn push_back(&mut self, value: T);

    /// Prepends `value` to the front.
    ///
    /// Mirrors `push_front(T)`.
    fn push_front(&mut self, value: T);

    /// Removes and returns the first element.
    ///
    /// Mirrors `pop_front()`.
    ///
    /// # Panics
    /// Panics if the list is empty.
    fn pop_front(&mut self) -> T;

    /// Removes and returns the last element.
    ///
    /// Mirrors `pop_back()`.
    ///
    /// # Panics
    /// Panics if the list is empty.
    fn pop_back(&mut self) -> T;

    /// Inserts `value` at the position named by `position`, shifting that
    /// element and all following it back. Returns an iterator positioned at
    /// the newly inserted element.
    ///
    /// Mirrors `insert(IteratorSTL<T>, T)`.
    fn insert(&mut self, position: &mut dyn IteratorStl<T>, value: T) -> Box<dyn IteratorStl<T>>;

    /// Removes the element at the position named by `position`, advancing
    /// `position` to the following element.
    ///
    /// Mirrors `erase(IteratorSTL<T>)`.
    fn erase(&mut self, position: &mut dyn IteratorStl<T>);

    /// Returns a forward iterator positioned at the first element.
    ///
    /// Mirrors `begin()`.
    fn begin(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a forward iterator positioned one past the last element.
    ///
    /// Mirrors `end()`.
    fn end(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a reverse iterator positioned at the last element.
    ///
    /// Mirrors `rBegin()`.
    fn r_begin(&self) -> Box<dyn IteratorStl<T>>;

    /// Returns a reverse iterator positioned one before the first element.
    ///
    /// Mirrors `rEnd()`.
    fn r_end(&self) -> Box<dyn IteratorStl<T>>;

    /// Moves the single element at `list_position` out of `list` and inserts
    /// it at `position` in this list, decreasing `list`'s length by one and
    /// increasing this list's length by one.
    ///
    /// Mirrors `splice(IteratorSTL<T>, ListSTL<T>, IteratorSTL<T>)`.
    fn splice(
        &mut self,
        position: &mut dyn IteratorStl<T>,
        list: &mut dyn ListStl<T>,
        list_position: &mut dyn IteratorStl<T>,
    );

    /// Sorts the list in place using `compare`.
    ///
    /// Mirrors `sort(Comparator<T>)`.
    fn sort_by(&mut self, compare: &mut dyn FnMut(&T, &T) -> Ordering);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Vec`-backed mock proving `ListStl` is object-safe and exercising
    /// real sequential-list behavior (positional insert/erase, push/pop at
    /// both ends, cross-list splice, sorting).
    struct VecList<T> {
        data: Vec<T>,
    }

    impl<T> VecList<T> {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl<T: Clone + 'static> ListStl<T> for VecList<T> {
        fn size(&self) -> usize {
            self.data.len()
        }

        fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        fn clear(&mut self) {
            self.data.clear();
        }

        fn front(&self) -> &T {
            &self.data[0]
        }

        fn back(&self) -> &T {
            &self.data[self.data.len() - 1]
        }

        fn push_back(&mut self, value: T) {
            self.data.push(value);
        }

        fn push_front(&mut self, value: T) {
            self.data.insert(0, value);
        }

        fn pop_front(&mut self) -> T {
            self.data.remove(0)
        }

        fn pop_back(&mut self) -> T {
            self.data.pop().expect("VecList::pop_back called on an empty list")
        }

        fn insert(
            &mut self,
            position: &mut dyn IteratorStl<T>,
            value: T,
        ) -> Box<dyn IteratorStl<T>> {
            let idx = self.data.len() - remaining_count(position);
            self.data.insert(idx, value);
            Box::new(VecListCursor { data: self.data.clone(), pos: idx as isize, step: 1 })
        }

        fn erase(&mut self, position: &mut dyn IteratorStl<T>) {
            let idx = self.data.len() - remaining_count(position);
            self.data.remove(idx);
            position.increment();
        }

        fn begin(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecListCursor { data: self.data.clone(), pos: 0, step: 1 })
        }

        fn end(&self) -> Box<dyn IteratorStl<T>> {
            let len = self.data.len() as isize;
            Box::new(VecListCursor { data: self.data.clone(), pos: len, step: 1 })
        }

        fn r_begin(&self) -> Box<dyn IteratorStl<T>> {
            let pos = self.data.len() as isize - 1;
            Box::new(VecListCursor { data: self.data.clone(), pos, step: -1 })
        }

        fn r_end(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecListCursor { data: self.data.clone(), pos: -1, step: -1 })
        }

        fn splice(
            &mut self,
            position: &mut dyn IteratorStl<T>,
            list: &mut dyn ListStl<T>,
            list_position: &mut dyn IteratorStl<T>,
        ) {
            let value = list_position.get().clone();
            list.erase(list_position);
            let _ = self.insert(position, value);
        }

        fn sort_by(&mut self, compare: &mut dyn FnMut(&T, &T) -> Ordering) {
            self.data.sort_by(|a, b| compare(a, b));
        }
    }

    /// Forward (`step == 1`) or reverse (`step == -1`) cursor over a snapshot
    /// of a [`VecList`]'s entries.
    struct VecListCursor<T> {
        data: Vec<T>,
        pos: isize,
        step: isize,
    }

    impl<T: Clone + 'static> IteratorStl<T> for VecListCursor<T> {
        fn get(&self) -> &T {
            &self.data[self.pos as usize]
        }

        fn set(&mut self, value: T) {
            self.data[self.pos as usize] = value;
        }

        fn increment(&mut self) {
            assert!(!self.is_end(), "increment past end");
            self.pos += self.step;
        }

        fn increment_by(&mut self, n: usize) {
            for _ in 0..n {
                self.increment();
            }
        }

        fn decrement(&mut self) {
            assert!(!self.is_begin(), "decrement past beginning");
            self.pos -= self.step;
        }

        fn decrement_by(&mut self, n: usize) {
            for _ in 0..n {
                self.decrement();
            }
        }

        fn is_begin(&self) -> bool {
            if self.data.is_empty() {
                return false;
            }
            if self.step > 0 {
                self.pos == 0
            } else {
                self.pos == self.data.len() as isize - 1
            }
        }

        fn is_end(&self) -> bool {
            if self.step > 0 {
                self.pos >= self.data.len() as isize
            } else {
                self.pos < 0
            }
        }

        fn insert(&mut self, value: T) {
            self.data.insert(self.pos as usize, value);
        }

        fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
            Box::new(VecListCursor { data: self.data.clone(), pos: self.pos, step: self.step })
        }

        fn assign(&mut self, other: &dyn IteratorStl<T>) {
            if other.is_end() {
                self.pos = if self.step > 0 { self.data.len() as isize } else { -1 };
            } else if other.is_begin() {
                self.pos = if self.step > 0 { 0 } else { self.data.len() as isize - 1 };
            }
        }
    }

    fn sample() -> VecList<i32> {
        let mut list = VecList::new();
        list.push_back(10);
        list.push_back(20);
        list.push_back(30);
        list
    }

    #[test]
    fn as_trait_object_push_and_size() {
        let mut list: Box<dyn ListStl<i32>> = Box::new(sample());
        assert_eq!(list.size(), 3);
        assert!(!list.is_empty());
        list.push_back(40);
        assert_eq!(list.size(), 4);
        assert_eq!(*list.back(), 40);
    }

    #[test]
    fn push_front_and_pop_front_back() {
        let mut list = sample();
        list.push_front(5);
        assert_eq!(*list.front(), 5);
        assert_eq!(list.pop_front(), 5);
        assert_eq!(list.pop_back(), 30);
        assert_eq!(list.size(), 2);
    }

    #[test]
    fn begin_end_walks_forward_in_order() {
        let list = sample();
        let mut it = list.begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![10, 20, 30]);
    }

    #[test]
    fn r_begin_r_end_walks_backward() {
        let list = sample();
        let mut it = list.r_begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![30, 20, 10]);
    }

    #[test]
    fn insert_at_middle_position() {
        let mut list = sample();
        let mut pos = list.begin();
        pos.increment();
        let inserted = list.insert(&mut *pos, 15);
        assert_eq!(*inserted.get(), 15);
        let mut it = list.begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![10, 15, 20, 30]);
    }

    #[test]
    fn erase_removes_current_and_advances() {
        let mut list = sample();
        let mut it = list.begin();
        it.increment();
        list.erase(&mut *it);
        assert_eq!(list.size(), 2);
        assert_eq!(*it.get(), 30);
        let mut walk = list.begin();
        let mut seen = Vec::new();
        while !walk.is_end() {
            seen.push(*walk.get());
            walk.increment();
        }
        assert_eq!(seen, vec![10, 30]);
    }

    #[test]
    fn splice_moves_element_between_lists() {
        let mut dest = sample();
        let mut src = VecList::new();
        src.push_back(100);
        src.push_back(200);
        src.push_back(300);

        let mut dest_pos = dest.end();
        let mut src_pos = src.begin();
        src_pos.increment();

        dest.splice(&mut *dest_pos, &mut src, &mut *src_pos);

        assert_eq!(src.size(), 2);
        let src_values: Vec<i32> = {
            let mut it = src.begin();
            let mut v = Vec::new();
            while !it.is_end() {
                v.push(*it.get());
                it.increment();
            }
            v
        };
        assert_eq!(src_values, vec![100, 300]);

        assert_eq!(dest.size(), 4);
        let dest_values: Vec<i32> = {
            let mut it = dest.begin();
            let mut v = Vec::new();
            while !it.is_end() {
                v.push(*it.get());
                it.increment();
            }
            v
        };
        assert_eq!(dest_values, vec![10, 20, 30, 200]);
    }

    #[test]
    fn sort_by_orders_elements() {
        let mut list = VecList::new();
        list.push_back(30);
        list.push_back(10);
        list.push_back(20);
        list.sort_by(&mut |a, b| a.cmp(b));
        let mut it = list.begin();
        let mut seen = Vec::new();
        while !it.is_end() {
            seen.push(*it.get());
            it.increment();
        }
        assert_eq!(seen, vec![10, 20, 30]);
    }
}
