/// A cursor-based bidirectional iterator over a mutable collection.
///
/// Mirrors `generic.stl.IteratorSTL<T>` from Ghidra. Unlike [`std::iter::Iterator`],
/// this cursor can move in both directions and supports in-place element replacement
/// and insertion at the current position.
pub trait IteratorStl<T> {
    /// Returns a reference to the value at the current cursor position.
    ///
    /// # Panics
    ///
    /// Panics when positioned before the first element or past the last.
    fn get(&self) -> &T;

    /// Replaces the value at the current cursor position with `value`.
    ///
    /// # Panics
    ///
    /// Panics when positioned before the first element or past the last.
    fn set(&mut self, value: T);

    /// Advances the cursor by one position.
    ///
    /// # Panics
    ///
    /// Panics if already positioned past the last element.
    fn increment(&mut self);

    /// Advances the cursor by `n` positions.
    ///
    /// # Panics
    ///
    /// Panics if advancing would push past the end of the collection.
    fn increment_by(&mut self, n: usize);

    /// Moves the cursor back one position.
    ///
    /// Only supported by bidirectional iterators; unidirectional implementors
    /// should panic.
    fn decrement(&mut self);

    /// Moves the cursor back by `n` positions.
    ///
    /// # Panics
    ///
    /// Panics if retreating would push past the beginning of the collection.
    fn decrement_by(&mut self, n: usize);

    /// Returns `true` when the cursor is on the first element.
    ///
    /// Always `false` for an empty collection.
    fn is_begin(&self) -> bool;

    /// Returns `true` when the cursor is positioned past the last element.
    ///
    /// Always `true` for an empty collection.
    fn is_end(&self) -> bool;

    /// Inserts `value` at the current position, shifting existing elements forward.
    ///
    /// The cursor lands on the newly inserted element after the call.
    ///
    /// # Panics
    ///
    /// Panics if positioned before the first item.
    fn insert(&mut self, value: T);

    /// Creates an independent copy of this iterator at the same cursor position.
    fn copy_iter(&self) -> Box<dyn IteratorStl<T>>;

    /// Copies the cursor position from `other` into this iterator.
    ///
    /// Mirrors C++'s iterator assignment (`*this = other`).
    fn assign(&mut self, other: &dyn IteratorStl<T>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecCursor {
        data: Vec<i32>,
        pos: usize,
    }

    impl VecCursor {
        fn new(data: Vec<i32>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl IteratorStl<i32> for VecCursor {
        fn get(&self) -> &i32 {
            &self.data[self.pos]
        }

        fn set(&mut self, value: i32) {
            self.data[self.pos] = value;
        }

        fn increment(&mut self) {
            assert!(self.pos < self.data.len(), "increment past end");
            self.pos += 1;
        }

        fn increment_by(&mut self, n: usize) {
            assert!(self.pos + n <= self.data.len(), "increment_by past end");
            self.pos += n;
        }

        fn decrement(&mut self) {
            assert!(self.pos > 0, "decrement past beginning");
            self.pos -= 1;
        }

        fn decrement_by(&mut self, n: usize) {
            assert!(self.pos >= n, "decrement_by past beginning");
            self.pos -= n;
        }

        fn is_begin(&self) -> bool {
            self.pos == 0 && !self.data.is_empty()
        }

        fn is_end(&self) -> bool {
            self.pos >= self.data.len()
        }

        fn insert(&mut self, value: i32) {
            self.data.insert(self.pos, value);
        }

        fn copy_iter(&self) -> Box<dyn IteratorStl<i32>> {
            Box::new(VecCursor { data: self.data.clone(), pos: self.pos })
        }

        fn assign(&mut self, other: &dyn IteratorStl<i32>) {
            if other.is_end() {
                self.pos = self.data.len();
            } else if other.is_begin() {
                self.pos = 0;
            }
        }
    }

    #[test]
    fn test_get_first() {
        let c = VecCursor::new(vec![10, 20, 30]);
        assert_eq!(*c.get(), 10);
    }

    #[test]
    fn test_set_replaces_current() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.set(99);
        assert_eq!(*c.get(), 99);
    }

    #[test]
    fn test_increment_advances() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment();
        assert_eq!(*c.get(), 20);
        c.increment();
        assert_eq!(*c.get(), 30);
    }

    #[test]
    fn test_increment_by_skips() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment_by(2);
        assert_eq!(*c.get(), 30);
    }

    #[test]
    fn test_decrement_retreats() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment_by(2);
        c.decrement();
        assert_eq!(*c.get(), 20);
    }

    #[test]
    fn test_decrement_by_skips_back() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment_by(2);
        c.decrement_by(2);
        assert_eq!(*c.get(), 10);
    }

    #[test]
    fn test_is_begin_at_start() {
        let c = VecCursor::new(vec![10, 20, 30]);
        assert!(c.is_begin());
    }

    #[test]
    fn test_is_begin_false_after_increment() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment();
        assert!(!c.is_begin());
    }

    #[test]
    fn test_is_begin_false_for_empty() {
        let c = VecCursor::new(vec![]);
        assert!(!c.is_begin());
    }

    #[test]
    fn test_is_end_false_initially() {
        let c = VecCursor::new(vec![10, 20, 30]);
        assert!(!c.is_end());
    }

    #[test]
    fn test_is_end_true_past_last() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment_by(3);
        assert!(c.is_end());
    }

    #[test]
    fn test_is_end_true_for_empty() {
        let c = VecCursor::new(vec![]);
        assert!(c.is_end());
    }

    #[test]
    fn test_insert_shifts_elements() {
        let mut c = VecCursor::new(vec![10, 30]);
        c.increment();
        c.insert(20);
        assert_eq!(*c.get(), 20);
        c.increment();
        assert_eq!(*c.get(), 30);
    }

    #[test]
    fn test_insert_at_begin() {
        let mut c = VecCursor::new(vec![20, 30]);
        c.insert(10);
        assert_eq!(*c.get(), 10);
        c.increment();
        assert_eq!(*c.get(), 20);
    }

    #[test]
    fn test_copy_iter_is_independent() {
        let c = VecCursor::new(vec![10, 20, 30]);
        let mut c2 = c.copy_iter();
        c2.increment();
        assert_eq!(*c2.get(), 20);
        assert_eq!(*c.get(), 10);
    }

    #[test]
    fn test_copy_iter_same_position() {
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment();
        let c2 = c.copy_iter();
        assert_eq!(*c2.get(), 20);
    }

    #[test]
    fn test_assign_to_begin() {
        let c_begin = VecCursor::new(vec![10, 20, 30]);
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.increment_by(2);
        c.assign(&c_begin);
        assert!(c.is_begin());
    }

    #[test]
    fn test_assign_to_end() {
        let mut c_end = VecCursor::new(vec![10, 20, 30]);
        c_end.increment_by(3);
        let mut c = VecCursor::new(vec![10, 20, 30]);
        c.assign(&c_end);
        assert!(c.is_end());
    }
}
