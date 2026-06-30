/// A bidirectional, cursor-based iterator over a list.
///
/// Port of `java.util.ListIterator` — used as the inner and outer type for
/// [`ReversedListIterator`].
pub trait ListIterator<E> {
    fn has_next(&self) -> bool;
    fn next(&mut self) -> E;
    fn has_previous(&self) -> bool;
    fn previous(&mut self) -> E;
    /// Returns the index of the element that would be returned by a subsequent [`next`] call.
    fn next_index(&self) -> i64;
    /// Returns the index of the element that would be returned by a subsequent [`previous`]
    /// call, or `-1` if the cursor is at the start of the list.
    fn previous_index(&self) -> i64;
    fn remove(&mut self);
    fn set(&mut self, e: E);
    fn add(&mut self, e: E);
}

/// Wraps a [`ListIterator`] so that forward and backward traversal are swapped.
///
/// The wrapped iterator must already be positioned at its end before construction.
/// For example, to traverse a list in reverse, obtain the inner iterator positioned
/// at `list.size()` before passing it here.
///
/// Port of `ghidra.util.ReversedListIterator`.
pub struct ReversedListIterator<E> {
    it: Box<dyn ListIterator<E>>,
}

impl<E> ReversedListIterator<E> {
    /// Creates a reversed view over `it`. `it` must already be at its end.
    pub fn new(it: Box<dyn ListIterator<E>>) -> Self {
        Self { it }
    }
}

impl<E> ListIterator<E> for ReversedListIterator<E> {
    fn has_next(&self) -> bool {
        self.it.has_previous()
    }

    fn next(&mut self) -> E {
        self.it.previous()
    }

    fn has_previous(&self) -> bool {
        self.it.has_next()
    }

    fn previous(&mut self) -> E {
        self.it.next()
    }

    fn next_index(&self) -> i64 {
        self.it.previous_index()
    }

    fn previous_index(&self) -> i64 {
        self.it.next_index()
    }

    fn remove(&mut self) {
        self.it.remove()
    }

    fn set(&mut self, e: E) {
        self.it.set(e)
    }

    fn add(&mut self, e: E) {
        self.it.add(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecListIterator<E> {
        data: Vec<E>,
        cursor: usize,
    }

    impl<E: Clone> VecListIterator<E> {
        fn at_end(data: Vec<E>) -> Self {
            let cursor = data.len();
            Self { data, cursor }
        }

        fn at_start(data: Vec<E>) -> Self {
            Self { data, cursor: 0 }
        }
    }

    impl<E: Clone> ListIterator<E> for VecListIterator<E> {
        fn has_next(&self) -> bool {
            self.cursor < self.data.len()
        }

        fn next(&mut self) -> E {
            let v = self.data[self.cursor].clone();
            self.cursor += 1;
            v
        }

        fn has_previous(&self) -> bool {
            self.cursor > 0
        }

        fn previous(&mut self) -> E {
            self.cursor -= 1;
            self.data[self.cursor].clone()
        }

        fn next_index(&self) -> i64 {
            self.cursor as i64
        }

        fn previous_index(&self) -> i64 {
            self.cursor as i64 - 1
        }

        fn remove(&mut self) {}

        fn set(&mut self, e: E) {
            if self.cursor > 0 {
                self.data[self.cursor - 1] = e;
            }
        }

        fn add(&mut self, e: E) {
            self.data.insert(self.cursor, e);
            self.cursor += 1;
        }
    }

    #[test]
    fn reversed_full_traversal() {
        let inner = VecListIterator::at_end(vec![1, 2, 3]);
        let mut rev = ReversedListIterator::new(Box::new(inner));
        assert!(rev.has_next());
        assert_eq!(rev.next(), 3);
        assert_eq!(rev.next(), 2);
        assert_eq!(rev.next(), 1);
        assert!(!rev.has_next());
    }

    #[test]
    fn reversed_has_next_false_at_start() {
        // Inner at start → has_previous = false → reversed has_next = false
        let inner = VecListIterator::at_start(vec![1, 2, 3]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert!(!rev.has_next());
    }

    #[test]
    fn reversed_has_previous_false_at_end() {
        // Inner at end → has_next = false → reversed has_previous = false
        let inner = VecListIterator::at_end(vec![1, 2, 3]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert!(!rev.has_previous());
    }

    #[test]
    fn reversed_previous_goes_forward() {
        let inner = VecListIterator::at_end(vec![1, 2, 3]);
        let mut rev = ReversedListIterator::new(Box::new(inner));
        rev.next(); // consume 3 (cursor in inner moves to 2)
        rev.next(); // consume 2 (cursor in inner moves to 1)
        // reversed previous() calls inner.next()
        assert!(rev.has_previous());
        assert_eq!(rev.previous(), 2);
        assert_eq!(rev.previous(), 3);
        assert!(!rev.has_previous());
    }

    #[test]
    fn reversed_next_index_maps_to_inner_previous_index() {
        // Inner at end of [1,2,3]: previous_index = 2
        let inner = VecListIterator::at_end(vec![1, 2, 3]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert_eq!(rev.next_index(), 2);
    }

    #[test]
    fn reversed_previous_index_maps_to_inner_next_index() {
        // Inner at end of [1,2,3]: next_index = 3
        let inner = VecListIterator::at_end(vec![1, 2, 3]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert_eq!(rev.previous_index(), 3);
    }

    #[test]
    fn reversed_next_index_at_start_is_minus_one() {
        // Inner at start: previous_index = -1
        let inner = VecListIterator::<i32>::at_start(vec![1, 2, 3]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert_eq!(rev.next_index(), -1);
    }

    #[test]
    fn empty_list_has_no_next() {
        let inner = VecListIterator::<i32>::at_end(vec![]);
        let rev = ReversedListIterator::new(Box::new(inner));
        assert!(!rev.has_next());
    }

    #[test]
    fn single_element_full_cycle() {
        let inner = VecListIterator::at_end(vec![42]);
        let mut rev = ReversedListIterator::new(Box::new(inner));
        assert!(rev.has_next());
        assert!(!rev.has_previous());
        assert_eq!(rev.next(), 42);
        assert!(!rev.has_next());
        assert!(rev.has_previous());
    }

    #[test]
    fn remove_delegates_without_panic() {
        let inner = VecListIterator::at_end(vec![1, 2]);
        let mut rev = ReversedListIterator::new(Box::new(inner));
        rev.next();
        rev.remove();
    }

    #[test]
    fn add_delegates_without_panic() {
        let inner = VecListIterator::at_end(vec![1, 2]);
        let mut rev = ReversedListIterator::new(Box::new(inner));
        rev.add(99);
    }
}
