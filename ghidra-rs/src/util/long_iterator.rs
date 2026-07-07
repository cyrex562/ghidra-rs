/// Iterator over a sequence of `i64` values with bidirectional support.
///
/// Port of `ghidra.util.LongIterator`.
pub trait LongIterator {
    /// Returns `true` if there is a next value in the forward direction.
    fn has_next(&self) -> bool;
    /// Returns the next `i64` value.
    fn next(&mut self) -> i64;
    /// Returns `true` if there is a previous value in the backward direction.
    fn has_previous(&self) -> bool;
    /// Returns the previous `i64` value.
    fn previous(&mut self) -> i64;
}

/// An empty [`LongIterator`] that contains no values.
///
/// Corresponds to `LongIterator.EMPTY` in the Java source.
pub struct EmptyLongIterator;

impl LongIterator for EmptyLongIterator {
    fn has_next(&self) -> bool {
        false
    }
    fn next(&mut self) -> i64 {
        0
    }
    fn has_previous(&self) -> bool {
        false
    }
    fn previous(&mut self) -> i64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_next() {
        assert!(!EmptyLongIterator.has_next());
    }

    #[test]
    fn empty_has_no_previous() {
        assert!(!EmptyLongIterator.has_previous());
    }

    #[test]
    fn empty_next_returns_zero() {
        assert_eq!(EmptyLongIterator.next(), 0);
    }

    #[test]
    fn empty_previous_returns_zero() {
        assert_eq!(EmptyLongIterator.previous(), 0);
    }

    #[test]
    fn trait_object_empty() {
        let mut it: Box<dyn LongIterator> = Box::new(EmptyLongIterator);
        assert!(!it.has_next());
        assert!(!it.has_previous());
        assert_eq!(it.next(), 0);
        assert_eq!(it.previous(), 0);
    }

    struct VecIterator {
        values: Vec<i64>,
        pos: usize,
    }

    impl VecIterator {
        fn new(values: Vec<i64>) -> Self {
            Self { values, pos: 0 }
        }
    }

    impl LongIterator for VecIterator {
        fn has_next(&self) -> bool {
            self.pos < self.values.len()
        }
        fn next(&mut self) -> i64 {
            let v = self.values[self.pos];
            self.pos += 1;
            v
        }
        fn has_previous(&self) -> bool {
            self.pos > 0
        }
        fn previous(&mut self) -> i64 {
            self.pos -= 1;
            self.values[self.pos]
        }
    }

    #[test]
    fn forward_iteration() {
        let mut it = VecIterator::new(vec![10, 20, 30]);
        assert!(it.has_next());
        assert_eq!(it.next(), 10);
        assert_eq!(it.next(), 20);
        assert_eq!(it.next(), 30);
        assert!(!it.has_next());
    }

    #[test]
    fn backward_iteration() {
        let mut it = VecIterator::new(vec![10, 20, 30]);
        it.next();
        it.next();
        it.next();
        assert!(it.has_previous());
        assert_eq!(it.previous(), 30);
        assert_eq!(it.previous(), 20);
        assert_eq!(it.previous(), 10);
        assert!(!it.has_previous());
    }

    #[test]
    fn bidirectional_ping_pong() {
        let mut it = VecIterator::new(vec![1, 2, 3]);
        assert_eq!(it.next(), 1);
        assert_eq!(it.next(), 2);
        assert_eq!(it.previous(), 2);
        assert_eq!(it.next(), 2);
        assert_eq!(it.next(), 3);
        assert!(!it.has_next());
    }

    #[test]
    fn single_element() {
        let mut it = VecIterator::new(vec![42]);
        assert!(it.has_next());
        assert!(!it.has_previous());
        assert_eq!(it.next(), 42);
        assert!(!it.has_next());
        assert!(it.has_previous());
        assert_eq!(it.previous(), 42);
    }
}
