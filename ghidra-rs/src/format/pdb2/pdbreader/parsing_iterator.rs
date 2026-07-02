use crate::util::exception::CancelledException;

/// Error type for ParsingIterator operations.
///
/// Corresponds to Java's `CancelledException` and `NoSuchElementException`.
#[derive(Debug)]
pub enum ParsingIteratorError {
    /// Operation was cancelled by the user.
    Cancelled(CancelledException),
    /// Iterator has no more elements.
    NoSuchElement,
}

impl std::fmt::Display for ParsingIteratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsingIteratorError::Cancelled(e) => write!(f, "{}", e),
            ParsingIteratorError::NoSuchElement => write!(f, "No such element"),
        }
    }
}

impl std::error::Error for ParsingIteratorError {}

/// A parsing iterator that allows cancellation via CancelledException.
///
/// Mirrors `ParsingIterator<E>` from Ghidra. This trait provides methods to iterate
/// over elements with support for cancellation and peeking without consuming the element.
///
/// # Type parameter
/// - `E` — the type of elements yielded by the iterator
pub trait ParsingIterator<E> {
    /// Returns `true` if more elements exist.
    ///
    /// # Errors
    /// Returns [`CancelledException`] upon user cancellation.
    fn has_next(&mut self) -> Result<bool, CancelledException>;

    /// Returns the next element in the iteration.
    ///
    /// # Errors
    /// - Returns [`ParsingIteratorError::Cancelled`] upon user cancellation.
    /// - Returns [`ParsingIteratorError::NoSuchElement`] if the iteration has no more elements.
    fn next(&mut self) -> Result<E, ParsingIteratorError>;

    /// Returns the next element in the iteration without advancing the iterator.
    ///
    /// # Errors
    /// - Returns [`ParsingIteratorError::Cancelled`] upon user cancellation.
    /// - Returns [`ParsingIteratorError::NoSuchElement`] if the iteration has no more elements.
    fn peek(&mut self) -> Result<E, ParsingIteratorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIterator {
        items: Vec<i32>,
        position: usize,
    }

    impl TestIterator {
        fn new(items: Vec<i32>) -> Self {
            TestIterator { items, position: 0 }
        }
    }

    impl ParsingIterator<i32> for TestIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(self.position < self.items.len())
        }

        fn next(&mut self) -> Result<i32, ParsingIteratorError> {
            if self.position < self.items.len() {
                let item = self.items[self.position];
                self.position += 1;
                Ok(item)
            } else {
                Err(ParsingIteratorError::NoSuchElement)
            }
        }

        fn peek(&mut self) -> Result<i32, ParsingIteratorError> {
            if self.position < self.items.len() {
                Ok(self.items[self.position])
            } else {
                Err(ParsingIteratorError::NoSuchElement)
            }
        }
    }

    #[test]
    fn has_next_returns_true_when_elements_exist() {
        let mut iter = TestIterator::new(vec![1, 2, 3]);
        assert!(iter.has_next().unwrap());
    }

    #[test]
    fn has_next_returns_false_when_exhausted() {
        let mut iter = TestIterator::new(vec![1]);
        iter.next().unwrap();
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn has_next_returns_false_for_empty() {
        let mut iter = TestIterator::new(vec![]);
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn next_returns_elements_in_order() {
        let mut iter = TestIterator::new(vec![10, 20, 30]);
        assert_eq!(iter.next().unwrap(), 10);
        assert_eq!(iter.next().unwrap(), 20);
        assert_eq!(iter.next().unwrap(), 30);
    }

    #[test]
    fn next_raises_error_when_exhausted() {
        let mut iter = TestIterator::new(vec![1]);
        iter.next().unwrap();
        assert!(matches!(iter.next(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn next_raises_error_for_empty() {
        let mut iter = TestIterator::new(vec![]);
        assert!(matches!(iter.next(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn peek_returns_next_element_without_advancing() {
        let mut iter = TestIterator::new(vec![5, 10, 15]);
        assert_eq!(iter.peek().unwrap(), 5);
        assert_eq!(iter.peek().unwrap(), 5);
        assert_eq!(iter.next().unwrap(), 5);
        assert_eq!(iter.peek().unwrap(), 10);
    }

    #[test]
    fn peek_raises_error_when_exhausted() {
        let mut iter = TestIterator::new(vec![1]);
        iter.next().unwrap();
        assert!(matches!(iter.peek(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn peek_raises_error_for_empty() {
        let mut iter = TestIterator::new(vec![]);
        assert!(matches!(iter.peek(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn peek_does_not_advance_iterator() {
        let mut iter = TestIterator::new(vec![100, 200]);
        let _ = iter.peek();
        let _ = iter.peek();
        let _ = iter.peek();
        assert_eq!(iter.next().unwrap(), 100);
    }

    #[test]
    fn error_display_for_no_such_element() {
        let err = ParsingIteratorError::NoSuchElement;
        assert_eq!(err.to_string(), "No such element");
    }
}
