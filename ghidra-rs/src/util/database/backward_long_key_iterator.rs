//! Port of `ghidra.util.database.BackwardLongKeyIterator`: a wrapper of
//! [`DBLongIterator`](crate::framework::db::DBLongIterator) that runs it backward and implements
//! [`DirectedLongKeyIterator`](crate::util::database::DirectedLongKeyIterator).
//!
//! Mirror image of [`ForwardLongKeyIterator`](super::forward_long_key_iterator::ForwardLongKeyIterator):
//! `hasNext`/`next` delegate to the wrapped iterator's *backward*-direction methods
//! (`hasPrevious`/`previous`). See that module's doc comment for why the wrapped iterator is
//! held as a plain field rather than composing
//! [`AbstractDirectedLongKeyIterator`](crate::util::database::AbstractDirectedLongKeyIterator)
//! directly.

use std::io;

use crate::framework::db::DBLongIterator;
use crate::util::database::{DirectedIterator, DirectedLongKeyIterator};

/// A wrapper of [`DBLongIterator`] that runs it backward. Mirrors
/// `ghidra.util.database.BackwardLongKeyIterator`.
pub struct BackwardLongKeyIterator {
    it: Box<dyn DBLongIterator>,
}

impl BackwardLongKeyIterator {
    /// Mirrors `BackwardLongKeyIterator(DBLongIterator)`.
    pub fn new(it: Box<dyn DBLongIterator>) -> Self {
        Self { it }
    }
}

impl DirectedIterator<i64> for BackwardLongKeyIterator {
    /// Mirrors `hasNext()`: delegates to the wrapped iterator's backward-direction
    /// `hasPrevious()`.
    fn has_next(&mut self) -> io::Result<bool> {
        self.it.has_previous()
    }

    /// Mirrors `next()`: delegates to the wrapped iterator's backward-direction `previous()`.
    fn next(&mut self) -> io::Result<i64> {
        self.it.previous()
    }

    /// Mirrors the inherited `AbstractDirectedLongKeyIterator.delete()`.
    fn delete(&mut self) -> io::Result<bool> {
        self.it.delete()
    }
}

impl DirectedLongKeyIterator for BackwardLongKeyIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock `DBLongIterator` over a `Vec<i64>`, positioned at the end so backward iteration
    /// has somewhere to go.
    struct VecLongIterator {
        values: Vec<i64>,
        pos: usize,
        /// Index of the value most recently returned by `next`/`previous`, tracked explicitly
        /// (rather than re-derived from `pos`) so `delete` works correctly regardless of which
        /// direction produced it.
        last_yielded: Option<usize>,
    }

    impl DBLongIterator for VecLongIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.values.len())
        }

        fn has_previous(&mut self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }

        fn next(&mut self) -> io::Result<i64> {
            if self.pos >= self.values.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "no next value"));
            }
            let v = self.values[self.pos];
            self.last_yielded = Some(self.pos);
            self.pos += 1;
            Ok(v)
        }

        fn previous(&mut self) -> io::Result<i64> {
            if self.pos == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "no previous value"));
            }
            self.pos -= 1;
            self.last_yielded = Some(self.pos);
            Ok(self.values[self.pos])
        }

        fn delete(&mut self) -> io::Result<bool> {
            match self.last_yielded.take() {
                Some(idx) => {
                    self.values.remove(idx);
                    if self.pos > idx {
                        self.pos -= 1;
                    }
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    #[test]
    fn walks_backward_using_has_previous_and_previous() {
        // Positioned at the end: iterating "forward" through this backward wrapper yields
        // 30, 20, 10 -- the reverse of insertion order.
        let inner = VecLongIterator { values: vec![10, 20, 30], pos: 3, last_yielded: None };
        let mut bwd = BackwardLongKeyIterator::new(Box::new(inner));

        assert!(bwd.has_next().unwrap());
        assert_eq!(bwd.next().unwrap(), 30);
        assert_eq!(bwd.next().unwrap(), 20);
        assert_eq!(bwd.next().unwrap(), 10);
        assert!(!bwd.has_next().unwrap());
        assert!(bwd.next().is_err());
    }

    #[test]
    fn delete_delegates_to_wrapped_iterator() {
        let inner = VecLongIterator { values: vec![1, 2, 3], pos: 3, last_yielded: None };
        let mut bwd = BackwardLongKeyIterator::new(Box::new(inner));

        assert_eq!(bwd.next().unwrap(), 3);
        assert_eq!(bwd.next().unwrap(), 2);
        assert!(bwd.delete().unwrap());
        // Deleting removed element "2" (index 1); remaining backing vec is [1, 3], and the
        // wrapped iterator's position moved back accordingly so continued backward walking
        // reaches "1" next.
        assert_eq!(bwd.next().unwrap(), 1);
        assert!(!bwd.has_next().unwrap());
    }

    #[test]
    fn object_safe_as_directed_long_key_iterator() {
        let inner = VecLongIterator { values: vec![7, 8], pos: 2, last_yielded: None };
        let mut boxed: Box<dyn DirectedLongKeyIterator> =
            Box::new(BackwardLongKeyIterator::new(Box::new(inner)));

        assert_eq!(boxed.next().unwrap(), 8);
        assert_eq!(boxed.next().unwrap(), 7);
        assert!(!boxed.has_next().unwrap());
    }
}
