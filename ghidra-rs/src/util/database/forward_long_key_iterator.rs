//! Port of `ghidra.util.database.ForwardLongKeyIterator`: a wrapper of
//! [`DBLongIterator`](crate::framework::db::DBLongIterator) that runs it forward and implements
//! [`DirectedLongKeyIterator`](crate::util::database::DirectedLongKeyIterator).
//!
//! The Java class `extends AbstractDirectedLongKeyIterator`, inheriting `delete()` and adding
//! only `hasNext`/`next`, which delegate to the wrapped iterator's forward-direction methods
//! (`hasNext`/`next`, as opposed to `BackwardLongKeyIterator`'s `hasPrevious`/`previous`).
//! Per this crate's composition-over-inheritance convention, the wrapped iterator is a plain
//! field rather than a composed [`AbstractDirectedLongKeyIterator`] (composing that trait here
//! would give this type two independently-implemented `delete()` methods in scope --
//! [`DirectedIterator::delete`](crate::util::database::DirectedIterator::delete)'s own required
//! member, and the abstract trait's default -- which is exactly the kind of same-name-method
//! ambiguity Rust's dot-call resolution can't silently paper over the way Java's single-parent
//! `extends` chain does); `delete` is implemented directly here, delegating to the same
//! `it.delete()` the abstract trait's default would have called anyway, so behavior is
//! unaffected.

use std::io;

use crate::framework::db::DBLongIterator;
use crate::util::database::{DirectedIterator, DirectedLongKeyIterator};

/// A wrapper of [`DBLongIterator`] that runs it forward. Mirrors
/// `ghidra.util.database.ForwardLongKeyIterator`.
pub struct ForwardLongKeyIterator {
    it: Box<dyn DBLongIterator>,
}

impl ForwardLongKeyIterator {
    /// Mirrors `ForwardLongKeyIterator(DBLongIterator)`.
    pub fn new(it: Box<dyn DBLongIterator>) -> Self {
        Self { it }
    }
}

impl DirectedIterator<i64> for ForwardLongKeyIterator {
    /// Mirrors `hasNext()`: delegates to the wrapped iterator's forward-direction `hasNext()`.
    fn has_next(&mut self) -> io::Result<bool> {
        self.it.has_next()
    }

    /// Mirrors `next()`: delegates to the wrapped iterator's forward-direction `next()`.
    fn next(&mut self) -> io::Result<i64> {
        self.it.next()
    }

    /// Mirrors the inherited `AbstractDirectedLongKeyIterator.delete()`.
    fn delete(&mut self) -> io::Result<bool> {
        self.it.delete()
    }
}

impl DirectedLongKeyIterator for ForwardLongKeyIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock `DBLongIterator` over a `Vec<i64>`.
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
    fn walks_forward_using_has_next_and_next() {
        let inner = VecLongIterator { values: vec![10, 20, 30], pos: 0, last_yielded: None };
        let mut fwd = ForwardLongKeyIterator::new(Box::new(inner));

        assert!(fwd.has_next().unwrap());
        assert_eq!(fwd.next().unwrap(), 10);
        assert_eq!(fwd.next().unwrap(), 20);
        assert_eq!(fwd.next().unwrap(), 30);
        assert!(!fwd.has_next().unwrap());
        assert!(fwd.next().is_err());
    }

    #[test]
    fn delete_delegates_to_wrapped_iterator() {
        let inner = VecLongIterator { values: vec![1, 2, 3], pos: 0, last_yielded: None };
        let mut fwd = ForwardLongKeyIterator::new(Box::new(inner));

        assert_eq!(fwd.next().unwrap(), 1);
        assert_eq!(fwd.next().unwrap(), 2);
        assert!(fwd.delete().unwrap());
        // The deleted element (2) is gone; only 1 and 3 remain, and we're positioned after 1.
        assert_eq!(fwd.next().unwrap(), 3);
        assert!(!fwd.has_next().unwrap());
    }

    #[test]
    fn object_safe_as_directed_long_key_iterator() {
        let inner = VecLongIterator { values: vec![7, 8], pos: 0, last_yielded: None };
        let mut boxed: Box<dyn DirectedLongKeyIterator> =
            Box::new(ForwardLongKeyIterator::new(Box::new(inner)));

        assert_eq!(boxed.next().unwrap(), 7);
        assert_eq!(boxed.next().unwrap(), 8);
        assert!(!boxed.has_next().unwrap());
    }
}
