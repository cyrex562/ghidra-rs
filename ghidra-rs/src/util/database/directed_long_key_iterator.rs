//! Mirrors `ghidra.util.database.DirectedLongKeyIterator`: an iterator over the primary keys of
//! a [`Table`](crate::framework::db::Table).
//!
//! The Java interface extends `DirectedIterator<Long>` and adds one static factory,
//! `getIterator(Table, KeySpan, Direction)`, that builds a `ForwardLongKeyIterator` or
//! `BackwardLongKeyIterator` wrapping `Table.longKeyIterator(min, max, start)`. `Table`'s ranged
//! key iteration and the `Abstract`/`Forward`/`Backward` wrapper classes are not yet ported, so
//! the factory is represented as a construction contract,
//! [`DirectedLongKeyIteratorFactory`](crate::util::seam_stubs::DirectedLongKeyIteratorFactory),
//! rather than transliterated here; this trait carries only the inherited iteration contract,
//! same as the Java interface itself.

use crate::util::database::DirectedIterator;

/// An iterator over the primary keys of a table, in the given
/// [`Direction`](crate::util::database::Direction).
///
/// Adds no methods beyond [`DirectedIterator`]: the Java interface's only member besides the
/// inherited `hasNext`/`next`/`delete` is the static `getIterator` factory (see the module docs).
pub trait DirectedLongKeyIterator: DirectedIterator<i64> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A mock over a `Vec<i64>`, proving `DirectedLongKeyIterator` is object-safe and behaves
    /// like a real key iterator (walks, then deletes the last-yielded key).
    struct VecKeyIterator {
        keys: Vec<i64>,
        pos: usize,
        yielded: bool,
    }

    impl DirectedIterator<i64> for VecKeyIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.keys.len())
        }

        fn next(&mut self) -> io::Result<i64> {
            if self.pos >= self.keys.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more keys"));
            }
            let value = self.keys[self.pos];
            self.pos += 1;
            self.yielded = true;
            Ok(value)
        }

        fn delete(&mut self) -> io::Result<bool> {
            if !self.yielded {
                return Ok(false);
            }
            self.keys.remove(self.pos - 1);
            self.pos -= 1;
            self.yielded = false;
            Ok(true)
        }
    }

    impl DirectedLongKeyIterator for VecKeyIterator {}

    #[test]
    fn object_safe_and_walks_backing_keys() {
        let mut iter: Box<dyn DirectedLongKeyIterator> =
            Box::new(VecKeyIterator { keys: vec![100, 200, 300], pos: 0, yielded: false });

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 100);
        assert_eq!(iter.next().unwrap(), 200);
        assert!(iter.delete().unwrap());
        assert_eq!(iter.next().unwrap(), 300);
        assert!(!iter.has_next().unwrap());
        assert!(iter.next().is_err());
    }
}
