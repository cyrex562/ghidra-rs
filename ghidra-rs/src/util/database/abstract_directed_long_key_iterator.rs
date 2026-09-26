//! Mirrors `ghidra.util.database.AbstractDirectedLongKeyIterator`: an abstract implementation of
//! [`DirectedLongKeyIterator`](crate::util::database::DirectedLongKeyIterator).
//!
//! The Java class wraps a `db.DBLongIterator` (already ported as
//! [`DBLongIterator`](crate::framework::db::DBLongIterator)) in a `protected final` field and
//! implements only `delete()` by delegating to it, leaving `hasNext`/`next` to concrete
//! subclasses (`ForwardLongKeyIterator`/`BackwardLongKeyIterator`, not yet ported) which impose
//! the iteration direction. Rust has no class inheritance, so this is expressed as a standalone
//! trait: implementors provide [`it`](Self::it), an accessor for the wrapped iterator, and get
//! [`delete`](Self::delete) for free. Method names mirror
//! [`DirectedLongKeyIterator`](crate::util::database::DirectedLongKeyIterator)/
//! [`DirectedIterator`](crate::util::database::DirectedIterator) so a future implementor can
//! adopt both with minimal friction.

use crate::framework::db::DBLongIterator;

/// Default `delete()` for a `DirectedLongKeyIterator` built on a wrapped
/// [`DBLongIterator`](crate::framework::db::DBLongIterator).
pub trait AbstractDirectedLongKeyIterator {
    /// Accessor for the wrapped iterator. Mirrors the `protected final DBLongIterator it` field.
    fn it(&mut self) -> &mut dyn DBLongIterator;

    /// Mirrors `delete()`: delegates to the wrapped iterator's `delete`.
    fn delete(&mut self) -> std::io::Result<bool> {
        self.it().delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock `DBLongIterator` over a `Vec<i64>`, tracking whether `delete` was invoked.
    struct VecLongIterator {
        values: Vec<i64>,
        pos: usize,
        deleted: bool,
    }

    impl DBLongIterator for VecLongIterator {
        fn has_next(&mut self) -> std::io::Result<bool> {
            Ok(self.pos < self.values.len())
        }

        fn has_previous(&mut self) -> std::io::Result<bool> {
            Ok(self.pos > 0)
        }

        fn next(&mut self) -> std::io::Result<i64> {
            let value = self.values[self.pos];
            self.pos += 1;
            Ok(value)
        }

        fn previous(&mut self) -> std::io::Result<i64> {
            self.pos -= 1;
            Ok(self.values[self.pos])
        }

        fn delete(&mut self) -> std::io::Result<bool> {
            self.deleted = true;
            Ok(true)
        }
    }

    /// A stand-in for a concrete `Forward`/`BackwardLongKeyIterator` subclass: it only needs
    /// to supply the wrapped iterator to inherit `delete` from `AbstractDirectedLongKeyIterator`.
    struct StubDirectedIterator {
        inner: VecLongIterator,
    }

    impl AbstractDirectedLongKeyIterator for StubDirectedIterator {
        fn it(&mut self) -> &mut dyn DBLongIterator {
            &mut self.inner
        }
    }

    #[test]
    fn delete_delegates_to_wrapped_db_long_iterator_through_trait_object() {
        let mut iter = StubDirectedIterator {
            inner: VecLongIterator { values: vec![1, 2, 3], pos: 0, deleted: false },
        };
        let dyn_iter: &mut dyn AbstractDirectedLongKeyIterator = &mut iter;

        assert!(dyn_iter.delete().unwrap());
        assert!(iter.inner.deleted);
    }
}
