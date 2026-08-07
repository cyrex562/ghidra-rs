//! Mirrors `ghidra.util.database.AbstractDirectedRecordIterator`: an abstract implementation of
//! [`DirectedRecordIterator`](crate::util::database::DirectedRecordIterator).
//!
//! The Java class wraps a `db.RecordIterator` in a `protected final` field and implements only
//! `delete()` by delegating to it, leaving `hasNext`/`next` to concrete subclasses
//! (`ForwardRecordIterator`/`BackwardRecordIterator`, not yet ported) which impose the iteration
//! direction. Rust has no class inheritance, so this is expressed as a standalone trait:
//! implementors provide [`it`](Self::it), an accessor for the wrapped iterator, and get
//! [`delete`](Self::delete) for free -- the same shape used for
//! [`AbstractDirectedLongKeyIterator`](crate::util::database::AbstractDirectedLongKeyIterator).
//!
//! The ported [`RecordIterator`](crate::framework::db::RecordIterator) trait only carries the
//! `next`/`has_next` members ported so far; `delete` (the only member this class needs) hasn't
//! been added to it yet. Until it is, the wrapped iterator is accessed through
//! [`RecordIteratorDelete`](crate::util::seam_stubs::RecordIteratorDelete), a minimal placeholder
//! standing in for that one missing member.

use crate::util::seam_stubs::RecordIteratorDelete;

/// Default `delete()` for a `DirectedRecordIterator` built on a wrapped
/// `db.RecordIterator`-like deletable iterator.
pub trait AbstractDirectedRecordIterator {
    /// Accessor for the wrapped iterator. Mirrors the `protected final RecordIterator it` field.
    fn it(&mut self) -> &mut dyn RecordIteratorDelete;

    /// Mirrors `delete()`: delegates to the wrapped iterator's `delete`.
    fn delete(&mut self) -> std::io::Result<bool> {
        self.it().delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock deletable record iterator over a `Vec<i64>` "record" ids, tracking whether
    /// `delete` was invoked.
    struct VecDeletableIterator {
        records: Vec<i64>,
        pos: usize,
        deleted: bool,
    }

    impl RecordIteratorDelete for VecDeletableIterator {
        fn delete(&mut self) -> std::io::Result<bool> {
            if self.pos == 0 || self.pos > self.records.len() {
                return Ok(false);
            }
            self.records.remove(self.pos - 1);
            self.pos -= 1;
            self.deleted = true;
            Ok(true)
        }
    }

    /// A stand-in for a concrete `Forward`/`BackwardRecordIterator` subclass: it only needs
    /// to supply the wrapped iterator to inherit `delete` from `AbstractDirectedRecordIterator`.
    struct StubDirectedRecordIterator {
        inner: VecDeletableIterator,
    }

    impl AbstractDirectedRecordIterator for StubDirectedRecordIterator {
        fn it(&mut self) -> &mut dyn RecordIteratorDelete {
            &mut self.inner
        }
    }

    #[test]
    fn delete_delegates_to_wrapped_record_iterator_through_trait_object() {
        let mut iter = StubDirectedRecordIterator {
            inner: VecDeletableIterator { records: vec![1, 2, 3], pos: 2, deleted: false },
        };
        let dyn_iter: &mut dyn AbstractDirectedRecordIterator = &mut iter;

        assert!(dyn_iter.delete().unwrap());
        assert!(iter.inner.deleted);
        assert_eq!(iter.inner.records, vec![1, 3]);
        assert_eq!(iter.inner.pos, 1);
    }
}
