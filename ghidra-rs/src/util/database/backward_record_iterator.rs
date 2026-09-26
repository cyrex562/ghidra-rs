//! Port of `ghidra.util.database.BackwardRecordIterator`.

use crate::framework::db::record::DBRecord;
use crate::framework::db::RecordIterator;
use crate::util::database::{AbstractDirectedRecordIterator, DirectedIterator, DirectedRecordIterator};
use crate::util::seam_stubs::RecordIteratorDelete;

/// Bridges any real [`RecordIterator`] into the narrower [`RecordIteratorDelete`] contract that
/// [`AbstractDirectedRecordIterator::it`] needs. `RecordIteratorDelete` was written as a
/// placeholder standing in for `delete()` before `RecordIterator` itself declared that method (see
/// [`AbstractDirectedRecordIterator`]'s doc comment); now that it does, every `RecordIterator` is
/// trivially also a `RecordIteratorDelete`.
impl<T: RecordIterator + Send + Sync> RecordIteratorDelete for T {
    fn delete(&mut self) -> std::io::Result<bool> {
        RecordIterator::delete(self)
    }
}

/// A wrapper of [`RecordIterator`] that runs it backward and implements
/// [`DirectedRecordIterator`].
///
/// Port of `ghidra.util.database.BackwardRecordIterator`. Java extends
/// `AbstractDirectedRecordIterator` (a `protected final RecordIterator it` field plus a `delete()`
/// that delegates to it); Rust has no class inheritance, so this composes the wrapped iterator
/// directly and implements [`AbstractDirectedRecordIterator`] as a trait to inherit its default
/// `delete()`, mirroring the precedent already established for
/// [`AbstractDirectedLongKeyIterator`](crate::util::database::AbstractDirectedLongKeyIterator)'s
/// own concrete wrappers.
pub struct BackwardRecordIterator<I: RecordIterator + Send + Sync> {
    it: I,
}

impl<I: RecordIterator + Send + Sync> BackwardRecordIterator<I> {
    /// Port of `BackwardRecordIterator(RecordIterator)`.
    pub fn new(it: I) -> Self {
        BackwardRecordIterator { it }
    }
}

impl<I: RecordIterator + Send + Sync> AbstractDirectedRecordIterator for BackwardRecordIterator<I> {
    fn it(&mut self) -> &mut dyn RecordIteratorDelete {
        &mut self.it
    }
}

impl<I: RecordIterator + Send + Sync> DirectedIterator<DBRecord> for BackwardRecordIterator<I> {
    /// Port of `hasNext()`: `it.hasPrevious()`.
    fn has_next(&mut self) -> std::io::Result<bool> {
        self.it.has_previous()
    }

    /// Port of `next()`: `it.previous()`.
    fn next(&mut self) -> std::io::Result<DBRecord> {
        self.it.previous()?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no previous record")
        })
    }

    /// Mirrors the inherited `AbstractDirectedRecordIterator.delete()`.
    fn delete(&mut self) -> std::io::Result<bool> {
        AbstractDirectedRecordIterator::delete(self)
    }
}

impl<I: RecordIterator + Send + Sync> DirectedRecordIterator for BackwardRecordIterator<I> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use std::io;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(0, FieldType::Long, "key".to_string(), vec![], vec![], vec![]))
    }

    /// A mock `RecordIterator` over a `Vec<DBRecord>` that only supports the reverse direction
    /// (`has_next`/`next` always report "nothing available"), matching what
    /// `BackwardRecordIterator` actually calls.
    struct VecReverseIterator {
        records: Vec<DBRecord>,
        pos: usize, // one past the last record already yielded via `previous`
        yielded: bool,
    }

    impl RecordIterator for VecReverseIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }

        fn has_next(&self) -> bool {
            false
        }

        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }

        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.pos == 0 {
                return Ok(None);
            }
            self.pos -= 1;
            self.yielded = true;
            Ok(Some(self.records[self.pos].clone()))
        }

        fn delete(&mut self) -> io::Result<bool> {
            if !self.yielded {
                return Ok(false);
            }
            self.records.remove(self.pos);
            self.yielded = false;
            Ok(true)
        }
    }

    fn records(keys: &[i64]) -> (Vec<DBRecord>, Arc<Schema>) {
        let schema = test_schema();
        let recs = keys
            .iter()
            .map(|k| DBRecord::new(schema.clone(), Field::Long(Some(*k))))
            .collect();
        (recs, schema)
    }

    #[test]
    fn walks_records_in_reverse_like_java_backward_record_iterator() {
        let (recs, _schema) = records(&[1, 2, 3]);
        let pos = recs.len();
        let mut iter =
            BackwardRecordIterator::new(VecReverseIterator { records: recs, pos, yielded: false });

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(3)));
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(2)));
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(1)));
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn delete_delegates_through_abstract_directed_record_iterator() {
        let (recs, _schema) = records(&[10, 20]);
        let pos = recs.len();
        let mut iter =
            BackwardRecordIterator::new(VecReverseIterator { records: recs, pos, yielded: false });

        // Java: delete() before any next()/previous() call is a no-op (nothing yielded yet).
        assert!(!DirectedIterator::delete(&mut iter).unwrap());

        iter.next().unwrap();
        assert!(DirectedIterator::delete(&mut iter).unwrap());
        assert_eq!(iter.it.records.len(), 1);
    }

    #[test]
    fn is_usable_as_dyn_directed_record_iterator() {
        let (recs, _schema) = records(&[7]);
        let pos = recs.len();
        let mut iter =
            BackwardRecordIterator::new(VecReverseIterator { records: recs, pos, yielded: false });
        let dyn_iter: &mut dyn DirectedRecordIterator = &mut iter;

        assert!(dyn_iter.has_next().unwrap());
        assert_eq!(dyn_iter.next().unwrap().get_key(), &Field::Long(Some(7)));
    }
}
