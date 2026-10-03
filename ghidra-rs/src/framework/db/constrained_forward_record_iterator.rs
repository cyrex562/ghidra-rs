use std::cell::RefCell;
use std::io;

use super::record::DBRecord;
use super::RecordIterator;

/// Provides the ability to both filter and translate records returned from an underlying
/// [`RecordIterator`].
///
/// Port of `db.ConstrainedForwardRecordIterator`. Java's `recordPredicateAndTranslate` is a
/// `Function<DBRecord, DBRecord>` returning `null` to skip a record; this port uses
/// `FnMut(DBRecord) -> Option<DBRecord>` for the same effect.
///
/// [`RecordIterator::has_next`] is `&self` on this port's trait, but Java's real `hasNext()`
/// mutates state while scanning ahead (skipping and discarding filtered-out records until a
/// surviving one is found, or the underlying iterator is exhausted) -- it is not a pure query.
/// `it`, `record_predicate_and_translate`, and `next_converted_record` are therefore kept in
/// [`RefCell`]s purely to bridge that mutability mismatch, mirroring the same technique
/// `KeyToRecordIterator` already uses for the same reason: there is no actual shared ownership or
/// aliasing, since this iterator is the sole owner of all three.
pub struct ConstrainedForwardRecordIterator {
    next_converted_record: RefCell<Option<DBRecord>>,
    it: RefCell<Box<dyn RecordIterator>>,
    record_predicate_and_translate: RefCell<Box<dyn FnMut(DBRecord) -> Option<DBRecord>>>,
}

impl ConstrainedForwardRecordIterator {
    /// Construct a constrained/filtered record iterator.
    ///
    /// `record_predicate_and_translate`: function which enables both filtering of records (`None`
    /// returned if the record should be skipped) and the ability to translate the record to an
    /// alternate table/record schema.
    ///
    /// Mirrors `ConstrainedForwardRecordIterator(RecordIterator, Function<DBRecord, DBRecord>)`.
    pub fn new(
        it: Box<dyn RecordIterator>,
        record_predicate_and_translate: Box<dyn FnMut(DBRecord) -> Option<DBRecord>>,
    ) -> Self {
        Self {
            next_converted_record: RefCell::new(None),
            it: RefCell::new(it),
            record_predicate_and_translate: RefCell::new(record_predicate_and_translate),
        }
    }
}

impl RecordIterator for ConstrainedForwardRecordIterator {
    /// Mirrors `ConstrainedForwardRecordIterator.hasNext()`. An underlying I/O error is folded
    /// into `false` (nothing further available), matching how this port's infallible
    /// `RecordIterator::has_next` signature is used elsewhere (e.g. `KeyToRecordIterator`).
    fn has_next(&self) -> bool {
        if self.next_converted_record.borrow().is_some() {
            return true;
        }
        loop {
            let next = match self.it.borrow_mut().next() {
                Ok(Some(record)) => record,
                Ok(None) => return false,
                Err(_) => return false,
            };
            let converted = (self.record_predicate_and_translate.borrow_mut())(next);
            if converted.is_some() {
                *self.next_converted_record.borrow_mut() = converted;
                return true;
            }
        }
    }

    /// Mirrors `ConstrainedForwardRecordIterator.next()`.
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        if self.has_next() {
            Ok(self.next_converted_record.borrow_mut().take())
        } else {
            Ok(None)
        }
    }

    /// Always fails with [`io::ErrorKind::Unsupported`]: mirrors
    /// `ConstrainedForwardRecordIterator.hasPrevious()`, which unconditionally throws
    /// `UnsupportedOperationException`.
    fn has_previous(&self) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConstrainedForwardRecordIterator does not support hasPrevious",
        ))
    }

    /// Always fails with [`io::ErrorKind::Unsupported`]: mirrors
    /// `ConstrainedForwardRecordIterator.previous()`, which unconditionally throws
    /// `UnsupportedOperationException`.
    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConstrainedForwardRecordIterator does not support previous",
        ))
    }

    /// Always fails with [`io::ErrorKind::Unsupported`]: mirrors
    /// `ConstrainedForwardRecordIterator.delete()`, which unconditionally throws
    /// `UnsupportedOperationException`.
    fn delete(&mut self) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConstrainedForwardRecordIterator does not support delete",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        pos: isize,
    }

    impl VecRecordIterator {
        fn new(records: Vec<DBRecord>) -> Self {
            Self { records, pos: -1 }
        }
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            let next = self.pos + 1;
            if next >= self.records.len() as isize {
                return Ok(None);
            }
            self.pos = next;
            Ok(Some(self.records[self.pos as usize].clone()))
        }

        fn has_next(&self) -> bool {
            (self.pos + 1) < self.records.len() as isize
        }
    }

    fn make_records(values: &[i32]) -> Vec<DBRecord> {
        let schema = schema();
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut r = DBRecord::new(schema.clone(), Field::Long(Some(i as i64)));
                r.set_field(0, Field::Int(Some(v)));
                r
            })
            .collect()
    }

    /// Filters out odd values, doubling the ones that remain -- proves both the filtering and
    /// translation halves of `recordPredicateAndTranslate` in one pass.
    fn even_doubling_filter() -> Box<dyn FnMut(DBRecord) -> Option<DBRecord>> {
        Box::new(|mut rec: DBRecord| {
            let v = rec.get_field(0).get_int_value();
            if v % 2 != 0 {
                return None;
            }
            rec.set_field(0, Field::Int(Some(v * 2)));
            Some(rec)
        })
    }

    #[test]
    fn test_filters_and_translates() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[1, 2, 3, 4, 5, 6])));
        let mut it = ConstrainedForwardRecordIterator::new(inner, even_doubling_filter());

        let mut seen = Vec::new();
        while let Some(rec) = it.next().unwrap() {
            seen.push(rec.get_field(0).get_int_value());
        }
        assert_eq!(seen, vec![4, 8, 12]);
    }

    #[test]
    fn test_has_next_scans_ahead_through_filtered_records() {
        // The first two records (1, 3) are filtered out; has_next() must scan past both and
        // cache the surviving (2 -> 4) record, without needing next() to be called first.
        let inner = Box::new(VecRecordIterator::new(make_records(&[1, 3, 2])));
        let mut it = ConstrainedForwardRecordIterator::new(inner, even_doubling_filter());
        assert!(it.has_next());
        assert!(it.has_next()); // idempotent: second call reuses the cached record
        let rec = it.next().unwrap().unwrap();
        assert_eq!(rec.get_field(0).get_int_value(), 4);
        assert!(!it.has_next());
    }

    #[test]
    fn test_all_filtered_out_yields_none() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[1, 3, 5])));
        let mut it = ConstrainedForwardRecordIterator::new(inner, even_doubling_filter());
        assert!(!it.has_next());
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn test_previous_has_previous_and_delete_are_unsupported() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[2])));
        let mut it = ConstrainedForwardRecordIterator::new(inner, even_doubling_filter());
        assert_eq!(it.has_previous().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(it.previous().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(it.delete().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_object_safety() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[2])));
        let mut it: Box<dyn RecordIterator> =
            Box::new(ConstrainedForwardRecordIterator::new(inner, even_doubling_filter()));
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_int_value(), 4);
    }
}
