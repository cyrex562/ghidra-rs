//! Mirrors `ghidra.util.database.DirectedRecordIterator`: an iterator over records of a
//! [`Table`](crate::framework::db::Table).
//!
//! The Java interface extends `DirectedIterator<DBRecord>` and adds two static factories --
//! `getIterator(Table, KeySpan, Direction)` and `getIndexIterator(Table, int, FieldSpan,
//! Direction)` -- plus private `applyBegFilter`/`applyEndFilter`/`applyFilters` helpers used only
//! by those factories, and an `EMPTY` constant built from an anonymous `AbstractDirectedRecordIterator`.
//! `Table.iterator(min, max, start)`/`Table.indexIterator(...)` and the
//! `Abstract`/`Forward`/`BackwardRecordIterator` classes those factories and `EMPTY` depend on are
//! not yet ported, so the factories are represented as a construction contract,
//! [`DirectedRecordIteratorFactory`](crate::util::seam_stubs::DirectedRecordIteratorFactory),
//! rather than transliterated here; this trait carries only the inherited iteration contract, same
//! as the Java interface itself.

use crate::framework::db::record::DBRecord;
use crate::util::database::DirectedIterator;

/// An iterator over the records of a table, in the given
/// [`Direction`](crate::util::database::Direction).
///
/// Adds no methods beyond [`DirectedIterator`]: the Java interface's only members besides the
/// inherited `hasNext`/`next`/`delete` are the `EMPTY` constant and the static
/// `getIterator`/`getIndexIterator` factories (see the module docs).
pub trait DirectedRecordIterator: DirectedIterator<DBRecord> {}

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

    /// A mock over a `Vec<DBRecord>`, proving `DirectedRecordIterator` is object-safe and
    /// behaves like a real record iterator (walks, then deletes the last-yielded record).
    struct VecRecordIterator {
        records: Vec<DBRecord>,
        pos: usize,
        yielded: bool,
    }

    impl DirectedIterator<DBRecord> for VecRecordIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.records.len())
        }

        fn next(&mut self) -> io::Result<DBRecord> {
            if self.pos >= self.records.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more records"));
            }
            let record = self.records[self.pos].clone();
            self.pos += 1;
            self.yielded = true;
            Ok(record)
        }

        fn delete(&mut self) -> io::Result<bool> {
            if !self.yielded {
                return Ok(false);
            }
            self.records.remove(self.pos - 1);
            self.pos -= 1;
            self.yielded = false;
            Ok(true)
        }
    }

    impl DirectedRecordIterator for VecRecordIterator {}

    #[test]
    fn object_safe_and_walks_backing_records() {
        let schema = test_schema();
        let records = vec![
            DBRecord::new(schema.clone(), Field::Long(Some(1))),
            DBRecord::new(schema.clone(), Field::Long(Some(2))),
            DBRecord::new(schema.clone(), Field::Long(Some(3))),
        ];
        let mut iter: Box<dyn DirectedRecordIterator> =
            Box::new(VecRecordIterator { records, pos: 0, yielded: false });

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(1)));
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(2)));
        assert!(iter.delete().unwrap());
        assert_eq!(iter.next().unwrap().get_key(), &Field::Long(Some(3)));
        assert!(!iter.has_next().unwrap());
        assert!(iter.next().is_err());
    }
}
