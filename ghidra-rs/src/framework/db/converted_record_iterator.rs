use std::io;

use super::record::DBRecord;
use super::RecordIterator;

/// A [`RecordIterator`] wrapper that performs record conversion, frequently required when reading
/// older data.
///
/// Port of `db.ConvertedRecordIterator`, an `abstract class` whose sole abstract method
/// (`convertRecord`) is implemented by each concrete subclass. Per this crate's
/// composition-over-inheritance convention, that single-abstract-method shape is ported as a
/// struct holding a boxed conversion closure rather than as a trait subclasses would implement --
/// observably equivalent (every real subclass just supplies a `DBRecord -> DBRecord` mapping) and
/// avoids fabricating Rust trait inheritance to stand in for `extends`.
pub struct ConvertedRecordIterator {
    original_iterator: Box<dyn RecordIterator>,
    delete_allowed: bool,
    convert_record: Box<dyn FnMut(DBRecord) -> DBRecord>,
}

impl ConvertedRecordIterator {
    /// Construct a converting record iterator.
    ///
    /// `delete_allowed`: if `false` and [`Self::delete`] is attempted, it fails with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// Mirrors the protected `ConvertedRecordIterator(RecordIterator, boolean)` constructor; the
    /// `convertRecord` abstract method a real subclass would implement is supplied here directly
    /// as `convert_record` (see the struct-level doc comment).
    pub fn new(
        original_iterator: Box<dyn RecordIterator>,
        delete_allowed: bool,
        convert_record: Box<dyn FnMut(DBRecord) -> DBRecord>,
    ) -> Self {
        Self { original_iterator, delete_allowed, convert_record }
    }
}

impl RecordIterator for ConvertedRecordIterator {
    /// Mirrors `ConvertedRecordIterator.next()`.
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        match self.original_iterator.next()? {
            Some(record) => Ok(Some((self.convert_record)(record))),
            None => Ok(None),
        }
    }

    /// Mirrors `ConvertedRecordIterator.hasNext()`.
    fn has_next(&self) -> bool {
        self.original_iterator.has_next()
    }

    /// Mirrors `ConvertedRecordIterator.hasPrevious()`.
    fn has_previous(&self) -> io::Result<bool> {
        self.original_iterator.has_previous()
    }

    /// Mirrors `ConvertedRecordIterator.previous()`.
    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        match self.original_iterator.previous()? {
            Some(record) => Ok(Some((self.convert_record)(record))),
            None => Ok(None),
        }
    }

    /// Mirrors `ConvertedRecordIterator.delete()`: fails with [`io::ErrorKind::Unsupported`]
    /// (standing in for Java's `UnsupportedOperationException`) unless this instance was
    /// constructed with `delete_allowed = true`.
    fn delete(&mut self) -> io::Result<bool> {
        if !self.delete_allowed {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "record delete not allowed",
            ));
        }
        self.original_iterator.delete()
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
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        pos: isize,
        deleted: Vec<bool>,
    }

    impl VecRecordIterator {
        fn new(records: Vec<DBRecord>) -> Self {
            let len = records.len();
            Self { records, pos: -1, deleted: vec![false; len] }
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

        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.pos >= 0)
        }

        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.pos < 0 {
                return Ok(None);
            }
            let rec = self.records[self.pos as usize].clone();
            self.pos -= 1;
            Ok(Some(rec))
        }

        fn delete(&mut self) -> io::Result<bool> {
            if self.pos < 0 {
                return Ok(false);
            }
            let idx = self.pos as usize;
            if self.deleted[idx] {
                Ok(false)
            } else {
                self.deleted[idx] = true;
                Ok(true)
            }
        }
    }

    fn make_records(names: &[&str]) -> Vec<DBRecord> {
        let schema = schema();
        names
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let mut r = DBRecord::new(schema.clone(), Field::Long(Some(i as i64)));
                r.set_field(0, Field::String(Some(n.to_string())));
                r
            })
            .collect()
    }

    fn upcase_converter() -> Box<dyn FnMut(DBRecord) -> DBRecord> {
        Box::new(|mut rec: DBRecord| {
            let upper = rec.get_field(0).get_string_value().unwrap_or("").to_uppercase();
            rec.set_field(0, Field::String(Some(upper)));
            rec
        })
    }

    #[test]
    fn test_next_converts_each_record() {
        let inner = Box::new(VecRecordIterator::new(make_records(&["a", "b"])));
        let mut it = ConvertedRecordIterator::new(inner, true, upcase_converter());

        assert!(it.has_next());
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_string_value(), Some("A"));
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_string_value(), Some("B"));
        assert!(!it.has_next());
    }

    #[test]
    fn test_previous_converts_each_record() {
        let inner = Box::new(VecRecordIterator::new(make_records(&["x", "y"])));
        let mut it = ConvertedRecordIterator::new(inner, true, upcase_converter());
        it.next().unwrap();
        it.next().unwrap();

        assert!(it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap().unwrap().get_field(0).get_string_value(), Some("Y"));
        assert_eq!(it.previous().unwrap().unwrap().get_field(0).get_string_value(), Some("X"));
    }

    #[test]
    fn test_delete_allowed_delegates_to_original() {
        let inner = Box::new(VecRecordIterator::new(make_records(&["a"])));
        let mut it = ConvertedRecordIterator::new(inner, true, upcase_converter());
        it.next().unwrap();
        assert!(it.delete().unwrap());
        assert!(!it.delete().unwrap()); // already deleted
    }

    #[test]
    fn test_delete_disallowed_is_unsupported() {
        let inner = Box::new(VecRecordIterator::new(make_records(&["a"])));
        let mut it = ConvertedRecordIterator::new(inner, false, upcase_converter());
        it.next().unwrap();
        let err = it.delete().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_object_safety() {
        let inner = Box::new(VecRecordIterator::new(make_records(&["z"])));
        let mut it: Box<dyn RecordIterator> =
            Box::new(ConvertedRecordIterator::new(inner, true, upcase_converter()));
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_string_value(), Some("Z"));
    }
}
