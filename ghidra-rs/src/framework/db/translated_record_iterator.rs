use std::io;

use super::record::DBRecord;
use super::record_translator::RecordTranslator;
use super::RecordIterator;

/// A [`RecordIterator`] that translates each record produced by an underlying iterator into its
/// current-version form via a [`RecordTranslator`].
///
/// Port of `db.TranslatedRecordIterator`.
pub struct TranslatedRecordIterator {
    it: Box<dyn RecordIterator>,
    translator: Box<dyn RecordTranslator>,
}

impl TranslatedRecordIterator {
    /// Construct a translating record iterator. Mirrors
    /// `TranslatedRecordIterator(RecordIterator, RecordTranslator)`.
    pub fn new(it: Box<dyn RecordIterator>, translator: Box<dyn RecordTranslator>) -> Self {
        Self { it, translator }
    }
}

impl RecordIterator for TranslatedRecordIterator {
    /// Mirrors `TranslatedRecordIterator.next()`.
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        match self.it.next()? {
            Some(old_record) => Ok(Some(self.translator.translate_record(old_record)?)),
            None => Ok(None),
        }
    }

    /// Mirrors `TranslatedRecordIterator.hasNext()`.
    fn has_next(&self) -> bool {
        self.it.has_next()
    }

    /// Mirrors `TranslatedRecordIterator.hasPrevious()`.
    fn has_previous(&self) -> io::Result<bool> {
        self.it.has_previous()
    }

    /// Mirrors `TranslatedRecordIterator.previous()`.
    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        match self.it.previous()? {
            Some(old_record) => Ok(Some(self.translator.translate_record(old_record)?)),
            None => Ok(None),
        }
    }

    /// Always fails with [`io::ErrorKind::Unsupported`]: mirrors `TranslatedRecordIterator.delete()`,
    /// which unconditionally throws `UnsupportedOperationException`.
    fn delete(&mut self) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TranslatedRecordIterator does not support delete",
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

    /// Forward/backward iterator over a fixed `Vec<DBRecord>`, standing in for a real underlying
    /// `RecordIterator`.
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
    }

    /// Translator that doubles the stored int value, proving real per-record transformation
    /// rather than a pass-through stub.
    struct DoublingTranslator;

    impl RecordTranslator for DoublingTranslator {
        fn translate_record(&self, mut old_record: DBRecord) -> io::Result<DBRecord> {
            let v = old_record.get_field(0).get_int_value();
            old_record.set_field(0, Field::Int(Some(v * 2)));
            Ok(old_record)
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

    #[test]
    fn test_next_translates_each_record() {
        let records = make_records(&[1, 2, 3]);
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = TranslatedRecordIterator::new(inner, Box::new(DoublingTranslator));

        assert!(it.has_next());
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_int_value(), 2);
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_int_value(), 4);
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_int_value(), 6);
        assert!(!it.has_next());
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn test_previous_translates_each_record() {
        let records = make_records(&[10, 20]);
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = TranslatedRecordIterator::new(inner, Box::new(DoublingTranslator));

        it.next().unwrap();
        it.next().unwrap();

        assert!(it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap().unwrap().get_field(0).get_int_value(), 40);
        assert_eq!(it.previous().unwrap().unwrap().get_field(0).get_int_value(), 20);
        assert!(!it.has_previous().unwrap());
    }

    #[test]
    fn test_delete_is_unsupported() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[1])));
        let mut it = TranslatedRecordIterator::new(inner, Box::new(DoublingTranslator));
        it.next().unwrap();
        let err = it.delete().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_object_safety() {
        let inner = Box::new(VecRecordIterator::new(make_records(&[5])));
        let mut it: Box<dyn RecordIterator> =
            Box::new(TranslatedRecordIterator::new(inner, Box::new(DoublingTranslator)));
        assert_eq!(it.next().unwrap().unwrap().get_field(0).get_int_value(), 10);
    }
}
