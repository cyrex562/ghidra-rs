use std::io;

use super::db_field_iterator::DBFieldIterator;
use super::field::Field;
use super::record::DBRecord;

/// A simplified index table whose key is a fixed or variable length indexed field consisting of a
/// concatenation of the index field value and associated primary table key.
///
/// Mirrors `db.FieldIndexTable`, the sole concrete subclass of `db.IndexTable` (which is not yet
/// ported). Ported here as an object-safe trait, a cycle cut-point, so that dependents can hold
/// `Box<dyn FieldIndexTable>` / `&dyn FieldIndexTable` instead of a concrete type. Only the
/// methods `FieldIndexTable` itself declares or overrides are represented; behavior inherited
/// unchanged from `IndexTable` (e.g. `deleteAll`, `isConsistent`) belongs to that type once it is
/// ported.
pub trait FieldIndexTable {
    /// Find all primary keys which correspond to the specified indexed field value.
    fn find_primary_keys(&self, index_value: &Field) -> io::Result<Vec<Field>>;

    /// Get the number of primary keys which correspond to the specified indexed field value.
    fn get_key_count(&self, index_value: &Field) -> io::Result<usize>;

    /// Add an entry to this index. Caller is responsible for ensuring that this is not a
    /// duplicate entry.
    fn add_entry(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Delete an entry from this index.
    fn delete_entry(&mut self, old_record: &DBRecord) -> io::Result<()>;

    /// Determine if there is an occurrence of the specified index key value.
    fn has_record(&self, field: &Field) -> io::Result<bool>;

    /// Iterate over all index keys. Index keys are sorted in ascending order.
    fn index_iterator(&self) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all the unique index field values within the specified range identified by
    /// `min_field` and `max_field`. Index values are returned in ascending sorted order.
    ///
    /// `before`: if true, initial position is before `min_field`, else position is after
    /// `max_field`.
    fn index_iterator_range(
        &self,
        min_field: Option<&Field>,
        max_field: Option<&Field>,
        before: bool,
    ) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all the unique index field values within the specified range identified by
    /// `min_field` and `max_field`, with the initial iterator position corresponding to
    /// `start_field`.
    ///
    /// `before`: if true, initial position is before `start_field` value, else position is after
    /// `start_field` value.
    fn index_iterator_from(
        &self,
        min_field: Option<&Field>,
        max_field: Option<&Field>,
        start_field: &Field,
        before: bool,
    ) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key.
    fn key_iterator(&self) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, initially
    /// positioned before the first entry whose index key is greater than or equal to
    /// `start_field`.
    fn key_iterator_before(&self, start_field: &Field) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, initially
    /// positioned after the entry whose index key equals `start_field`, or immediately before the
    /// first entry whose index key is greater than `start_field`.
    fn key_iterator_after(&self, start_field: &Field) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, initially
    /// positioned before `primary_key` within the entry whose index key equals `start_field`, or
    /// immediately before the first entry whose index key is greater than `start_field`.
    fn key_iterator_before_at(
        &self,
        start_field: &Field,
        primary_key: &Field,
    ) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, initially
    /// positioned after `primary_key` within the entry whose index key equals `start_field`, or
    /// immediately before the first entry whose index key is greater than `start_field`.
    fn key_iterator_after_at(
        &self,
        start_field: &Field,
        primary_key: &Field,
    ) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, limited to the
    /// range of index keys `min_field` through `max_field`, inclusive.
    ///
    /// If `at_start` is true, the iterator is initially positioned before the first entry whose
    /// index key is greater than or equal to `min_field`. Otherwise, it is positioned after the
    /// first entry whose index key is less than or equal to `max_field`.
    fn key_iterator_range(
        &self,
        min_field: &Field,
        max_field: &Field,
        at_start: bool,
    ) -> io::Result<Box<dyn DBFieldIterator>>;

    /// Iterate over all primary keys sorted based upon the associated index key, limited to the
    /// range of index keys `min_field` through `max_field`, inclusive, initially positioned
    /// before or after `start_field`.
    ///
    /// `before`: if true positioned before `start_field` value, else positioned after `max_field`
    /// value.
    fn key_iterator_range_from(
        &self,
        min_field: &Field,
        max_field: &Field,
        start_field: &Field,
        before: bool,
    ) -> io::Result<Box<dyn DBFieldIterator>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Minimal in-memory `FieldIndexTable` mock: maps indexed field value -> primary keys.
    /// Proves object-safety and exercises real add/delete/find/iterate behavior rather than
    /// trivially-true assertions.
    struct MockFieldIndexTable {
        entries: BTreeMap<Field, Vec<Field>>,
    }

    impl MockFieldIndexTable {
        fn new() -> Self {
            Self { entries: BTreeMap::new() }
        }

        fn indexed_value(record: &DBRecord) -> Field {
            record.get_field(0).clone()
        }
    }

    struct VecFieldIterator {
        values: Vec<Field>,
        pos: isize,
    }

    impl VecFieldIterator {
        fn new(values: Vec<Field>) -> Self {
            Self { values, pos: -1 }
        }
    }

    impl DBFieldIterator for VecFieldIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok((self.pos + 1) < self.values.len() as isize)
        }

        fn has_previous(&mut self) -> io::Result<bool> {
            Ok(self.pos >= 0)
        }

        fn next(&mut self) -> io::Result<Option<Field>> {
            let next = self.pos + 1;
            if next >= self.values.len() as isize {
                return Ok(None);
            }
            self.pos = next;
            Ok(Some(self.values[self.pos as usize].clone()))
        }

        fn previous(&mut self) -> io::Result<Option<Field>> {
            if self.pos < 0 {
                return Ok(None);
            }
            let val = self.values[self.pos as usize].clone();
            self.pos -= 1;
            Ok(Some(val))
        }

        fn delete(&mut self) -> io::Result<bool> {
            Ok(false)
        }
    }

    impl FieldIndexTable for MockFieldIndexTable {
        fn find_primary_keys(&self, index_value: &Field) -> io::Result<Vec<Field>> {
            Ok(self.entries.get(index_value).cloned().unwrap_or_default())
        }

        fn get_key_count(&self, index_value: &Field) -> io::Result<usize> {
            Ok(self.find_primary_keys(index_value)?.len())
        }

        fn add_entry(&mut self, record: &DBRecord) -> io::Result<()> {
            let indexed = Self::indexed_value(record);
            self.entries.entry(indexed).or_default().push(record.get_key().clone());
            Ok(())
        }

        fn delete_entry(&mut self, old_record: &DBRecord) -> io::Result<()> {
            let indexed = Self::indexed_value(old_record);
            if let Some(keys) = self.entries.get_mut(&indexed) {
                keys.retain(|k| k != old_record.get_key());
                if keys.is_empty() {
                    self.entries.remove(&indexed);
                }
            }
            Ok(())
        }

        fn has_record(&self, field: &Field) -> io::Result<bool> {
            Ok(self.entries.contains_key(field))
        }

        fn index_iterator(&self) -> io::Result<Box<dyn DBFieldIterator>> {
            Ok(Box::new(VecFieldIterator::new(self.entries.keys().cloned().collect())))
        }

        fn index_iterator_range(
            &self,
            _min_field: Option<&Field>,
            _max_field: Option<&Field>,
            _before: bool,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.index_iterator()
        }

        fn index_iterator_from(
            &self,
            _min_field: Option<&Field>,
            _max_field: Option<&Field>,
            _start_field: &Field,
            _before: bool,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.index_iterator()
        }

        fn key_iterator(&self) -> io::Result<Box<dyn DBFieldIterator>> {
            let keys: Vec<Field> = self.entries.values().flatten().cloned().collect();
            Ok(Box::new(VecFieldIterator::new(keys)))
        }

        fn key_iterator_before(&self, _start_field: &Field) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }

        fn key_iterator_after(&self, _start_field: &Field) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }

        fn key_iterator_before_at(
            &self,
            _start_field: &Field,
            _primary_key: &Field,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }

        fn key_iterator_after_at(
            &self,
            _start_field: &Field,
            _primary_key: &Field,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }

        fn key_iterator_range(
            &self,
            _min_field: &Field,
            _max_field: &Field,
            _at_start: bool,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }

        fn key_iterator_range_from(
            &self,
            _min_field: &Field,
            _max_field: &Field,
            _start_field: &Field,
            _before: bool,
        ) -> io::Result<Box<dyn DBFieldIterator>> {
            self.key_iterator()
        }
    }

    fn make_record(schema: &std::sync::Arc<super::super::schema::Schema>, key: i64, value: i32) -> DBRecord {
        let mut record = DBRecord::new(schema.clone(), Field::Long(Some(key)));
        record.set_field(0, Field::Int(Some(value)));
        record
    }

    fn test_schema() -> std::sync::Arc<super::super::schema::Schema> {
        use super::super::field::FieldType;
        std::sync::Arc::new(super::super::schema::Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["Indexed".to_string()],
            vec![],
        ))
    }

    #[test]
    fn test_object_safe_add_find_delete() {
        let schema = test_schema();
        let mut table: Box<dyn FieldIndexTable> = Box::new(MockFieldIndexTable::new());

        let rec1 = make_record(&schema, 1, 100);
        let rec2 = make_record(&schema, 2, 100);
        let rec3 = make_record(&schema, 3, 200);

        table.add_entry(&rec1).unwrap();
        table.add_entry(&rec2).unwrap();
        table.add_entry(&rec3).unwrap();

        assert!(table.has_record(&Field::Int(Some(100))).unwrap());
        assert!(!table.has_record(&Field::Int(Some(999))).unwrap());

        let keys = table.find_primary_keys(&Field::Int(Some(100))).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(table.get_key_count(&Field::Int(Some(100))).unwrap(), 2);
        assert_eq!(table.get_key_count(&Field::Int(Some(200))).unwrap(), 1);

        table.delete_entry(&rec1).unwrap();
        assert_eq!(table.get_key_count(&Field::Int(Some(100))).unwrap(), 1);
        assert!(table.has_record(&Field::Int(Some(100))).unwrap());

        table.delete_entry(&rec2).unwrap();
        assert!(!table.has_record(&Field::Int(Some(100))).unwrap());
    }

    #[test]
    fn test_index_and_key_iterators() {
        let schema = test_schema();
        let mut table: Box<dyn FieldIndexTable> = Box::new(MockFieldIndexTable::new());
        table.add_entry(&make_record(&schema, 1, 10)).unwrap();
        table.add_entry(&make_record(&schema, 2, 20)).unwrap();

        let mut idx_iter = table.index_iterator().unwrap();
        let mut seen = Vec::new();
        while let Some(f) = idx_iter.next().unwrap() {
            seen.push(f);
        }
        assert_eq!(seen.len(), 2);

        let mut key_iter = table.key_iterator().unwrap();
        let mut keys = Vec::new();
        while let Some(f) = key_iter.next().unwrap() {
            keys.push(f);
        }
        assert_eq!(keys.len(), 2);
    }
}
