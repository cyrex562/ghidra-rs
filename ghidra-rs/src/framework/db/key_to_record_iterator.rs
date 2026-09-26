use std::cell::RefCell;
use std::io;
use std::sync::{Arc, RwLock};

use super::db_field_iterator::DBFieldIterator;
use super::record::DBRecord;
use super::table::Table;
use super::RecordIterator;

/// A [`RecordIterator`] backed by a secondary index key iterator: each key is looked up in
/// `table` on demand to produce the corresponding record.
///
/// Port of `db.KeyToRecordIterator`. Java's constructor also retains the owning `DBHandle`
/// purely to `synchronized (db) { ... }` around every method body; this port relies on `table`'s
/// own `RwLock` for that instead (the same simplification already made by other `RecordIterator`
/// implementors in this port, e.g. `AddressKeyRecordIterator`), so no `DBHandle` reference is
/// held here.
///
/// [`RecordIterator::has_next`]/[`RecordIterator::has_previous`] query the underlying
/// [`DBFieldIterator`], but that trait's `has_next`/`has_previous` require `&mut self` (they may
/// need to read ahead), while `RecordIterator::has_next` is `&self`. `key_iter` is therefore kept
/// in a [`RefCell`] purely to bridge that mutability mismatch -- there is no actual shared
/// ownership or aliasing here, since `KeyToRecordIterator` is the sole owner of its `key_iter`.
pub struct KeyToRecordIterator {
    table: Arc<RwLock<Table>>,
    key_iter: RefCell<Box<dyn DBFieldIterator>>,
}

impl KeyToRecordIterator {
    /// Construct a record iterator from a secondary index key iterator. Mirrors
    /// `KeyToRecordIterator(Table, DBFieldIterator)`.
    pub fn new(table: Arc<RwLock<Table>>, key_iter: Box<dyn DBFieldIterator>) -> Self {
        Self { table, key_iter: RefCell::new(key_iter) }
    }
}

impl RecordIterator for KeyToRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        match self.key_iter.borrow_mut().next()? {
            Some(key) => self.table.read().unwrap().get_record(&key),
            None => Ok(None),
        }
    }

    /// Mirrors `KeyToRecordIterator.hasNext()`. Java's version can throw `IOException`, but
    /// `RecordIterator::has_next` in this port has no `Result` in its signature; an I/O error
    /// here is folded into `false` (nothing further available) rather than panicking.
    fn has_next(&self) -> bool {
        self.key_iter.borrow_mut().has_next().unwrap_or(false)
    }

    /// Mirrors `KeyToRecordIterator.hasPrevious()`.
    fn has_previous(&self) -> io::Result<bool> {
        self.key_iter.borrow_mut().has_previous()
    }

    /// Mirrors `KeyToRecordIterator.previous()`.
    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        match self.key_iter.borrow_mut().previous()? {
            Some(key) => self.table.read().unwrap().get_record(&key),
            None => Ok(None),
        }
    }

    /// Mirrors `KeyToRecordIterator.delete()`.
    fn delete(&mut self) -> io::Result<bool> {
        self.key_iter.borrow_mut().delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use crate::framework::db::{DBHandle, DBRecord};

    fn make_table_with_records(keys: &[i64]) -> Arc<RwLock<Table>> {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ));
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        {
            let mut t = table.write().unwrap();
            for &key in keys {
                let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
                rec.set_string(0, Some(format!("value-{}", key)));
                t.put_record(rec).unwrap();
            }
        }
        table
    }

    /// A simple forward-only [`DBFieldIterator`] over a fixed key list, standing in for a real
    /// secondary index key iterator.
    struct VecKeyIterator {
        keys: Vec<Field>,
        pos: isize,
    }

    impl VecKeyIterator {
        fn new(keys: Vec<i64>) -> Self {
            Self { keys: keys.into_iter().map(|k| Field::Long(Some(k))).collect(), pos: -1 }
        }
    }

    impl DBFieldIterator for VecKeyIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok((self.pos + 1) < self.keys.len() as isize)
        }

        fn has_previous(&mut self) -> io::Result<bool> {
            Ok(self.pos >= 0)
        }

        fn next(&mut self) -> io::Result<Option<Field>> {
            let next = self.pos + 1;
            if next >= self.keys.len() as isize {
                return Ok(None);
            }
            self.pos = next;
            Ok(Some(self.keys[self.pos as usize].clone()))
        }

        fn previous(&mut self) -> io::Result<Option<Field>> {
            if self.pos < 0 {
                return Ok(None);
            }
            let val = self.keys[self.pos as usize].clone();
            self.pos -= 1;
            Ok(Some(val))
        }

        fn delete(&mut self) -> io::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_next_resolves_keys_to_records_via_table() {
        let table = make_table_with_records(&[10, 20, 30]);
        let key_iter = Box::new(VecKeyIterator::new(vec![10, 20, 30]));
        let mut it = KeyToRecordIterator::new(table, key_iter);

        assert!(it.has_next());
        let r1 = it.next().unwrap().unwrap();
        assert_eq!(r1.get_key(), &Field::Long(Some(10)));
        assert_eq!(r1.get_string(0), Some("value-10"));

        let r2 = it.next().unwrap().unwrap();
        assert_eq!(r2.get_key(), &Field::Long(Some(20)));

        let r3 = it.next().unwrap().unwrap();
        assert_eq!(r3.get_key(), &Field::Long(Some(30)));

        assert!(!it.has_next());
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn test_previous_resolves_keys_to_records_via_table() {
        let table = make_table_with_records(&[1, 2]);
        let key_iter = Box::new(VecKeyIterator::new(vec![1, 2]));
        let mut it = KeyToRecordIterator::new(table, key_iter);

        it.next().unwrap();
        it.next().unwrap();

        assert!(it.has_previous().unwrap());
        let back = it.previous().unwrap().unwrap();
        assert_eq!(back.get_key(), &Field::Long(Some(2)));
    }

    #[test]
    fn test_next_returns_none_when_key_iterator_is_empty() {
        let table = make_table_with_records(&[]);
        let key_iter = Box::new(VecKeyIterator::new(vec![]));
        let mut it = KeyToRecordIterator::new(table, key_iter);
        assert!(!it.has_next());
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn test_object_safety() {
        let table = make_table_with_records(&[5]);
        let key_iter = Box::new(VecKeyIterator::new(vec![5]));
        let mut it: Box<dyn RecordIterator> = Box::new(KeyToRecordIterator::new(table, key_iter));
        assert_eq!(it.next().unwrap().unwrap().get_key(), &Field::Long(Some(5)));
    }
}
