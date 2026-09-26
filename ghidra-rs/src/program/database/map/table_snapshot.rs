//! Internal snapshot-gathering helpers shared by this module's `Table`-backed, address-ordered
//! iterators. **Not itself a port of a Java class** -- see the module docs on
//! [`cursor`](super::cursor) for why an eager snapshot stands in for Java's live B-tree cursor
//! crawl.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{Field, Table};
use crate::program::model::address::KeyRange;

fn in_ranges(key: i64, ranges: &[KeyRange]) -> bool {
    ranges.iter().any(|r| r.contains(key))
}

/// Collects every primary (long) key in `table` that falls within any of `ranges`, sorted
/// ascending. Backs [`AddressKeyIterator`](super::address_key_iterator::AddressKeyIterator) and
/// [`AddressKeyRecordIterator`](super::address_key_record_iterator::AddressKeyRecordIterator).
pub(crate) fn snapshot_long_keys(
    table: &Arc<RwLock<Table>>,
    ranges: &[KeyRange],
) -> io::Result<Vec<i64>> {
    let table = table.read().unwrap();
    let mut iter = table.get_record_iterator()?;
    let mut keys = Vec::new();
    while let Some(record) = iter.next()? {
        if let Field::Long(Some(key)) = record.get_key() {
            if in_ranges(*key, ranges) {
                keys.push(*key);
            }
        }
    }
    keys.sort_unstable();
    Ok(keys)
}

/// Collects `(index column value, primary key)` for every record in `table` whose `index_col`
/// field is a non-null `Field::Long` falling within any of `ranges`, sorted by `(value, primary
/// key)`. Backs
/// [`AddressIndexPrimaryKeyIterator`](super::address_index_primary_key_iterator::AddressIndexPrimaryKeyIterator)
/// and [`AddressIndexKeyIterator`](super::address_index_key_iterator::AddressIndexKeyIterator).
pub(crate) fn snapshot_index_entries(
    table: &Arc<RwLock<Table>>,
    index_col: usize,
    ranges: &[KeyRange],
) -> io::Result<Vec<(i64, Field)>> {
    let table = table.read().unwrap();
    let mut iter = table.get_record_iterator()?;
    let mut entries = Vec::new();
    while let Some(record) = iter.next()? {
        if let Field::Long(Some(value)) = record.get_field(index_col) {
            if in_ranges(*value, ranges) {
                entries.push((*value, record.get_key().clone()));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};

    fn make_table(indexed: bool) -> Arc<RwLock<Table>> {
        let mut handle = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long],
            vec!["Value".to_string()],
            if indexed { vec![0] } else { vec![] },
        ));
        handle.create_table("T".to_string(), schema).unwrap()
    }

    #[test]
    fn snapshot_long_keys_filters_and_sorts() {
        let table = make_table(false);
        {
            let mut t = table.write().unwrap();
            for k in [30i64, 5, 20, 1] {
                let schema = t.get_schema();
                let mut rec = DBRecord::new(schema, Field::Long(Some(k)));
                rec.set_field(0, Field::Long(Some(k)));
                t.put_record(rec).unwrap();
            }
        }
        let ranges = [KeyRange::new(1, 20)];
        let keys = snapshot_long_keys(&table, &ranges).unwrap();
        assert_eq!(keys, vec![1, 5, 20]);
    }

    #[test]
    fn snapshot_index_entries_sorted_by_value_then_key() {
        let table = make_table(true);
        {
            let mut t = table.write().unwrap();
            for (key, value) in [(0i64, 100i64), (1, 50), (2, 50), (3, 200)] {
                let schema = t.get_schema();
                let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
                rec.set_field(0, Field::Long(Some(value)));
                t.put_record(rec).unwrap();
            }
        }
        let ranges = [KeyRange::new(0, 100)];
        let entries = snapshot_index_entries(&table, 0, &ranges).unwrap();
        assert_eq!(
            entries,
            vec![
                (50, Field::Long(Some(1))),
                (50, Field::Long(Some(2))),
                (100, Field::Long(Some(0))),
            ]
        );
    }
}
