//! Port of `ghidra.program.database.map.AddressRecordDeleter`.
//!
//! Java models this as a class of static methods only (private constructor, never
//! instantiated); this port keeps that shape as two free functions.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBFieldIterator, Table};
use crate::program::database::map::address_index_primary_key_iterator::AddressIndexPrimaryKeyIterator;
use crate::program::database::map::address_map::AddressMap;
use crate::program::database::util::RecordFilter;
use crate::program::model::address::Address;

/// Deletes the records that fall within the given address range.
///
/// Uses `addr_map` to convert the address range into one or more key ranges (address ranges may
/// not be contiguous once converted into key space). Returns `true` if any record was deleted.
///
/// NOTE: absolute key encodings are not handled currently, matching Java.
///
/// Port of `AddressRecordDeleter.deleteRecords(Table, AddressMap, Address, Address)`.
pub fn delete_records(
    table: &Arc<RwLock<Table>>,
    addr_map: &dyn AddressMap,
    start: &Address,
    end: &Address,
) -> io::Result<bool> {
    let key_range_list = addr_map.get_key_ranges(start, end, false);
    let mut success = false;
    let mut table = table.write().unwrap();
    for key_range in key_range_list {
        success |= table.delete_records(key_range.min_key, key_range.max_key)?;
    }
    Ok(success)
}

/// Deletes the records that have indexed address fields falling within the given address range.
///
/// Uses `addr_map` to convert the address range into one or more key ranges. If `filter` is
/// supplied, only records matching it are deleted.
///
/// NOTE: absolute key encodings are not handled currently, matching Java.
///
/// Port of `AddressRecordDeleter.deleteRecords(Table, int, AddressMap, Address, Address,
/// RecordFilter)`.
pub fn delete_records_by_indexed_column(
    table: &Arc<RwLock<Table>>,
    col_ix: usize,
    addr_map: &dyn AddressMap,
    start: &Address,
    end: &Address,
    filter: Option<&dyn RecordFilter>,
) -> io::Result<bool> {
    let mut success = false;
    let mut iter = AddressIndexPrimaryKeyIterator::new_over_range(table, col_ix, addr_map, start, end, true)?;
    while iter.has_next()? {
        let Some(next) = iter.next()? else {
            break;
        };
        if let Some(filter) = filter {
            let record = table.read().unwrap().get_record(&next)?;
            match record {
                Some(record) if !filter.matches(&record) => continue,
                _ => {}
            }
        }
        success |= iter.delete()?;
    }
    Ok(success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema};
    use crate::program::database::map::test_support::TestAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn make_table(handle: &mut DBHandle, name: &str, indexed_col: Option<usize>) -> Arc<RwLock<Table>> {
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long],
            vec!["Address".to_string()],
            indexed_col.into_iter().collect(),
        ));
        handle.create_table(name.to_string(), schema).unwrap()
    }

    #[test]
    fn delete_records_removes_only_keys_in_range() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_table(&mut handle, "T", None);
        {
            let mut t = table.write().unwrap();
            for k in [1i64, 5, 10, 15, 20] {
                let schema = t.get_schema();
                let mut rec = DBRecord::new(schema, Field::Long(Some(k)));
                rec.set_field(0, Field::Long(Some(k)));
                t.put_record(rec).unwrap();
            }
        }

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr_map = TestAddressMap::new(space.clone());
        let start = space.address(5);
        let end = space.address(15);

        let deleted = delete_records(&table, &addr_map, &start, &end).unwrap();
        assert!(deleted);

        let t = table.read().unwrap();
        assert!(!t.has_record(&Field::Long(Some(5))));
        assert!(!t.has_record(&Field::Long(Some(10))));
        assert!(!t.has_record(&Field::Long(Some(15))));
        assert!(t.has_record(&Field::Long(Some(1))));
        assert!(t.has_record(&Field::Long(Some(20))));
    }

    #[test]
    fn delete_records_returns_false_when_nothing_in_range() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_table(&mut handle, "T", None);
        {
            let mut t = table.write().unwrap();
            let schema = t.get_schema();
            let mut rec = DBRecord::new(schema, Field::Long(Some(100)));
            rec.set_field(0, Field::Long(Some(100)));
            t.put_record(rec).unwrap();
        }

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr_map = TestAddressMap::new(space.clone());
        let start = space.address(0);
        let end = space.address(10);

        let deleted = delete_records(&table, &addr_map, &start, &end).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn delete_records_by_indexed_column_respects_filter() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_table(&mut handle, "T", Some(0));
        {
            let mut t = table.write().unwrap();
            for (key, addr_val) in [(0i64, 5i64), (1, 6), (2, 7)] {
                let schema = t.get_schema();
                let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
                rec.set_field(0, Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }

        struct OddAddrFilter;
        impl RecordFilter for OddAddrFilter {
            fn matches(&self, record: &DBRecord) -> bool {
                matches!(record.get_field(0), Field::Long(Some(v)) if v % 2 == 1)
            }
        }

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr_map = TestAddressMap::new(space.clone());
        let start = space.address(5);
        let end = space.address(7);

        let deleted = delete_records_by_indexed_column(
            &table,
            0,
            &addr_map,
            &start,
            &end,
            Some(&OddAddrFilter),
        )
        .unwrap();
        assert!(deleted);

        let t = table.read().unwrap();
        // addr 5 and 7 are odd -> deleted; addr 6 is even -> kept.
        assert!(!t.has_record(&Field::Long(Some(0))));
        assert!(t.has_record(&Field::Long(Some(1))));
        assert!(!t.has_record(&Field::Long(Some(2))));
    }
}
