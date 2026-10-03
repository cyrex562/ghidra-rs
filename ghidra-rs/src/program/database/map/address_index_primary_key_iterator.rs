//! Port of `ghidra.program.database.map.AddressIndexPrimaryKeyIterator`.
//!
//! A `DBFieldIterator` over the primary keys of records in a `Table`, ordered by the value of
//! one of that table's *indexed* address-encoded columns (not by the primary key itself).
//! Restricted to whatever `KeyRange`s `addr_map` derives from the requested address range/set.
//!
//! Java crawls a live `db.Table.indexKeyIterator` cursor range-by-range; this port takes a
//! single eager snapshot instead. See `super::cursor` and `super::table_snapshot` for why that
//! is observably equivalent given this port's `Table`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBFieldIterator, Field, Table};
use crate::program::database::map::address_map::AddressMap;
use crate::program::database::map::cursor::{initial_gap_by, Cursor};
use crate::program::database::map::table_snapshot::snapshot_index_entries;
use crate::program::model::address::{Address, AddressSet, AddressSetView};

/// Long iterator over indexed addresses: primary keys, returned in the order of the address
/// field they contain.
///
/// Port of `ghidra.program.database.map.AddressIndexPrimaryKeyIterator`.
pub struct AddressIndexPrimaryKeyIterator {
    table: Option<Arc<RwLock<Table>>>,
    entries: Vec<(i64, Field)>,
    cursor: Cursor,
}

impl AddressIndexPrimaryKeyIterator {
    /// Constructs an empty iterator.
    ///
    /// Port of the no-arg `AddressIndexPrimaryKeyIterator()` constructor.
    pub fn new_empty() -> Self {
        AddressIndexPrimaryKeyIterator { table: None, entries: Vec::new(), cursor: Cursor::new(0, 0) }
    }

    /// Constructs an iterator over all addresses in `index_col`. Memory addresses encoded as
    /// absolute are not included.
    ///
    /// Port of `AddressIndexPrimaryKeyIterator(Table, int, AddressMap, boolean)`.
    pub fn new(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        at_start: bool,
    ) -> io::Result<Self> {
        Self::new_general(table, index_col, addr_map, false, None, at_start)
    }

    /// Constructs an iterator over `[min_addr, max_addr]` in `index_col`. Memory addresses
    /// encoded as absolute are not included.
    ///
    /// Port of `AddressIndexPrimaryKeyIterator(Table, int, AddressMap, Address, Address,
    /// boolean)`.
    pub fn new_over_range(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        min_addr: &Address,
        max_addr: &Address,
        at_start: bool,
    ) -> io::Result<Self> {
        let set = AddressSet::from_start_end(min_addr.clone(), max_addr.clone());
        Self::new_general(table, index_col, addr_map, false, Some(&set), at_start)
    }

    /// Constructs an iterator over `set` in `index_col`. Memory addresses encoded as absolute
    /// are not included.
    ///
    /// Port of `AddressIndexPrimaryKeyIterator(Table, int, AddressMap, AddressSetView,
    /// boolean)`.
    pub fn new_over_set(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        set: Option<&dyn AddressSetView>,
        at_start: bool,
    ) -> io::Result<Self> {
        Self::new_general(table, index_col, addr_map, false, set, at_start)
    }

    /// Constructs an iterator over `set` in `index_col`. If `absolute` is true, only absolute
    /// memory address encodings are considered; otherwise only standard/relocatable encodings
    /// are.
    ///
    /// Port of the package-private `AddressIndexPrimaryKeyIterator(Table, int, AddressMap,
    /// boolean, AddressSetView, boolean)`.
    pub fn new_general(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        absolute: bool,
        set: Option<&dyn AddressSetView>,
        at_start: bool,
    ) -> io::Result<Self> {
        let ranges = addr_map.get_key_ranges_for_set_absolute(set, absolute, false);
        let entries = snapshot_index_entries(table, index_col, &ranges)?;
        let pos = if at_start { 0 } else { entries.len() };
        Ok(AddressIndexPrimaryKeyIterator {
            table: Some(table.clone()),
            cursor: Cursor::new(pos, entries.len()),
            entries,
        })
    }

    /// Constructs an iterator over `index_col` positioned at `start`.
    ///
    /// Port of `AddressIndexPrimaryKeyIterator(Table, int, AddressMap, Address, boolean)`.
    pub fn new_at(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        start: &Address,
        before: bool,
    ) -> io::Result<Self> {
        Self::new_at_general(table, index_col, addr_map, false, start, before)
    }

    /// Constructs an iterator over `index_col` positioned at `start`. If `absolute` is true,
    /// only absolute memory address encodings are considered; otherwise only
    /// standard/relocatable encodings are.
    ///
    /// Port of the package-private `AddressIndexPrimaryKeyIterator(Table, int, AddressMap,
    /// boolean, Address, boolean)`.
    pub fn new_at_general(
        table: &Arc<RwLock<Table>>,
        index_col: usize,
        addr_map: &dyn AddressMap,
        absolute: bool,
        start: &Address,
        before: bool,
    ) -> io::Result<Self> {
        let ranges = addr_map.get_key_ranges_for_set_absolute(None, absolute, false);
        let entries = snapshot_index_entries(table, index_col, &ranges)?;
        let start_key = if absolute {
            addr_map.get_absolute_encoding(start, false)
        } else {
            addr_map.get_key(start, false)
        };
        let pos = initial_gap_by(&entries, Some(start_key), before, |e| e.0);
        Ok(AddressIndexPrimaryKeyIterator {
            table: Some(table.clone()),
            cursor: Cursor::new(pos, entries.len()),
            entries,
        })
    }
}

impl DBFieldIterator for AddressIndexPrimaryKeyIterator {
    fn has_next(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_next())
    }

    fn has_previous(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_previous())
    }

    fn next(&mut self) -> io::Result<Option<Field>> {
        Ok(self
            .cursor
            .advance_next()
            .map(|idx| self.entries[idx].1.clone()))
    }

    fn previous(&mut self) -> io::Result<Option<Field>> {
        Ok(self
            .cursor
            .advance_previous()
            .map(|idx| self.entries[idx].1.clone()))
    }

    fn delete(&mut self) -> io::Result<bool> {
        let Some(table) = &self.table else {
            return Ok(false);
        };
        let Some(idx) = self.cursor.take_last() else {
            return Ok(false);
        };
        let key = self.entries[idx].1.clone();
        let deleted = table.write().unwrap().delete_record(&key)?;
        if deleted {
            self.entries.remove(idx);
            self.cursor.on_removed(idx);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
    use crate::program::database::map::test_support::TestAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn make_table() -> Arc<RwLock<Table>> {
        let mut handle = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long],
            vec!["Address".to_string()],
            vec![0],
        ));
        let table = handle.create_table("T".to_string(), schema).unwrap();
        {
            let mut t = table.write().unwrap();
            // primary key 0..4, index column (address) values out of primary-key order.
            for (key, addr_val) in [(0i64, 40i64), (1, 10), (2, 30), (3, 20)] {
                let s = t.get_schema();
                let mut rec = DBRecord::new(s, Field::Long(Some(key)));
                rec.set_field(0, Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }
        table
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn empty_iterator_has_neither_direction() {
        let mut it = AddressIndexPrimaryKeyIterator::new_empty();
        assert!(!it.has_next().unwrap());
        assert!(!it.has_previous().unwrap());
        assert_eq!(it.next().unwrap(), None);
    }

    #[test]
    fn iterates_primary_keys_ordered_by_indexed_address_value() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it =
            AddressIndexPrimaryKeyIterator::new(&table, 0, &addr_map, true).unwrap();

        let mut order = Vec::new();
        while it.has_next().unwrap() {
            if let Field::Long(Some(k)) = it.next().unwrap().unwrap() {
                order.push(k);
            }
        }
        // addr values sorted: 10(key1), 20(key3), 30(key2), 40(key0)
        assert_eq!(order, vec![1, 3, 2, 0]);
    }

    #[test]
    fn reverse_iteration_from_end() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it =
            AddressIndexPrimaryKeyIterator::new(&table, 0, &addr_map, false).unwrap();

        let mut order = Vec::new();
        while it.has_previous().unwrap() {
            if let Field::Long(Some(k)) = it.previous().unwrap().unwrap() {
                order.push(k);
            }
        }
        assert_eq!(order, vec![0, 2, 3, 1]);
    }

    #[test]
    fn delete_removes_from_table() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it =
            AddressIndexPrimaryKeyIterator::new(&table, 0, &addr_map, true).unwrap();

        assert!(it.has_next().unwrap());
        let first = it.next().unwrap().unwrap();
        assert_eq!(first, Field::Long(Some(1))); // addr 10 -> key 1
        assert!(it.delete().unwrap());

        assert!(!table.read().unwrap().has_record(&Field::Long(Some(1))));

        let mut remaining = Vec::new();
        while it.has_next().unwrap() {
            if let Field::Long(Some(k)) = it.next().unwrap().unwrap() {
                remaining.push(k);
            }
        }
        assert_eq!(remaining, vec![3, 2, 0]);
    }

    #[test]
    fn range_restricted_iteration_only_yields_matching_addresses() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressIndexPrimaryKeyIterator::new_over_range(
            &table,
            0,
            &addr_map,
            &s.address(15),
            &s.address(35),
            true,
        )
        .unwrap();

        let mut order = Vec::new();
        while it.has_next().unwrap() {
            if let Field::Long(Some(k)) = it.next().unwrap().unwrap() {
                order.push(k);
            }
        }
        assert_eq!(order, vec![3, 2]); // addr 20 (key3), addr 30 (key2)
    }
}
