//! Port of `ghidra.program.database.map.AddressIndexKeyIterator`.
//!
//! A `db.DBLongIterator` over the *values* of one of a `Table`'s indexed address-encoded
//! columns (not the primary keys, unlike its sibling `AddressIndexPrimaryKeyIterator`),
//! restricted to whatever `KeyRange`s `addr_map` derives from the requested address range/set.
//!
//! Java crawls a live `db.Table.indexFieldIterator` cursor range-by-range; this port takes a
//! single eager snapshot instead. See `super::cursor` and `super::table_snapshot` for why that
//! is observably equivalent given this port's `Table`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBLongIterator, Field, Table};
use crate::program::database::map::address_map::AddressMap;
use crate::program::database::map::cursor::{initial_gap_by, Cursor};
use crate::program::database::map::table_snapshot::snapshot_index_entries;
use crate::program::model::address::{Address, AddressSet, AddressSetView};

/// Iterator of indexed fields that are addresses. The `i64`s returned are the address longs
/// stored in the indexed column (one per matching record, not deduplicated).
///
/// Port of `ghidra.program.database.map.AddressIndexKeyIterator`.
pub struct AddressIndexKeyIterator {
    table: Option<Arc<RwLock<Table>>>,
    entries: Vec<(i64, Field)>,
    cursor: Cursor,
}

impl AddressIndexKeyIterator {
    /// Constructs an empty iterator.
    ///
    /// Port of the no-arg `AddressIndexKeyIterator()` constructor.
    pub fn new_empty() -> Self {
        AddressIndexKeyIterator { table: None, entries: Vec::new(), cursor: Cursor::new(0, 0) }
    }

    /// Constructs an iterator over all addresses in `index_col`. Memory addresses encoded as
    /// absolute are not included.
    ///
    /// Port of `AddressIndexKeyIterator(Table, int, AddressMap, boolean)`.
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
    /// Port of `AddressIndexKeyIterator(Table, int, AddressMap, Address, Address, boolean)`.
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
    /// Port of `AddressIndexKeyIterator(Table, int, AddressMap, AddressSetView, boolean)`.
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
    /// Port of the public `AddressIndexKeyIterator(Table, int, AddressMap, boolean,
    /// AddressSetView, boolean)`.
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
        Ok(AddressIndexKeyIterator {
            table: Some(table.clone()),
            cursor: Cursor::new(pos, entries.len()),
            entries,
        })
    }

    /// Constructs an iterator over `index_col` positioned at `start`.
    ///
    /// Port of `AddressIndexKeyIterator(Table, int, AddressMap, Address, boolean)`.
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
    /// Port of the package-private `AddressIndexKeyIterator(Table, int, AddressMap, boolean,
    /// Address, boolean)`.
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
        Ok(AddressIndexKeyIterator {
            table: Some(table.clone()),
            cursor: Cursor::new(pos, entries.len()),
            entries,
        })
    }
}

impl DBLongIterator for AddressIndexKeyIterator {
    fn has_next(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_next())
    }

    fn has_previous(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_previous())
    }

    fn next(&mut self) -> io::Result<i64> {
        match self.cursor.advance_next() {
            Some(idx) => Ok(self.entries[idx].0),
            None => Err(io::Error::new(io::ErrorKind::Other, "no next value")),
        }
    }

    fn previous(&mut self) -> io::Result<i64> {
        match self.cursor.advance_previous() {
            Some(idx) => Ok(self.entries[idx].0),
            None => Err(io::Error::new(io::ErrorKind::Other, "no previous value")),
        }
    }

    fn delete(&mut self) -> io::Result<bool> {
        let Some(table) = &self.table else {
            return Ok(false);
        };
        let Some(idx) = self.cursor.take_last() else {
            return Ok(false);
        };
        let primary_key = self.entries[idx].1.clone();
        let deleted = table.write().unwrap().delete_record(&primary_key)?;
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
            for (key, addr_val) in [(0i64, 40i64), (1, 10), (2, 30), (3, 10)] {
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
        let mut it = AddressIndexKeyIterator::new_empty();
        assert!(!it.has_next().unwrap());
        assert!(it.next().is_err());
    }

    #[test]
    fn forward_iteration_yields_index_values_in_order_with_duplicates() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressIndexKeyIterator::new(&table, 0, &addr_map, true).unwrap();

        let mut values = Vec::new();
        while it.has_next().unwrap() {
            values.push(it.next().unwrap());
        }
        assert_eq!(values, vec![10, 10, 30, 40]);
    }

    #[test]
    fn backward_iteration_from_end() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressIndexKeyIterator::new(&table, 0, &addr_map, false).unwrap();

        let mut values = Vec::new();
        while it.has_previous().unwrap() {
            values.push(it.previous().unwrap());
        }
        assert_eq!(values, vec![40, 30, 10, 10]);
    }

    #[test]
    fn positioned_before_start_skips_no_duplicates_going_forward() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it =
            AddressIndexKeyIterator::new_at(&table, 0, &addr_map, &s.address(10), true).unwrap();
        assert_eq!(it.next().unwrap(), 10);
        assert_eq!(it.next().unwrap(), 10);
        assert_eq!(it.next().unwrap(), 30);
    }

    #[test]
    fn positioned_after_start_skips_all_duplicates_going_forward() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it =
            AddressIndexKeyIterator::new_at(&table, 0, &addr_map, &s.address(10), false).unwrap();
        assert_eq!(it.next().unwrap(), 30);
        assert!(it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap(), 30);
        assert_eq!(it.previous().unwrap(), 10);
        assert_eq!(it.previous().unwrap(), 10);
    }

    #[test]
    fn delete_removes_underlying_record_by_primary_key() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressIndexKeyIterator::new(&table, 0, &addr_map, true).unwrap();

        assert_eq!(it.next().unwrap(), 10); // first "10" entry -> could be key 1 or 3
        assert!(it.delete().unwrap());
        assert_eq!(table.read().unwrap().get_record_count(), 3);

        let mut remaining = Vec::new();
        while it.has_next().unwrap() {
            remaining.push(it.next().unwrap());
        }
        assert_eq!(remaining, vec![10, 30, 40]);
    }

    #[test]
    fn range_restricted_iteration() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressIndexKeyIterator::new_over_range(
            &table,
            0,
            &addr_map,
            &s.address(15),
            &s.address(35),
            true,
        )
        .unwrap();

        let mut values = Vec::new();
        while it.has_next().unwrap() {
            values.push(it.next().unwrap());
        }
        assert_eq!(values, vec![30]);
    }

    #[test]
    fn behaves_as_trait_object() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it: Box<dyn DBLongIterator> =
            Box::new(AddressIndexKeyIterator::new(&table, 0, &addr_map, true).unwrap());
        assert_eq!(it.next().unwrap(), 10);
    }
}
