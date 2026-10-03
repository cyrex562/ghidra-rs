//! Port of `ghidra.program.database.map.AddressKeyRecordIterator`.
//!
//! A `db.RecordIterator` over records that are address-keyed, restricted to whatever
//! `KeyRange`s `addr_map` derives from the requested address range/set, and optionally
//! positioned at a starting address. Backed by the same eager-snapshot "gap cursor" as
//! `AddressKeyIterator` (see `super::cursor`/`super::table_snapshot`) rather than Java's live
//! B-tree cursor crawl.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::map::address_map::AddressMap;
use crate::program::database::map::cursor::{initial_gap_by, Cursor};
use crate::program::database::map::table_snapshot::snapshot_long_keys;
use crate::program::model::address::{Address, AddressSet, AddressSetView};

/// Iterator over records keyed by address, restricted to an address range/set and optionally
/// positioned at a starting address.
///
/// Port of `ghidra.program.database.map.AddressKeyRecordIterator`.
pub struct AddressKeyRecordIterator {
    table: Arc<RwLock<Table>>,
    keys: Vec<i64>,
    cursor: Cursor,
}

impl AddressKeyRecordIterator {
    /// Constructs an iterator over all records in ascending order. Memory addresses encoded as
    /// absolute are not included.
    ///
    /// Port of `AddressKeyRecordIterator(Table, AddressMap)`.
    pub fn new(table: &Arc<RwLock<Table>>, addr_map: &dyn AddressMap) -> io::Result<Self> {
        Self::new_general(table, addr_map, false, None, None, true)
    }

    /// Constructs an iterator over all records, positioned at `start_addr`. Memory addresses
    /// encoded as absolute are not included.
    ///
    /// Port of `AddressKeyRecordIterator(Table, AddressMap, Address, boolean)`.
    pub fn new_at(
        table: &Arc<RwLock<Table>>,
        addr_map: &dyn AddressMap,
        start_addr: &Address,
        before: bool,
    ) -> io::Result<Self> {
        Self::new_general(table, addr_map, false, None, Some(start_addr), before)
    }

    /// Constructs an iterator over `[min_addr, max_addr]`, optionally positioned at `start_addr`
    /// within that range. Memory addresses encoded as absolute are not included.
    ///
    /// Port of `AddressKeyRecordIterator(Table, AddressMap, Address, Address, Address,
    /// boolean)`.
    pub fn new_over_range(
        table: &Arc<RwLock<Table>>,
        addr_map: &dyn AddressMap,
        min_addr: &Address,
        max_addr: &Address,
        start_addr: Option<&Address>,
        before: bool,
    ) -> io::Result<Self> {
        let set = AddressSet::from_start_end(min_addr.clone(), max_addr.clone());
        Self::new_general(table, addr_map, false, Some(&set), start_addr, before)
    }

    /// Constructs an iterator over `set`, optionally positioned at `start_addr` within it.
    /// Memory addresses encoded as absolute are not included.
    ///
    /// Port of `AddressKeyRecordIterator(Table, AddressMap, AddressSetView, Address, boolean)`.
    pub fn new_over_set(
        table: &Arc<RwLock<Table>>,
        addr_map: &dyn AddressMap,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        before: bool,
    ) -> io::Result<Self> {
        Self::new_general(table, addr_map, false, set, start_addr, before)
    }

    /// Constructs an iterator over `set`, optionally positioned at `start_addr` within it. If
    /// `absolute` is true, only absolute memory address encodings are considered; otherwise only
    /// standard/relocatable encodings are.
    ///
    /// Port of the package-private `AddressKeyRecordIterator(Table, AddressMap, boolean,
    /// AddressSetView, Address, boolean)`.
    pub fn new_general(
        table: &Arc<RwLock<Table>>,
        addr_map: &dyn AddressMap,
        absolute: bool,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        before: bool,
    ) -> io::Result<Self> {
        let ranges = addr_map.get_key_ranges_for_set_absolute(set, absolute, false);
        let keys = snapshot_long_keys(table, &ranges)?;
        let start_key = start_addr.map(|addr| {
            if absolute {
                addr_map.get_absolute_encoding(addr, false)
            } else {
                addr_map.get_key(addr, false)
            }
        });
        let pos = initial_gap_by(&keys, start_key, before, |k| *k);
        Ok(AddressKeyRecordIterator { table: table.clone(), cursor: Cursor::new(pos, keys.len()), keys })
    }
}

impl RecordIterator for AddressKeyRecordIterator {
    fn has_next(&self) -> bool {
        self.cursor.has_next()
    }

    fn has_previous(&self) -> io::Result<bool> {
        Ok(self.cursor.has_previous())
    }

    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        let Some(idx) = self.cursor.advance_next() else {
            return Ok(None);
        };
        let key = self.keys[idx];
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        let Some(idx) = self.cursor.advance_previous() else {
            return Ok(None);
        };
        let key = self.keys[idx];
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn delete(&mut self) -> io::Result<bool> {
        let Some(idx) = self.cursor.take_last() else {
            return Ok(false);
        };
        let key = self.keys[idx];
        let deleted = self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        if deleted {
            self.keys.remove(idx);
            self.cursor.on_removed(idx);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, FieldType, Schema};
    use crate::program::database::map::test_support::TestAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn make_table() -> Arc<RwLock<Table>> {
        let mut handle = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ));
        let table = handle.create_table("T".to_string(), schema).unwrap();
        {
            let mut t = table.write().unwrap();
            for k in [10i64, 5, 20, 15] {
                let s = t.get_schema();
                let mut rec = DBRecord::new(s, Field::Long(Some(k)));
                rec.set_field(0, Field::Int(Some(k as i32 * 10)));
                t.put_record(rec).unwrap();
            }
        }
        table
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn iterates_records_in_key_order() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyRecordIterator::new(&table, &addr_map).unwrap();

        let mut keys = Vec::new();
        while it.has_next() {
            let rec = it.next().unwrap().unwrap();
            keys.push(rec.get_key().get_long_value());
        }
        assert_eq!(keys, vec![5, 10, 15, 20]);
    }

    #[test]
    fn positioned_before_start_yields_start_going_forward_and_its_predecessor_going_backward() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();

        // before=true at 15 (which exists) => next() yields 15, without having been called yet.
        let mut forward =
            AddressKeyRecordIterator::new_at(&table, &addr_map, &s.address(15), true).unwrap();
        assert!(forward.has_next());
        assert_eq!(forward.next().unwrap().unwrap().get_key().get_long_value(), 15);

        // Same starting position, queried backward first (independently) => previous() yields
        // the true predecessor of 15, which is 10.
        let mut backward =
            AddressKeyRecordIterator::new_at(&table, &addr_map, &s.address(15), true).unwrap();
        assert!(backward.has_previous().unwrap());
        assert_eq!(backward.previous().unwrap().unwrap().get_key().get_long_value(), 10);
    }

    #[test]
    fn delete_removes_current_record_and_shifts_iteration() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyRecordIterator::new(&table, &addr_map).unwrap();

        assert_eq!(it.next().unwrap().unwrap().get_key().get_long_value(), 5);
        assert!(it.delete().unwrap());
        assert!(!table.read().unwrap().has_record(&Field::Long(Some(5))));

        let mut remaining = Vec::new();
        while it.has_next() {
            remaining.push(it.next().unwrap().unwrap().get_key().get_long_value());
        }
        assert_eq!(remaining, vec![10, 15, 20]);
    }

    #[test]
    fn range_restricted_iteration() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressKeyRecordIterator::new_over_range(
            &table,
            &addr_map,
            &s.address(6),
            &s.address(16),
            None,
            true,
        )
        .unwrap();

        let mut keys = Vec::new();
        while it.has_next() {
            keys.push(it.next().unwrap().unwrap().get_key().get_long_value());
        }
        assert_eq!(keys, vec![10, 15]);
    }

    #[test]
    fn default_iterator_trait_methods_are_overridden() {
        let table = make_table();
        let addr_map = TestAddressMap::new(space());
        let it: Box<dyn RecordIterator> =
            Box::new(AddressKeyRecordIterator::new(&table, &addr_map).unwrap());
        // Sanity check this is not silently using the trait's default has_previous/previous.
        let mut it = it;
        assert!(!it.has_previous().unwrap());
        it.next().unwrap();
        assert!(it.has_previous().unwrap());
    }
}
