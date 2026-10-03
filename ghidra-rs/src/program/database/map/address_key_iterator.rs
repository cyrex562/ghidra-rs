//! Port of `ghidra.program.database.map.AddressKeyIterator`.
//!
//! A `db.DBLongIterator` over the primary keys of a `Table` that is keyed by address, restricted
//! to whatever `KeyRange`s `addr_map` derives from the requested address range/set, and
//! optionally positioned at a starting address. This is the class most directly named as
//! blocking `ghidra.program.database.references`' `FromAdapterV0`/`ToAdapterV0` (see
//! `PORT_MANIFEST.tsv`), so its behavior deserves the most scrutiny of this batch.
//!
//! Java crawls a live `db.Table.longKeyIterator` cursor range-by-range as `keyRangeList` is
//! exhausted. This port instead takes a single eager snapshot of every matching key across *all*
//! ranges at once (already sorted), and drives it with the "gap cursor" in `super::cursor`. See
//! that module's docs for why this is observably equivalent (both visit the same keys in the
//! same order) given this port's `Table` has no live B-tree cursor primitives to crawl in the
//! first place -- and for the derivation showing the gap-cursor model reproduces Java's
//! `ShortDurationLongKeyIterator` "positioned exactly at an existing key" ambiguity resolution
//! without needing to replicate the ambiguity itself.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBLongIterator, Field, Table};
use crate::program::database::map::address_map::AddressMap;
use crate::program::database::map::cursor::{initial_gap_by, Cursor};
use crate::program::database::map::table_snapshot::snapshot_long_keys;
use crate::program::model::address::{Address, AddressSet, AddressSetView};

/// Iterator of primary keys that are addresses. The `i64`s returned are the address-encoded
/// keys.
///
/// Port of `ghidra.program.database.map.AddressKeyIterator`.
pub struct AddressKeyIterator {
    table: Option<Arc<RwLock<Table>>>,
    keys: Vec<i64>,
    cursor: Cursor,
}

impl AddressKeyIterator {
    /// Constructs an empty iterator.
    ///
    /// Port of the Java class's `EMPTY_ITERATOR` constant / private no-arg constructor.
    pub fn new_empty() -> Self {
        AddressKeyIterator { table: None, keys: Vec::new(), cursor: Cursor::new(0, 0) }
    }

    /// Constructs an iterator over all addresses. Memory addresses encoded as absolute are not
    /// included.
    ///
    /// * `before` -- positions the iterator before the min value; otherwise after the max value.
    ///
    /// Port of `AddressKeyIterator(Table, AddressMap, boolean)`.
    pub fn new(table: &Arc<RwLock<Table>>, addr_map: &dyn AddressMap, before: bool) -> io::Result<Self> {
        Self::new_general(table, addr_map, false, None, None, before)
    }

    /// Constructs an iterator over all addresses, positioned at `start_addr`. Memory addresses
    /// encoded as absolute are not included.
    ///
    /// Port of `AddressKeyIterator(Table, AddressMap, Address, boolean)`.
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
    /// Port of `AddressKeyIterator(Table, AddressMap, Address, Address, Address, boolean)`.
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
    /// Port of `AddressKeyIterator(Table, AddressMap, AddressSetView, Address, boolean)`.
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
    /// Port of the package-private `AddressKeyIterator(Table, AddressMap, boolean,
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
        Ok(AddressKeyIterator {
            table: Some(table.clone()),
            cursor: Cursor::new(pos, keys.len()),
            keys,
        })
    }
}

impl DBLongIterator for AddressKeyIterator {
    fn has_next(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_next())
    }

    fn has_previous(&mut self) -> io::Result<bool> {
        Ok(self.table.is_some() && self.cursor.has_previous())
    }

    fn next(&mut self) -> io::Result<i64> {
        match self.cursor.advance_next() {
            Some(idx) => Ok(self.keys[idx]),
            None => Err(io::Error::new(io::ErrorKind::Other, "no next value")),
        }
    }

    fn previous(&mut self) -> io::Result<i64> {
        match self.cursor.advance_previous() {
            Some(idx) => Ok(self.keys[idx]),
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
        let key = self.keys[idx];
        let deleted = table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
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
    use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
    use crate::program::database::map::test_support::TestAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn make_table(keys: &[i64]) -> Arc<RwLock<Table>> {
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
            for &k in keys {
                let s = t.get_schema();
                let mut rec = DBRecord::new(s, Field::Long(Some(k)));
                rec.set_field(0, Field::Int(Some(0)));
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
        let mut it = AddressKeyIterator::new_empty();
        assert!(!it.has_next().unwrap());
        assert!(!it.has_previous().unwrap());
        assert!(it.next().is_err());
        assert!(it.previous().is_err());
        assert!(!it.delete().unwrap());
    }

    #[test]
    fn forward_iteration_over_all_addresses() {
        let table = make_table(&[30, 10, 20]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, true).unwrap();

        let mut values = Vec::new();
        while it.has_next().unwrap() {
            values.push(it.next().unwrap());
        }
        assert_eq!(values, vec![10, 20, 30]);
        assert!(it.next().is_err());
    }

    #[test]
    fn backward_iteration_over_all_addresses() {
        let table = make_table(&[30, 10, 20]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, false).unwrap();

        let mut values = Vec::new();
        while it.has_previous().unwrap() {
            values.push(it.previous().unwrap());
        }
        assert_eq!(values, vec![30, 20, 10]);
    }

    #[test]
    fn positioned_at_existing_key_before_true_yields_it_going_forward() {
        let table = make_table(&[5, 10, 15, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressKeyIterator::new_at(&table, &addr_map, &s.address(10), true).unwrap();

        assert!(it.has_next().unwrap());
        assert_eq!(it.next().unwrap(), 10);
        assert_eq!(it.next().unwrap(), 15);
    }

    #[test]
    fn positioned_at_existing_key_before_true_predecessor_via_previous() {
        let table = make_table(&[5, 10, 15, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let it = AddressKeyIterator::new_at(&table, &addr_map, &s.address(10), true).unwrap();
        let mut it = it;
        assert!(it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap(), 5);
    }

    #[test]
    fn positioned_at_existing_key_before_false_yields_it_going_backward() {
        let table = make_table(&[5, 10, 15, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressKeyIterator::new_at(&table, &addr_map, &s.address(10), false).unwrap();

        assert!(it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap(), 10);
        assert_eq!(it.previous().unwrap(), 5);
    }

    #[test]
    fn positioned_at_existing_key_before_false_successor_via_next() {
        let table = make_table(&[5, 10, 15, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressKeyIterator::new_at(&table, &addr_map, &s.address(10), false).unwrap();
        assert!(it.has_next().unwrap());
        assert_eq!(it.next().unwrap(), 15);
    }

    #[test]
    fn positioned_at_missing_key_splits_the_same_way_regardless_of_before() {
        let table = make_table(&[5, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();

        let mut before_it =
            AddressKeyIterator::new_at(&table, &addr_map, &s.address(12), true).unwrap();
        assert_eq!(before_it.next().unwrap(), 20);

        let mut after_it =
            AddressKeyIterator::new_at(&table, &addr_map, &s.address(12), false).unwrap();
        assert_eq!(after_it.previous().unwrap(), 5);
    }

    #[test]
    fn no_start_address_before_true_positions_at_the_very_beginning() {
        let table = make_table(&[5, 10]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, true).unwrap();
        assert!(!it.has_previous().unwrap());
        assert_eq!(it.next().unwrap(), 5);
    }

    #[test]
    fn no_start_address_before_false_positions_at_the_very_end() {
        let table = make_table(&[5, 10]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, false).unwrap();
        assert!(!it.has_next().unwrap());
        assert_eq!(it.previous().unwrap(), 10);
    }

    #[test]
    fn range_restricted_iteration_only_yields_matching_keys() {
        let table = make_table(&[1, 5, 10, 15, 20]);
        let addr_map = TestAddressMap::new(space());
        let s = space();
        let mut it = AddressKeyIterator::new_over_range(
            &table,
            &addr_map,
            &s.address(5),
            &s.address(15),
            None,
            true,
        )
        .unwrap();

        let mut values = Vec::new();
        while it.has_next().unwrap() {
            values.push(it.next().unwrap());
        }
        assert_eq!(values, vec![5, 10, 15]);
    }

    #[test]
    fn delete_removes_from_table_and_keeps_iteration_consistent() {
        let table = make_table(&[5, 10, 15]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, true).unwrap();

        assert_eq!(it.next().unwrap(), 5);
        assert!(it.delete().unwrap());
        assert!(!table.read().unwrap().has_record(&Field::Long(Some(5))));

        let mut remaining = Vec::new();
        while it.has_next().unwrap() {
            remaining.push(it.next().unwrap());
        }
        assert_eq!(remaining, vec![10, 15]);
    }

    #[test]
    fn delete_without_prior_next_or_previous_is_false() {
        let table = make_table(&[5]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, true).unwrap();
        assert!(!it.delete().unwrap());
    }

    #[test]
    fn next_then_previous_echoes_the_same_key() {
        // Standard ListIterator invariant: calling next() then previous() returns to the same
        // element with no net movement. This is the property the "gap cursor" model relies on
        // (see the module docs) instead of replicating Java's ambiguous dual-echo initial state.
        let table = make_table(&[5, 10, 15]);
        let addr_map = TestAddressMap::new(space());
        let mut it = AddressKeyIterator::new(&table, &addr_map, true).unwrap();

        let forward = it.next().unwrap();
        let backward = it.previous().unwrap();
        assert_eq!(forward, backward);
    }

    #[test]
    fn behaves_as_trait_object() {
        let table = make_table(&[5, 10]);
        let addr_map = TestAddressMap::new(space());
        let mut it: Box<dyn DBLongIterator> =
            Box::new(AddressKeyIterator::new(&table, &addr_map, true).unwrap());
        assert_eq!(it.next().unwrap(), 5);
    }
}
