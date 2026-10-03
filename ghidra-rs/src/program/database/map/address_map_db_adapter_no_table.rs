//! Port of `ghidra.program.database.map.AddressMapDBAdapterNoTable`.
//!
//! Adapter used when no address map table exists at all (predates the address map table's
//! introduction). Base addresses are derived directly from the current `AddressFactory`'s
//! address spaces (each space's address `0`, sorted), rather than persisted rows, and most
//! mutating operations are unsupported, matching Java.
//!
//! Also ports the Java class's private inner class `FactoryBasedAddressMap` (Java's
//! `AddressMapDBAdapter.oldAddrMap` field, set here to an instance of it) as
//! [`FactoryBasedAddressMap`]: a minimal [`AddressMap`] that delegates directly to the
//! `AddressFactory` rather than an on-disk key encoding. The `AddressMapDBAdapter` trait (see
//! `address_map_db_adapter.rs`'s module docs) does not model the `oldAddrMap` field itself, so
//! it is exposed here as a plain inherent accessor, [`AddressMapDBAdapterNoTable::old_address_map`],
//! for whichever future caller needs it (mirroring `AddressMapDB`, not yet ported).

use std::io;
use std::sync::{Arc, RwLock};

use crate::program::database::map::address_map::AddressMap;
use crate::program::database::map::address_map_db_adapter::{AddressMapDBAdapter, AddressMapEntry};
use crate::program::model::address::{
    Address, AddressFactory, AddressRangeIterator, AddressSetView, KeyRange,
};

/// Address map that translates directly through an [`AddressFactory`], without any persisted key
/// encoding.
///
/// Port of the private inner class `AddressMapDBAdapterNoTable.FactoryBasedAddressMap`.
pub struct FactoryBasedAddressMap {
    factory: Arc<RwLock<Arc<dyn AddressFactory>>>,
}

impl FactoryBasedAddressMap {
    fn factory(&self) -> Arc<dyn AddressFactory> {
        self.factory.read().unwrap().clone()
    }
}

impl AddressMap for FactoryBasedAddressMap {
    fn get_key(&self, addr: &Address, create: bool) -> i64 {
        if create {
            panic!("Old address map does not support key creation");
        }
        self.factory().get_index(addr)
    }

    fn get_absolute_encoding(&self, addr: &Address, create: bool) -> i64 {
        if create {
            panic!("Old address map does not support key creation");
        }
        self.factory().get_index(addr)
    }

    fn find_key_range(&self, key_range_list: &[KeyRange], addr: Option<&Address>) -> i32 {
        let Some(addr) = addr else {
            return -1;
        };
        match key_range_list.binary_search_by(|range| {
            let min = self.decode_address(range.min_key);
            if min > *addr {
                return std::cmp::Ordering::Greater;
            }
            let max = self.decode_address(range.max_key);
            if max < *addr {
                return std::cmp::Ordering::Less;
            }
            std::cmp::Ordering::Equal
        }) {
            Ok(index) => index as i32,
            Err(index) => -(index as i32) - 1,
        }
    }

    fn decode_address(&self, value: i64) -> Address {
        self.factory()
            .old_get_address_from_long(value)
            .expect("value did not decode to a valid address")
    }

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        Some(self.factory())
    }

    fn get_key_ranges_absolute(
        &self,
        start: &Address,
        end: &Address,
        absolute: bool,
        create: bool,
    ) -> Vec<KeyRange> {
        let set = self.factory().get_address_set_range(start, end);
        self.get_key_ranges_for_set_absolute(Some(&set), absolute, create)
    }

    fn get_key_ranges_for_set_absolute(
        &self,
        set: Option<&dyn AddressSetView>,
        absolute: bool,
        _create: bool,
    ) -> Vec<KeyRange> {
        if absolute {
            return Vec::new();
        }
        match set {
            None => vec![KeyRange::new(i64::MIN, i64::MAX)],
            Some(set) => {
                let mut ranges = Vec::new();
                let mut it: Box<dyn AddressRangeIterator> = set.address_ranges();
                while let Some(range) = it.next() {
                    ranges.push(KeyRange::new(
                        self.factory().get_index(range.min_address()),
                        self.factory().get_index(range.max_address()),
                    ));
                }
                ranges
            }
        }
    }

    fn get_old_address_map(&self) -> Box<dyn AddressMap> {
        Box::new(FactoryBasedAddressMap { factory: self.factory.clone() })
    }

    fn is_upgraded(&self) -> bool {
        false
    }

    fn get_image_base(&self) -> Address {
        self.factory()
            .get_default_address_space()
            .expect("address factory has no default address space")
            .address(0)
    }
}

/// Adapter for when no address map table exists.
///
/// Port of `ghidra.program.database.map.AddressMapDBAdapterNoTable`.
pub struct AddressMapDBAdapterNoTable {
    factory: Arc<RwLock<Arc<dyn AddressFactory>>>,
    addresses: Vec<Address>,
    old_address_map: FactoryBasedAddressMap,
}

impl AddressMapDBAdapterNoTable {
    /// Constructs a new adapter, deriving base addresses from `factory`'s current address
    /// spaces.
    ///
    /// Port of `AddressMapDBAdapterNoTable(DBHandle, AddressFactory)`. Java's `handle` parameter
    /// is accepted but never used by the constructor body; this port omits it accordingly.
    pub fn new(factory: Arc<dyn AddressFactory>) -> Self {
        let mut addresses: Vec<Address> =
            factory.get_address_spaces().iter().map(|space| space.address(0)).collect();
        addresses.sort();
        let shared_factory = Arc::new(RwLock::new(factory));
        AddressMapDBAdapterNoTable {
            factory: shared_factory.clone(),
            addresses,
            old_address_map: FactoryBasedAddressMap { factory: shared_factory },
        }
    }

    /// Returns the [`AddressMap`] capable of decoding old (factory-index-based) address
    /// encodings.
    ///
    /// Accessor for Java's protected `AddressMapDBAdapter.oldAddrMap` field (not modeled by the
    /// [`AddressMapDBAdapter`] trait itself; see this module's docs).
    pub fn old_address_map(&self) -> &dyn AddressMap {
        &self.old_address_map
    }
}

impl AddressMapDBAdapter for AddressMapDBAdapterNoTable {
    fn delete_table(&mut self) -> io::Result<()> {
        // "don't have a table to delete" -- matches Java's empty method body.
        Ok(())
    }

    fn add_base_address(&mut self, _addr: &Address, _normalized_offset: i64) -> Vec<Address> {
        panic!("AddressMapDBAdapterNoTable does not support adding base addresses");
    }

    fn get_base_addresses(&mut self, _force_read: bool) -> io::Result<Vec<Address>> {
        Ok(self.addresses.clone())
    }

    fn get_entries(&self) -> io::Result<Vec<AddressMapEntry>> {
        Ok(self
            .addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| AddressMapEntry::new(i as i32, addr.space().name(), 0, false))
            .collect())
    }

    fn set_entries(&mut self, _entries: Vec<AddressMapEntry>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AddressMapDBAdapterNoTable does not support setting entries",
        ))
    }

    fn clear_all(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AddressMapDBAdapterNoTable does not support clearing entries",
        ))
    }

    fn set_address_factory(&mut self, addr_factory: Arc<dyn AddressFactory>) {
        *self.factory.write().unwrap() = addr_factory;
    }

    fn rename_overlay_space(&mut self, _old_name: &str, _new_name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AddressMapDBAdapterNoTable does not support renaming overlay spaces",
        ))
    }

    fn delete_overlay_space(&mut self, _name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AddressMapDBAdapterNoTable does not support deleting overlay spaces",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    fn make_factory() -> Arc<dyn AddressFactory> {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Arc::new(DefaultAddressFactory::new(vec![ram]))
    }

    #[test]
    fn base_addresses_come_from_factory_spaces() {
        let mut adapter = AddressMapDBAdapterNoTable::new(make_factory());
        let bases = adapter.get_base_addresses(false).unwrap();
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].offset(), 0);
    }

    #[test]
    fn get_entries_reports_one_per_space_never_deleted() {
        let adapter = AddressMapDBAdapterNoTable::new(make_factory());
        let entries = adapter.get_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].deleted);
        assert_eq!(entries[0].name, "ram");
    }

    #[test]
    fn delete_table_and_unsupported_ops() {
        let mut adapter = AddressMapDBAdapterNoTable::new(make_factory());
        assert!(adapter.delete_table().is_ok());
        assert!(adapter.set_entries(Vec::new()).is_err());
        assert!(adapter.clear_all().is_err());
        assert!(adapter.rename_overlay_space("a", "b").is_err());
        assert!(adapter.delete_overlay_space("a").is_err());
    }

    #[test]
    #[should_panic]
    fn add_base_address_panics() {
        let mut adapter = AddressMapDBAdapterNoTable::new(make_factory());
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        adapter.add_base_address(&space.address(0), 0);
    }

    #[test]
    fn old_address_map_round_trips_through_factory_index() {
        let factory = make_factory();
        let adapter = AddressMapDBAdapterNoTable::new(factory.clone());
        let old_map = adapter.old_address_map();

        let space = factory.get_address_spaces().into_iter().next().unwrap();
        let addr = space.address(0x10);
        let key = old_map.get_key(&addr, false);
        assert_eq!(old_map.decode_address(key), addr);
        assert!(!old_map.is_upgraded());
    }

    #[test]
    fn set_address_factory_updates_old_address_map_too() {
        let factory = make_factory();
        let mut adapter = AddressMapDBAdapterNoTable::new(factory);

        let new_space = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let new_factory: Arc<dyn AddressFactory> =
            Arc::new(DefaultAddressFactory::new(vec![new_space.clone()]));
        adapter.set_address_factory(new_factory);

        let old_map = adapter.old_address_map();
        assert_eq!(old_map.get_image_base().space(), &new_space);
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn AddressMapDBAdapter> = Box::new(AddressMapDBAdapterNoTable::new(make_factory()));
        assert_eq!(adapter.get_entries().unwrap().len(), 1);
    }
}
