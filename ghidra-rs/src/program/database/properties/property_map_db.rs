//! Port of `ghidra.program.database.properties.PropertyMapDB`.
//!
//! `PropertyMapDB<T>` is the abstract database-backed base class for every property map
//! implementation (`IntPropertyMapDB`, `LongPropertyMapDB`, `StringPropertyMapDB`,
//! `ObjectPropertyMapDB`, `VoidPropertyMapDB`) and was selected as a dependency-cycle
//! cut-point. It combines two already-ported traits as supertraits:
//! [`DbObject`] (the shared database-object lifecycle contract) and
//! [`PropertyMap`](crate::program::model::util::PropertyMap) (the type-erased public property
//! map contract, which already covers `getName`/`clear`/`intersects`/`removeRange`/`remove`/
//! `hasProperty`/the `getXxxPropertyAddress` family/`getSize`/the `getPropertyIterator`
//! overloads/`moveRange`), and adds the members Java declares directly on `PropertyMapDB` that
//! `PropertyMap` does not: cache sizing, whole-map deletion, invalidation, and the
//! lower-level, `long`-keyed `getAddressKeyIterator` overloads used by subclasses to walk the
//! underlying table.
//!
//! Not ported here: `checkMapVersion`/`createTable` are package-private/`protected` methods
//! that Java subclass constructors call on themselves directly (never through a polymorphic
//! `PropertyMapDB` reference), so they are construction-time details for each concrete subclass
//! port rather than part of the dynamic-dispatch surface this trait exists to cut the cycle
//! for.
//!
//! `getAddressKeyIterator`'s return type, `ghidra.program.database.map.AddressKeyIterator`,
//! is not yet ported, so its `DBLongIterator` surface (`hasNext`/`hasPrevious`/`next`/
//! `previous`) is captured as the minimal [`AddressKeyIteratorLike`](
//! crate::program::seam_stubs::AddressKeyIteratorLike) placeholder in `seam_stubs.rs`.

use std::io;

use crate::program::database::db_object::DbObject;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::AddressKeyIteratorLike;

/// Prefix prepended to a property name to form its underlying database table name. Stands in
/// for `PropertyMapDB.PROPERTY_TABLE_PREFIX`.
pub const PROPERTY_TABLE_PREFIX: &str = "Property Map - ";

/// Get the default property table name for a given property name. Stands in for the static
/// `PropertyMapDB.getTableName(String)`.
pub fn get_table_name(property_name: &str) -> String {
    format!("{PROPERTY_TABLE_PREFIX}{property_name}")
}

/// A database-backed map containing properties over a set of addresses.
///
/// Port of `ghidra.program.database.properties.PropertyMapDB<T>`. See the module docs for why
/// this is a trait (cycle cut-point) and what was intentionally left out.
pub trait PropertyMapDB: DbObject + PropertyMap {
    /// Adjust the size of the underlying read cache. Stands in for
    /// `PropertyMapDB.setCacheSize(int)`.
    fn set_cache_size(&mut self, size: usize);

    /// Delete this property map and all underlying tables. Stands in for
    /// `PropertyMapDB.delete()`.
    ///
    /// # Errors
    /// Returns an error if an I/O error occurs while deleting the underlying table.
    fn delete(&mut self) -> io::Result<()>;

    /// Get an iterator over the long address keys which contain a property value, over the
    /// given address set (`None` indicates all defined memory regions). Stands in for
    /// `PropertyMapDB.getAddressKeyIterator(AddressSetView, boolean)`.
    ///
    /// # Errors
    /// Returns an error if an I/O error occurs while constructing the iterator.
    fn get_address_key_iterator_for_set(
        &self,
        set: Option<&dyn AddressSetView>,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Get an iterator over the long address keys which contain a property value, positioned at
    /// `start`. Stands in for `PropertyMapDB.getAddressKeyIterator(Address, boolean)`.
    ///
    /// # Errors
    /// Returns an error if an I/O error occurs while constructing the iterator.
    fn get_address_key_iterator_from(
        &self,
        start: &Address,
        before: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Get an iterator over the long address keys which contain a property value, within
    /// `[start, end]`. Stands in for `PropertyMapDB.getAddressKeyIterator(Address, Address,
    /// boolean)`.
    ///
    /// # Errors
    /// Returns an error if an I/O error occurs while constructing the iterator.
    fn get_address_key_iterator_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Invalidates the cache. Stands in for `PropertyMapDB.invalidate()`.
    fn invalidate(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBRecord;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{
        Address, BoxedAddressIterator, AddressIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType,
    };
    use std::any::{Any, TypeId};
    use std::collections::BTreeMap;

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// Mock iterator over `long` address keys, proving [`AddressKeyIteratorLike`] is usable as a
    /// trait object with real forward/backward cursor behavior.
    struct MockAddressKeyIterator {
        keys: Vec<i64>,
        pos: usize,
    }

    impl AddressKeyIteratorLike for MockAddressKeyIterator {
        fn has_next(&mut self) -> bool {
            self.pos < self.keys.len()
        }

        fn has_previous(&mut self) -> bool {
            self.pos > 0
        }

        fn next(&mut self) -> Option<i64> {
            if !self.has_next() {
                return None;
            }
            let v = self.keys[self.pos];
            self.pos += 1;
            Some(v)
        }

        fn previous(&mut self) -> Option<i64> {
            if !self.has_previous() {
                return None;
            }
            self.pos -= 1;
            Some(self.keys[self.pos])
        }
    }

    /// Mock database-backed property map (`long`-valued), proving [`PropertyMapDB`] (with its
    /// [`DbObject`] and [`PropertyMap`] supertraits) is object-safe and can be driven through a
    /// `Box<dyn PropertyMapDB>`.
    struct MockPropertyMapDB {
        state: DbObjectState,
        name: String,
        values: BTreeMap<Address, i64>,
        cache_size: usize,
    }

    impl MockPropertyMapDB {
        fn new(name: &str) -> Self {
            MockPropertyMapDB {
                state: DbObjectState::new(0),
                name: name.to_string(),
                values: BTreeMap::new(),
                cache_size: 100,
            }
        }
    }

    impl DbObject for MockPropertyMapDB {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    impl PropertyMap for MockPropertyMapDB {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<i64>())
        }

        fn clear(&mut self) {
            self.values.clear();
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.values.keys().any(|a| a >= start && a <= end)
        }

        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.values.keys().any(|a| set.contains(a))
        }

        fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
            let before = self.values.len();
            self.values.retain(|a, _| !(a >= start && a <= end));
            self.values.len() != before
        }

        fn remove(&mut self, addr: &Address) -> bool {
            self.values.remove(addr).is_some()
        }

        fn has_property(&self, addr: &Address) -> bool {
            self.values.contains_key(addr)
        }

        fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
            match value {
                Some(v) => {
                    let i = *v.downcast::<i64>().expect("expected i64 value");
                    self.values.insert(addr.clone(), i);
                }
                None => {
                    self.values.remove(addr);
                }
            }
        }

        fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
            self.values.get(addr).map(|v| Box::new(*v) as Box<dyn Any>)
        }

        fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
            self.values.keys().find(|a| *a > addr).cloned()
        }

        fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
            self.values.keys().rev().find(|a| *a < addr).cloned()
        }

        fn get_first_property_address(&self) -> Option<Address> {
            self.values.keys().next().cloned()
        }

        fn get_last_property_address(&self) -> Option<Address> {
            self.values.keys().next_back().cloned()
        }

        fn get_size(&self) -> usize {
            self.values.len()
        }

        fn get_property_iterator_range(
            &self,
            start: &Address,
            end: &Address,
        ) -> BoxedAddressIterator {
            self.get_property_iterator_range_ordered(start, end, true)
        }

        fn get_property_iterator_range_ordered(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> BoxedAddressIterator {
            let mut addrs: Vec<Address> = self
                .values
                .keys()
                .filter(|a| *a >= start && *a <= end)
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_property_iterator(&self) -> BoxedAddressIterator {
            Box::new(AddressIteratorAdapter::from_vec(
                self.values.keys().cloned().collect(),
            ))
        }

        fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> BoxedAddressIterator {
            self.get_property_iterator_set_ordered(asv, true)
        }

        fn get_property_iterator_set_ordered(
            &self,
            asv: &dyn AddressSetView,
            forward: bool,
        ) -> BoxedAddressIterator {
            let mut addrs: Vec<Address> = self
                .values
                .keys()
                .filter(|a| asv.contains(a))
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_property_iterator_from(
            &self,
            start: &Address,
            forward: bool,
        ) -> BoxedAddressIterator {
            let mut addrs: Vec<Address> = self
                .values
                .keys()
                .filter(|a| if forward { *a >= start } else { *a <= start })
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
            let moved: Vec<(Address, i64)> = self
                .values
                .iter()
                .filter(|(a, _)| *a >= start && *a <= end)
                .map(|(a, v)| (a.clone(), *v))
                .collect();
            for (a, _) in &moved {
                self.values.remove(a);
            }
            for (a, v) in moved {
                let offset = a.offset() - start.offset();
                let new_addr = Address::new(new_start.space().clone(), new_start.offset() + offset);
                self.values.insert(new_addr, v);
            }
        }
    }

    impl PropertyMapDB for MockPropertyMapDB {
        fn set_cache_size(&mut self, size: usize) {
            self.cache_size = size;
        }

        fn delete(&mut self) -> io::Result<()> {
            self.values.clear();
            self.set_deleted();
            Ok(())
        }

        fn get_address_key_iterator_for_set(
            &self,
            set: Option<&dyn AddressSetView>,
            at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let mut keys: Vec<i64> = self
                .values
                .keys()
                .filter(|a| set.map_or(true, |s| s.contains(a)))
                .map(|a| a.offset())
                .collect();
            if !at_start {
                keys.reverse();
            }
            Ok(Box::new(MockAddressKeyIterator { keys, pos: 0 }))
        }

        fn get_address_key_iterator_from(
            &self,
            start: &Address,
            before: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let keys: Vec<i64> = self
                .values
                .keys()
                .filter(|a| if before { *a <= start } else { *a >= start })
                .map(|a| a.offset())
                .collect();
            Ok(Box::new(MockAddressKeyIterator { keys, pos: 0 }))
        }

        fn get_address_key_iterator_range(
            &self,
            start: &Address,
            end: &Address,
            at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let mut keys: Vec<i64> = self
                .values
                .keys()
                .filter(|a| *a >= start && *a <= end)
                .map(|a| a.offset())
                .collect();
            if !at_start {
                keys.reverse();
            }
            Ok(Box::new(MockAddressKeyIterator { keys, pos: 0 }))
        }

        fn invalidate(&mut self) {
            self.set_invalid();
        }
    }

    #[test]
    fn get_table_name_prefixes_property_name() {
        assert_eq!(get_table_name("MyProp"), "Property Map - MyProp");
    }

    #[test]
    fn usable_as_trait_object_through_full_lifecycle() {
        let mut map: Box<dyn PropertyMapDB> = Box::new(MockPropertyMapDB::new("longs"));

        assert_eq!(map.get_name(), "longs");
        map.add(&addr(0x1000), Some(Box::new(1i64)));
        map.add(&addr(0x2000), Some(Box::new(2i64)));
        map.add(&addr(0x3000), Some(Box::new(3i64)));
        assert_eq!(map.get_size(), 3);

        map.set_cache_size(4);

        // Forward iterator over the full range.
        let mut iter = map
            .get_address_key_iterator_range(&addr(0x1000), &addr(0x3000), true)
            .unwrap();
        let mut forward = Vec::new();
        while iter.has_next() {
            forward.push(iter.next().unwrap());
        }
        assert_eq!(forward, vec![0x1000, 0x2000, 0x3000]);
        assert!(iter.next().is_none());

        // Walking it back the other way from where the forward iterator ended.
        let mut backward = Vec::new();
        while iter.has_previous() {
            backward.push(iter.previous().unwrap());
        }
        assert_eq!(backward, vec![0x3000, 0x2000, 0x1000]);

        // Set-scoped iterator excludes addresses outside the set.
        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1000));
        set.add_range(&addr(0x3000), &addr(0x3000));
        let mut set_iter = map.get_address_key_iterator_for_set(Some(&set), true).unwrap();
        let mut in_set = Vec::new();
        while set_iter.has_next() {
            in_set.push(set_iter.next().unwrap());
        }
        assert_eq!(in_set, vec![0x1000, 0x3000]);

        assert!(map.is_valid());
        map.invalidate();
        assert!(!map.is_valid());
        assert!(map.refresh_if_needed());
        assert!(map.is_valid());

        map.delete().unwrap();
        assert_eq!(map.get_size(), 0);
        assert!(map.is_deleted(&crate::util::lock::ReentrantLock::new("test")));
    }
}
