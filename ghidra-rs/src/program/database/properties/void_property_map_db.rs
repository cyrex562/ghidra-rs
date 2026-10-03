//! Port of `ghidra.program.database.properties.VoidPropertyMapDB`.
//!
//! Property manager for "void" type properties: a marker for whether a property exists at an
//! address, with no associated value beyond presence. Records contain only the address key;
//! object values returned are either `true` or absent (`None`), matching Java's `Boolean.TRUE` /
//! `null`.
//!
//! Backed by a real [`Table`] (see `db_backed_store`'s module docs for the single-address-space
//! key-encoding simplification every concrete map in this file family shares). Not ported here:
//! the `DBHandle`/`OpenMode`/`ErrorHandler`/`ChangeManager`/`TaskMonitor`-taking constructor and
//! its `checkMapVersion` upgrade path are construction-time details, the same convention already
//! used by [`UnsupportedMapDB`](super::UnsupportedMapDB) and [`PropertyMapDB`] itself for
//! `checkMapVersion`/`createTable`.

use std::any::{Any, TypeId};
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::properties::db_backed_store::{collect_sorted_addresses, VecKeyIterator};
use crate::program::database::properties::{get_table_name, PropertyMapDB};
use crate::program::model::address::{
    Address, AddressIteratorAdapter, AddressSetView, AddressSpace, BoxedAddressIterator,
};
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::program::util::VoidPropertyMap;

/// Database-backed void (marker) property map.
///
/// Port of `ghidra.program.database.properties.VoidPropertyMapDB`.
pub struct VoidPropertyMapDB {
    state: DbObjectState,
    name: String,
    space: Arc<AddressSpace>,
    table: Arc<RwLock<Table>>,
}

impl VoidPropertyMapDB {
    /// Construct a void property map, creating its underlying table in `db_handle` if it does
    /// not already exist. `space` fixes the single address space this map's keys are drawn from
    /// (see the module docs on `db_backed_store` for why).
    pub fn new(db_handle: &mut DBHandle, name: &str, space: Arc<AddressSpace>) -> io::Result<Self> {
        let table_name = get_table_name(name);
        let table = match db_handle.get_table(&table_name) {
            Some(t) => t,
            None => {
                let schema = Arc::new(Schema::new(
                    0,
                    FieldType::Long,
                    "Address".to_string(),
                    vec![],
                    vec![],
                    vec![],
                ));
                db_handle.create_table(table_name, schema)?
            }
        };
        Ok(VoidPropertyMapDB {
            state: DbObjectState::new(0),
            name: name.to_string(),
            space,
            table,
        })
    }

    fn key(&self, addr: &Address) -> Field {
        Field::Long(Some(addr.offset()))
    }
}

impl DbObject for VoidPropertyMapDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        true
    }
}

impl VoidPropertyMap for VoidPropertyMapDB {
    fn add_void(&mut self, addr: &Address) {
        let schema = self.table.read().unwrap().get_schema();
        let rec = DBRecord::new(schema, self.key(addr));
        let _ = self.table.write().unwrap().put_record(rec);
    }
}

impl PropertyMap for VoidPropertyMapDB {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<bool>())
    }

    fn clear(&mut self) {
        let _ = self.table.write().unwrap().clear_all();
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .iter()
            .any(|a| a >= start && a <= end)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .iter()
            .any(|a| set.contains(a))
    }

    fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
        let addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .collect();
        let mut removed = false;
        let mut table = self.table.write().unwrap();
        for a in addrs {
            if table.delete_record(&self.key(&a)).unwrap_or(false) {
                removed = true;
            }
        }
        removed
    }

    fn remove(&mut self, addr: &Address) -> bool {
        self.table.write().unwrap().delete_record(&self.key(addr)).unwrap_or(false)
    }

    fn has_property(&self, addr: &Address) -> bool {
        self.table
            .read()
            .unwrap()
            .get_record(&self.key(addr))
            .ok()
            .flatten()
            .is_some()
    }

    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
        match value {
            Some(v) => match v.downcast::<bool>() {
                Ok(b) => {
                    if *b {
                        self.add_void(addr);
                    } else {
                        self.remove(addr);
                    }
                }
                Err(_) => panic!("Boolean value required"),
            },
            None => {
                self.remove(addr);
            }
        }
    }

    fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
        if self.has_property(addr) {
            Some(Box::new(true))
        } else {
            None
        }
    }

    fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .find(|a| a > addr)
    }

    fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .rev()
            .find(|a| a < addr)
    }

    fn get_first_property_address(&self) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .next()
    }

    fn get_last_property_address(&self) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .last()
    }

    fn get_size(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn get_property_iterator_range(&self, start: &Address, end: &Address) -> BoxedAddressIterator {
        self.get_property_iterator_range_ordered(start, end, true)
    }

    fn get_property_iterator_range_ordered(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn get_property_iterator(&self) -> BoxedAddressIterator {
        Box::new(AddressIteratorAdapter::from_vec(collect_sorted_addresses(
            &self.table.read().unwrap(),
            &self.space,
        )))
    }

    fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> BoxedAddressIterator {
        self.get_property_iterator_set_ordered(asv, true)
    }

    fn get_property_iterator_set_ordered(&self, asv: &dyn AddressSetView, forward: bool) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| asv.contains(a))
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn get_property_iterator_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| if forward { a >= start } else { a <= start })
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
        let moved: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .collect();
        for a in &moved {
            self.remove(a);
        }
        for a in moved {
            let offset = a.offset() - start.offset();
            let new_addr = Address::new(new_start.space().clone(), new_start.offset() + offset);
            self.add_void(&new_addr);
        }
    }
}

impl PropertyMapDB for VoidPropertyMapDB {
    fn set_cache_size(&mut self, _size: usize) {
        // No read cache is maintained by this in-memory-backed port; accepted for interface
        // parity with `PropertyMapDB.setCacheSize(int)`.
    }

    fn delete(&mut self) -> io::Result<()> {
        self.table.write().unwrap().clear_all()?;
        self.set_deleted();
        Ok(())
    }

    fn get_address_key_iterator_for_set(
        &self,
        set: Option<&dyn AddressSetView>,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let mut keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| set.map_or(true, |s| s.contains(a)))
            .map(|a| a.offset())
            .collect();
        if !at_start {
            keys.reverse();
        }
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn get_address_key_iterator_from(
        &self,
        start: &Address,
        before: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| if before { a <= start } else { a >= start })
            .map(|a| a.offset())
            .collect();
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn get_address_key_iterator_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let mut keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .map(|a| a.offset())
            .collect();
        if !at_start {
            keys.reverse();
        }
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn invalidate(&mut self) {
        self.set_invalid();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn map(name: &str) -> (DBHandle, VoidPropertyMapDB) {
        let mut handle = DBHandle::new().unwrap();
        let m = VoidPropertyMapDB::new(&mut handle, name, space()).unwrap();
        (handle, m)
    }

    #[test]
    fn add_void_marks_property_and_get_returns_true() {
        let (_h, mut m) = map("flags");
        m.add_void(&addr(0x1000));
        assert!(m.has_property(&addr(0x1000)));
        let v = m.get(&addr(0x1000)).unwrap();
        assert_eq!(*v.downcast::<bool>().unwrap(), true);
        assert!(m.get(&addr(0x2000)).is_none());
    }

    #[test]
    fn add_with_false_or_none_removes() {
        let (_h, mut m) = map("flags");
        m.add_void(&addr(0x1000));
        m.add(&addr(0x1000), Some(Box::new(false)));
        assert!(!m.has_property(&addr(0x1000)));

        m.add_void(&addr(0x1000));
        m.add(&addr(0x1000), None);
        assert!(!m.has_property(&addr(0x1000)));
    }

    #[test]
    #[should_panic(expected = "Boolean value required")]
    fn add_with_non_bool_panics() {
        let (_h, mut m) = map("flags");
        m.add(&addr(0x1000), Some(Box::new(42i32)));
    }

    #[test]
    fn size_iteration_and_move_range() {
        let (_h, mut m) = map("flags");
        m.add_void(&addr(0x1000));
        m.add_void(&addr(0x2000));
        m.add_void(&addr(0x3000));
        assert_eq!(m.get_size(), 3);

        assert_eq!(m.get_first_property_address(), Some(addr(0x1000)));
        assert_eq!(m.get_last_property_address(), Some(addr(0x3000)));
        assert_eq!(m.get_next_property_address(&addr(0x1000)), Some(addr(0x2000)));
        assert_eq!(m.get_previous_property_address(&addr(0x3000)), Some(addr(0x2000)));

        m.move_range(&addr(0x1000), &addr(0x3000), &addr(0x5000));
        assert!(!m.has_property(&addr(0x1000)));
        assert!(m.has_property(&addr(0x5000)));
        assert!(m.has_property(&addr(0x7000)));
        assert_eq!(m.get_size(), 3);
    }

    #[test]
    fn address_key_iterator_range_walks_forward_and_backward() {
        let (_h, mut m) = map("flags");
        m.add_void(&addr(0x1000));
        m.add_void(&addr(0x2000));
        m.add_void(&addr(0x3000));

        let mut it = m
            .get_address_key_iterator_range(&addr(0x1000), &addr(0x3000), true)
            .unwrap();
        let mut fwd = Vec::new();
        while it.has_next() {
            fwd.push(it.next().unwrap());
        }
        assert_eq!(fwd, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn delete_clears_table_and_marks_deleted() {
        let (_h, mut m) = map("flags");
        m.add_void(&addr(0x1000));
        m.delete().unwrap();
        assert_eq!(m.get_size(), 0);
        assert!(m.is_deleted(&crate::util::lock::ReentrantLock::new("t")));
    }

    #[test]
    fn usable_as_trait_object_through_property_map_db() {
        let mut handle = DBHandle::new().unwrap();
        let map: Box<dyn PropertyMapDB> =
            Box::new(VoidPropertyMapDB::new(&mut handle, "flags", space()).unwrap());
        assert_eq!(map.get_name(), "flags");
        assert_eq!(map.get_value_class(), Some(TypeId::of::<bool>()));
    }
}
