//! Port of `ghidra.program.database.properties.IntPropertyMapDB`.
//!
//! Property manager for `int`-valued properties, stored one value column per record. See
//! `db_backed_store`'s module docs for the single-address-space key-encoding simplification every
//! concrete map in this file family shares, and `VoidPropertyMapDB`'s module docs for why the
//! `DBHandle`/`OpenMode`/.../`TaskMonitor` constructor and `checkMapVersion` are not ported here.

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
use crate::program::util::IntPropertyMap;
use crate::util::exception::NoValueException;

const VALUE_COL: usize = 0;

/// Database-backed integer-valued property map.
///
/// Port of `ghidra.program.database.properties.IntPropertyMapDB`.
pub struct IntPropertyMapDB {
    state: DbObjectState,
    name: String,
    space: Arc<AddressSpace>,
    table: Arc<RwLock<Table>>,
}

impl IntPropertyMapDB {
    /// Construct an integer property map, creating its underlying table in `db_handle` if it
    /// does not already exist.
    pub fn new(db_handle: &mut DBHandle, name: &str, space: Arc<AddressSpace>) -> io::Result<Self> {
        let table_name = get_table_name(name);
        let table = match db_handle.get_table(&table_name) {
            Some(t) => t,
            None => {
                let schema = Arc::new(Schema::new(
                    0,
                    FieldType::Long,
                    "Address".to_string(),
                    vec![FieldType::Int],
                    vec!["Value".to_string()],
                    vec![],
                ));
                db_handle.create_table(table_name, schema)?
            }
        };
        Ok(IntPropertyMapDB {
            state: DbObjectState::new(0),
            name: name.to_string(),
            space,
            table,
        })
    }

    fn key(&self, addr: &Address) -> Field {
        Field::Long(Some(addr.offset()))
    }

    fn value_at(&self, addr: &Address) -> Option<i32> {
        self.table
            .read()
            .unwrap()
            .get_record(&self.key(addr))
            .ok()
            .flatten()
            .and_then(|rec| rec.get_int(VALUE_COL))
    }
}

impl DbObject for IntPropertyMapDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        true
    }
}

impl IntPropertyMap for IntPropertyMapDB {
    fn add_int(&mut self, addr: &Address, value: i32) {
        let schema = self.table.read().unwrap().get_schema();
        let mut rec = DBRecord::new(schema, self.key(addr));
        rec.set_int(VALUE_COL, value);
        let _ = self.table.write().unwrap().put_record(rec);
    }

    fn get_int(&self, addr: &Address) -> Result<i32, NoValueException> {
        self.value_at(addr).ok_or_else(NoValueException::new)
    }
}

impl PropertyMap for IntPropertyMapDB {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<i32>())
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
        self.value_at(addr).is_some()
    }

    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
        match value {
            Some(v) => match v.downcast::<i32>() {
                Ok(i) => self.add_int(addr, *i),
                Err(_) => panic!("Integer value required"),
            },
            None => {
                self.remove(addr);
            }
        }
    }

    fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
        self.value_at(addr).map(|v| Box::new(v) as Box<dyn Any>)
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
        let moved: Vec<(Address, i32)> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .filter_map(|a| self.value_at(&a).map(|v| (a, v)))
            .collect();
        for (a, _) in &moved {
            self.remove(a);
        }
        for (a, v) in moved {
            let offset = a.offset() - start.offset();
            let new_addr = Address::new(new_start.space().clone(), new_start.offset() + offset);
            self.add_int(&new_addr, v);
        }
    }
}

impl PropertyMapDB for IntPropertyMapDB {
    fn set_cache_size(&mut self, _size: usize) {}

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

    fn map(name: &str) -> (DBHandle, IntPropertyMapDB) {
        let mut handle = DBHandle::new().unwrap();
        let m = IntPropertyMapDB::new(&mut handle, name, space()).unwrap();
        (handle, m)
    }

    #[test]
    fn add_int_and_get_int_round_trip() {
        let (_h, mut m) = map("ints");
        m.add_int(&addr(0x1000), 42);
        assert_eq!(m.get_int(&addr(0x1000)).unwrap(), 42);
        assert!(m.get_int(&addr(0x2000)).is_err());
    }

    #[test]
    fn add_with_dyn_any_dispatches_and_removes() {
        let (_h, mut m) = map("ints");
        m.add(&addr(0x1000), Some(Box::new(7i32)));
        assert_eq!(m.get_int(&addr(0x1000)).unwrap(), 7);

        m.add(&addr(0x1000), None);
        assert!(!m.has_property(&addr(0x1000)));
    }

    #[test]
    #[should_panic(expected = "Integer value required")]
    fn add_with_non_int_panics() {
        let (_h, mut m) = map("ints");
        m.add(&addr(0x1000), Some(Box::new("nope")));
    }

    #[test]
    fn overwrite_updates_value() {
        let (_h, mut m) = map("ints");
        m.add_int(&addr(0x1000), 1);
        m.add_int(&addr(0x1000), 2);
        assert_eq!(m.get_int(&addr(0x1000)).unwrap(), 2);
        assert_eq!(m.get_size(), 1);
    }

    #[test]
    fn move_range_preserves_values() {
        let (_h, mut m) = map("ints");
        m.add_int(&addr(0x1000), 1);
        m.add_int(&addr(0x2000), 2);
        m.move_range(&addr(0x1000), &addr(0x2000), &addr(0x5000));

        assert!(!m.has_property(&addr(0x1000)));
        assert_eq!(m.get_int(&addr(0x5000)).unwrap(), 1);
        assert_eq!(m.get_int(&addr(0x6000)).unwrap(), 2);
    }

    #[test]
    fn iterator_range_and_negative_range() {
        let (_h, mut m) = map("ints");
        m.add_int(&addr(0x1000), 1);
        m.add_int(&addr(0x2000), 2);
        m.add_int(&addr(0x3000), 3);

        let vals: Vec<Address> = m.get_property_iterator_range(&addr(0x1500), &addr(0x3000)).collect();
        assert_eq!(vals, vec![addr(0x2000), addr(0x3000)]);

        let vals: Vec<Address> = m.get_property_iterator_range_ordered(&addr(0x1000), &addr(0x3000), false).collect();
        assert_eq!(vals, vec![addr(0x3000), addr(0x2000), addr(0x1000)]);
    }

    #[test]
    fn get_value_class_is_i32() {
        let (_h, m) = map("ints");
        assert_eq!(m.get_value_class(), Some(TypeId::of::<i32>()));
    }
}
