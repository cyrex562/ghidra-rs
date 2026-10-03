//! Port of `ghidra.program.database.properties.StringPropertyMapDB`.
//!
//! Property manager for `String`-valued properties, stored one value column per record. See
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
use crate::program::util::StringPropertyMap;
use crate::util::exception::NoValueException;

const VALUE_COL: usize = 0;

/// Database-backed string-valued property map.
///
/// Port of `ghidra.program.database.properties.StringPropertyMapDB`.
pub struct StringPropertyMapDB {
    state: DbObjectState,
    name: String,
    space: Arc<AddressSpace>,
    table: Arc<RwLock<Table>>,
}

impl StringPropertyMapDB {
    /// Construct a string property map, creating its underlying table in `db_handle` if it does
    /// not already exist.
    pub fn new(db_handle: &mut DBHandle, name: &str, space: Arc<AddressSpace>) -> io::Result<Self> {
        let table_name = get_table_name(name);
        let table = match db_handle.get_table(&table_name) {
            Some(t) => t,
            None => {
                let schema = Arc::new(Schema::new(
                    0,
                    FieldType::Long,
                    "Address".to_string(),
                    vec![FieldType::String],
                    vec!["Value".to_string()],
                    vec![],
                ));
                db_handle.create_table(table_name, schema)?
            }
        };
        Ok(StringPropertyMapDB {
            state: DbObjectState::new(0),
            name: name.to_string(),
            space,
            table,
        })
    }

    fn key(&self, addr: &Address) -> Field {
        Field::Long(Some(addr.offset()))
    }

    fn value_at(&self, addr: &Address) -> Option<String> {
        self.table
            .read()
            .unwrap()
            .get_record(&self.key(addr))
            .ok()
            .flatten()
            .and_then(|rec| rec.get_string(VALUE_COL).map(|s| s.to_string()))
    }
}

impl DbObject for StringPropertyMapDB {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        true
    }
}

impl StringPropertyMap for StringPropertyMapDB {
    fn add_string(&mut self, addr: &Address, value: String) {
        let schema = self.table.read().unwrap().get_schema();
        let mut rec = DBRecord::new(schema, self.key(addr));
        rec.set_string(VALUE_COL, Some(value));
        let _ = self.table.write().unwrap().put_record(rec);
    }

    fn get_string(&self, addr: &Address) -> Result<String, NoValueException> {
        self.value_at(addr).ok_or_else(NoValueException::new)
    }
}

impl PropertyMap for StringPropertyMapDB {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<String>())
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
            Some(v) => match v.downcast::<String>() {
                Ok(s) => self.add_string(addr, *s),
                Err(_) => panic!("String value required"),
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
        let moved: Vec<(Address, String)> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
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
            self.add_string(&new_addr, v);
        }
    }
}

impl PropertyMapDB for StringPropertyMapDB {
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

    fn map(name: &str) -> (DBHandle, StringPropertyMapDB) {
        let mut handle = DBHandle::new().unwrap();
        let m = StringPropertyMapDB::new(&mut handle, name, space()).unwrap();
        (handle, m)
    }

    #[test]
    fn add_string_and_get_string_round_trip() {
        let (_h, mut m) = map("strs");
        m.add_string(&addr(0x1000), "hello".to_string());
        assert_eq!(m.get_string(&addr(0x1000)).unwrap(), "hello");
        assert!(m.get_string(&addr(0x2000)).is_err());
    }

    #[test]
    fn add_with_dyn_any_dispatches_and_removes() {
        let (_h, mut m) = map("strs");
        m.add(&addr(0x1000), Some(Box::new("world".to_string())));
        assert_eq!(m.get_string(&addr(0x1000)).unwrap(), "world");

        m.add(&addr(0x1000), None);
        assert!(!m.has_property(&addr(0x1000)));
    }

    #[test]
    #[should_panic(expected = "String value required")]
    fn add_with_non_string_panics() {
        let (_h, mut m) = map("strs");
        m.add(&addr(0x1000), Some(Box::new(42i32)));
    }

    #[test]
    fn empty_and_unicode_strings() {
        let (_h, mut m) = map("strs");
        m.add_string(&addr(0x1000), String::new());
        assert_eq!(m.get_string(&addr(0x1000)).unwrap(), "");

        let unicode = "こんにちは".to_string();
        m.add_string(&addr(0x2000), unicode.clone());
        assert_eq!(m.get_string(&addr(0x2000)).unwrap(), unicode);
    }

    #[test]
    fn move_range_preserves_values() {
        let (_h, mut m) = map("strs");
        m.add_string(&addr(0x1000), "a".to_string());
        m.add_string(&addr(0x2000), "b".to_string());
        m.move_range(&addr(0x1000), &addr(0x2000), &addr(0x5000));

        assert!(!m.has_property(&addr(0x1000)));
        assert_eq!(m.get_string(&addr(0x5000)).unwrap(), "a");
        assert_eq!(m.get_string(&addr(0x6000)).unwrap(), "b");
    }

    #[test]
    fn get_value_class_is_string() {
        let (_h, m) = map("strs");
        assert_eq!(m.get_value_class(), Some(TypeId::of::<String>()));
    }

    #[test]
    fn overwrite_updates_value_and_size_stays_one() {
        let (_h, mut m) = map("strs");
        m.add_string(&addr(0x1000), "first".to_string());
        m.add_string(&addr(0x1000), "second".to_string());
        assert_eq!(m.get_string(&addr(0x1000)).unwrap(), "second");
        assert_eq!(m.get_size(), 1);
    }
}
