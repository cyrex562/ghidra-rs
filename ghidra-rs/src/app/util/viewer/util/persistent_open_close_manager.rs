//! Address-based open/close management that persists state via `ProgramUserData`.

use std::cell::{Cell, RefCell};

use crate::program::model::address::Address;
use crate::program::model::listing::ProgramUserData;
use crate::program::util::VoidPropertyMap;

use super::OpenCloseManager;

/// Address based open/close management that uses [`ProgramUserData`] to persist the
/// open/close state for that address. Currently used for persisting the open/close state
/// of functions in the listing.
///
/// Corresponds to Java `ghidra.app.util.viewer.util.PersistentOpenCloseManager`.
pub struct PersistentOpenCloseManager {
    open_by_default: bool,
    boolean_property: Box<dyn VoidPropertyMap>,
    program_user_data: Box<dyn ProgramUserData>,

    // Often, is_open will be called on the same function address many times in a row so cache
    // the last address and result.
    cached_address: RefCell<Option<Address>>,
    cached_result: Cell<bool>,

    default_open_close_property_name: String,
}

impl PersistentOpenCloseManager {
    /// Creates a new manager that persists open/close state through `data`.
    ///
    /// # Panics
    ///
    /// Panics if `owner`/`property_name` are already defined as a property map of a
    /// conflicting type.
    pub fn new(mut data: Box<dyn ProgramUserData>, owner: &str, property_name: &str) -> Self {
        let default_open_close_property_name = format!("{property_name}Default");

        let tx = data.start_transaction();
        let boolean_property = data.get_boolean_property_map(owner, property_name, true);
        data.end_transaction(tx);
        let boolean_property =
            boolean_property.expect("conflicting property map definition found");

        // Get the default open state. Only addresses different from default have properties
        // stored.
        let function_state = data.get_string_property(&default_open_close_property_name, "Open");
        let open_by_default = function_state == "Open";

        Self {
            open_by_default,
            boolean_property,
            program_user_data: data,
            cached_address: RefCell::new(None),
            cached_result: Cell::new(false),
            default_open_close_property_name,
        }
    }

    fn add_address_property(&mut self, address: &Address) {
        let tx = self.program_user_data.start_transaction();
        self.boolean_property.add_void(address);
        self.program_user_data.end_transaction(tx);
    }

    fn remove_address_property(&mut self, address: &Address) {
        let tx = self.program_user_data.start_transaction();
        self.boolean_property.remove(address);
        self.program_user_data.end_transaction(tx);
    }

    fn clear_properties(&mut self) {
        let tx = self.program_user_data.start_transaction();
        self.boolean_property.clear();
        self.program_user_data.end_transaction(tx);
    }
}

impl OpenCloseManager for PersistentOpenCloseManager {
    fn is_open(&self, address: &Address) -> bool {
        if self.cached_address.borrow().as_ref() == Some(address) {
            return self.cached_result.get();
        }
        *self.cached_address.borrow_mut() = Some(address.clone());
        let contains = self.boolean_property.has_property(address);
        let result = if self.open_by_default { !contains } else { contains };
        self.cached_result.set(result);
        result
    }

    fn open(&mut self, address: &Address) {
        *self.cached_address.borrow_mut() = None;
        if self.open_by_default {
            self.remove_address_property(address);
        } else {
            self.add_address_property(address);
        }
    }

    fn close(&mut self, address: &Address) {
        *self.cached_address.borrow_mut() = None;
        if self.open_by_default {
            self.add_address_property(address);
        } else {
            self.remove_address_property(address);
        }
    }

    fn is_open_by_default(&self) -> bool {
        self.open_by_default
    }

    fn open_all(&mut self) {
        *self.cached_address.borrow_mut() = None;
        self.open_by_default = true;
        self.clear_properties();
        self.program_user_data
            .set_string_property(&self.default_open_close_property_name, "Open");
    }

    fn close_all(&mut self) {
        *self.cached_address.borrow_mut() = None;
        self.open_by_default = false;
        self.clear_properties();
        self.program_user_data
            .set_string_property(&self.default_open_close_property_name, "Closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::UserData;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::Transaction;
    use crate::program::util::{
        IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap,
    };
    use crate::util::exception::PropertyTypeMismatchException;
    use std::any::{Any, TypeId};
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockTransaction;
    impl Transaction for MockTransaction {}

    #[derive(Default)]
    struct MockVoidPropertyMap {
        properties: BTreeMap<Address, bool>,
    }

    impl PropertyMap for MockVoidPropertyMap {
        fn get_name(&self) -> String {
            "test".to_string()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<bool>())
        }

        fn clear(&mut self) {
            self.properties.clear();
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.properties.keys().any(|a| a >= start && a <= end)
        }

        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.properties.keys().any(|a| set.contains(a))
        }

        fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
            let before = self.properties.len();
            self.properties.retain(|a, _| !(a >= start && a <= end));
            self.properties.len() != before
        }

        fn remove(&mut self, addr: &Address) -> bool {
            self.properties.remove(addr).is_some()
        }

        fn has_property(&self, addr: &Address) -> bool {
            self.properties.contains_key(addr)
        }

        fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
            match value {
                Some(v) if *v.downcast::<bool>().unwrap() => {
                    self.add_void(addr);
                }
                _ => {
                    self.remove(addr);
                }
            }
        }

        fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
            self.properties.get(addr).map(|_| Box::new(true) as Box<dyn Any>)
        }

        fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
            self.properties.keys().find(|a| *a > addr).cloned()
        }

        fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
            self.properties.keys().rev().find(|a| *a < addr).cloned()
        }

        fn get_first_property_address(&self) -> Option<Address> {
            self.properties.keys().next().cloned()
        }

        fn get_last_property_address(&self) -> Option<Address> {
            self.properties.keys().next_back().cloned()
        }

        fn get_size(&self) -> usize {
            self.properties.len()
        }

        fn get_property_iterator_range(
            &self,
            start: &Address,
            end: &Address,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.get_property_iterator_range_ordered(start, end, true)
        }

        fn get_property_iterator_range_ordered(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            let mut addrs: Vec<Address> = self
                .properties
                .keys()
                .filter(|a| *a >= start && *a <= end)
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(crate::program::model::address::AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_property_iterator(&self) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(crate::program::model::address::AddressIteratorAdapter::from_vec(
                self.properties.keys().cloned().collect(),
            ))
        }

        fn get_property_iterator_set(
            &self,
            asv: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.get_property_iterator_set_ordered(asv, true)
        }

        fn get_property_iterator_set_ordered(
            &self,
            asv: &dyn crate::program::model::address::AddressSetView,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            let mut addrs: Vec<Address> = self
                .properties
                .keys()
                .filter(|a| asv.contains(a))
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(crate::program::model::address::AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_property_iterator_from(
            &self,
            start: &Address,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            let mut addrs: Vec<Address> = self
                .properties
                .keys()
                .filter(|a| if forward { *a >= start } else { *a <= start })
                .cloned()
                .collect();
            if !forward {
                addrs.reverse();
            }
            Box::new(crate::program::model::address::AddressIteratorAdapter::from_vec(addrs))
        }

        fn move_range(&mut self, _start: &Address, _end: &Address, _new_start: &Address) {}
    }

    impl VoidPropertyMap for MockVoidPropertyMap {
        fn add_void(&mut self, addr: &Address) {
            self.properties.insert(addr.clone(), true);
        }
    }

    #[derive(Default)]
    struct MockProgramUserData {
        string_properties: std::collections::HashMap<String, String>,
        boolean_map: Option<MockVoidPropertyMap>,
    }

    impl UserData for MockProgramUserData {}

    impl ProgramUserData for MockProgramUserData {
        fn open_transaction(&self) -> Box<dyn Transaction> {
            Box::new(MockTransaction)
        }

        fn start_transaction(&self) -> i32 {
            1
        }

        fn end_transaction(&self, _transaction_id: i32) {}

        fn get_string_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn StringPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_long_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn LongPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_int_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn IntPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_boolean_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn VoidPropertyMap>, PropertyTypeMismatchException> {
            // The real ProgramUserData returns a live handle backed by the same store; this
            // mock keeps the map inline and hands out a cloned snapshot boxed as a trait
            // object, which is sufficient since the test manager only ever reads the field
            // it was given back at construction time.
            let map = self.boolean_map.take().unwrap_or_default();
            Ok(Box::new(map))
        }

        fn get_object_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn ObjectPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_properties(&self, _owner: &str) -> Vec<Box<dyn PropertyMap>> {
            Vec::new()
        }

        fn get_property_owners(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options(&self, _options_name: &str) -> Box<dyn crate::framework::options::Options> {
            unimplemented!("not used by PersistentOpenCloseManager tests")
        }

        fn set_string_property(&mut self, property_name: &str, value: &str) {
            self.string_properties
                .insert(property_name.to_string(), value.to_string());
        }

        fn get_string_property(&self, property_name: &str, default_value: &str) -> String {
            self.string_properties
                .get(property_name)
                .cloned()
                .unwrap_or_else(|| default_value.to_string())
        }

        fn remove_string_property(&mut self, property_name: &str) -> Option<String> {
            self.string_properties.remove(property_name)
        }

        fn get_string_property_names(&self) -> HashSet<String> {
            self.string_properties.keys().cloned().collect()
        }
    }

    fn new_manager() -> PersistentOpenCloseManager {
        let data: Box<dyn ProgramUserData> = Box::new(MockProgramUserData::default());
        PersistentOpenCloseManager::new(data, "test", "test")
    }

    #[test]
    fn open_by_default_close_all_open_all() {
        let mut mgr = new_manager();
        assert!(mgr.is_open(&addr(0)));
        assert!(mgr.is_open(&addr(100)));
        assert!(mgr.is_open_by_default());

        mgr.close_all();
        assert!(!mgr.is_open(&addr(0)));
        assert!(!mgr.is_open(&addr(100)));
        assert!(!mgr.is_open_by_default());

        mgr.open_all();
        assert!(mgr.is_open(&addr(0)));
        assert!(mgr.is_open(&addr(100)));
        assert!(mgr.is_open_by_default());
    }

    #[test]
    fn close_and_open_specific_addresses() {
        let mut mgr = new_manager();
        assert!(mgr.is_open(&addr(0)));
        assert!(mgr.is_open(&addr(100)));

        mgr.close(&addr(0));
        assert!(!mgr.is_open(&addr(0)));
        assert!(mgr.is_open(&addr(100)));

        mgr.open(&addr(0));
        assert!(mgr.is_open(&addr(0)));
        assert!(mgr.is_open(&addr(100)));
    }

    #[test]
    fn open_and_close_specific_addresses_with_default_closed() {
        let mut mgr = new_manager();
        mgr.close_all();

        assert!(!mgr.is_open(&addr(0)));
        assert!(!mgr.is_open(&addr(100)));

        mgr.open(&addr(0));
        assert!(mgr.is_open(&addr(0)));
        assert!(!mgr.is_open(&addr(100)));

        mgr.close(&addr(0));
        assert!(!mgr.is_open(&addr(0)));
        assert!(!mgr.is_open(&addr(100)));
    }

    #[test]
    fn caches_repeated_lookups_for_same_address() {
        let mut mgr = new_manager();
        let a = addr(0x1000);

        assert!(mgr.is_open(&a));
        assert!(mgr.is_open(&a));

        mgr.close(&a);
        assert!(!mgr.is_open(&a));
        assert!(!mgr.is_open(&a));
    }
}
