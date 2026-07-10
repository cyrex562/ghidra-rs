use std::any::{Any, TypeId};

use crate::program::model::address::Address;
use crate::program::model::util::PropertyMap;

/// Property manager for "void" type properties, which are markers for whether a property exists.
///
/// Port of `ghidra.program.model.util.VoidPropertyMap`.
///
/// Object values returned are either `true` or removed. The `add` method with a boolean value
/// treats `null`, `false`, or the absence of the property as equivalent, while `true` marks
/// the address as having the property.
pub trait VoidPropertyMap: PropertyMap {
    /// Mark the specified address as having a property.
    fn add_void(&mut self, addr: &Address);
}

impl<T: VoidPropertyMap + ?Sized> PropertyMap for T {
    fn get_name(&self) -> String {
        <Self as PropertyMap>::get_name(self)
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<bool>())
    }

    fn clear(&mut self) {
        <Self as PropertyMap>::clear(self);
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        <Self as PropertyMap>::intersects_range(self, start, end)
    }

    fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
        <Self as PropertyMap>::intersects_set(self, set)
    }

    fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
        <Self as PropertyMap>::remove_range(self, start, end)
    }

    fn remove(&mut self, addr: &Address) -> bool {
        <Self as PropertyMap>::remove(self, addr)
    }

    fn has_property(&self, addr: &Address) -> bool {
        <Self as PropertyMap>::has_property(self, addr)
    }

    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
        match value {
            None => {
                self.remove(addr);
            }
            Some(v) => {
                if let Ok(b) = v.downcast::<bool>() {
                    if *b {
                        self.add_void(addr);
                    } else {
                        self.remove(addr);
                    }
                } else {
                    panic!("Boolean value required");
                }
            }
        }
    }

    fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
        <Self as PropertyMap>::get(self, addr)
    }

    fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
        <Self as PropertyMap>::get_next_property_address(self, addr)
    }

    fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
        <Self as PropertyMap>::get_previous_property_address(self, addr)
    }

    fn get_first_property_address(&self) -> Option<Address> {
        <Self as PropertyMap>::get_first_property_address(self)
    }

    fn get_last_property_address(&self) -> Option<Address> {
        <Self as PropertyMap>::get_last_property_address(self)
    }

    fn get_size(&self) -> usize {
        <Self as PropertyMap>::get_size(self)
    }

    fn get_property_iterator_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator_range(self, start, end)
    }

    fn get_property_iterator_range_ordered(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator_range_ordered(self, start, end, forward)
    }

    fn get_property_iterator(&self) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator(self)
    }

    fn get_property_iterator_set(
        &self,
        asv: &dyn crate::program::model::address::AddressSetView,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator_set(self, asv)
    }

    fn get_property_iterator_set_ordered(
        &self,
        asv: &dyn crate::program::model::address::AddressSetView,
        forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator_set_ordered(self, asv, forward)
    }

    fn get_property_iterator_from(
        &self,
        start: &Address,
        forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        <Self as PropertyMap>::get_property_iterator_from(self, start, forward)
    }

    fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
        <Self as PropertyMap>::move_range(self, start, end, new_start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[derive(Default)]
    struct MockVoidPropertyMap {
        name: String,
        properties: BTreeMap<Address, bool>,
    }

    impl PropertyMap for MockVoidPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
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
                Some(v) => {
                    if let Ok(b) = v.downcast::<bool>() {
                        if *b {
                            self.properties.insert(addr.clone(), true);
                        } else {
                            self.properties.remove(addr);
                        }
                    } else {
                        panic!("Boolean value required");
                    }
                }
                None => {
                    self.properties.remove(addr);
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
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_property_iterator(&self) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(
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
            Box::new(AddressIteratorAdapter::from_vec(addrs))
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
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
            let moved: Vec<Address> = self
                .properties
                .keys()
                .filter(|a| *a >= start && *a <= end)
                .cloned()
                .collect();
            for a in &moved {
                self.properties.remove(a);
            }
            for a in moved {
                let offset = a.offset() - start.offset();
                let new_addr = Address::new(new_start.space().clone(), new_start.offset() + offset);
                self.properties.insert(new_addr, true);
            }
        }
    }

    // `add_void` is provided as an inherent method rather than via the `VoidPropertyMap`
    // trait: the mock supplies its own concrete `PropertyMap` implementation, and the
    // blanket `impl<T: VoidPropertyMap> PropertyMap for T` would otherwise conflict with it.
    impl MockVoidPropertyMap {
        fn add_void(&mut self, addr: &Address) {
            self.properties.insert(addr.clone(), true);
        }
    }

    #[test]
    fn add_void_marks_property() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_void(&addr(0x1000));
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_true_marks_property() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new(true)));
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_false_removes_property() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new(true)));
        assert!(map.has_property(&addr(0x1000)));

        map.add(&addr(0x1000), Some(Box::new(false)));
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_none_removes_property() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new(true)));
        assert!(map.has_property(&addr(0x1000)));

        map.add(&addr(0x1000), None);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_non_bool_panics() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            map.add(&addr(0x1000), Some(Box::new(42i32)));
        }));

        assert!(result.is_err());
    }

    #[test]
    fn get_returns_true_for_existing_property() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_void(&addr(0x1000));
        let value = map.get(&addr(0x1000)).unwrap();
        assert_eq!(*value.downcast::<bool>().unwrap(), true);
    }

    #[test]
    fn get_returns_none_for_missing_property() {
        let map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert!(map.get(&addr(0x1000)).is_none());
    }

    #[test]
    fn get_value_class_returns_bool() {
        let map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert_eq!(map.get_value_class(), Some(TypeId::of::<bool>()));
    }

    #[test]
    fn multiple_addresses() {
        let mut map = MockVoidPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_void(&addr(0x1000));
        map.add_void(&addr(0x2000));
        map.add_void(&addr(0x3000));

        assert_eq!(map.get_size(), 3);
        assert!(map.has_property(&addr(0x1000)));
        assert!(map.has_property(&addr(0x2000)));
        assert!(map.has_property(&addr(0x3000)));

        map.remove(&addr(0x2000));
        assert_eq!(map.get_size(), 2);
        assert!(!map.has_property(&addr(0x2000)));
    }
}
