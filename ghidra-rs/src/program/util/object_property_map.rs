use crate::program::model::address::Address;
use crate::util::exception::NoValueException;
use crate::util::Saveable;

/// Property manager that deals with properties that are of Saveable object type.
///
/// Port of `ghidra.program.model.util.ObjectPropertyMap<T extends Saveable>`.
///
/// Implementors should also implement the [`PropertyMap`](crate::program::model::util::PropertyMap) trait to provide the full interface.
/// The `add` method must dispatch to [`add_object`](ObjectPropertyMap::add_object) for `Box<dyn Saveable>` values, and panic for other types.
/// The `get_value_class` method should return a `TypeId` corresponding to the expected Saveable type.
pub trait ObjectPropertyMap {
    /// Add a Saveable object value at the specified address.
    fn add_object(&mut self, addr: &Address, value: Box<dyn Saveable>);

    /// Get the Saveable object value at the given address.
    ///
    /// Returns `NoValueException` if there is no property value at addr.
    fn get_object(&self, addr: &Address) -> Result<Box<dyn Saveable>, NoValueException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::util::PropertyMap;
    use crate::util::{ObjectStorage, ObjectStorageFieldType};
    use std::any::{Any, TypeId};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[derive(Clone)]
    struct MockSaveable {
        id: i32,
    }

    impl Saveable for MockSaveable {
        fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
            vec![ObjectStorageFieldType::Int]
        }

        fn save(&self, obj_storage: &mut dyn ObjectStorage) {
            obj_storage.put_int(self.id);
        }

        fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
            self.id = obj_storage.get_int();
        }

        fn get_schema_version(&self) -> i32 {
            1
        }

        fn is_upgradeable(&self, old_schema_version: i32) -> bool {
            old_schema_version <= self.get_schema_version()
        }

        fn upgrade(
            &mut self,
            old_obj_storage: &mut dyn ObjectStorage,
            old_schema_version: i32,
            current_obj_storage: &mut dyn ObjectStorage,
        ) -> bool {
            if !self.is_upgradeable(old_schema_version) {
                return false;
            }
            self.restore(old_obj_storage);
            self.save(current_obj_storage);
            true
        }

        fn is_private(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct MockObjectPropertyMap {
        name: String,
        values: BTreeMap<Address, Box<dyn Saveable>>,
    }

    impl PropertyMap for MockObjectPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<Box<dyn Saveable>>())
        }

        fn clear(&mut self) {
            self.values.clear();
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.values.keys().any(|a| a >= start && a <= end)
        }

        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
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
                    if let Ok(saveable) = v.downcast::<Box<dyn Saveable>>() {
                        self.values.insert(addr.clone(), *saveable);
                    } else {
                        panic!("Saveable object value required");
                    }
                }
                None => {
                    self.values.remove(addr);
                }
            }
        }

        fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
            self.values
                .get(addr)
                .map(|v| Box::clone(v) as Box<dyn Any>)
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

        fn get_property_iterator(&self) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(
                self.values.keys().cloned().collect(),
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
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
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
            let moved: Vec<(Address, Box<dyn Saveable>)> = self
                .values
                .iter()
                .filter(|(a, _)| *a >= start && *a <= end)
                .map(|(a, v)| (a.clone(), Box::clone(v)))
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

    impl ObjectPropertyMap for MockObjectPropertyMap {
        fn add_object(&mut self, addr: &Address, value: Box<dyn Saveable>) {
            self.values.insert(addr.clone(), value);
        }

        fn get_object(&self, addr: &Address) -> Result<Box<dyn Saveable>, NoValueException> {
            self.values
                .get(addr)
                .map(|v| Box::clone(v))
                .ok_or_else(NoValueException::new)
        }
    }

    #[test]
    fn add_object_stores_value() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_object(&addr(0x1000), Box::new(MockSaveable { id: 42 }));
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn get_object_returns_value() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_object(&addr(0x1000), Box::new(MockSaveable { id: 42 }));
        let result = map.get_object(&addr(0x1000));
        assert!(result.is_ok());
    }

    #[test]
    fn get_object_returns_error_for_missing_property() {
        let map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert!(map.get_object(&addr(0x1000)).is_err());
    }

    #[test]
    fn add_with_saveable_value() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(
            &addr(0x1000),
            Some(Box::new(Box::new(MockSaveable { id: 99 }) as Box<dyn Saveable>)),
        );
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_none_removes_property() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_object(&addr(0x1000), Box::new(MockSaveable { id: 42 }));
        assert!(map.has_property(&addr(0x1000)));

        map.add(&addr(0x1000), None);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_non_saveable_panics() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            map.add(&addr(0x1000), Some(Box::new(42i32)));
        }));

        assert!(result.is_err());
    }

    #[test]
    fn get_value_class_returns_typeid() {
        let map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert_eq!(
            map.get_value_class(),
            Some(TypeId::of::<Box<dyn Saveable>>())
        );
    }

    #[test]
    fn multiple_addresses() {
        let mut map = MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_object(&addr(0x1000), Box::new(MockSaveable { id: 1 }));
        map.add_object(&addr(0x2000), Box::new(MockSaveable { id: 2 }));
        map.add_object(&addr(0x3000), Box::new(MockSaveable { id: 3 }));

        assert_eq!(map.get_size(), 3);
        assert!(map.has_property(&addr(0x1000)));
        assert!(map.has_property(&addr(0x2000)));
        assert!(map.has_property(&addr(0x3000)));

        map.remove(&addr(0x2000));
        assert_eq!(map.get_size(), 2);
        assert!(!map.has_property(&addr(0x2000)));
    }

    #[test]
    fn usable_as_trait_object() {
        let mut map: Box<dyn ObjectPropertyMap> = Box::new(MockObjectPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        });

        map.add_object(&addr(0x1000), Box::new(MockSaveable { id: 42 }));
        assert!(map.get_object(&addr(0x1000)).is_ok());

        map.add_object(&addr(0x2000), Box::new(MockSaveable { id: 7 }));
        assert!(map.get_object(&addr(0x2000)).is_ok());

        assert_eq!(map.get_size(), 2);

        let first = map.get_first_property_address();
        assert_eq!(first, Some(addr(0x1000)));

        let last = map.get_last_property_address();
        assert_eq!(last, Some(addr(0x2000)));
    }
}
