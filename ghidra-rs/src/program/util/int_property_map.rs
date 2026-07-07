use crate::program::model::address::Address;
use crate::util::exception::NoValueException;

/// Property manager that deals with properties that are of int type.
///
/// Port of `ghidra.program.model.util.IntPropertyMap`.
///
/// Implementors should also implement the [`PropertyMap`] trait to provide the full interface.
/// The `add` method must dispatch to [`add_int`] for `i32` values, and panic for other types.
/// The `get_value_class` method should return `Some(TypeId::of::<i32>())`.
pub trait IntPropertyMap {
    /// Add an int value at the specified address.
    fn add_int(&mut self, addr: &Address, value: i32);

    /// Get the integer value at the given address.
    ///
    /// Returns `NoValueException` if there is no property value at addr.
    fn get_int(&self, addr: &Address) -> Result<i32, NoValueException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::util::PropertyMap;
    use std::any::{Any, TypeId};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[derive(Default)]
    struct MockIntPropertyMap {
        name: String,
        values: BTreeMap<Address, i32>,
    }

    impl PropertyMap for MockIntPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<i32>())
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
                    let i = *v.downcast::<i32>().expect("expected i32 value");
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
            let moved: Vec<(Address, i32)> = self
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

    impl IntPropertyMap for MockIntPropertyMap {
        fn add_int(&mut self, addr: &Address, value: i32) {
            self.values.insert(addr.clone(), value);
        }

        fn get_int(&self, addr: &Address) -> Result<i32, NoValueException> {
            self.values
                .get(addr)
                .copied()
                .ok_or_else(NoValueException::new)
        }
    }

    #[test]
    fn add_int_stores_value() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_int(&addr(0x1000), 42);
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn get_int_returns_value() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_int(&addr(0x1000), 42);
        assert_eq!(map.get_int(&addr(0x1000)).unwrap(), 42);
    }

    #[test]
    fn get_int_returns_error_for_missing_property() {
        let map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert!(map.get_int(&addr(0x1000)).is_err());
    }

    #[test]
    fn add_with_integer_value() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new(42i32)));
        assert_eq!(map.get_int(&addr(0x1000)).unwrap(), 42);
    }

    #[test]
    fn add_with_none_removes_property() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new(42i32)));
        assert!(map.has_property(&addr(0x1000)));

        map.add(&addr(0x1000), None);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_non_integer_panics() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            map.add(&addr(0x1000), Some(Box::new("not an int")));
        }));

        assert!(result.is_err());
    }

    #[test]
    fn get_value_class_returns_i32() {
        let map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert_eq!(map.get_value_class(), Some(TypeId::of::<i32>()));
    }

    #[test]
    fn multiple_addresses() {
        let mut map = MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_int(&addr(0x1000), 1);
        map.add_int(&addr(0x2000), 2);
        map.add_int(&addr(0x3000), 3);

        assert_eq!(map.get_size(), 3);
        assert_eq!(map.get_int(&addr(0x1000)).unwrap(), 1);
        assert_eq!(map.get_int(&addr(0x2000)).unwrap(), 2);
        assert_eq!(map.get_int(&addr(0x3000)).unwrap(), 3);

        map.remove(&addr(0x2000));
        assert_eq!(map.get_size(), 2);
        assert!(map.get_int(&addr(0x2000)).is_err());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut map: Box<dyn IntPropertyMap> = Box::new(MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        });

        map.add_int(&addr(0x1000), 42);
        assert_eq!(map.get_int(&addr(0x1000)).unwrap(), 42);

        map.add_int(&addr(0x2000), 7);
        assert_eq!(map.get_int(&addr(0x2000)).unwrap(), 7);

        assert_eq!(map.get_size(), 2);

        let first = map.get_first_property_address();
        assert_eq!(first, Some(addr(0x1000)));

        let last = map.get_last_property_address();
        assert_eq!(last, Some(addr(0x2000)));
    }
}
