use crate::program::model::address::Address;
use crate::util::exception::NoValueException;

/// Property manager that deals with properties that are of String type.
///
/// Port of `ghidra.program.model.util.StringPropertyMap`.
///
/// Implementors should also implement the [`PropertyMap`] trait to provide the full interface.
/// The `add` method must dispatch to [`add_string`] for `String` values, and panic for other types.
/// The `get_value_class` method should return `Some(TypeId::of::<String>())`.
pub trait StringPropertyMap {
    /// Add a String value at the specified address.
    fn add_string(&mut self, addr: &Address, value: String);

    /// Get the String value at the given address.
    ///
    /// Returns `NoValueException` if there is no property value at addr.
    fn get_string(&self, addr: &Address) -> Result<String, NoValueException>;
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
    struct MockStringPropertyMap {
        name: String,
        values: BTreeMap<Address, String>,
    }

    impl PropertyMap for MockStringPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<String>())
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
                    if let Ok(s) = v.downcast::<String>() {
                        self.values.insert(addr.clone(), *s);
                    } else {
                        panic!("String value required");
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
                .map(|v| Box::new(v.clone()) as Box<dyn Any>)
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
            let moved: Vec<(Address, String)> = self
                .values
                .iter()
                .filter(|(a, _)| *a >= start && *a <= end)
                .map(|(a, v)| (a.clone(), v.clone()))
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

    impl StringPropertyMap for MockStringPropertyMap {
        fn add_string(&mut self, addr: &Address, value: String) {
            self.values.insert(addr.clone(), value);
        }

        fn get_string(&self, addr: &Address) -> Result<String, NoValueException> {
            self.values
                .get(addr)
                .cloned()
                .ok_or_else(NoValueException::new)
        }
    }

    #[test]
    fn add_string_stores_value() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_string(&addr(0x1000), "hello".to_string());
        assert!(map.has_property(&addr(0x1000)));
    }

    #[test]
    fn get_string_returns_value() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_string(&addr(0x1000), "hello".to_string());
        let result = map.get_string(&addr(0x1000));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn get_string_returns_error_for_missing_property() {
        let map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert!(map.get_string(&addr(0x1000)).is_err());
    }

    #[test]
    fn add_with_string_value() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add(&addr(0x1000), Some(Box::new("world".to_string())));
        assert!(map.has_property(&addr(0x1000)));
        assert_eq!(map.get_string(&addr(0x1000)).unwrap(), "world");
    }

    #[test]
    fn add_with_none_removes_property() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_string(&addr(0x1000), "test".to_string());
        assert!(map.has_property(&addr(0x1000)));

        map.add(&addr(0x1000), None);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn add_with_non_string_panics() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            map.add(&addr(0x1000), Some(Box::new(42i32)));
        }));

        assert!(result.is_err());
    }

    #[test]
    fn get_value_class_returns_string_typeid() {
        let map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        assert_eq!(map.get_value_class(), Some(TypeId::of::<String>()));
    }

    #[test]
    fn multiple_addresses() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_string(&addr(0x1000), "first".to_string());
        map.add_string(&addr(0x2000), "second".to_string());
        map.add_string(&addr(0x3000), "third".to_string());

        assert_eq!(map.get_size(), 3);
        assert!(map.has_property(&addr(0x1000)));
        assert!(map.has_property(&addr(0x2000)));
        assert!(map.has_property(&addr(0x3000)));

        map.remove(&addr(0x2000));
        assert_eq!(map.get_size(), 2);
        assert!(!map.has_property(&addr(0x2000)));
    }

    #[test]
    fn empty_string_value() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_string(&addr(0x1000), String::new());
        assert!(map.has_property(&addr(0x1000)));
        assert_eq!(map.get_string(&addr(0x1000)).unwrap(), "");
    }

    #[test]
    fn unicode_string_value() {
        let mut map = MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let unicode = "こんにちは".to_string();
        map.add_string(&addr(0x1000), unicode.clone());
        assert_eq!(map.get_string(&addr(0x1000)).unwrap(), unicode);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut map: Box<dyn StringPropertyMap> = Box::new(MockStringPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        });

        map.add_string(&addr(0x1000), "first".to_string());
        assert!(map.get_string(&addr(0x1000)).is_ok());

        map.add_string(&addr(0x2000), "second".to_string());
        assert!(map.get_string(&addr(0x2000)).is_ok());

        let first = map.get_first_property_address();
        assert_eq!(first, Some(addr(0x1000)));

        let last = map.get_last_property_address();
        assert_eq!(last, Some(addr(0x2000)));
    }
}
