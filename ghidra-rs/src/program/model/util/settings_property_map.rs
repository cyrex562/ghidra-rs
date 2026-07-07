use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::util::exception::NoValueException;

/// Property manager that deals with properties that are of Settings type.
///
/// Port of `ghidra.program.model.util.SettingsPropertyMap`.
///
/// Implementors should also implement the [`PropertyMap`](crate::program::model::util::PropertyMap) trait to provide the full interface.
/// The `add` method must dispatch to [`add_settings`](SettingsPropertyMap::add_settings) for `Box<dyn Settings>` values, and panic for other types.
/// The `get_value_class` method should return a `TypeId` corresponding to the Settings type.
pub trait SettingsPropertyMap {
    /// Add a Settings object value at the specified address.
    fn add_settings(&mut self, addr: &Address, value: Box<dyn Settings>);

    /// Get the Settings object value at the given address.
    ///
    /// Returns `NoValueException` if there is no property value at addr.
    fn get_settings(&self, addr: &Address) -> Result<Box<dyn Settings>, NoValueException>;
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

    #[derive(Clone)]
    struct MockSettings {
        id: i32,
    }

    impl Settings for MockSettings {}

    #[derive(Default)]
    struct MockSettingsPropertyMap {
        name: String,
        values: BTreeMap<Address, Box<dyn Settings>>,
    }

    impl PropertyMap for MockSettingsPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<Box<dyn Settings>>())
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
                    let settings = v
                        .downcast::<Box<dyn Settings>>()
                        .expect("expected Box<dyn Settings> value");
                    self.values.insert(addr.clone(), *settings);
                }
                None => {
                    self.values.remove(addr);
                }
            }
        }

        fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
            self.values.get(addr).map(|_| {
                Box::new(()) as Box<dyn Any>
            })
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
            let moved: Vec<(Address, Box<dyn Settings>)> = self
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

    impl SettingsPropertyMap for MockSettingsPropertyMap {
        fn add_settings(&mut self, addr: &Address, value: Box<dyn Settings>) {
            self.values.insert(addr.clone(), value);
        }

        fn get_settings(&self, addr: &Address) -> Result<Box<dyn Settings>, NoValueException> {
            self.values
                .get(addr)
                .map(|v| v.clone())
                .ok_or_else(|| NoValueException::new("No value at address".to_string()))
        }
    }

    #[test]
    fn test_settings_property_map_add_and_get() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let settings = Box::new(MockSettings { id: 42 }) as Box<dyn Settings>;
        map.add_settings(&addr(0x1000), settings);

        assert!(map.has_property(&addr(0x1000)));
        assert_eq!(map.get_size(), 1);

        let result = map.get_settings(&addr(0x1000));
        assert!(result.is_ok());
    }

    #[test]
    fn test_settings_property_map_remove() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let settings = Box::new(MockSettings { id: 42 }) as Box<dyn Settings>;
        map.add_settings(&addr(0x1000), settings);
        assert_eq!(map.get_size(), 1);

        assert!(map.remove(&addr(0x1000)));
        assert_eq!(map.get_size(), 0);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn test_settings_property_map_multiple_addresses() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_settings(&addr(0x1000), Box::new(MockSettings { id: 1 }));
        map.add_settings(&addr(0x2000), Box::new(MockSettings { id: 2 }));
        map.add_settings(&addr(0x3000), Box::new(MockSettings { id: 3 }));

        assert_eq!(map.get_size(), 3);
        assert!(map.has_property(&addr(0x1000)));
        assert!(map.has_property(&addr(0x2000)));
        assert!(map.has_property(&addr(0x3000)));
    }

    #[test]
    fn test_settings_property_map_intersects_range() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_settings(&addr(0x1000), Box::new(MockSettings { id: 1 }));
        map.add_settings(&addr(0x2000), Box::new(MockSettings { id: 2 }));

        assert!(map.intersects_range(&addr(0x0), &addr(0x1500)));
        assert!(map.intersects_range(&addr(0x1000), &addr(0x2000)));
        assert!(!map.intersects_range(&addr(0x3000), &addr(0x4000)));
    }

    #[test]
    fn test_settings_property_map_next_previous() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_settings(&addr(0x1000), Box::new(MockSettings { id: 1 }));
        map.add_settings(&addr(0x2000), Box::new(MockSettings { id: 2 }));
        map.add_settings(&addr(0x3000), Box::new(MockSettings { id: 3 }));

        assert_eq!(map.get_first_property_address(), Some(addr(0x1000)));
        assert_eq!(map.get_last_property_address(), Some(addr(0x3000)));
        assert_eq!(map.get_next_property_address(&addr(0x1000)), Some(addr(0x2000)));
        assert_eq!(map.get_previous_property_address(&addr(0x2000)), Some(addr(0x1000)));
    }

    #[test]
    fn test_settings_property_map_get_nonexistent() {
        let map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        let result = map.get_settings(&addr(0x1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_settings_property_map_clear() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_settings(&addr(0x1000), Box::new(MockSettings { id: 1 }));
        map.add_settings(&addr(0x2000), Box::new(MockSettings { id: 2 }));
        assert_eq!(map.get_size(), 2);

        map.clear();
        assert_eq!(map.get_size(), 0);
        assert!(!map.has_property(&addr(0x1000)));
    }

    #[test]
    fn test_settings_property_map_move_range() {
        let mut map = MockSettingsPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        };

        map.add_settings(&addr(0x1000), Box::new(MockSettings { id: 1 }));
        map.add_settings(&addr(0x1100), Box::new(MockSettings { id: 2 }));
        map.add_settings(&addr(0x2000), Box::new(MockSettings { id: 3 }));

        map.move_range(&addr(0x1000), &addr(0x1100), &addr(0x2100));

        assert!(!map.has_property(&addr(0x1000)));
        assert!(!map.has_property(&addr(0x1100)));
        assert!(map.has_property(&addr(0x2100)));
        assert!(map.has_property(&addr(0x2200)));
        assert!(map.has_property(&addr(0x2000)));
    }
}
