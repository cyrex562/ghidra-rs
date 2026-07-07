use std::any::{Any, TypeId};

use crate::program::model::address::{Address, AddressIterator, AddressSetView};

/// A map containing properties over a set of addresses.
///
/// Port of `ghidra.program.model.util.PropertyMap<T>`.
///
/// The Java interface is generic over the property value type `T`, but every known usage in the
/// Java codebase (e.g. `Listing.getPropertyMap`) accesses it through the type-erased wildcard
/// `PropertyMap<?>`, so this trait is likewise type-erased: `T`-typed accessors (`get`/`add`) work
/// in terms of [`Box<dyn Any>`] and `getValueClass()` returns the value's [`TypeId`] rather than a
/// Java `Class<T>`. Concrete subinterfaces (`IntPropertyMap`, `StringPropertyMap`, etc.) can narrow
/// this to a specific `T` when they are ported.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
///
/// The overloaded `getPropertyIterator` methods from Java are split into distinctly-named methods
/// here since Rust does not support overloading on parameter types.
pub trait PropertyMap {
    /// Get the name for this property map.
    fn get_name(&self) -> String;

    /// Returns the [`TypeId`] of the property value type, or `None` for an unsupported map type.
    fn get_value_class(&self) -> Option<TypeId>;

    /// Removes all properties from this map.
    fn clear(&mut self);

    /// Given two addresses, indicate whether there is an address in that range (inclusive) having
    /// the property.
    fn intersects_range(&self, start: &Address, end: &Address) -> bool;

    /// Indicate whether there is an address within the set which exists within this map.
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool;

    /// Removes all property values within a given range (inclusive). Returns true if any property
    /// value was removed, false otherwise.
    fn remove_range(&mut self, start: &Address, end: &Address) -> bool;

    /// Remove the property value at the given address. Returns true if the property value was
    /// removed, false otherwise.
    fn remove(&mut self, addr: &Address) -> bool;

    /// Returns whether there is a property value at `addr`.
    fn has_property(&self, addr: &Address) -> bool;

    /// Add a map-specific value type to the specified address. `None` removes the value at the
    /// address.
    ///
    /// # Panics
    /// May panic (mirroring Java's unchecked `IllegalArgumentException`) if the value's type is
    /// inappropriate for this map.
    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>);

    /// Returns the property value stored at the specified address, or `None` if no property is
    /// found.
    fn get(&self, addr: &Address) -> Option<Box<dyn Any>>;

    /// Get the next address (exclusive of `addr`) where the property value exists.
    fn get_next_property_address(&self, addr: &Address) -> Option<Address>;

    /// Get the previous address (exclusive of `addr`) where the property value exists.
    fn get_previous_property_address(&self, addr: &Address) -> Option<Address>;

    /// Get the first address where a property value exists.
    fn get_first_property_address(&self) -> Option<Address>;

    /// Get the last address where a property value exists.
    fn get_last_property_address(&self) -> Option<Address>;

    /// Get the number of properties in the map.
    fn get_size(&self) -> usize;

    /// Returns a forward iterator over the addresses in `[start, end]` that have a property value.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator(Address, Address)`.
    fn get_property_iterator_range(&self, start: &Address, end: &Address) -> Box<dyn AddressIterator>;

    /// Returns an iterator over the addresses in `[start, end]` that have a property value, in
    /// increasing (`forward = true`) or decreasing (`forward = false`) address order.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator(Address, Address, boolean)`.
    fn get_property_iterator_range_ordered(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns a forward iterator over all addresses that have a property value.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator()`.
    fn get_property_iterator(&self) -> Box<dyn AddressIterator>;

    /// Returns a forward iterator over the addresses in `asv` that have a property value.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator(AddressSetView)`.
    fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> Box<dyn AddressIterator>;

    /// Returns an iterator over the addresses in `asv` that have a property value, in increasing
    /// (`forward = true`) or decreasing (`forward = false`) address order.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator(AddressSetView, boolean)`.
    fn get_property_iterator_set_ordered(
        &self,
        asv: &dyn AddressSetView,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns an iterator over the addresses that have a property value, starting at `start` and
    /// moving in increasing (`forward = true`) or decreasing (`forward = false`) address order.
    ///
    /// Stands in for `PropertyMap.getPropertyIterator(Address, boolean)`.
    fn get_property_iterator_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator>;

    /// Moves the properties defined in the range from `start` thru `end` to now be located
    /// beginning at `new_start`. The moved properties are located at the same relative position to
    /// `new_start` as they were previously to `start`.
    fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address);
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
        ) -> Box<dyn AddressIterator> {
            self.get_property_iterator_range_ordered(start, end, true)
        }

        fn get_property_iterator_range_ordered(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> Box<dyn AddressIterator> {
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

        fn get_property_iterator(&self) -> Box<dyn AddressIterator> {
            Box::new(AddressIteratorAdapter::from_vec(
                self.values.keys().cloned().collect(),
            ))
        }

        fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> Box<dyn AddressIterator> {
            self.get_property_iterator_set_ordered(asv, true)
        }

        fn get_property_iterator_set_ordered(
            &self,
            asv: &dyn AddressSetView,
            forward: bool,
        ) -> Box<dyn AddressIterator> {
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
        ) -> Box<dyn AddressIterator> {
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

    #[test]
    fn usable_as_trait_object() {
        let mut map: Box<dyn PropertyMap> = Box::new(MockIntPropertyMap {
            name: "test".to_string(),
            ..Default::default()
        });

        assert_eq!(map.get_name(), "test");
        assert_eq!(map.get_value_class(), Some(TypeId::of::<i32>()));
        assert_eq!(map.get_size(), 0);

        map.add(&addr(0x1000), Some(Box::new(42i32)));
        map.add(&addr(0x2000), Some(Box::new(7i32)));

        assert!(map.has_property(&addr(0x1000)));
        assert!(!map.has_property(&addr(0x1500)));
        assert_eq!(map.get_size(), 2);

        let value = map.get(&addr(0x1000)).unwrap();
        assert_eq!(*value.downcast::<i32>().unwrap(), 42);

        assert!(map.intersects_range(&addr(0x0), &addr(0x1500)));
        assert!(!map.intersects_range(&addr(0x3000), &addr(0x4000)));

        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1000));
        assert!(map.intersects_set(&set));

        assert_eq!(
            map.get_first_property_address(),
            Some(addr(0x1000))
        );
        assert_eq!(map.get_last_property_address(), Some(addr(0x2000)));
        assert_eq!(
            map.get_next_property_address(&addr(0x1000)),
            Some(addr(0x2000))
        );
        assert_eq!(
            map.get_previous_property_address(&addr(0x2000)),
            Some(addr(0x1000))
        );

        assert!(map.remove(&addr(0x1000)));
        assert!(!map.has_property(&addr(0x1000)));
        assert_eq!(map.get_size(), 1);

        map.add(&addr(0x2000), None);
        assert_eq!(map.get_size(), 0);
    }
}
