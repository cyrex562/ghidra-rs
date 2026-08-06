use crate::program::model::address::{Address, BoxedAddressIterator, AddressRangeIterator, AddressSet, AddressSetView};

/// Marks ranges of addresses in a property map.
///
/// Port of `ghidra.program.model.util.AddressSetPropertyMap`.
///
/// The overloaded Java `add`/`remove` methods are split into distinctly-named methods here since
/// Rust does not support overloading on parameter types.
pub trait AddressSetPropertyMap {
    /// Add the address range to the property map.
    fn add_range(&mut self, start: &Address, end: &Address);

    /// Add the address set to the property map.
    fn add_address_set(&mut self, address_set: &dyn AddressSetView);

    /// Clear the property map and set it with the given address set.
    fn set(&mut self, address_set: &dyn AddressSetView);

    /// Remove the address range from the property map.
    fn remove_range(&mut self, start: &Address, end: &Address);

    /// Remove the address set from the property map.
    fn remove_address_set(&mut self, address_set: &dyn AddressSetView);

    /// Return the address set for the property map.
    fn get_address_set(&self) -> AddressSet;

    /// Return an address iterator over the property map.
    fn get_addresses(&self) -> BoxedAddressIterator;

    /// Return an address range iterator over the property map.
    fn get_address_ranges(&self) -> Box<dyn AddressRangeIterator>;

    /// Clear the property map.
    fn clear(&mut self);

    /// Return whether the property map contains the given address.
    fn contains(&self, addr: &Address) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[derive(Default)]
    struct MockAddressSetPropertyMap {
        set: AddressSet,
    }

    impl AddressSetPropertyMap for MockAddressSetPropertyMap {
        fn add_range(&mut self, start: &Address, end: &Address) {
            self.set.add_range(start, end);
        }

        fn add_address_set(&mut self, address_set: &dyn AddressSetView) {
            self.set.add_set(address_set);
        }

        fn set(&mut self, address_set: &dyn AddressSetView) {
            self.set = AddressSet::from_set(address_set);
        }

        fn remove_range(&mut self, start: &Address, end: &Address) {
            self.set.delete_range(start, end);
        }

        fn remove_address_set(&mut self, address_set: &dyn AddressSetView) {
            self.set.delete_set(address_set);
        }

        fn get_address_set(&self) -> AddressSet {
            self.set.clone()
        }

        fn get_addresses(&self) -> BoxedAddressIterator {
            self.set.addresses(true)
        }

        fn get_address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            self.set.address_ranges()
        }

        fn clear(&mut self) {
            self.set.clear();
        }

        fn contains(&self, addr: &Address) -> bool {
            self.set.contains(addr)
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let mut map: Box<dyn AddressSetPropertyMap> =
            Box::new(MockAddressSetPropertyMap::default());

        map.add_range(&addr(0x1000), &addr(0x1010));
        assert!(map.contains(&addr(0x1005)));
        assert!(!map.contains(&addr(0x2000)));

        let mut other = AddressSet::new();
        other.add_range(&addr(0x2000), &addr(0x2010));
        map.add_address_set(&other);
        assert!(map.contains(&addr(0x2005)));

        map.remove_range(&addr(0x1000), &addr(0x1010));
        assert!(!map.contains(&addr(0x1005)));
        assert!(map.contains(&addr(0x2005)));

        let mut addr_iter = map.get_addresses();
        let mut count = 0;
        while addr_iter.next().is_some() {
            count += 1;
        }
        assert_eq!(count, 0x11);

        let mut range_iter = map.get_address_ranges();
        let range = range_iter.next_range().unwrap();
        assert_eq!(*range.min_address(), addr(0x2000));
        assert_eq!(*range.max_address(), addr(0x2010));
        assert!(range_iter.next_range().is_none());
        map.remove_address_set(&other);
        assert!(!map.contains(&addr(0x2005)));

        let mut fresh = AddressSet::new();
        fresh.add_range(&addr(0x3000), &addr(0x3005));
        map.set(&fresh);
        assert!(map.contains(&addr(0x3002)));
        assert!(!map.contains(&addr(0x2005)));

        let snapshot = map.get_address_set();
        assert!(snapshot.contains(&addr(0x3002)));

        map.clear();
        assert!(!map.contains(&addr(0x3002)));
    }
}
