use crate::program::model::address::{Address, AddressSet, AddressSetView};

/// Collection of one or more address sets.
///
/// This mirrors Ghidra's `AddressSetCollection` interface.
pub trait AddressSetCollection {
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool;
    fn intersects_range(&self, start: &Address, end: &Address) -> bool;
    fn contains(&self, address: &Address) -> bool;
    fn has_fewer_ranges_than(&self, range_threshold: usize) -> bool;
    fn combined_address_set(&self) -> AddressSet;
    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address>;
    fn is_empty(&self) -> bool;
    fn min_address(&self) -> Option<Address>;
    fn max_address(&self) -> Option<Address>;
}

/// Address set collection containing exactly one address set.
///
/// This mirrors Ghidra's `SingleAddressSetCollection`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SingleAddressSetCollection {
    set: AddressSet,
}

impl SingleAddressSetCollection {
    pub fn new(set: Option<&dyn AddressSetView>) -> Self {
        Self {
            set: set.map(AddressSet::from_set).unwrap_or_default(),
        }
    }
}

impl AddressSetCollection for SingleAddressSetCollection {
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.intersects_set(set)
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.set.intersects_range(start, end)
    }

    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }

    fn has_fewer_ranges_than(&self, range_threshold: usize) -> bool {
        self.set.num_address_ranges() < range_threshold
    }

    fn combined_address_set(&self) -> AddressSet {
        self.set.clone()
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        self.set.find_first_address_in_common(set)
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn min_address(&self) -> Option<Address> {
        self.set.min_address()
    }

    fn max_address(&self) -> Option<Address> {
        self.set.max_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn none_constructor_uses_empty_set() {
        let collection = SingleAddressSetCollection::new(None);

        assert!(collection.is_empty());
        assert_eq!(collection.combined_address_set(), AddressSet::new());
    }

    #[test]
    fn single_collection_delegates_to_wrapped_set() {
        let set = AddressSet::from_start_end(addr(0x1000), addr(0x1005));
        let collection = SingleAddressSetCollection::new(Some(&set));
        let other = AddressSet::from_start_end(addr(0x1003), addr(0x2000));

        assert!(collection.contains(&addr(0x1001)));
        assert!(collection.intersects_set(&other));
        assert!(collection.intersects_range(&addr(0x1005), &addr(0x1006)));
        assert!(collection.has_fewer_ranges_than(2));
        assert_eq!(collection.min_address(), Some(addr(0x1000)));
        assert_eq!(collection.max_address(), Some(addr(0x1005)));
        assert_eq!(
            collection.find_first_address_in_common(&other),
            Some(addr(0x1003))
        );
        assert!(collection.combined_address_set().has_same_addresses(&set));
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
