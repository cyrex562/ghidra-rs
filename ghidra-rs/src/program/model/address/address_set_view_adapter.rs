use crate::program::model::address::{
    Address, AddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
};

/// Read-only wrapper around an address set view.
///
/// This mirrors Ghidra's `AddressSetViewAdapter`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressSetViewAdapter {
    set: AddressSet,
}

impl AddressSetViewAdapter {
    pub fn new(set: &dyn AddressSetView) -> Self {
        Self {
            set: AddressSet::from_set(set),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }
}

impl AddressSetView for AddressSetViewAdapter {
    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }

    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.set.contains_range(start, end)
    }

    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.contains_set(set)
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

    fn num_address_ranges(&self) -> usize {
        self.set.num_address_ranges()
    }

    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges()
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges_from(start, forward)
    }

    fn num_addresses(&self) -> u64 {
        self.set.num_addresses()
    }

    fn addresses(&self, forward: bool) -> Box<dyn AddressIterator> {
        self.set.addresses(forward)
    }

    fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator> {
        self.set.addresses_from(start, forward)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.intersects_set(set)
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.set.intersects_range(start, end)
    }

    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.intersect(set)
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.set.intersect_range(start, end)
    }

    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.union(set)
    }

    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.subtract(set)
    }

    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.xor(set)
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        self.set.has_same_addresses(set)
    }

    fn first_range(&self) -> Option<AddressRange> {
        self.set.first_range()
    }

    fn last_range(&self) -> Option<AddressRange> {
        self.set.last_range()
    }

    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        self.set.range_containing(address)
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        self.set.find_first_address_in_common(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn empty_adapter_wraps_empty_set() {
        let adapter = AddressSetViewAdapter::empty();

        assert!(adapter.is_empty());
        assert_eq!(adapter.num_address_ranges(), 0);
        assert_eq!(adapter.min_address(), None);
    }

    #[test]
    fn adapter_delegates_read_only_view_operations() {
        let set = AddressSet::from_start_end(addr(0x1000), addr(0x1002));
        let adapter = AddressSetViewAdapter::new(&set);

        assert!(adapter.contains(&addr(0x1001)));
        assert_eq!(adapter.num_addresses(), 3);
        assert_eq!(adapter.first_range().unwrap().min_address(), &addr(0x1000));
        assert!(adapter.has_same_addresses(&set));
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
