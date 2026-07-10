use crate::program::model::address::{
    Address, AddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetCollection,
    AddressSetView,
};

/// A modifiable address set collection that extends AddressSet with the AddressSetCollection interface.
///
/// This mirrors Ghidra's `ModifiableAddressSetCollection` which extends `AddressSet`
/// and implements `AddressSetCollection`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModifiableAddressSetCollection {
    set: AddressSet,
}

impl ModifiableAddressSetCollection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_set(set: &dyn AddressSetView) -> Self {
        Self {
            set: AddressSet::from_set(set),
        }
    }

    pub fn add_address(&mut self, address: &Address) {
        self.set.add_address(address);
    }

    pub fn add_range(&mut self, start: &Address, end: &Address) {
        self.set.add_range(start, end);
    }

    pub fn add_range_object(&mut self, range: &AddressRange) {
        self.set.add_range_object(range);
    }

    pub fn add_set(&mut self, set: &dyn AddressSetView) {
        self.set.add_set(set);
    }

    pub fn delete_range(&mut self, start: &Address, end: &Address) {
        self.set.delete_range(start, end);
    }

    pub fn delete_range_object(&mut self, range: &AddressRange) {
        self.set.delete_range_object(range);
    }

    pub fn delete_set(&mut self, set: &dyn AddressSetView) {
        self.set.delete_set(set);
    }

    pub fn clear(&mut self) {
        self.set.clear();
    }
}

impl AddressSetView for ModifiableAddressSetCollection {
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

impl AddressSetCollection for ModifiableAddressSetCollection {
    fn has_fewer_ranges_than(&self, range_threshold: usize) -> bool {
        self.num_address_ranges() < range_threshold
    }

    fn combined_address_set(&self) -> AddressSet {
        AddressSet::from_set(self)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.intersects_set(set)
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.set.intersects_range(start, end)
    }

    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
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

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn test_new_creates_empty_collection() {
        let collection = ModifiableAddressSetCollection::new();
        assert!(AddressSetView::is_empty(&collection));
        assert_eq!(collection.num_address_ranges(), 0);
    }

    #[test]
    fn test_has_fewer_ranges_than() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1005));
        collection.add_range(&addr(0x2000), &addr(0x2005));

        assert!(collection.has_fewer_ranges_than(3));
        assert!(!collection.has_fewer_ranges_than(2));
        assert!(!collection.has_fewer_ranges_than(1));
    }

    #[test]
    fn test_combined_address_set() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1005));
        collection.add_range(&addr(0x2000), &addr(0x2005));

        let combined = collection.combined_address_set();
        assert_eq!(combined.num_address_ranges(), 2);
        assert!(combined.contains(&addr(0x1000)));
        assert!(combined.contains(&addr(0x2000)));
    }

    #[test]
    fn test_add_and_remove_ranges() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1005));
        assert_eq!(collection.num_address_ranges(), 1);
        assert!(AddressSetView::contains(&collection, &addr(0x1002)));

        collection.delete_range(&addr(0x1002), &addr(0x1003));
        assert_eq!(collection.num_address_ranges(), 2);
        assert!(!AddressSetView::contains(&collection, &addr(0x1002)));
        assert!(AddressSetView::contains(&collection, &addr(0x1001)));
        assert!(AddressSetView::contains(&collection, &addr(0x1004)));
    }

    #[test]
    fn test_add_set() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1005));

        let other = AddressSet::from_start_end(addr(0x1003), addr(0x2000));
        collection.add_set(&other);

        assert!(AddressSetView::contains(&collection, &addr(0x1000)));
        assert!(AddressSetView::contains(&collection, &addr(0x2000)));
    }

    #[test]
    fn test_clear() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1005));
        collection.add_range(&addr(0x2000), &addr(0x2005));
        assert!(!AddressSetView::is_empty(&collection));

        collection.clear();
        assert!(AddressSetView::is_empty(&collection));
        assert_eq!(collection.num_address_ranges(), 0);
    }

    #[test]
    fn test_address_set_view_operations() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1009));

        assert_eq!(AddressSetView::min_address(&collection), Some(addr(0x1000)));
        assert_eq!(AddressSetView::max_address(&collection), Some(addr(0x1009)));
        assert!(AddressSetView::contains(&collection, &addr(0x1005)));
        assert!(!AddressSetView::contains(&collection, &addr(0x0FFF)));
    }

    #[test]
    fn test_set_operations_via_address_set_view() {
        let mut collection = ModifiableAddressSetCollection::new();
        collection.add_range(&addr(0x1000), &addr(0x1009));

        let other = AddressSet::from_start_end(addr(0x1005), addr(0x100f));
        let intersection = collection.intersect(&other);

        assert!(intersection.contains(&addr(0x1005)));
        assert!(!intersection.contains(&addr(0x0FFF)));
        assert_eq!(intersection.num_addresses(), 5);
    }
}
