use crate::program::model::address::{
    Address, AddressIterator, AddressIteratorAdapter, AddressRange, AddressRangeIterator,
    AddressRangeIteratorAdapter, EmptyAddressIterator, EmptyAddressRangeIterator,
};

/// Read-only view of an address set.
///
/// This mirrors Ghidra's `AddressSetView` contract.
pub trait AddressSetView {
    fn contains(&self, address: &Address) -> bool;
    fn contains_range(&self, start: &Address, end: &Address) -> bool;
    fn contains_set(&self, set: &dyn AddressSetView) -> bool;
    fn is_empty(&self) -> bool;
    fn min_address(&self) -> Option<Address>;
    fn max_address(&self) -> Option<Address>;
    fn num_address_ranges(&self) -> usize;
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator>;
    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator>;
    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator>;
    fn num_addresses(&self) -> u64;
    fn addresses(&self, forward: bool) -> Box<dyn AddressIterator>;
    fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator>;
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool;
    fn intersects_range(&self, start: &Address, end: &Address) -> bool;
    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet;
    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet;
    fn union(&self, set: &dyn AddressSetView) -> AddressSet;
    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet;
    fn xor(&self, set: &dyn AddressSetView) -> AddressSet;
    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool;
    fn first_range(&self) -> Option<AddressRange>;
    fn last_range(&self) -> Option<AddressRange>;
    fn range_containing(&self, address: &Address) -> Option<AddressRange>;
    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address>;
}

/// Normalized set of addresses represented as sorted, non-overlapping ranges.
///
/// This mirrors Ghidra's `AddressSet` public behavior without using the Java
/// red-black-tree storage strategy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_range(range: AddressRange) -> Self {
        let mut set = Self::new();
        set.add_range_object(&range);
        set
    }

    pub fn from_start_end(start: Address, end: Address) -> Self {
        let mut set = Self::new();
        set.add_range(&start, &end);
        set
    }

    pub fn from_address(address: Address) -> Self {
        Self::from_start_end(address.clone(), address)
    }

    pub fn from_set(set: &dyn AddressSetView) -> Self {
        let mut new_set = Self::new();
        new_set.add_set(set);
        new_set
    }

    pub fn add_address(&mut self, address: &Address) {
        self.add_range(address, address);
    }

    pub fn add_range_object(&mut self, range: &AddressRange) {
        self.add_range(range.min_address(), range.max_address());
    }

    pub fn add_range(&mut self, start: &Address, end: &Address) {
        let range = AddressRange::new(start.clone(), end.clone());
        self.ranges.push(range);
        self.normalize();
    }

    pub fn add_set(&mut self, set: &dyn AddressSetView) {
        let mut iterator = set.address_ranges();
        while let Some(range) = iterator.next_range() {
            self.ranges.push(range);
        }
        self.normalize();
    }

    pub fn delete_range_object(&mut self, range: &AddressRange) {
        self.delete_range(range.min_address(), range.max_address());
    }

    pub fn delete_range(&mut self, start: &Address, end: &Address) {
        let delete = AddressRange::new(start.clone(), end.clone());
        let mut new_ranges = Vec::new();
        for range in &self.ranges {
            if !range.intersects(&delete) {
                new_ranges.push(range.clone());
                continue;
            }
            if delete.min_address() > range.min_address() {
                let left_end = delete.min_address().add(-1).unwrap();
                new_ranges.push(AddressRange::new(range.min_address().clone(), left_end));
            }
            if delete.max_address() < range.max_address() {
                let right_start = delete.max_address().add(1).unwrap();
                new_ranges.push(AddressRange::new(right_start, range.max_address().clone()));
            }
        }
        self.ranges = new_ranges;
    }

    pub fn delete_set(&mut self, set: &dyn AddressSetView) {
        let mut iterator = set.address_ranges();
        while let Some(range) = iterator.next_range() {
            self.delete_range_object(&range);
        }
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    pub fn to_list(&self) -> Vec<AddressRange> {
        self.ranges.clone()
    }

    pub fn print_ranges(&self) -> String {
        self.ranges
            .iter()
            .map(|range| format!("[{}, {}]", range.min_address(), range.max_address()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn delete_from_min(&mut self, to_address: &Address) {
        if let Some(max) = self.max_address() {
            self.delete_range(&max.min(to_address.clone()), to_address);
        }
    }

    pub fn delete_to_max(&mut self, from_address: &Address) {
        if let Some(max) = self.max_address() {
            self.delete_range(from_address, &max);
        }
    }

    fn normalize(&mut self) {
        if self.ranges.is_empty() {
            return;
        }
        self.ranges.sort();
        let mut normalized: Vec<AddressRange> = Vec::new();
        for range in self.ranges.drain(..) {
            if let Some(last) = normalized.last_mut() {
                if can_merge(last, &range) {
                    let max = last.max_address().max(range.max_address()).clone();
                    *last = AddressRange::new(last.min_address().clone(), max);
                    continue;
                }
            }
            normalized.push(range);
        }
        self.ranges = normalized;
    }
}

impl AddressSetView for AddressSet {
    fn contains(&self, address: &Address) -> bool {
        self.ranges.iter().any(|range| range.contains(address))
    }

    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        let range = AddressRange::new(start.clone(), end.clone());
        self.ranges.iter().any(|existing| {
            existing.contains(range.min_address()) && existing.contains(range.max_address())
        })
    }

    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        let mut iterator = set.address_ranges();
        while let Some(range) = iterator.next_range() {
            if !self.contains_range(range.min_address(), range.max_address()) {
                return false;
            }
        }
        true
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    fn min_address(&self) -> Option<Address> {
        self.ranges.first().map(|range| range.min_address().clone())
    }

    fn max_address(&self) -> Option<Address> {
        self.ranges.last().map(|range| range.max_address().clone())
    }

    fn num_address_ranges(&self) -> usize {
        self.ranges.len()
    }

    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.address_ranges_ordered(true)
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        if self.ranges.is_empty() {
            return Box::new(EmptyAddressRangeIterator);
        }
        let mut ranges = self.ranges.clone();
        if !forward {
            ranges.reverse();
        }
        Box::new(AddressRangeIteratorAdapter::new(ranges))
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        let mut ranges: Vec<_> = self
            .ranges
            .iter()
            .filter(|range| {
                if forward {
                    range.max_address() >= start
                } else {
                    range.min_address() <= start
                }
            })
            .cloned()
            .collect();
        if !forward {
            ranges.reverse();
        }
        Box::new(AddressRangeIteratorAdapter::new(ranges))
    }

    fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(AddressRange::length).sum()
    }

    fn addresses(&self, forward: bool) -> Box<dyn AddressIterator> {
        let mut addresses: Vec<_> = self
            .ranges
            .iter()
            .flat_map(|range| range.addresses())
            .collect();
        if !forward {
            addresses.reverse();
        }
        if addresses.is_empty() {
            Box::new(EmptyAddressIterator)
        } else {
            Box::new(AddressIteratorAdapter::new(addresses))
        }
    }

    fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator> {
        let mut addresses: Vec<_> = self
            .ranges
            .iter()
            .flat_map(|range| range.addresses())
            .filter(|address| {
                if forward {
                    address >= start
                } else {
                    address <= start
                }
            })
            .collect();
        if !forward {
            addresses.reverse();
        }
        if addresses.is_empty() {
            Box::new(EmptyAddressIterator)
        } else {
            Box::new(AddressIteratorAdapter::new(addresses))
        }
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        let mut iterator = set.address_ranges();
        while let Some(range) = iterator.next_range() {
            if self.intersects_range(range.min_address(), range.max_address()) {
                return true;
            }
        }
        false
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        let range = AddressRange::new(start.clone(), end.clone());
        self.ranges
            .iter()
            .any(|existing| existing.intersects(&range))
    }

    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        let mut iterator = set.address_ranges();
        while let Some(range) = iterator.next_range() {
            result.add_set(&self.intersect_range(range.min_address(), range.max_address()));
        }
        result
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        let target = AddressRange::new(start.clone(), end.clone());
        let mut result = AddressSet::new();
        for range in &self.ranges {
            if let Some(intersection) = range.intersect(&target) {
                result.add_range_object(&intersection);
            }
        }
        result
    }

    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        let mut result = self.clone();
        result.add_set(set);
        result
    }

    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        let mut result = self.clone();
        result.delete_set(set);
        result
    }

    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        let union = self.union(set);
        let intersection = self.intersect(set);
        union.subtract(&intersection)
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        let other = AddressSet::from_set(set);
        self.ranges == other.ranges
    }

    fn first_range(&self) -> Option<AddressRange> {
        self.ranges.first().cloned()
    }

    fn last_range(&self) -> Option<AddressRange> {
        self.ranges.last().cloned()
    }

    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        self.ranges
            .iter()
            .find(|range| range.contains(address))
            .cloned()
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        let intersection = self.intersect(set);
        intersection.min_address()
    }
}

fn can_merge(left: &AddressRange, right: &AddressRange) -> bool {
    if left.space() != right.space() {
        return false;
    }
    left.intersects(right)
        || left
            .max_address()
            .add(1)
            .map(|next| next >= *right.min_address())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn add_merges_overlapping_and_adjacent_ranges() {
        let mut set = AddressSet::new();

        set.add_range(&addr(0x1000), &addr(0x1005));
        set.add_range(&addr(0x1006), &addr(0x1008));
        set.add_range(&addr(0x1003), &addr(0x1010));

        assert_eq!(set.num_address_ranges(), 1);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1010)));
        assert_eq!(set.num_addresses(), 0x11);
    }

    #[test]
    fn delete_splits_ranges() {
        let mut set = AddressSet::from_start_end(addr(0x1000), addr(0x1009));

        set.delete_range(&addr(0x1003), &addr(0x1006));

        assert_eq!(set.to_list().len(), 2);
        assert!(set.contains_range(&addr(0x1000), &addr(0x1002)));
        assert!(set.contains_range(&addr(0x1007), &addr(0x1009)));
        assert!(!set.contains(&addr(0x1004)));
    }

    #[test]
    fn set_operations_return_normalized_results() {
        let left = AddressSet::from_start_end(addr(0x1000), addr(0x1009));
        let right = AddressSet::from_start_end(addr(0x1005), addr(0x100f));

        let intersection = left.intersect(&right);
        assert!(intersection.contains_range(&addr(0x1005), &addr(0x1009)));
        assert_eq!(intersection.num_addresses(), 5);

        let union = left.union(&right);
        assert_eq!(union.num_address_ranges(), 1);
        assert!(union.contains_range(&addr(0x1000), &addr(0x100f)));

        let subtract = left.subtract(&right);
        assert!(subtract.contains_range(&addr(0x1000), &addr(0x1004)));
        assert_eq!(subtract.num_addresses(), 5);

        let xor = left.xor(&right);
        assert!(xor.contains_range(&addr(0x1000), &addr(0x1004)));
        assert!(xor.contains_range(&addr(0x100a), &addr(0x100f)));
        assert!(!xor.contains(&addr(0x1007)));
    }

    #[test]
    fn iterators_support_order_and_start_address() {
        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1002));
        set.add_range(&addr(0x2000), &addr(0x2001));

        let mut forward = set.addresses(true);
        assert_eq!(forward.next_address(), Some(addr(0x1000)));
        assert_eq!(forward.next_address(), Some(addr(0x1001)));

        let mut reverse = set.addresses(false);
        assert_eq!(reverse.next_address(), Some(addr(0x2001)));
        assert_eq!(reverse.next_address(), Some(addr(0x2000)));

        let mut from = set.address_ranges_from(&addr(0x1001), true);
        assert_eq!(from.next_range().unwrap().min_address(), &addr(0x1000));
        assert_eq!(from.next_range().unwrap().min_address(), &addr(0x2000));
    }

    #[test]
    fn range_lookup_and_first_common_address_match_view_contract() {
        let set = AddressSet::from_start_end(addr(0x1000), addr(0x1009));
        let other = AddressSet::from_start_end(addr(0x1005), addr(0x2000));

        assert_eq!(set.min_address(), Some(addr(0x1000)));
        assert_eq!(set.max_address(), Some(addr(0x1009)));
        assert_eq!(set.first_range().unwrap().min_address(), &addr(0x1000));
        assert_eq!(set.last_range().unwrap().max_address(), &addr(0x1009));
        assert!(set.range_containing(&addr(0x1002)).is_some());
        assert!(set.range_containing(&addr(0x1010)).is_none());
        assert_eq!(set.find_first_address_in_common(&other), Some(addr(0x1005)));
        assert!(set.has_same_addresses(&AddressSet::from_set(&set)));
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
