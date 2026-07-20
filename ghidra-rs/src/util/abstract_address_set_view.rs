use crate::program::model::address::{
    Address, AddressIterator, AddressIteratorAdapter, AddressRange, AddressRangeIterator,
    AddressSet, AddressSetView,
};

/// Adjusts `start` so that if it lands in the first range yielded by `rev`, the adjustment
/// snaps to that range's boundary (min address for forward iteration, max address for
/// backward). Only the first element of `rev` is consumed.
///
/// Mirrors the protected static `AbstractAddressSetView.fixStart` helper. Callers must
/// position `rev` themselves, exactly as documented on the Java original.
pub fn fix_start(rev: &mut dyn AddressRangeIterator, start: Address, forward: bool) -> Address {
    if !rev.has_next() {
        return start;
    }
    match rev.next_range() {
        Some(range) if range.contains(&start) => {
            if forward {
                range.min_address().clone()
            } else {
                range.max_address().clone()
            }
        }
        _ => start,
    }
}

/// Default method bodies for a read-only address-set view, built on top of the three
/// "primitive" range-iteration methods a concrete implementation must supply.
///
/// Mirrors Ghidra's `AbstractAddressSetView`, which supplies default behavior for most of
/// the `AddressSetView` interface's methods to subclasses such as `IntersectionAddressSetView`,
/// `UnionAddressSetView`, `DifferenceAddressSetView`, and `SymmetricDifferenceAddressSetView`
/// (none of which are ported yet). Rust has no class inheritance, so this is expressed as a
/// standalone trait: implementors provide [`address_ranges`](Self::address_ranges),
/// [`address_ranges_ordered`](Self::address_ranges_ordered), and
/// [`address_ranges_from`](Self::address_ranges_from), and get the rest of the read-only-view
/// surface for free. Method names mirror [`AddressSetView`] so a future implementor can adopt
/// both with minimal friction.
///
/// A few Java methods here (`intersect`, `union`, `subtract`, `xor`, `contains`, `intersects`)
/// delegate in the original to `ghidra.util.AddressRangeIterators` and the not-yet-ported
/// `*AddressSetView` combinator classes. Those combinators only exist to lazily compute a
/// merged range stream; since the semantics only depend on already-ported types
/// ([`AddressRange`], [`AddressSet`], [`AddressSetView`]), the default bodies below recompute
/// the same results directly against those types rather than introducing placeholder
/// collaborators for classes whose sole purpose is an alternate (lazy) computation strategy.
pub trait AbstractAddressSetView {
    /// Mirrors `getAddressRanges()`.
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator>;

    /// Mirrors `getAddressRanges(boolean forward)`.
    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator>;

    /// Mirrors `getAddressRanges(Address start, boolean forward)`.
    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator>;

    /// Mirrors `isEmpty`.
    fn is_empty(&self) -> bool {
        !self.address_ranges().has_next()
    }

    /// Mirrors `contains(Address start, Address end)`.
    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        let target_len = AddressRange::new(start.clone(), end.clone()).length();
        self.intersect_range(start, end).num_addresses() == target_len
    }

    /// Mirrors `contains(AddressSetView rangeSet)`.
    fn contains_set(&self, range_set: &dyn AddressSetView) -> bool {
        let mut it = range_set.address_ranges();
        while let Some(range) = it.next_range() {
            if !self.contains_range(range.min_address(), range.max_address()) {
                return false;
            }
        }
        true
    }

    /// Mirrors `getMinAddress`.
    fn min_address(&self) -> Option<Address> {
        self.address_ranges_ordered(true)
            .next_range()
            .map(|range| range.min_address().clone())
    }

    /// Mirrors `getMaxAddress`.
    fn max_address(&self) -> Option<Address> {
        self.address_ranges_ordered(false)
            .next_range()
            .map(|range| range.max_address().clone())
    }

    /// Mirrors `getNumAddressRanges`.
    fn num_address_ranges(&self) -> usize {
        let mut it = self.address_ranges();
        let mut count = 0;
        while it.next_range().is_some() {
            count += 1;
        }
        count
    }

    /// Mirrors `getNumAddresses`.
    fn num_addresses(&self) -> u64 {
        let mut it = self.address_ranges();
        let mut count = 0u64;
        while let Some(range) = it.next_range() {
            count += range.length();
        }
        count
    }

    /// Mirrors `getAddresses(boolean forward)`.
    fn addresses(&self, forward: bool) -> Box<dyn AddressIterator> {
        let mut it = self.address_ranges_ordered(forward);
        let mut addresses = Vec::new();
        while let Some(range) = it.next_range() {
            let mut range_addresses: Vec<Address> = range.addresses().collect();
            if !forward {
                range_addresses.reverse();
            }
            addresses.extend(range_addresses);
        }
        Box::new(AddressIteratorAdapter::new(addresses.into_iter()))
    }

    /// Mirrors `getAddresses(Address start, boolean forward)`.
    fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator> {
        let mut it = self.address_ranges_from(start, forward);
        let mut addresses = Vec::new();
        while let Some(range) = it.next_range() {
            let mut range_addresses: Vec<Address> = range
                .addresses()
                .filter(|address| if forward { address >= start } else { address <= start })
                .collect();
            if !forward {
                range_addresses.reverse();
            }
            addresses.extend(range_addresses);
        }
        Box::new(AddressIteratorAdapter::new(addresses.into_iter()))
    }

    /// Mirrors `hasSameAddresses`.
    fn has_same_addresses(&self, view: &dyn AddressSetView) -> bool {
        let mut ait = self.address_ranges();
        let mut bit = view.address_ranges();
        loop {
            match (ait.next_range(), bit.next_range()) {
                (Some(a), Some(b)) => {
                    if a != b {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    /// Mirrors `getFirstRange`.
    fn first_range(&self) -> Option<AddressRange> {
        self.address_ranges_ordered(true).next_range()
    }

    /// Mirrors `getLastRange`.
    fn last_range(&self) -> Option<AddressRange> {
        self.address_ranges_ordered(false).next_range()
    }

    /// Mirrors `intersects(AddressSetView addrSet)`.
    fn intersects_set(&self, addr_set: &dyn AddressSetView) -> bool {
        let mut ait = self.address_ranges();
        while let Some(a) = ait.next_range() {
            let mut bit = addr_set.address_ranges();
            while let Some(b) = bit.next_range() {
                if a.intersects(&b) {
                    return true;
                }
            }
        }
        false
    }

    /// Mirrors `intersects(Address start, Address end)`.
    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        let target = AddressRange::new(start.clone(), end.clone());
        let mut it = self.address_ranges();
        while let Some(range) = it.next_range() {
            if range.intersects(&target) {
                return true;
            }
        }
        false
    }

    /// Mirrors `intersect(AddressSetView view)`.
    fn intersect(&self, view: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        let mut ait = self.address_ranges();
        while let Some(a) = ait.next_range() {
            let mut bit = view.address_ranges();
            while let Some(b) = bit.next_range() {
                if let Some(overlap) = a.intersect(&b) {
                    result.add_range_object(&overlap);
                }
            }
        }
        result
    }

    /// Mirrors `intersectRange(Address start, Address end)`.
    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.intersect(&AddressSet::from_start_end(start.clone(), end.clone()))
    }

    /// Mirrors `union(AddressSetView addrSet)`.
    fn union(&self, addr_set: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        let mut it = self.address_ranges();
        while let Some(range) = it.next_range() {
            result.add_range_object(&range);
        }
        result.add_set(addr_set);
        result
    }

    /// Mirrors `subtract(AddressSetView addrSet)`.
    fn subtract(&self, addr_set: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        let mut it = self.address_ranges();
        while let Some(range) = it.next_range() {
            result.add_range_object(&range);
        }
        result.delete_set(addr_set);
        result
    }

    /// Mirrors `xor(AddressSetView addrSet)`.
    fn xor(&self, addr_set: &dyn AddressSetView) -> AddressSet {
        let mut result = self.union(addr_set);
        result.delete_set(&self.intersect(addr_set));
        result
    }

    /// Mirrors `findFirstAddressInCommon(AddressSetView set)`.
    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        self.intersect(set).min_address()
    }

    /// Mirrors `getRangeContaining(Address address)`.
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        let range = self.address_ranges_from(address, true).next_range()?;
        if range.contains(address) {
            Some(range)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRangeIteratorAdapter, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn range(start: i64, end: i64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    /// Mock view backed by a fixed, sorted, non-overlapping range list — proves
    /// `AbstractAddressSetView` is object-safe (used through `&dyn`) and that its default
    /// methods, built only on the three primitive iterators, behave correctly.
    struct MockView {
        ranges: Vec<AddressRange>,
    }

    impl AbstractAddressSetView for MockView {
        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            Box::new(AddressRangeIteratorAdapter::new(self.ranges.clone()))
        }

        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
            let mut ranges = self.ranges.clone();
            if !forward {
                ranges.reverse();
            }
            Box::new(AddressRangeIteratorAdapter::new(ranges))
        }

        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
            let mut ranges: Vec<AddressRange> = self
                .ranges
                .iter()
                .filter(|range| if forward { range.max_address() >= start } else { range.min_address() <= start })
                .cloned()
                .collect();
            if !forward {
                ranges.reverse();
            }
            Box::new(AddressRangeIteratorAdapter::new(ranges))
        }
    }

    #[test]
    fn primitives_drive_min_max_and_counts_through_trait_object() {
        let view = MockView {
            ranges: vec![range(0x1000, 0x1005), range(0x2000, 0x2002)],
        };
        let dyn_view: &dyn AbstractAddressSetView = &view;

        assert!(!dyn_view.is_empty());
        assert_eq!(dyn_view.min_address(), Some(addr(0x1000)));
        assert_eq!(dyn_view.max_address(), Some(addr(0x2002)));
        assert_eq!(dyn_view.num_address_ranges(), 2);
        assert_eq!(dyn_view.num_addresses(), 6 + 3);
        assert_eq!(dyn_view.first_range(), Some(range(0x1000, 0x1005)));
        assert_eq!(dyn_view.last_range(), Some(range(0x2000, 0x2002)));
    }

    #[test]
    fn contains_checks_full_coverage_not_just_overlap() {
        let view = MockView {
            ranges: vec![range(0x1000, 0x100f)],
        };

        assert!(view.contains_range(&addr(0x1002), &addr(0x1008)));
        assert!(!view.contains_range(&addr(0x1002), &addr(0x1020)));
    }

    #[test]
    fn set_algebra_matches_expected_ranges() {
        let left = MockView {
            ranges: vec![range(0x1000, 0x1009)],
        };
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

        assert_eq!(left.find_first_address_in_common(&right), Some(addr(0x1005)));
    }

    #[test]
    fn range_containing_and_intersects_use_primitive_iterators() {
        let view = MockView {
            ranges: vec![range(0x1000, 0x100f), range(0x2000, 0x200f)],
        };

        assert_eq!(view.range_containing(&addr(0x1005)), Some(range(0x1000, 0x100f)));
        assert_eq!(view.range_containing(&addr(0x1500)), None);
        assert!(view.intersects_range(&addr(0x1008), &addr(0x1500)));
        assert!(!view.intersects_range(&addr(0x1500), &addr(0x1fff)));
    }

    #[test]
    fn fix_start_snaps_to_range_boundary_when_start_is_contained() {
        let mut rev = AddressRangeIteratorAdapter::new(vec![range(0x1000, 0x100f)]);
        let adjusted = fix_start(&mut rev, addr(0x1008), true);
        assert_eq!(adjusted, addr(0x1000));

        let mut rev = AddressRangeIteratorAdapter::new(vec![range(0x1000, 0x100f)]);
        let adjusted = fix_start(&mut rev, addr(0x1008), false);
        assert_eq!(adjusted, addr(0x100f));

        let mut rev = AddressRangeIteratorAdapter::new(vec![range(0x1000, 0x100f)]);
        let adjusted = fix_start(&mut rev, addr(0x2000), true);
        assert_eq!(adjusted, addr(0x2000));
    }
}
