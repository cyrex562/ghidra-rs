//! Port of `ghidra.util.SymmetricDifferenceAddressSetView`.
//!
//! Java's `SymmetricDifferenceAddressSetView extends AbstractAddressSetView` lazily computes the
//! symmetric difference `a XOR b` (addresses in exactly one of `a`/`b`) by delegating
//! `getAddressRanges(...)` to `AddressRangeIterators.xor(...)`, a merge over
//! `TwoWayBreakdownAddressRangeIterator` that never materializes the combined set, plus a pair of
//! `fixStart`/`rewindIfBounding` helpers used only to seed that lazy walk's starting point
//! correctly for the from-`start` overload.
//!
//! As with [`UnionAddressSetView`](crate::util::union_address_set_view::UnionAddressSetView),
//! [`IntersectionAddressSetView`](crate::util::intersection_address_set_view::IntersectionAddressSetView),
//! and [`DifferenceAddressSetView`](crate::util::difference_address_set_view::DifferenceAddressSetView),
//! porting that lazy merge machinery (`AddressRangeIterators`, still `TODO` in
//! `PORT_MANIFEST.tsv`) is out of scope here; `address_ranges`/`address_ranges_ordered`/
//! `address_ranges_from` instead recompute `a XOR b` eagerly via [`AddressSetView::xor`] (which
//! already implements the same "in exactly one side" contract Java's doc comment describes) and
//! delegate to the resulting [`AddressSet`]'s own already-tested `address_ranges*` methods,
//! producing the identical observable range sequence. Since that eager path makes `fixStart`/
//! `rewindIfBounding` (pure optimizations for seeding the lazy walk) unnecessary, they are not
//! ported.
//!
//! `getRangeContaining`, however, *is* ported faithfully following Java's own formula: find the
//! range (if any) each of `a` and `b` has containing `address`; if both or neither have one,
//! `address` is not in the symmetric difference (`None`) -- covered by both means it's excluded,
//! covered by neither means there's nothing to report. Otherwise `address` is covered by exactly
//! one side, and that side's enclosing range is truncated against the *other* side's neighboring
//! ranges via [`DifferenceAddressSetView::truncate`], exactly as Java calls
//! `DifferenceAddressSetView.truncate` directly from this class.
//!
//! Every method overridden here (`contains` and the three range-producing methods, plus
//! `getRangeContaining`) mirrors an explicit override in
//! `SymmetricDifferenceAddressSetView.java`; everything else is inherited unchanged from
//! [`AbstractAddressSetView`]'s defaults, exactly as in Java (where this class does not override
//! e.g. `isEmpty`, `getMinAddress`, `getMaxAddress`, `contains(Address, Address)`,
//! `contains(AddressSetView)`, ...).

use crate::program::model::address::{
    Address, BoxedAddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
};
use crate::util::abstract_address_set_view::AbstractAddressSetView;
use crate::util::difference_address_set_view::DifferenceAddressSetView;

/// A lazily-recomputed [`AddressSetView`] defined as the symmetric difference between two given
/// [`AddressSetView`]s (addresses in exactly one of `a`/`b`).
///
/// Port of `ghidra.util.SymmetricDifferenceAddressSetView`. See the module docs for the
/// recompute-vs-lazy-stream distinction.
pub struct SymmetricDifferenceAddressSetView {
    a: Box<dyn AddressSetView>,
    b: Box<dyn AddressSetView>,
}

impl SymmetricDifferenceAddressSetView {
    /// Construct the symmetric difference between two address sets.
    pub fn new(a: Box<dyn AddressSetView>, b: Box<dyn AddressSetView>) -> Self {
        Self { a, b }
    }
}

impl AbstractAddressSetView for SymmetricDifferenceAddressSetView {
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.a.xor(self.b.as_ref()).address_ranges()
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.xor(self.b.as_ref()).address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.xor(self.b.as_ref()).address_ranges_from(start, forward)
    }
}

impl AddressSetView for SymmetricDifferenceAddressSetView {
    /// Matches Java's `SymmetricDifferenceAddressSetView.contains(Address)` override: true if
    /// `address` is in exactly one of `a`/`b`. `AbstractAddressSetView` has no default for plain
    /// single-address `contains`, so every implementor (Java's included) must supply this
    /// directly.
    fn contains(&self, address: &Address) -> bool {
        self.a.contains(address) ^ self.b.contains(address)
    }

    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        AbstractAddressSetView::contains_range(self, start, end)
    }

    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        AbstractAddressSetView::contains_set(self, set)
    }

    fn is_empty(&self) -> bool {
        AbstractAddressSetView::is_empty(self)
    }

    fn min_address(&self) -> Option<Address> {
        AbstractAddressSetView::min_address(self)
    }

    fn max_address(&self) -> Option<Address> {
        AbstractAddressSetView::max_address(self)
    }

    fn num_address_ranges(&self) -> usize {
        AbstractAddressSetView::num_address_ranges(self)
    }

    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        AbstractAddressSetView::address_ranges(self)
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        AbstractAddressSetView::address_ranges_ordered(self, forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        AbstractAddressSetView::address_ranges_from(self, start, forward)
    }

    fn num_addresses(&self) -> u64 {
        AbstractAddressSetView::num_addresses(self)
    }

    fn addresses(&self, forward: bool) -> BoxedAddressIterator {
        AbstractAddressSetView::addresses(self, forward)
    }

    fn addresses_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        AbstractAddressSetView::addresses_from(self, start, forward)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        AbstractAddressSetView::intersects_set(self, set)
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        AbstractAddressSetView::intersects_range(self, start, end)
    }

    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        AbstractAddressSetView::intersect(self, set)
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        AbstractAddressSetView::intersect_range(self, start, end)
    }

    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        AbstractAddressSetView::union(self, set)
    }

    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        AbstractAddressSetView::subtract(self, set)
    }

    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        AbstractAddressSetView::xor(self, set)
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        AbstractAddressSetView::has_same_addresses(self, set)
    }

    fn first_range(&self) -> Option<AddressRange> {
        AbstractAddressSetView::first_range(self)
    }

    fn last_range(&self) -> Option<AddressRange> {
        AbstractAddressSetView::last_range(self)
    }

    /// Matches Java's `SymmetricDifferenceAddressSetView.getRangeContaining(Address)` override:
    /// find `a`'s and `b`'s range containing `address`; if both or neither exist, `address` isn't
    /// in the symmetric difference. Otherwise truncate whichever range does exist against the
    /// *other* set's neighboring ranges, via [`DifferenceAddressSetView::truncate`] (shared with
    /// `DifferenceAddressSetView`, exactly as Java calls it directly by class name).
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        let a_range = self.a.range_containing(address);
        let b_range = self.b.range_containing(address);
        if a_range.is_some() == b_range.is_some() {
            return None;
        }
        let (rng, other): (AddressRange, &dyn AddressSetView) = if let Some(ar) = a_range {
            (ar, self.b.as_ref())
        } else {
            (b_range.unwrap(), self.a.as_ref())
        };
        Some(DifferenceAddressSetView::truncate(&rng, address, other))
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        AbstractAddressSetView::find_first_address_in_common(self, set)
    }
}

#[cfg(test)]
mod tests {
    // Deliberately not `use super::*`: see the identical note in `union_address_set_view.rs`'s
    // test module -- `AbstractAddressSetView` and `AddressSetView` overlap on method names, so
    // only `AddressSetView` is imported here to keep calls unambiguous.
    use super::SymmetricDifferenceAddressSetView;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn set(ranges: &[(i64, i64)]) -> AddressSet {
        let mut s = AddressSet::new();
        for &(start, end) in ranges {
            s.add_range(&addr(start), &addr(end));
        }
        s
    }

    #[test]
    fn disjoint_ranges_are_all_in_the_symmetric_difference() {
        let view = SymmetricDifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1005)])),
            Box::new(set(&[(0x2000, 0x2005)])),
        );
        assert_eq!(view.num_address_ranges(), 2);
        assert!(view.contains(&addr(0x1002)));
        assert!(view.contains(&addr(0x2002)));
    }

    #[test]
    fn identical_sets_have_empty_symmetric_difference() {
        let view = SymmetricDifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1000, 0x100f)])),
        );
        assert!(view.is_empty());
        assert!(!view.contains(&addr(0x1005)));
        assert_eq!(view.range_containing(&addr(0x1005)), None);
    }

    #[test]
    fn overlapping_ranges_exclude_the_shared_middle() {
        let view = SymmetricDifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1009)])),
            Box::new(set(&[(0x1005, 0x100f)])),
        );
        // [0x1000,0x1004] only in a, [0x100a,0x100f] only in b, [0x1005,0x1009] in both (excluded).
        assert!(view.contains(&addr(0x1002)));
        assert!(!view.contains(&addr(0x1007)));
        assert!(view.contains(&addr(0x100d)));
        assert_eq!(view.num_address_ranges(), 2);
    }

    #[test]
    fn range_containing_truncates_against_the_other_set() {
        let view = SymmetricDifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1009)])),
            Box::new(set(&[(0x1005, 0x100f)])),
        );
        assert_eq!(
            view.range_containing(&addr(0x1002)),
            Some(AddressRange::new(addr(0x1000), addr(0x1004)))
        );
        assert_eq!(
            view.range_containing(&addr(0x100d)),
            Some(AddressRange::new(addr(0x100a), addr(0x100f)))
        );
        // In both (or neither) -> no containing range in the symmetric difference.
        assert_eq!(view.range_containing(&addr(0x1007)), None);
        assert_eq!(view.range_containing(&addr(0x2000)), None);
    }

    #[test]
    fn xor_is_the_boolean_definition_of_contains() {
        let a = set(&[(0x1000, 0x1005)]);
        let b = set(&[(0x1003, 0x1008)]);
        let view = SymmetricDifferenceAddressSetView::new(Box::new(a.clone()), Box::new(b.clone()));
        for offset in 0x1000..=0x1008 {
            let address = addr(offset);
            assert_eq!(
                view.contains(&address),
                a.contains(&address) ^ b.contains(&address),
                "mismatch at {offset:#x}"
            );
        }
    }

    #[test]
    fn works_through_dyn_address_set_view_dispatch() {
        let view = SymmetricDifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1002)])),
            Box::new(set(&[(0x2000, 0x2002)])),
        );
        let dyn_view: &dyn AddressSetView = &view;
        assert!(dyn_view.contains(&addr(0x1001)));
        assert_eq!(dyn_view.num_address_ranges(), 2);
    }
}
