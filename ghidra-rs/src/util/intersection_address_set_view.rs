//! Port of `ghidra.util.IntersectionAddressSetView`.
//!
//! Java's `IntersectionAddressSetView extends AbstractAddressSetView` lazily computes the
//! intersection of exactly two [`AddressSetView`]s. `getAddressRanges()`/`getAddressRanges(boolean)`
//! seed a starting address via `findStart` (the `cmax`/`cmin` of both views' bounds, so the walk
//! never wastes time on a region only one side could cover) and `getAddressRanges(Address,
//! boolean)` seeds from `adjustStart` (the later, forward, or earlier, backward, of both views'
//! first-range starts from the caller's requested start); both then hand off to
//! `AddressRangeIterators.intersect`, a merge over `TwoWayBreakdownAddressRangeIterator` that
//! never materializes the combined set.
//!
//! As with [`UnionAddressSetView`](crate::util::union_address_set_view::UnionAddressSetView),
//! porting that merge machinery is out of scope here (still `TODO` in `PORT_MANIFEST.tsv`); the
//! `findStart`/`adjustStart` seeding is a pure performance optimization for the lazy walk (its
//! result never excludes a range that would otherwise be part of the true intersection -- any
//! overlap between `a` and `b` necessarily falls at or after `cmax(a.min, b.min)`, and any range
//! returned "from start" necessarily begins at or before the first range each input view would
//! itself return "from start"), so recomputing the intersection eagerly via
//! [`AddressSetView::intersect`] and then delegating to the resulting [`AddressSet`]'s own
//! already-tested `address_ranges*` methods produces the identical observable range sequence.
//!
//! Every method overridden here (`contains` in all three overloads, plus the three
//! range-producing methods and `getRangeContaining`) mirrors an explicit override in
//! `IntersectionAddressSetView.java`; everything else (`isEmpty`, `getMinAddress`,
//! `getMaxAddress`, `getNumAddresses`, ...) is inherited unchanged from
//! [`AbstractAddressSetView`]'s defaults, exactly as in Java.

use crate::program::model::address::{
    Address, BoxedAddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
};
use crate::util::abstract_address_set_view::AbstractAddressSetView;

/// A lazily-recomputed [`AddressSetView`] defined as the intersection of two given
/// [`AddressSetView`]s.
///
/// Port of `ghidra.util.IntersectionAddressSetView`. See the module docs for the
/// recompute-vs-lazy-stream distinction.
pub struct IntersectionAddressSetView {
    a: Box<dyn AddressSetView>,
    b: Box<dyn AddressSetView>,
}

impl IntersectionAddressSetView {
    /// Construct the intersection of two address sets.
    pub fn new(a: Box<dyn AddressSetView>, b: Box<dyn AddressSetView>) -> Self {
        Self { a, b }
    }
}

impl AbstractAddressSetView for IntersectionAddressSetView {
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        // Matches Java's `getAddressRanges()`, which just calls `getAddressRanges(true)`.
        <Self as AbstractAddressSetView>::address_ranges_ordered(self, true)
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.intersect(self.b.as_ref()).address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.intersect(self.b.as_ref()).address_ranges_from(start, forward)
    }
}

impl AddressSetView for IntersectionAddressSetView {
    /// Matches Java's `IntersectionAddressSetView.contains(Address)` override.
    /// `AbstractAddressSetView` has no default for plain single-address `contains`, so every
    /// implementor (Java's included) must supply this directly.
    fn contains(&self, address: &Address) -> bool {
        self.a.contains(address) && self.b.contains(address)
    }

    /// Matches Java's `IntersectionAddressSetView.contains(Address, Address)` override, rather
    /// than falling back to `AbstractAddressSetView`'s generic range-based default.
    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.a.contains_range(start, end) && self.b.contains_range(start, end)
    }

    /// Matches Java's `IntersectionAddressSetView.contains(AddressSetView)` override.
    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        self.a.contains_set(set) && self.b.contains_set(set)
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

    /// Matches Java's `IntersectionAddressSetView.getRangeContaining(Address)` override exactly:
    /// find the range containing `address` in each of `a` and `b` (if either has none, `address`
    /// cannot be in the intersection), then intersect those two single ranges. Since each is the
    /// unique maximal contiguous chunk of its own set containing `address`, their overlap is
    /// exactly the maximal contiguous chunk of `a ∩ b` containing `address` -- the same answer
    /// [`AbstractAddressSetView`]'s generic default would eventually compute by re-deriving it
    /// from `address_ranges_from`, just without materializing anything.
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        let a_range = self.a.range_containing(address)?;
        let b_range = self.b.range_containing(address)?;
        a_range.intersect(&b_range)
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
    use super::IntersectionAddressSetView;
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
    fn overlapping_ranges_intersect_to_the_common_span() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1009)])),
            Box::new(set(&[(0x1005, 0x100f)])),
        );
        assert_eq!(view.num_address_ranges(), 1);
        assert_eq!(view.min_address(), Some(addr(0x1005)));
        assert_eq!(view.max_address(), Some(addr(0x1009)));
        assert!(view.contains(&addr(0x1007)));
        assert!(!view.contains(&addr(0x1002)));
        assert!(!view.contains(&addr(0x100c)));
    }

    #[test]
    fn disjoint_ranges_produce_empty_intersection() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1002)])),
            Box::new(set(&[(0x2000, 0x2002)])),
        );
        assert!(view.is_empty());
        assert_eq!(view.min_address(), None);
        assert_eq!(view.range_containing(&addr(0x1001)), None);
    }

    #[test]
    fn contains_range_and_set_require_both_sides() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1000, 0x100f)])),
        );
        assert!(view.contains_range(&addr(0x1002), &addr(0x1008)));
        let other = set(&[(0x1002, 0x1008)]);
        assert!(view.contains_set(&other));

        let view2 = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1005)])),
            Box::new(set(&[(0x1003, 0x100f)])),
        );
        // [0x1000,0x100f] is not contained since the intersection is only [0x1003,0x1005].
        assert!(!view2.contains_range(&addr(0x1000), &addr(0x100f)));
        assert!(view2.contains_range(&addr(0x1003), &addr(0x1005)));
    }

    #[test]
    fn range_containing_matches_intersection_of_the_two_enclosing_ranges() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1020)])),
            Box::new(set(&[(0x1010, 0x1030)])),
        );
        assert_eq!(
            view.range_containing(&addr(0x1015)),
            Some(AddressRange::new(addr(0x1010), addr(0x1020)))
        );
        // Address in `a` but outside `b` entirely: no containing range.
        assert_eq!(view.range_containing(&addr(0x1005)), None);
    }

    #[test]
    fn multiple_disjoint_overlaps_yield_multiple_ranges_in_order() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1005), (0x2000, 0x2005)])),
            Box::new(set(&[(0x1002, 0x1008), (0x2002, 0x2008)])),
        );
        assert_eq!(view.num_address_ranges(), 2);
        let mut it = view.address_ranges();
        assert_eq!(it.next(), Some(AddressRange::new(addr(0x1002), addr(0x1005))));
        assert_eq!(it.next(), Some(AddressRange::new(addr(0x2002), addr(0x2005))));
        assert!(it.next().is_none());
    }

    #[test]
    fn address_ranges_from_seeks_forward_and_backward() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1005), (0x2000, 0x2005)])),
            Box::new(set(&[(0x1000, 0x1005), (0x2000, 0x2005)])),
        );
        let mut fwd = view.address_ranges_from(&addr(0x1800), true);
        assert_eq!(fwd.next(), Some(AddressRange::new(addr(0x2000), addr(0x2005))));

        let mut bwd = view.address_ranges_from(&addr(0x1800), false);
        assert_eq!(bwd.next(), Some(AddressRange::new(addr(0x1000), addr(0x1005))));
    }

    #[test]
    fn works_through_dyn_address_set_view_dispatch() {
        let view = IntersectionAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1000, 0x100f)])),
        );
        let dyn_view: &dyn AddressSetView = &view;
        assert!(dyn_view.contains(&addr(0x1005)));
        assert_eq!(dyn_view.num_address_ranges(), 1);
    }
}
