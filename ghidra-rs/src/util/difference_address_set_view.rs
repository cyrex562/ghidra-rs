//! Port of `ghidra.util.DifferenceAddressSetView`.
//!
//! Java's `DifferenceAddressSetView extends AbstractAddressSetView` lazily computes `a - b` (the
//! minuend `a` minus the subtrahend `b`) by delegating `getAddressRanges(...)` to
//! `AddressRangeIterators.subtract`, a merge over `TwoWayBreakdownAddressRangeIterator` that never
//! materializes the combined set, and computes `getRangeContaining` via a `truncate` helper that
//! clips `a`'s enclosing range down to exclude whatever portion `b` covers around the requested
//! address.
//!
//! As with [`UnionAddressSetView`](crate::util::union_address_set_view::UnionAddressSetView) and
//! [`IntersectionAddressSetView`](crate::util::intersection_address_set_view::IntersectionAddressSetView),
//! porting that merge machinery is out of scope here (still `TODO` in `PORT_MANIFEST.tsv`);
//! `address_ranges`/`address_ranges_ordered`/`address_ranges_from` instead recompute `a - b`
//! eagerly via [`AddressSetView::subtract`] (which already implements the same splitting/clipping
//! behavior around removed sub-ranges) and delegate to the resulting [`AddressSet`]'s own
//! already-tested `address_ranges*` methods, producing the identical observable range sequence.
//! `range_containing`, however, *is* ported faithfully following Java's own two-step formula
//! (check whether `address` falls in `b` at all; if not, truncate `a`'s enclosing range against
//! `b`'s neighboring ranges) rather than being routed through the eager `subtract`, since it is
//! cheap, self-contained, and mirrors the Java source almost line for line.
//!
//! Every method overridden here (`contains` in all three overloads, the three range-producing
//! methods, and `getRangeContaining`) mirrors an explicit override in
//! `DifferenceAddressSetView.java`; everything else is inherited unchanged from
//! [`AbstractAddressSetView`]'s defaults, exactly as in Java.

use crate::program::model::address::{
    Address, BoxedAddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
};
use crate::util::abstract_address_set_view::AbstractAddressSetView;

/// A lazily-recomputed [`AddressSetView`] defined as the difference between two given
/// [`AddressSetView`]s (`a - b`).
///
/// Port of `ghidra.util.DifferenceAddressSetView`. See the module docs for the
/// recompute-vs-lazy-stream distinction.
pub struct DifferenceAddressSetView {
    /// The minuend.
    a: Box<dyn AddressSetView>,
    /// The subtrahend.
    b: Box<dyn AddressSetView>,
}

impl DifferenceAddressSetView {
    /// Construct the difference between two address sets (`a` minus `b`).
    pub fn new(a: Box<dyn AddressSetView>, b: Box<dyn AddressSetView>) -> Self {
        Self { a, b }
    }

    /// Port of the Java `static AddressRange truncate(AddressRange rng, Address address,
    /// AddressSetView v)` helper: clips `rng` (a range of `a` known to contain `address`) so it
    /// excludes any portion covered by `v`'s (`b`'s) immediately preceding/following ranges.
    ///
    /// `pub(crate)` (rather than private) because Java declares this `protected static`, making
    /// it visible to other classes in the same package -- `SymmetricDifferenceAddressSetView`
    /// (`symmetric_difference_address_set_view.rs`) reuses it the same way Java's
    /// `SymmetricDifferenceAddressSetView.getRangeContaining` calls
    /// `DifferenceAddressSetView.truncate` directly.
    pub(crate) fn truncate(rng: &AddressRange, address: &Address, v: &dyn AddressSetView) -> AddressRange {
        let prev = v.address_ranges_from(address, false).next();
        let next = v.address_ranges_from(address, true).next();

        let trunc_prev = prev.as_ref().is_some_and(|p| p.intersects(rng));
        let trunc_next = next.as_ref().is_some_and(|n| n.intersects(rng));
        if !trunc_prev && !trunc_next {
            return rng.clone();
        }
        let min = if trunc_prev {
            prev.unwrap()
                .max_address()
                .next()
                .expect("address overflow while truncating DifferenceAddressSetView range (prev)")
        } else {
            rng.min_address().clone()
        };
        let max = if trunc_next {
            next.unwrap()
                .min_address()
                .previous()
                .expect("address overflow while truncating DifferenceAddressSetView range (next)")
        } else {
            rng.max_address().clone()
        };
        AddressRange::new(min, max)
    }
}

impl AbstractAddressSetView for DifferenceAddressSetView {
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.a.subtract(self.b.as_ref()).address_ranges()
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.subtract(self.b.as_ref()).address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.a.subtract(self.b.as_ref()).address_ranges_from(start, forward)
    }
}

impl AddressSetView for DifferenceAddressSetView {
    /// Matches Java's `DifferenceAddressSetView.contains(Address)` override.
    /// `AbstractAddressSetView` has no default for plain single-address `contains`, so every
    /// implementor (Java's included) must supply this directly.
    fn contains(&self, address: &Address) -> bool {
        self.a.contains(address) && !self.b.contains(address)
    }

    /// Matches Java's `DifferenceAddressSetView.contains(Address, Address)` override.
    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.a.contains_range(start, end) && !self.b.intersects_range(start, end)
    }

    /// Matches Java's `DifferenceAddressSetView.contains(AddressSetView)` override.
    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        self.a.contains_set(set) && !self.b.intersects_set(set)
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

    /// Matches Java's `DifferenceAddressSetView.getRangeContaining(Address)` override: find `a`'s
    /// range containing `address` (if none, `address` cannot be in `a - b`); if `b` also has a
    /// range containing `address`, `address` is covered by `b` and so excluded from `a - b`
    /// entirely (`None`); otherwise, truncate `a`'s range against `b`'s neighboring ranges via
    /// [`Self::truncate`].
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        let rng = self.a.range_containing(address)?;
        if self.b.range_containing(address).is_some() {
            return None;
        }
        Some(Self::truncate(&rng, address, self.b.as_ref()))
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
    use super::DifferenceAddressSetView;
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
    fn subtracting_a_disjoint_set_leaves_a_unchanged() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x1005)])),
            Box::new(set(&[(0x2000, 0x2005)])),
        );
        assert_eq!(view.num_address_ranges(), 1);
        assert!(view.contains(&addr(0x1002)));
        assert_eq!(
            view.range_containing(&addr(0x1002)),
            Some(AddressRange::new(addr(0x1000), addr(0x1005)))
        );
    }

    #[test]
    fn subtracting_a_middle_chunk_splits_the_range() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1005, 0x1008)])),
        );
        assert_eq!(view.num_address_ranges(), 2);
        assert!(view.contains(&addr(0x1002)));
        assert!(!view.contains(&addr(0x1006)));
        assert!(view.contains(&addr(0x100a)));

        // Addresses just outside the removed chunk should have their `a` range truncated right up
        // to the boundary, not merely reported as `a`'s original (unsplit) range.
        assert_eq!(
            view.range_containing(&addr(0x1002)),
            Some(AddressRange::new(addr(0x1000), addr(0x1004)))
        );
        assert_eq!(
            view.range_containing(&addr(0x100a)),
            Some(AddressRange::new(addr(0x1009), addr(0x100f)))
        );
        assert_eq!(view.range_containing(&addr(0x1006)), None);
    }

    #[test]
    fn subtracting_a_prefix_truncates_only_from_the_front() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1000, 0x1005)])),
        );
        assert_eq!(
            view.range_containing(&addr(0x1008)),
            Some(AddressRange::new(addr(0x1006), addr(0x100f)))
        );
        assert_eq!(view.range_containing(&addr(0x1002)), None);
    }

    #[test]
    fn fully_covered_range_yields_empty_difference() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1000, 0x100f)])),
        );
        assert!(view.is_empty());
        assert_eq!(view.range_containing(&addr(0x1005)), None);
    }

    #[test]
    fn contains_range_and_set_require_no_intersection_with_b() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1008, 0x1010)])),
        );
        assert!(view.contains_range(&addr(0x1000), &addr(0x1007)));
        assert!(!view.contains_range(&addr(0x1000), &addr(0x1009)));

        let clean = set(&[(0x1001, 0x1002)]);
        assert!(view.contains_set(&clean));
        let overlapping = set(&[(0x1007, 0x1009)]);
        assert!(!view.contains_set(&overlapping));
    }

    #[test]
    fn works_through_dyn_address_set_view_dispatch() {
        let view = DifferenceAddressSetView::new(
            Box::new(set(&[(0x1000, 0x100f)])),
            Box::new(set(&[(0x1005, 0x1008)])),
        );
        let dyn_view: &dyn AddressSetView = &view;
        assert_eq!(dyn_view.num_address_ranges(), 2);
        assert!(!dyn_view.contains(&addr(0x1006)));
    }
}
