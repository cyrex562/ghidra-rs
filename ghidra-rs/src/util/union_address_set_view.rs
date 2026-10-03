//! Port of `ghidra.util.UnionAddressSetView`.
//!
//! Java's `UnionAddressSetView extends AbstractAddressSetView` and lazily computes the union of
//! an arbitrary collection of [`AddressSetView`]s by delegating `getAddressRanges(...)` to
//! `AddressRangeIterators.union(...)`, which walks a
//! `TwoWayBreakdownAddressRangeIterator`-style merge over the input iterators without ever
//! materializing the combined set. Porting that merge machinery
//! (`AddressRangeIterators`/`UnionAddressRangeIterator`, both still `TODO` in `PORT_MANIFEST.tsv`)
//! is out of scope here; instead -- following the precedent already established by this crate's
//! [`AbstractAddressSetView`] port ("the default bodies... recompute the same results directly...
//! rather than introducing placeholder collaborators for classes whose sole purpose is an
//! alternate (lazy) computation strategy") -- the three range-producing methods recompute the
//! merged, coalesced [`AddressSet`] on every call via [`AddressSet::add_set`], which already
//! implements the same "combine intersecting and abutting ranges" contract the Java doc comment
//! describes, and simply borrow that already-tested type's `address_ranges*` methods. The
//! *observable* range sequence (values, order, coalescing) is therefore identical to Java's lazy
//! version; only the eagerness/complexity differs, which no caller of [`AddressSetView`] can
//! observe.
//!
//! Every method [`UnionAddressSetView`] overrides here (`contains`, `is_empty`, `min_address`,
//! `max_address`, plus the three range-producing methods) mirrors an explicit override in
//! `UnionAddressSetView.java`; every other [`AddressSetView`] method is inherited unchanged from
//! [`AbstractAddressSetView`]'s defaults, exactly as in Java (where `UnionAddressSetView` does not
//! override e.g. `getNumAddresses`, `intersect`, `contains(AddressSetView)`, ...).

use crate::program::model::address::{
    Address, BoxedAddressIterator, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
};
use crate::util::abstract_address_set_view::AbstractAddressSetView;
use crate::util::MathUtilities;

/// A lazily-recomputed [`AddressSetView`] defined as the union of many given
/// [`AddressSetView`]s.
///
/// Port of `ghidra.util.UnionAddressSetView`. See the module docs for the recompute-vs-lazily
/// stream distinction.
pub struct UnionAddressSetView {
    views: Vec<Box<dyn AddressSetView>>,
}

impl UnionAddressSetView {
    /// Construct the union of the given address set views.
    ///
    /// Matches Java's `UnionAddressSetView(AddressSetView...)`/`UnionAddressSetView(Collection<AddressSetView>)`
    /// constructors, unified into a single `Vec`-taking constructor since Rust has no varargs.
    pub fn new(views: Vec<Box<dyn AddressSetView>>) -> Self {
        Self { views }
    }

    /// Recomputes the coalesced union of all input views as a materialized [`AddressSet`].
    fn merged(&self) -> AddressSet {
        let mut result = AddressSet::new();
        for view in &self.views {
            result.add_set(view.as_ref());
        }
        result
    }
}

impl AbstractAddressSetView for UnionAddressSetView {
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.merged().address_ranges()
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.merged().address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.merged().address_ranges_from(start, forward)
    }

    /// Matches Java's `UnionAddressSetView.isEmpty()` override: true only if every input view is
    /// empty (short-circuits on the first non-empty view), rather than falling back to
    /// `AbstractAddressSetView`'s generic `getAddressRanges().hasNext()`-based default.
    fn is_empty(&self) -> bool {
        self.views.iter().all(|view| view.is_empty())
    }

    /// Matches Java's `UnionAddressSetView.getMinAddress()` override: the minimum of every input
    /// view's own minimum address, skipping views with no minimum (i.e. empty views). Returns
    /// `None` (Java: `null`) if there are no views or all are empty.
    fn min_address(&self) -> Option<Address> {
        self.views
            .iter()
            .filter_map(|view| view.min_address())
            .reduce(MathUtilities::cmin)
    }

    /// Matches Java's `UnionAddressSetView.getMaxAddress()` override; see [`Self::min_address`].
    fn max_address(&self) -> Option<Address> {
        self.views
            .iter()
            .filter_map(|view| view.max_address())
            .reduce(MathUtilities::cmax)
    }
}

impl AddressSetView for UnionAddressSetView {
    /// Matches Java's `UnionAddressSetView.contains(Address)` override: true if any input view
    /// contains the address (short-circuits on the first match). `AbstractAddressSetView` has no
    /// default for plain single-address `contains`, so every implementor (Java's included) must
    /// supply this directly.
    fn contains(&self, address: &Address) -> bool {
        self.views.iter().any(|view| view.contains(address))
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

    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        AbstractAddressSetView::range_containing(self, address)
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        AbstractAddressSetView::find_first_address_in_common(self, set)
    }
}

#[cfg(test)]
mod tests {
    // Deliberately not `use super::*`: that would also bring `AbstractAddressSetView` into
    // scope, and since `UnionAddressSetView` implements both it and `AddressSetView` with
    // overlapping method names (`contains_range`, `min_address`, `address_ranges`, ...), calling
    // them as plain `view.method(...)` on the concrete (non-`dyn`) type would be ambiguous.
    // Importing only `AddressSetView` here makes every such call resolve unambiguously through
    // it, matching how any other external caller of this type would use it.
    use super::UnionAddressSetView;
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
    fn empty_when_all_views_empty() {
        let view = UnionAddressSetView::new(vec![Box::new(AddressSet::new()), Box::new(AddressSet::new())]);
        assert!(view.is_empty());
        assert_eq!(view.min_address(), None);
        assert_eq!(view.max_address(), None);
    }

    #[test]
    fn coalesces_overlapping_and_abutting_ranges_across_views() {
        // Java doc: "the union of [[1,2]] and [[3,4]] is [[1,4]]" (abutting ranges coalesce).
        let view = UnionAddressSetView::new(vec![
            Box::new(set(&[(0x1000, 0x1002)])),
            Box::new(set(&[(0x1003, 0x1004)])),
        ]);
        assert_eq!(view.num_address_ranges(), 1);
        assert!(view.contains(&addr(0x1003)));
        assert_eq!(view.min_address(), Some(addr(0x1000)));
        assert_eq!(view.max_address(), Some(addr(0x1004)));
    }

    #[test]
    fn overlapping_ranges_from_different_views_merge() {
        let view = UnionAddressSetView::new(vec![
            Box::new(set(&[(0x1000, 0x1010)])),
            Box::new(set(&[(0x1008, 0x1020)])),
        ]);
        assert_eq!(view.num_address_ranges(), 1);
        assert_eq!(view.min_address(), Some(addr(0x1000)));
        assert_eq!(view.max_address(), Some(addr(0x1020)));
        assert_eq!(view.num_addresses(), 0x21);
    }

    #[test]
    fn disjoint_ranges_stay_separate_and_contains_checks_every_view() {
        let view = UnionAddressSetView::new(vec![
            Box::new(set(&[(0x1000, 0x1002)])),
            Box::new(set(&[(0x2000, 0x2002)])),
        ]);
        assert_eq!(view.num_address_ranges(), 2);
        assert!(view.contains(&addr(0x1001)));
        assert!(view.contains(&addr(0x2001)));
        assert!(!view.contains(&addr(0x1800)));
    }

    #[test]
    fn min_and_max_skip_empty_views() {
        let view = UnionAddressSetView::new(vec![
            Box::new(AddressSet::new()),
            Box::new(set(&[(0x1000, 0x1002)])),
            Box::new(AddressSet::new()),
        ]);
        assert_eq!(view.min_address(), Some(addr(0x1000)));
        assert_eq!(view.max_address(), Some(addr(0x1002)));
        assert!(!view.is_empty());
    }

    #[test]
    fn address_ranges_from_matches_generic_address_set_semantics() {
        let view = UnionAddressSetView::new(vec![
            Box::new(set(&[(0x1000, 0x1005), (0x2000, 0x2005)])),
        ]);
        let mut it = view.address_ranges_from(&addr(0x1800), true);
        let first = it.next().unwrap();
        assert_eq!(first.min_address(), &addr(0x2000));
        assert!(it.next().is_none());
    }

    #[test]
    fn no_views_is_empty_with_no_bounds() {
        let view = UnionAddressSetView::new(vec![]);
        assert!(view.is_empty());
        assert_eq!(view.min_address(), None);
        assert_eq!(view.max_address(), None);
        assert_eq!(view.num_address_ranges(), 0);
    }

    #[test]
    fn works_through_dyn_address_set_view_dispatch() {
        let view = UnionAddressSetView::new(vec![Box::new(set(&[(0x1000, 0x1002)]))]);
        let dyn_view: &dyn AddressSetView = &view;
        assert!(dyn_view.contains(&addr(0x1001)));
        assert_eq!(dyn_view.num_address_ranges(), 1);
        assert_eq!(dyn_view.first_range(), Some(AddressRange::new(addr(0x1000), addr(0x1002))));
    }
}
