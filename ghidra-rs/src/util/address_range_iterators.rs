use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::util::seam_stubs::{TwoWayBreakdownFactory, UnionAddressRangeIteratorFactory};
use std::cell::RefCell;

/// Wraps a plain `Iterator<Item = AddressRange>` so it satisfies [`AddressRangeIterator`].
///
/// Mirrors the private `WrappingAddressRangeIterator` inner class of Ghidra's
/// `AddressRangeIterators`. Uses `RefCell` to cache the peeked next element, since
/// `AddressRangeIterator::has_next` takes `&self` while the wrapped iterator's `next()`
/// requires `&mut self`.
pub struct WrappingAddressRangeIterator {
    iterator: RefCell<Box<dyn Iterator<Item = AddressRange>>>,
    cached_next: RefCell<Option<Option<AddressRange>>>,
}

impl WrappingAddressRangeIterator {
    /// Creates a wrapper over the supplied iterator.
    pub fn new(iterator: Box<dyn Iterator<Item = AddressRange>>) -> Self {
        Self {
            iterator: RefCell::new(iterator),
            cached_next: RefCell::new(None),
        }
    }

    fn ensure_cached(&self) {
        if self.cached_next.borrow().is_none() {
            let next = self.iterator.borrow_mut().next();
            *self.cached_next.borrow_mut() = Some(next);
        }
    }
}

impl AddressRangeIterator for WrappingAddressRangeIterator {
    fn has_next(&self) -> bool {
        self.ensure_cached();
        self.cached_next.borrow().as_ref().map(|opt| opt.is_some()).unwrap_or(false)
    }

    fn next_range(&mut self) -> Option<AddressRange> {
        self.ensure_cached();
        self.cached_next.borrow_mut().take().flatten()
    }
}

/// Returns whether `range` should be included given the iteration `start` bound.
///
/// Mirrors the protected `doCheckStart` helper of Ghidra's `AddressRangeIterators`.
fn check_start(range: &AddressRange, start: Option<&Address>, forward: bool) -> bool {
    match start {
        None => true,
        Some(start) => {
            if forward {
                range.max_address() >= start
            } else {
                range.min_address() <= start
            }
        }
    }
}

/// Factory for lazily-computed set operations over [`AddressRangeIterator`]s.
///
/// Mirrors Ghidra's `AddressRangeIterators`, a zero-variant enum used purely as a namespace
/// of static factory methods. Rust has no direct equivalent of a static-only class, so this
/// is expressed as an object-safe trait with default method bodies (the type carries no
/// state, matching the Java original).
///
/// The `union` and `subtract`/`xor`/`intersect` methods depend on Ghidra's
/// `UnionAddressRangeIterator` and `TwoWayBreakdownAddressRangeIterator`, which are not yet
/// ported. Rather than porting those algorithms here, this trait takes the minimal
/// placeholder factories [`UnionAddressRangeIteratorFactory`] and [`TwoWayBreakdownFactory`]
/// (see `seam_stubs`) as injected collaborators, exactly as the Java methods delegate
/// construction to those other classes.
pub trait AddressRangeIteratorFactory {
    /// Wraps a plain iterator of `AddressRange` so it satisfies [`AddressRangeIterator`].
    ///
    /// Mirrors `AddressRangeIterators.castOrWrap`.
    fn cast_or_wrap(&self, it: Box<dyn Iterator<Item = AddressRange>>) -> Box<dyn AddressRangeIterator> {
        Box::new(WrappingAddressRangeIterator::new(it))
    }

    /// Creates an iterator over the union of address ranges produced by `iterators`.
    ///
    /// Mirrors `AddressRangeIterators.union`.
    fn union(
        &self,
        union_factory: &dyn UnionAddressRangeIteratorFactory,
        iterators: Vec<Box<dyn Iterator<Item = AddressRange>>>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator> {
        union_factory.build_union(iterators, forward)
    }

    /// Creates an iterator over the difference `a - b`.
    ///
    /// Mirrors `AddressRangeIterators.subtract`.
    fn subtract(
        &self,
        breakdown_factory: &dyn TwoWayBreakdownFactory,
        a: Box<dyn Iterator<Item = AddressRange>>,
        b: Box<dyn Iterator<Item = AddressRange>>,
        start: Option<Address>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator> {
        let breakdown = breakdown_factory.build_breakdown(a, b, forward);
        let ranges: Vec<AddressRange> = breakdown
            .filter(|entry| check_start(&entry.range, start.as_ref(), forward) && entry.in_subtract())
            .map(|entry| entry.range)
            .collect();
        Box::new(WrappingAddressRangeIterator::new(Box::new(ranges.into_iter())))
    }

    /// Creates an iterator over the symmetric difference of `a` and `b`.
    ///
    /// Mirrors `AddressRangeIterators.xor`.
    fn xor(
        &self,
        breakdown_factory: &dyn TwoWayBreakdownFactory,
        union_factory: &dyn UnionAddressRangeIteratorFactory,
        a: Box<dyn Iterator<Item = AddressRange>>,
        b: Box<dyn Iterator<Item = AddressRange>>,
        start: Option<Address>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator> {
        let breakdown = breakdown_factory.build_breakdown(a, b, forward);
        let xor_ranges: Vec<AddressRange> =
            breakdown.filter(|entry| entry.in_xor()).map(|entry| entry.range).collect();
        // Use union to coalesce just-connected ranges from opposite iterators.
        let mut unioned = union_factory.build_union(vec![Box::new(xor_ranges.into_iter())], forward);
        let mut result = Vec::new();
        // Have to filter by start after the union, otherwise parts of ranges are omitted.
        while unioned.has_next() {
            match unioned.next_range() {
                Some(range) => {
                    if check_start(&range, start.as_ref(), forward) {
                        result.push(range);
                    }
                }
                None => break,
            }
        }
        Box::new(WrappingAddressRangeIterator::new(Box::new(result.into_iter())))
    }

    /// Creates an iterator over the intersection of `a` and `b`.
    ///
    /// Mirrors `AddressRangeIterators.intersect`.
    fn intersect(
        &self,
        breakdown_factory: &dyn TwoWayBreakdownFactory,
        a: Box<dyn Iterator<Item = AddressRange>>,
        b: Box<dyn Iterator<Item = AddressRange>>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator> {
        let breakdown = breakdown_factory.build_breakdown(a, b, forward);
        let ranges: Vec<AddressRange> =
            breakdown.filter(|entry| entry.in_intersect()).map(|entry| entry.range).collect();
        Box::new(WrappingAddressRangeIterator::new(Box::new(ranges.into_iter())))
    }
}

/// Default, stateless implementation of [`AddressRangeIteratorFactory`].
///
/// Mirrors calling the static methods on Ghidra's `AddressRangeIterators` directly, since
/// that Java type has no instances (or subclasses) to vary behavior.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAddressRangeIteratorFactory;

impl AddressRangeIteratorFactory for DefaultAddressRangeIteratorFactory {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::seam_stubs::TwoWayBreakdownEntry;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn range(start: i64, end: i64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    /// Mock breakdown factory: classifies two single-range iterators by simple overlap.
    struct MockBreakdown;

    impl TwoWayBreakdownFactory for MockBreakdown {
        fn build_breakdown(
            &self,
            a: Box<dyn Iterator<Item = AddressRange>>,
            b: Box<dyn Iterator<Item = AddressRange>>,
            _forward: bool,
        ) -> Box<dyn Iterator<Item = TwoWayBreakdownEntry>> {
            let a_ranges: Vec<AddressRange> = a.collect();
            let b_ranges: Vec<AddressRange> = b.collect();
            let mut entries = Vec::new();
            for r in &a_ranges {
                let overlaps = b_ranges.iter().any(|br| br.min_address() <= r.max_address() && br.max_address() >= r.min_address());
                entries.push(TwoWayBreakdownEntry {
                    range: r.clone(),
                    in_a_only: !overlaps,
                    in_b_only: false,
                    in_both: overlaps,
                });
            }
            for r in &b_ranges {
                let overlaps = a_ranges.iter().any(|ar| ar.min_address() <= r.max_address() && ar.max_address() >= r.min_address());
                if !overlaps {
                    entries.push(TwoWayBreakdownEntry {
                        range: r.clone(),
                        in_a_only: false,
                        in_b_only: true,
                        in_both: false,
                    });
                }
            }
            Box::new(entries.into_iter())
        }
    }

    /// Mock union factory: sorts and returns ranges without coalescing (sufficient for tests).
    struct MockUnion;

    impl UnionAddressRangeIteratorFactory for MockUnion {
        fn build_union(
            &self,
            iterators: Vec<Box<dyn Iterator<Item = AddressRange>>>,
            forward: bool,
        ) -> Box<dyn AddressRangeIterator> {
            let mut ranges: Vec<AddressRange> = iterators.into_iter().flatten().collect();
            ranges.sort_by(|a, b| {
                if forward {
                    a.min_address().cmp(b.min_address())
                } else {
                    b.max_address().cmp(a.max_address())
                }
            });
            Box::new(WrappingAddressRangeIterator::new(Box::new(ranges.into_iter())))
        }
    }

    #[test]
    fn cast_or_wrap_iterates_and_terminates() {
        let factory = DefaultAddressRangeIteratorFactory;
        let ranges = vec![range(0x1000, 0x100f), range(0x2000, 0x200f)];
        let mut wrapped = factory.cast_or_wrap(Box::new(ranges.clone().into_iter()));

        assert!(wrapped.has_next());
        assert_eq!(wrapped.next_range(), Some(ranges[0].clone()));
        assert!(wrapped.has_next());
        assert_eq!(wrapped.next_range(), Some(ranges[1].clone()));
        assert!(!wrapped.has_next());
        assert_eq!(wrapped.next_range(), None);
    }

    #[test]
    fn union_delegates_to_injected_factory_via_trait_object() {
        // Proves AddressRangeIteratorFactory is object-safe: called through &dyn.
        let factory: &dyn AddressRangeIteratorFactory = &DefaultAddressRangeIteratorFactory;
        let union_factory = MockUnion;

        let iterators: Vec<Box<dyn Iterator<Item = AddressRange>>> = vec![
            Box::new(vec![range(0x2000, 0x2100)].into_iter()),
            Box::new(vec![range(0x1000, 0x1100)].into_iter()),
        ];
        let mut unioned = factory.union(&union_factory, iterators, true);

        assert_eq!(unioned.next_range(), Some(range(0x1000, 0x1100)));
        assert_eq!(unioned.next_range(), Some(range(0x2000, 0x2100)));
        assert_eq!(unioned.next_range(), None);
    }

    #[test]
    fn subtract_keeps_only_ranges_unique_to_a_after_start() {
        let factory = DefaultAddressRangeIteratorFactory;
        let breakdown = MockBreakdown;

        let a: Box<dyn Iterator<Item = AddressRange>> =
            Box::new(vec![range(0x1000, 0x1100), range(0x3000, 0x3100)].into_iter());
        let b: Box<dyn Iterator<Item = AddressRange>> = Box::new(vec![range(0x1000, 0x1100)].into_iter());

        let mut result = factory.subtract(&breakdown, a, b, None, true);
        assert_eq!(result.next_range(), Some(range(0x3000, 0x3100)));
        assert_eq!(result.next_range(), None);
    }

    #[test]
    fn subtract_respects_start_bound() {
        let factory = DefaultAddressRangeIteratorFactory;
        let breakdown = MockBreakdown;

        let a: Box<dyn Iterator<Item = AddressRange>> =
            Box::new(vec![range(0x1000, 0x1100), range(0x3000, 0x3100)].into_iter());
        let b: Box<dyn Iterator<Item = AddressRange>> = Box::new(vec![].into_iter());

        // Start after the first range's max address excludes it (forward iteration).
        let mut result = factory.subtract(&breakdown, a, b, Some(addr(0x2000)), true);
        assert_eq!(result.next_range(), Some(range(0x3000, 0x3100)));
        assert_eq!(result.next_range(), None);
    }

    #[test]
    fn intersect_keeps_only_overlapping_ranges() {
        let factory = DefaultAddressRangeIteratorFactory;
        let breakdown = MockBreakdown;

        let a: Box<dyn Iterator<Item = AddressRange>> =
            Box::new(vec![range(0x1000, 0x1100), range(0x3000, 0x3100)].into_iter());
        let b: Box<dyn Iterator<Item = AddressRange>> = Box::new(vec![range(0x1000, 0x1100)].into_iter());

        let mut result = factory.intersect(&breakdown, a, b, true);
        assert_eq!(result.next_range(), Some(range(0x1000, 0x1100)));
        assert_eq!(result.next_range(), None);
    }

    #[test]
    fn xor_unions_the_non_overlapping_ranges_from_both_sides() {
        let factory = DefaultAddressRangeIteratorFactory;
        let breakdown = MockBreakdown;
        let union_factory = MockUnion;

        let a: Box<dyn Iterator<Item = AddressRange>> =
            Box::new(vec![range(0x1000, 0x1100)].into_iter());
        let b: Box<dyn Iterator<Item = AddressRange>> =
            Box::new(vec![range(0x2000, 0x2100)].into_iter());

        let mut result = factory.xor(&breakdown, &union_factory, a, b, None, true);
        assert_eq!(result.next_range(), Some(range(0x1000, 0x1100)));
        assert_eq!(result.next_range(), Some(range(0x2000, 0x2100)));
        assert_eq!(result.next_range(), None);
    }
}
