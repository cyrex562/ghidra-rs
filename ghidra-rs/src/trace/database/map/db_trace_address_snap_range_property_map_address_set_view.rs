//! Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapAddressSetView`.
//!
//! This class was selected as a dependency-cycle cut-point. Its Java superclass,
//! `AbstractAddressSetView`, declares `contains(Address)`/`isEmpty()`/`getMinAddress()`/
//! `getMaxAddress()`/`getAddressRanges(Address, boolean)` as abstract (no default), so this class
//! must supply real implementations for them -- backed by testing a
//! [`SpatialMap`](crate::util::database::spatial::spatial_map::SpatialMap)`<TraceAddressSnapRange,
//! T, _>`'s entries against a predicate, under a read/write lock -- while every other
//! `AddressSetView` method it overrides (`getNumAddressRanges`, `getAddressRanges()`/`(boolean)`,
//! `getNumAddresses`, `intersects*`, `intersect*`, `union`, `subtract`, `xor`, `hasSameAddresses`,
//! `get{First,Last}Range`, `getRangeContaining`, `findFirstAddressInCommon`) merely re-adds the
//! same lock around a call to the superclass's default.
//!
//! Unlike the Java `AbstractAddressSetView`, the already-ported
//! [`AbstractAddressSetView`](crate::util::abstract_address_set_view::AbstractAddressSetView)
//! trait supplies default bodies for *all* of those atop just three "primitive" range-iteration
//! methods, and the already-ported
//! [`AddressSetView`](crate::program::model::address::AddressSetView) trait is exactly the full
//! method set this class overrides (including `contains(Address)`, which
//! `AbstractAddressSetView` leaves unimplemented in Rust too). So this class's entire public
//! contract -- lock-guarded or not -- already maps 1:1 onto [`AddressSetView`]; there is no added
//! method to declare. This port is therefore a supertrait bound, not a new method set: any type
//! implementing [`AddressSetView`] already satisfies it.
//!
//! The constructor -- and the `AddressSpace`/`ReadWriteLock`/`SpatialMap`/`Predicate` dependencies
//! it takes to build the lock-guarded, predicate-filtered view -- is implementation, not public
//! contract, so it is not represented here, matching the convention set by sibling cut-point ports
//! (e.g. [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)).
//!
//! `T` stands in for the Java class's own `T` type parameter (the property map's value type); it
//! does not appear in any method this class adds, so it is not reflected in the trait either.
use crate::program::model::address::AddressSetView;

/// An [`AddressSetView`] computed on demand from a spatial map's entries whose values pass a
/// predicate, guarded by a read/write lock.
///
/// Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapAddressSetView<T>`.
pub trait DBTraceAddressSnapRangePropertyMapAddressSetView: AddressSetView + Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressIteratorAdapter, AddressRange, AddressRangeIterator,
        AddressRangeIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType,
        BoxedAddressIterator,
    };
    use std::sync::Arc;

    /// Mirrors the real class's shape: a fixed set of `(range, value)` entries plus a predicate,
    /// with every [`AddressSetView`] method computed by filtering entries through the predicate --
    /// exactly what `DBTraceAddressSnapRangePropertyMapAddressSetView` does against its
    /// `SpatialMap`, minus the R*-tree storage and locking.
    struct PredicateFilteredView {
        entries: Vec<(AddressRange, i32)>,
        predicate: Box<dyn Fn(&i32) -> bool + Send + Sync>,
    }

    impl PredicateFilteredView {
        fn passing_ranges(&self) -> Vec<AddressRange> {
            self.entries
                .iter()
                .filter(|(_, v)| (self.predicate)(v))
                .map(|(r, _)| r.clone())
                .collect()
        }
    }

    impl AddressSetView for PredicateFilteredView {
        fn contains(&self, address: &Address) -> bool {
            self.entries
                .iter()
                .any(|(r, v)| r.contains(address) && (self.predicate)(v))
        }

        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            let target = AddressRange::new(start.clone(), end.clone());
            self.passing_ranges().iter().any(|r| {
                r.min_address() <= target.min_address() && r.max_address() >= target.max_address()
            })
        }

        fn contains_set(&self, set: &dyn AddressSetView) -> bool {
            let mut it = set.address_ranges();
            while let Some(range) = it.next_range() {
                if !self.contains_range(range.min_address(), range.max_address()) {
                    return false;
                }
            }
            true
        }

        fn is_empty(&self) -> bool {
            self.entries.iter().all(|(_, v)| !(self.predicate)(v))
        }

        fn min_address(&self) -> Option<Address> {
            self.passing_ranges()
                .iter()
                .map(|r| r.min_address().clone())
                .min()
        }

        fn max_address(&self) -> Option<Address> {
            self.passing_ranges()
                .iter()
                .map(|r| r.max_address().clone())
                .max()
        }

        fn num_address_ranges(&self) -> usize {
            self.passing_ranges().len()
        }

        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            Box::new(AddressRangeIteratorAdapter::new(self.passing_ranges()))
        }

        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
            let mut ranges = self.passing_ranges();
            ranges.sort_by(|a, b| a.min_address().cmp(b.min_address()));
            if !forward {
                ranges.reverse();
            }
            Box::new(AddressRangeIteratorAdapter::new(ranges))
        }

        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
            let mut ranges: Vec<AddressRange> = self
                .passing_ranges()
                .into_iter()
                .filter(|r| if forward { r.max_address() >= start } else { r.min_address() <= start })
                .collect();
            ranges.sort_by(|a, b| a.min_address().cmp(b.min_address()));
            if !forward {
                ranges.reverse();
            }
            Box::new(AddressRangeIteratorAdapter::new(ranges))
        }

        fn num_addresses(&self) -> u64 {
            self.passing_ranges().iter().map(|r| r.length()).sum()
        }

        fn addresses(&self, forward: bool) -> BoxedAddressIterator {
            let mut it = self.address_ranges_ordered(forward);
            let mut addrs = Vec::new();
            while let Some(range) = it.next_range() {
                addrs.extend(range.addresses());
            }
            Box::new(AddressIteratorAdapter::new(addrs.into_iter()))
        }

        fn addresses_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
            let mut it = self.address_ranges_from(start, forward);
            let mut addrs = Vec::new();
            while let Some(range) = it.next_range() {
                addrs.extend(range.addresses());
            }
            Box::new(AddressIteratorAdapter::new(addrs.into_iter()))
        }

        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            let mut it = set.address_ranges();
            while let Some(r) = it.next_range() {
                if self.intersects_range(r.min_address(), r.max_address()) {
                    return true;
                }
            }
            false
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            let target = AddressRange::new(start.clone(), end.clone());
            self.passing_ranges().iter().any(|r| r.intersects(&target))
        }

        fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
            let mut result = AddressSet::new();
            for r in self.passing_ranges() {
                let mut it = set.address_ranges();
                while let Some(other) = it.next_range() {
                    if let Some(overlap) = r.intersect(&other) {
                        result.add_range_object(&overlap);
                    }
                }
            }
            result
        }

        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.intersect(&AddressSet::from_start_end(start.clone(), end.clone()))
        }

        fn union(&self, set: &dyn AddressSetView) -> AddressSet {
            let mut result = AddressSet::new();
            for r in self.passing_ranges() {
                result.add_range_object(&r);
            }
            result.add_set(set);
            result
        }

        fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
            let mut result = AddressSet::new();
            for r in self.passing_ranges() {
                result.add_range_object(&r);
            }
            result.delete_set(set);
            result
        }

        fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
            let mut result = self.union(set);
            result.delete_set(&self.intersect(set));
            result
        }

        fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
            let mut a = self.address_ranges();
            let mut b = set.address_ranges();
            loop {
                match (a.next_range(), b.next_range()) {
                    (Some(x), Some(y)) => {
                        if x != y {
                            return false;
                        }
                    }
                    (None, None) => return true,
                    _ => return false,
                }
            }
        }

        fn first_range(&self) -> Option<AddressRange> {
            self.address_ranges_ordered(true).next_range()
        }

        fn last_range(&self) -> Option<AddressRange> {
            self.address_ranges_ordered(false).next_range()
        }

        fn range_containing(&self, address: &Address) -> Option<AddressRange> {
            self.passing_ranges().into_iter().find(|r| r.contains(address))
        }

        fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
            self.intersect(set).min_address()
        }
    }

    impl DBTraceAddressSnapRangePropertyMapAddressSetView for PredicateFilteredView {}

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn view() -> PredicateFilteredView {
        let sp = space();
        PredicateFilteredView {
            entries: vec![
                (AddressRange::new(addr(&sp, 0x1000), addr(&sp, 0x1fff)), 1),
                (AddressRange::new(addr(&sp, 0x3000), addr(&sp, 0x3fff)), 0),
            ],
            predicate: Box::new(|v: &i32| *v > 0),
        }
    }

    #[test]
    fn contains_only_honors_entries_passing_the_predicate() {
        let v = view();
        assert!(v.contains(&addr(&space(), 0x1500)));
        assert!(!v.contains(&addr(&space(), 0x3500)));
        assert!(!v.contains(&addr(&space(), 0x9999)));
    }

    #[test]
    fn min_and_max_address_skip_predicate_failing_entries() {
        let v = view();
        assert_eq!(v.min_address(), Some(addr(&space(), 0x1000)));
        assert_eq!(v.max_address(), Some(addr(&space(), 0x1fff)));
        assert!(!v.is_empty());
    }

    #[test]
    fn is_empty_when_no_entry_passes_the_predicate() {
        let sp = space();
        let v = PredicateFilteredView {
            entries: vec![(AddressRange::new(addr(&sp, 0x1000), addr(&sp, 0x1fff)), 0)],
            predicate: Box::new(|v: &i32| *v > 0),
        };
        assert!(v.is_empty());
        assert_eq!(v.min_address(), None);
    }

    #[test]
    fn reachable_and_object_safe_through_the_dyn_trait() {
        let v = view();
        let obj: &dyn DBTraceAddressSnapRangePropertyMapAddressSetView = &v;
        assert_eq!(obj.num_address_ranges(), 1);
        assert!(obj.contains(&addr(&space(), 0x1500)));
    }
}
