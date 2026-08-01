use std::cell::RefCell;
use std::rc::Rc;

use crate::program::model::address::{
    Address, AddressIterator, AddressIteratorAdapter, AddressRange, AddressRangeIterator,
    AddressSet, AddressSetView, EmptyAddressIterator, EmptyAddressRangeIterator,
};
use crate::util::MathUtilities;

/// Read-only, caching view over a delegate [`AddressSetView`] that is expensive to access
/// directly.
///
/// This mirrors Ghidra's `CachedAddressSetView`. It was pulled out as a trait (rather than
/// ported straight to a concrete struct) because it sits at a dependency-cycle cut-point:
/// callers that only need the caching contract can depend on this trait plus the already-ported
/// [`AddressSetView`] supertrait, without depending on the concrete caching strategy in
/// [`CachedAddressSetViewImpl`].
pub trait CachedAddressSetView: AddressSetView {
    /// Clears all cached state and re-initializes the cached bounds from the delegate.
    ///
    /// This mirrors Java's `invalidate()`.
    fn invalidate(&self);
}

/// Shared caching state for a [`CachedAddressSetViewImpl`], held behind an [`Rc`] so that
/// range/address iterators returned from the view can keep populating the cache lazily as
/// they're consumed (matching Java's inner-class `CachedRangeIterator`, which holds a reference
/// back to its enclosing `CachedAddressSetView`).
struct SharedState {
    delegate: Box<dyn AddressSetView>,
    cache: RefCell<AddressSet>,
    known: RefCell<AddressSet>,
    min_address: RefCell<Option<Address>>,
    max_address: RefCell<Option<Address>>,
    num_ranges: RefCell<Option<usize>>,
    num_addresses: RefCell<Option<u64>>,
}

impl SharedState {
    fn new(delegate: Box<dyn AddressSetView>) -> Self {
        let state = Self {
            delegate,
            cache: RefCell::new(AddressSet::new()),
            known: RefCell::new(AddressSet::new()),
            min_address: RefCell::new(None),
            max_address: RefCell::new(None),
            num_ranges: RefCell::new(None),
            num_addresses: RefCell::new(None),
        };
        state.init();
        state
    }

    fn init(&self) {
        *self.min_address.borrow_mut() = self.delegate.min_address();
        *self.max_address.borrow_mut() = self.delegate.max_address();
    }

    fn invalidate(&self) {
        self.cache.borrow_mut().clear();
        self.known.borrow_mut().clear();
        *self.num_ranges.borrow_mut() = None;
        *self.num_addresses.borrow_mut() = None;
        self.init();
    }

    fn add_mixed(set: &mut AddressSet, min: &Address, max: &Address) {
        if min.space() == max.space() {
            set.add_range(min, max);
        } else {
            set.add_range(min, &min.space().max_address());
            set.add_range(&max.space().min_address(), max);
        }
    }

    /// Ensures the cache holds every range of the delegate that overlaps `[min, max]`.
    ///
    /// This mirrors Java's `ensureKnown(Address, Address)`.
    fn ensure_known(&self, min: &Address, max: &Address) {
        let (bound_min, bound_max) = {
            let bound_min = self.min_address.borrow().clone();
            let bound_max = self.max_address.borrow().clone();
            match (bound_min, bound_max) {
                (Some(mn), Some(mx)) => (mn, mx),
                _ => return,
            }
        };
        if bound_min > *max || bound_max < *min {
            return;
        }
        let min = MathUtilities::cmax(min.clone(), bound_min.clone());
        let max = MathUtilities::cmin(max.clone(), bound_max.clone());

        if self.known.borrow().contains_range(&min, &max) {
            return;
        }

        let mut ranges_backward = self.delegate.address_ranges_from(&min, false);
        if let Some(prev) = ranges_backward.next_range() {
            self.cache.borrow_mut().add_range_object(&prev);
            Self::add_mixed(&mut self.known.borrow_mut(), prev.min_address(), &min);
        } else {
            Self::add_mixed(&mut self.known.borrow_mut(), &bound_min, &min);
        }

        let mut ranges_forward = self.delegate.address_ranges_from(&min, true);
        loop {
            match ranges_forward.next_range() {
                None => {
                    Self::add_mixed(&mut self.known.borrow_mut(), &min, &bound_max);
                    break;
                }
                Some(next) => {
                    self.cache.borrow_mut().add_range_object(&next);
                    if *next.max_address() >= max {
                        Self::add_mixed(&mut self.known.borrow_mut(), &min, next.max_address());
                        break;
                    }
                }
            }
        }
    }

    fn ensure_known_full(&self) {
        let bounds = {
            let mn = self.min_address.borrow().clone();
            let mx = self.max_address.borrow().clone();
            match (mn, mx) {
                (Some(mn), Some(mx)) => Some((mn, mx)),
                _ => None,
            }
        };
        if let Some((mn, mx)) = bounds {
            self.ensure_known(&mn, &mx);
        }
    }
}

/// Lazily caches ranges from a [`SharedState`]'s cache as they're pulled from the delegate.
///
/// This mirrors Java's `CachedAddressSetView.CachedRangeIterator`.
struct CachedRangeIterator {
    shared: Rc<SharedState>,
    cur: RefCell<Option<Address>>,
    forward: bool,
    cached_next: RefCell<Option<Option<AddressRange>>>,
}

impl CachedRangeIterator {
    fn new(shared: Rc<SharedState>, start: Option<Address>, forward: bool) -> Self {
        Self {
            shared,
            cur: RefCell::new(start),
            forward,
            cached_next: RefCell::new(None),
        }
    }

    fn seek_next(&self) -> Option<AddressRange> {
        let cur = self.cur.borrow().clone()?;
        self.shared.ensure_known(&cur, &cur);

        let result = {
            let cache = self.shared.cache.borrow();
            let mut it = cache.address_ranges_from(&cur, self.forward);
            it.next_range()
        }?;

        let next_cur = if self.forward {
            result.max_address().next().ok()
        } else {
            result.min_address().previous().ok()
        };
        *self.cur.borrow_mut() = next_cur;
        Some(result)
    }

    fn ensure_cached(&self) {
        if self.cached_next.borrow().is_none() {
            let next = self.seek_next();
            *self.cached_next.borrow_mut() = Some(next);
        }
    }
}

impl AddressRangeIterator for CachedRangeIterator {
    fn has_next(&self) -> bool {
        self.ensure_cached();
        self.cached_next
            .borrow()
            .as_ref()
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    fn next_range(&mut self) -> Option<AddressRange> {
        self.ensure_cached();
        self.cached_next.borrow_mut().take().flatten()
    }
}

/// Concrete [`CachedAddressSetView`] implementation that wraps an arbitrary delegate
/// [`AddressSetView`] and caches ranges as they're queried.
///
/// This mirrors Ghidra's `CachedAddressSetView` class.
pub struct CachedAddressSetViewImpl {
    shared: Rc<SharedState>,
}

impl CachedAddressSetViewImpl {
    pub fn new(delegate: Box<dyn AddressSetView>) -> Self {
        Self {
            shared: Rc::new(SharedState::new(delegate)),
        }
    }
}

impl AddressSetView for CachedAddressSetViewImpl {
    fn contains(&self, address: &Address) -> bool {
        self.shared.ensure_known(address, address);
        self.shared.cache.borrow().contains(address)
    }

    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.shared.ensure_known(start, end);
        self.shared.cache.borrow().contains_range(start, end)
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
        self.shared.min_address.borrow().is_none()
    }

    fn min_address(&self) -> Option<Address> {
        self.shared.min_address.borrow().clone()
    }

    fn max_address(&self) -> Option<Address> {
        self.shared.max_address.borrow().clone()
    }

    fn num_address_ranges(&self) -> usize {
        let mut cached = self.shared.num_ranges.borrow_mut();
        if cached.is_none() {
            *cached = Some(self.shared.delegate.num_address_ranges());
        }
        cached.unwrap()
    }

    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.address_ranges_ordered(true)
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        let start = if forward {
            self.shared.min_address.borrow().clone()
        } else {
            self.shared.max_address.borrow().clone()
        };
        match start {
            Some(start) => Box::new(CachedRangeIterator::new(
                self.shared.clone(),
                Some(start),
                forward,
            )),
            None => Box::new(EmptyAddressRangeIterator),
        }
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        Box::new(CachedRangeIterator::new(
            self.shared.clone(),
            Some(start.clone()),
            forward,
        ))
    }

    fn num_addresses(&self) -> u64 {
        let mut cached = self.shared.num_addresses.borrow_mut();
        if cached.is_none() {
            *cached = Some(self.shared.delegate.num_addresses());
        }
        cached.unwrap()
    }

    fn addresses(&self, forward: bool) -> Box<dyn AddressIterator> {
        let mut it = self.address_ranges_ordered(true);
        let mut addresses = Vec::new();
        while let Some(range) = it.next_range() {
            addresses.extend(range.addresses());
        }
        if !forward {
            addresses.reverse();
        }
        if addresses.is_empty() {
            Box::new(EmptyAddressIterator)
        } else {
            Box::new(AddressIteratorAdapter::from_vec(addresses))
        }
    }

    fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator> {
        let mut it = self.address_ranges_ordered(true);
        let mut addresses: Vec<Address> = Vec::new();
        while let Some(range) = it.next_range() {
            addresses.extend(range.addresses());
        }
        addresses.retain(|addr| if forward { addr >= start } else { addr <= start });
        if !forward {
            addresses.reverse();
        }
        if addresses.is_empty() {
            Box::new(EmptyAddressIterator)
        } else {
            Box::new(AddressIteratorAdapter::from_vec(addresses))
        }
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        let mut it = set.address_ranges();
        while let Some(range) = it.next_range() {
            if self.intersects_range(range.min_address(), range.max_address()) {
                return true;
            }
        }
        false
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.shared.ensure_known(start, end);
        self.shared.cache.borrow().intersects_range(start, end)
    }

    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        let mut it = set.address_ranges();
        while let Some(range) = it.next_range() {
            let piece = self.intersect_range(range.min_address(), range.max_address());
            result.add_set(&piece);
        }
        result
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.shared.ensure_known(start, end);
        self.shared.cache.borrow().intersect_range(start, end)
    }

    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        self.shared.ensure_known_full();
        self.shared.cache.borrow().union(set)
    }

    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        self.shared.ensure_known_full();
        self.shared.cache.borrow().subtract(set)
    }

    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        self.shared.ensure_known_full();
        self.shared.cache.borrow().xor(set)
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        let mut it = set.address_ranges();
        while let Some(range) = it.next_range() {
            let min = range.min_address();
            self.shared.ensure_known(min, range.max_address());
            match self.shared.cache.borrow().range_containing(min) {
                Some(found) if found == range => {}
                _ => return false,
            }
        }
        true
    }

    fn first_range(&self) -> Option<AddressRange> {
        let min = self.shared.min_address.borrow().clone()?;
        self.shared.ensure_known(&min, &min);
        self.shared.cache.borrow().first_range()
    }

    fn last_range(&self) -> Option<AddressRange> {
        let max = self.shared.max_address.borrow().clone()?;
        self.shared.ensure_known(&max, &max);
        self.shared.cache.borrow().last_range()
    }

    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        self.shared.ensure_known(address, address);
        self.shared.cache.borrow().range_containing(address)
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        let mut it = set.address_ranges();
        while let Some(range) = it.next_range() {
            self.shared
                .ensure_known(range.min_address(), range.max_address());
            let intersection = self
                .shared
                .cache
                .borrow()
                .intersect_range(range.min_address(), range.max_address());
            if let Some(min) = intersection.min_address() {
                return Some(min);
            }
        }
        None
    }
}

impl CachedAddressSetView for CachedAddressSetViewImpl {
    fn invalidate(&self) {
        self.shared.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn delegate_with_ranges() -> AddressSet {
        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1010));
        set.add_range(&addr(0x2000), &addr(0x2010));
        set
    }

    #[test]
    fn object_safe_trait_delegates_reads_and_supports_invalidate() {
        // Proves CachedAddressSetView is object-safe (usable as `Box<dyn CachedAddressSetView>`)
        // while exercising real caching behavior, not a trivially-true assertion.
        let delegate = delegate_with_ranges();
        let view: Box<dyn CachedAddressSetView> =
            Box::new(CachedAddressSetViewImpl::new(Box::new(delegate.clone())));

        assert!(!view.is_empty());
        assert!(view.contains(&addr(0x1005)));
        assert!(!view.contains(&addr(0x1800)));
        assert_eq!(view.min_address(), Some(addr(0x1000)));
        assert_eq!(view.max_address(), Some(addr(0x2010)));
        assert_eq!(view.num_address_ranges(), 2);
        assert_eq!(view.num_addresses(), delegate.num_addresses());

        let ranges: Vec<AddressRange> = {
            let mut it = view.address_ranges();
            let mut out = Vec::new();
            while let Some(r) = it.next_range() {
                out.push(r);
            }
            out
        };
        assert_eq!(
            ranges,
            vec![
                AddressRange::new(addr(0x1000), addr(0x1010)),
                AddressRange::new(addr(0x2000), addr(0x2010)),
            ]
        );

        view.invalidate();
        assert!(view.contains(&addr(0x2005)));
    }

    #[test]
    fn caches_ranges_lazily_matching_delegate_bounds() {
        let delegate = delegate_with_ranges();
        let view = CachedAddressSetViewImpl::new(Box::new(delegate));

        assert_eq!(
            view.range_containing(&addr(0x1005)),
            Some(AddressRange::new(addr(0x1000), addr(0x1010)))
        );
        assert_eq!(view.range_containing(&addr(0x1800)), None);
        assert_eq!(
            view.first_range(),
            Some(AddressRange::new(addr(0x1000), addr(0x1010)))
        );
        assert_eq!(
            view.last_range(),
            Some(AddressRange::new(addr(0x2000), addr(0x2010)))
        );
    }

    #[test]
    fn reverse_iteration_and_set_ops_match_delegate() {
        let delegate = delegate_with_ranges();
        let view = CachedAddressSetViewImpl::new(Box::new(delegate.clone()));

        let backward: Vec<AddressRange> = {
            let mut it = view.address_ranges_ordered(false);
            let mut out = Vec::new();
            while let Some(r) = it.next_range() {
                out.push(r);
            }
            out
        };
        assert_eq!(
            backward,
            vec![
                AddressRange::new(addr(0x2000), addr(0x2010)),
                AddressRange::new(addr(0x1000), addr(0x1010)),
            ]
        );

        assert!(view.has_same_addresses(&delegate));
        assert_eq!(
            view.find_first_address_in_common(&delegate),
            Some(addr(0x1000))
        );

        let other = AddressSet::from_start_end(addr(0x1008), addr(0x1800));
        let union = view.union(&other);
        assert!(union.contains(&addr(0x1500)));
        assert!(union.contains(&addr(0x2005)));
    }
}
