//! Port of `ghidra.program.database.register.AddressRangeObjectMap` (and its package-private
//! helper `AddressValueRange`).
//!
//! Associates arbitrary values with address ranges, automatically coalescing adjacent or
//! overlapping ranges that hold "equal" values. This is the in-memory workhorse behind
//! [`InMemoryRangeMapAdapter`](super::in_memory_range_map_adapter::InMemoryRangeMapAdapter); it
//! has no database dependency of its own.
//!
//! ## Nullable-value divergence
//!
//! Java's `T` is an object reference and can itself be `null` -- `setObject(start, end, null)`
//! establishes a *real* association (to the value `null`), which is exactly why the Java class
//! exposes a separate [`AddressRangeObjectMap::contains`]-equivalent (`contains()`) distinct from
//! `getObject()`: `contains()` is true and `getObject()` returns `null` for such a range, whereas
//! for an address with no association at all, `contains()` is false. This port's `T` is a plain
//! Rust value (no universal null), so [`AddressRangeObjectMap::set_object`] requires an actual
//! `T` for every call; callers that need Java's "explicitly associated with null" case can
//! instantiate `T = Option<Inner>`. In practice the only caller in this port,
//! `InMemoryRangeMapAdapter`, is driven by `RangeMapAdapter::set(&mut self, start, end,
//! bytes: &[u8])`, whose signature cannot express a null byte array in the first place, so the
//! distinction is unreachable there.
//!
//! ## Value-equality divergence
//!
//! Coalescing decides whether two adjacent/overlapping ranges hold "the same" value by asking
//! `T`'s own equality. For a type like `Integer` (used by Ghidra's own unit test for this class)
//! Java's `.equals()` is content equality, so this matches directly. But `byte[]` -- the `T` that
//! `InMemoryRangeMapAdapter` actually instantiates this with -- does *not* override `.equals()`,
//! so Java's real coalescing for that instantiation is reference-identity equality: two calls to
//! `set()` with distinct-but-content-equal `byte[]` arrays (the overwhelmingly common case, since
//! callers typically build a fresh array via `RegisterValue.toBytes()`) will *not* merge in real
//! Ghidra. This port uses `T: PartialEq` (content equality) uniformly, which for `Vec<u8>` means
//! adjacent equal-content ranges merge where stock Ghidra's `byte[]` reference identity would not.
//! Reproducing the identity-equality quirk faithfully would require wrapping every value in a
//! pointer-identity cell for behavior that looks like an accidental side effect of `byte[]` never
//! overriding `equals()`, not a documented feature -- so this divergence is deliberate rather than
//! an oversight, and is exercised by this module's tests using content-equal `Vec<u8>` values.

use std::cell::RefCell;

use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressRangeIteratorAdapter};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A value associated with an inclusive `[start, end]` address range.
///
/// Port of the package-private `ghidra.program.database.register.AddressValueRange`. Ordering
/// (used to keep [`AddressRangeObjectMap::ranges`] sorted for binary search) compares only the
/// start address, mirroring `AddressValueRange.compareTo`.
#[derive(Clone, Debug)]
struct AddressValueRange<T> {
    start: Address,
    end: Address,
    value: T,
}

impl<T> AddressValueRange<T> {
    fn new(start: Address, end: Address, value: T) -> Self {
        Self { start, end, value }
    }

    fn contains(&self, address: &Address) -> bool {
        address >= &self.start && address <= &self.end
    }
}

/// Associates objects with address ranges.
///
/// Port of `ghidra.program.database.register.AddressRangeObjectMap`.
pub struct AddressRangeObjectMap<T> {
    ranges: Vec<AddressValueRange<T>>,
    /// Cache of the most recently accessed range, mirroring the Java field of the same name
    /// (`lastRange`). A `RefCell` because Java's `getObject`/`contains`/
    /// `getAddressRangeContaining` are logically read-only (`&self` here) yet still populate this
    /// cache, matching this crate's interior-mutability convention for that shape.
    last_range: RefCell<Option<AddressValueRange<T>>>,
}

impl<T> Default for AddressRangeObjectMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AddressRangeObjectMap<T> {
    /// Constructs a new, empty map.
    pub fn new() -> Self {
        Self { ranges: Vec::new(), last_range: RefCell::new(None) }
    }

    /// Returns true if the map has no associated ranges.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Notification that something has changed that may affect internal caching.
    pub fn clear_cache(&self) {
        *self.last_range.borrow_mut() = None;
    }

    /// Position of the range whose start is `<=` the given range's start, biased towards "the
    /// range this new/query range would be inserted after" (see `getPositionOfRangeAtOrBefore`).
    /// Returns `-1` if every stored range starts after `start`.
    fn position_of_range_at_or_before(&self, start: &Address) -> i64 {
        match self.ranges.binary_search_by(|r| r.start.cmp(start)) {
            Ok(idx) => idx as i64,
            Err(insertion_point) => {
                let pos = insertion_point as i64 - 1;
                pos.min(self.ranges.len() as i64)
            }
        }
    }

    /// Position of the range strictly before the given start address (see
    /// `getPositionOfRangeBefore`): like [`Self::position_of_range_at_or_before`], but an exact
    /// start match returns the range *before* that match rather than the match itself.
    fn position_of_range_before(&self, start: &Address) -> i64 {
        match self.ranges.binary_search_by(|r| r.start.cmp(start)) {
            Ok(idx) => idx as i64 - 1,
            Err(insertion_point) => {
                let pos = insertion_point as i64 - 1;
                pos.min(self.ranges.len() as i64)
            }
        }
    }
}

impl<T: Clone + PartialEq> AddressRangeObjectMap<T> {
    /// Returns an iterator over all ranges that have associated values.
    ///
    /// Unlike the Java class's `SimpleAddressRangeIterator`, which walks the live `ranges` list
    /// lazily, this materializes the current ranges into a `Vec` up front (matching this crate's
    /// `AddressRangeIteratorAdapter` convention for `Box<dyn AddressRangeIterator>`, whose
    /// `'static` bound rules out borrowing from `&self` anyway). Output sequence is identical.
    pub fn get_address_range_iterator(&self) -> Box<dyn AddressRangeIterator> {
        let ranges = self
            .ranges
            .iter()
            .map(|r| AddressRange::new(r.start.clone(), r.end.clone()))
            .collect();
        Box::new(AddressRangeIteratorAdapter::new(ranges))
    }

    /// Returns an iterator over all ranges that have associated values within `[start, end]`.
    /// Ranges that overlap the beginning or end of `[start, end]` are included but clipped to it.
    ///
    /// Port of `getAddressRangeIterator(Address, Address)` / `RestrictedIndexRangeIterator`,
    /// materialized eagerly (see [`Self::get_address_range_iterator`] for why).
    pub fn get_address_range_iterator_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        let mut out = Vec::new();

        let pos = self.position_of_range_at_or_before(start);
        let mut next_index: i64;
        if pos >= 0 {
            let range = &self.ranges[pos as usize];
            next_index = pos + 1;
            if range.contains(start) {
                out.push(AddressRange::new(start.clone(), min_addr(&range.end, end)));
            }
        }
        else {
            next_index = 0;
        }

        next_index = next_index.max(0);
        let mut idx = next_index as usize;
        while idx < self.ranges.len() {
            let range = &self.ranges[idx];
            if range.start > *end {
                break;
            }
            out.push(AddressRange::new(range.start.clone(), min_addr(&range.end, end)));
            idx += 1;
        }

        Box::new(AddressRangeIteratorAdapter::new(out))
    }

    /// Move all values within an address range to a new range.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    ///
    /// # Panics
    /// If `from_addr + length - 1` or the destination addresses overflow their address space.
    /// Java's equivalent lets the analogous `AddressOutOfBoundsException` propagate uncaught;
    /// this port mirrors that by panicking rather than silently truncating.
    pub fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        if length == 0 {
            return Ok(());
        }

        let mut tmp_map: AddressRangeObjectMap<T> = AddressRangeObjectMap::new();

        let from_end_addr = from_addr
            .add(length as i64 - 1)
            .expect("moveAddressRange: from-range end overflowed its address space");

        let collected: Vec<(Address, Address, T)> = {
            let it = self.get_address_range_iterator_in_range(from_addr, &from_end_addr);
            let mut items = Vec::new();
            for range in it {
                monitor.check_cancelled()?;
                let min_addr = range.min_address().clone();
                let value = self
                    .get_object(&min_addr)
                    .expect("range returned by the iterator must have an associated value");
                let offset = min_addr.subtract(from_addr);
                let new_min = to_addr
                    .add(offset)
                    .expect("moveAddressRange: destination start overflowed its address space");

                let max_addr = range.max_address().clone();
                let offset = max_addr.subtract(from_addr);
                let new_max = to_addr
                    .add(offset)
                    .expect("moveAddressRange: destination end overflowed its address space");

                items.push((new_min, new_max, value));
            }
            items
        };
        for (min_addr, max_addr, value) in collected {
            tmp_map.set_object(min_addr, max_addr, value);
        }

        self.clear_range(from_addr, &from_end_addr);

        let moved: Vec<(Address, Address, T)> = {
            let it = tmp_map.get_address_range_iterator();
            let mut items = Vec::new();
            for range in it {
                monitor.check_cancelled()?;
                let value = tmp_map
                    .get_object(range.min_address())
                    .expect("range returned by the iterator must have an associated value");
                items.push((range.min_address().clone(), range.max_address().clone(), value));
            }
            items
        };
        for (min_addr, max_addr, value) in moved {
            self.set_object(min_addr, max_addr, value);
        }

        Ok(())
    }

    /// Associates `value` with every address in `[start, end]`. Any previously associated values
    /// in that range are overwritten (and, if their old range extends past `[start, end]`, the
    /// surviving portion keeps the old value). Adjacent/overlapping ranges whose value is "equal"
    /// (per `T: PartialEq`, see the module docs for the divergence from Java's `byte[]` identity
    /// equality) to `value` are coalesced into a single stored range.
    pub fn set_object(&mut self, start: Address, end: Address, value: T) {
        *self.last_range.borrow_mut() = None;
        let mut new_range = AddressValueRange::new(start.clone(), end.clone(), value.clone());

        if self.ranges.is_empty() {
            self.ranges.push(new_range);
            return;
        }

        let mut previous_index = self.position_of_range_before(&start);
        if previous_index >= 0 {
            let old_size = self.ranges.len();
            new_range = self.adjust_previous_range_for_overlap(&start, &end, value.clone(), new_range, previous_index as usize);
            if old_size > self.ranges.len() {
                previous_index -= 1;
            }
        }

        let insertion_index = (previous_index + 1).max(0) as usize;
        let new_end = new_range.end.clone();
        self.remove_completely_overlapped_ranges(insertion_index, &new_end);

        new_range = self.adjust_remaining_range_for_overlap(value, new_range, insertion_index, &new_end);

        self.ranges.insert(insertion_index, new_range);
    }

    fn adjust_remaining_range_for_overlap(
        &mut self,
        value: T,
        mut new_range: AddressValueRange<T>,
        insertion_index: usize,
        new_end: &Address,
    ) -> AddressValueRange<T> {
        if insertion_index >= self.ranges.len() {
            return new_range;
        }

        let range = &self.ranges[insertion_index];
        let next_addr = match new_end.next() {
            Ok(a) => a,
            // new_end is the address space's max address: nothing can start after it, so there
            // is no overlap to adjust.
            Err(_) => return new_range,
        };
        if range.start > next_addr {
            return new_range;
        }

        if range.value == value {
            let range = self.ranges.remove(insertion_index);
            new_range = AddressValueRange::new(new_range.start, range.end, value);
        }
        else {
            let range = &self.ranges[insertion_index];
            self.ranges[insertion_index] =
                AddressValueRange::new(next_addr, range.end.clone(), range.value.clone());
        }

        new_range
    }

    fn remove_completely_overlapped_ranges(&mut self, insertion_index: usize, new_end: &Address) {
        let idx = insertion_index;
        while idx < self.ranges.len() {
            let range = &self.ranges[idx];
            if range.end > *new_end {
                return;
            }
            self.ranges.remove(idx);
        }
    }

    fn adjust_previous_range_for_overlap(
        &mut self,
        start: &Address,
        end: &Address,
        value: T,
        mut new_range: AddressValueRange<T>,
        pos: usize,
    ) -> AddressValueRange<T> {
        let previous_range = self.ranges[pos].clone();

        let start_prev = match start.previous() {
            Ok(a) => a,
            Err(_) => return new_range, // start is the space's min address: no overlap possible
        };
        if previous_range.end < start_prev {
            return new_range; // no overlap
        }

        let old_start = previous_range.start.clone();
        let old_end = previous_range.end.clone();
        let old_value = previous_range.value.clone();

        if previous_range.value == value {
            self.ranges.remove(pos);
            new_range = AddressValueRange::new(old_start, max_addr(&old_end, end), value);
        }
        else {
            self.ranges[pos] = AddressValueRange::new(old_start, start_prev, old_value.clone());

            if previous_range.end > *end {
                let next_addr = end
                    .next()
                    .expect("end < previous_range.end, which is a valid address, so end.next() cannot overflow");
                self.ranges.insert(pos + 1, AddressValueRange::new(next_addr, old_end, old_value));
            }
        }

        new_range
    }

    /// Clears all associations.
    pub fn clear_all(&mut self) {
        self.ranges.clear();
        *self.last_range.borrow_mut() = None;
    }

    /// Clears any associations within `[start, end]`.
    pub fn clear_range(&mut self, start: &Address, end: &Address) {
        *self.last_range.borrow_mut() = None;

        let mut pos = self.position_of_range_before(start);
        if pos >= 0 {
            let range = self.ranges[pos as usize].clone();
            if range.end >= *start {
                let new_prev_end = start
                    .previous()
                    .expect("start > range.end >= start's own value, so start cannot be the space minimum here");
                self.ranges[pos as usize] =
                    AddressValueRange::new(range.start.clone(), new_prev_end, range.value.clone());
            }
            if range.end > *end {
                let next_addr = end
                    .next()
                    .expect("range.end > end, which is a valid address, so end.next() cannot overflow");
                self.ranges.insert(pos as usize + 1, AddressValueRange::new(next_addr, range.end, range.value));
            }
        }

        pos = (pos + 1).max(0);
        let idx = pos as usize;
        while idx < self.ranges.len() {
            let range = self.ranges[idx].clone();
            if range.end <= *end {
                self.ranges.remove(idx);
            }
            else if range.start > *end {
                break;
            }
            else {
                let next_addr = end
                    .next()
                    .expect("range.start <= end < range.end, so end.next() cannot overflow");
                self.ranges[idx] = AddressValueRange::new(next_addr, range.end, range.value);
            }
        }
    }

    /// Returns true if `address` has an associated value, even if that value is otherwise
    /// indistinguishable from "no value" to the caller (see the module docs' nullable-value
    /// section for why this rarely matters in this port).
    pub fn contains(&self, address: &Address) -> bool {
        {
            let cached = self.last_range.borrow();
            if let Some(range) = cached.as_ref() {
                if range.contains(address) {
                    return true;
                }
            }
        }

        let pos = self.position_of_range_at_or_before(address);
        if pos < 0 {
            return false;
        }
        let range = self.ranges[pos as usize].clone();
        let found = range.contains(address);
        *self.last_range.borrow_mut() = Some(range);
        found
    }

    /// Returns the value associated with `address`, or `None` if no association exists. If
    /// [`Self::contains`] would return true for this address, the result is cached so the next
    /// [`Self::get_object`] call is fast (mirrors Java's `lastRange` cache).
    pub fn get_object(&self, address: &Address) -> Option<T> {
        {
            let cached = self.last_range.borrow();
            if let Some(range) = cached.as_ref() {
                if range.contains(address) {
                    return Some(range.value.clone());
                }
            }
        }

        let pos = self.position_of_range_at_or_before(address);
        if pos < 0 {
            return None;
        }
        let range = self.ranges[pos as usize].clone();
        let result = if range.contains(address) { Some(range.value.clone()) } else { None };
        *self.last_range.borrow_mut() = Some(range);
        result
    }

    /// Returns the bounding value-or-gap range containing `addr`: if `addr` falls within a stored
    /// range, that range; otherwise the maximal gap between whichever stored ranges (if any)
    /// border it, clamped to `addr`'s address space.
    pub fn get_address_range_containing(&self, addr: &Address) -> AddressRange {
        {
            let cached = self.last_range.borrow();
            if let Some(range) = cached.as_ref() {
                if range.contains(addr) {
                    return AddressRange::new(range.start.clone(), range.end.clone());
                }
            }
        }

        let mut min = addr.space().min_address();
        let mut max = addr.space().max_address();

        let mut pos = self.position_of_range_at_or_before(addr);
        if pos >= 0 {
            let range = self.ranges[pos as usize].clone();
            if range.end >= *addr {
                *self.last_range.borrow_mut() = Some(range.clone());
                return AddressRange::new(range.start, range.end);
            }
            if min.space() == range.end.space() {
                if let Ok(next) = range.end.next() {
                    min = next;
                }
            }
            *self.last_range.borrow_mut() = Some(range);
        }
        pos += 1;
        if pos >= 0 && (pos as usize) < self.ranges.len() {
            let range = self.ranges[pos as usize].clone();
            if range.start == *addr {
                *self.last_range.borrow_mut() = Some(range.clone());
                return AddressRange::new(range.start, range.end);
            }
            if max.space() == range.start.space() {
                if let Ok(prev) = range.start.previous() {
                    max = prev;
                }
            }
            *self.last_range.borrow_mut() = Some(range);
        }
        AddressRange::new(min, max)
    }
}

fn min_addr(a: &Address, b: &Address) -> Address {
    if a <= b { a.clone() } else { b.clone() }
}

fn max_addr(a: &Address, b: &Address) -> Address {
    if a >= b { a.clone() } else { b.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("Test", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn a(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    #[test]
    fn empty_map_has_no_ranges_and_no_associations() {
        let space = space();
        let map: AddressRangeObjectMap<i32> = AddressRangeObjectMap::new();
        assert!(map.is_empty());
        assert!(!map.contains(&a(&space, 0x100)));
        assert_eq!(map.get_object(&a(&space, 0x100)), None);
    }

    #[test]
    fn two_spaces_with_second_range_at_zero() {
        let space1 = space();
        let space2 = AddressSpace::new("Test2", 32, 1, AddressSpaceType::Ram, 1);
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space1, 0x1000), a(&space1, 0x2000), 1);
        map.set_object(a(&space2, 0), a(&space2, 10), 1);

        let mut it = map.get_address_range_iterator();
        let r1 = it.next().expect("first range");
        assert_eq!(r1.min_address(), &a(&space1, 0x1000));
        assert_eq!(r1.max_address(), &a(&space1, 0x2000));

        let r2 = it.next().expect("second range");
        assert_eq!(r2.min_address(), &a(&space2, 0));
        assert_eq!(r2.max_address(), &a(&space2, 10));

        assert!(it.next().is_none());
    }

    #[test]
    fn add_overlapping_range_with_same_value_coalesces() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.set_object(a(&space, 0x1500), a(&space, 0x3000), 1);

        let mut it = map.get_address_range_iterator();
        let r = it.next().expect("merged range");
        assert_eq!(r.min_address(), &a(&space, 0x1000));
        assert_eq!(r.max_address(), &a(&space, 0x3000));
        assert_eq!(map.get_object(&a(&space, 0x1000)), Some(1));
        assert!(it.next().is_none());
    }

    #[test]
    fn add_adjoining_ranges_with_same_value_coalesces() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.set_object(a(&space, 0x2001), a(&space, 0x3000), 1);

        let mut it = map.get_address_range_iterator();
        let r = it.next().expect("merged range");
        assert_eq!(r.min_address(), &a(&space, 0x1000));
        assert_eq!(r.max_address(), &a(&space, 0x3000));
        assert_eq!(map.get_object(&a(&space, 0x1000)), Some(1));
        assert!(it.next().is_none());
    }

    #[test]
    fn add_adjoining_ranges_with_different_value_does_not_coalesce() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.set_object(a(&space, 0x2001), a(&space, 0x3000), 2);

        let mut it = map.get_address_range_iterator();
        let r1 = it.next().expect("first range");
        assert_eq!(r1.min_address(), &a(&space, 0x1000));
        assert_eq!(r1.max_address(), &a(&space, 0x2000));

        let r2 = it.next().expect("second range");
        assert_eq!(r2.min_address(), &a(&space, 0x2001));
        assert_eq!(r2.max_address(), &a(&space, 0x3000));

        assert_eq!(map.get_object(&a(&space, 0x1000)), Some(1));
        assert_eq!(map.get_object(&a(&space, 0x2001)), Some(2));
        assert!(it.next().is_none());
    }

    /// Mirrors Java's (unannotated, so never actually executed by JUnit)
    /// `testAddCompletelyCoveredRangeWithDifferentObject`: setting a range that completely
    /// swallows an existing narrower range with a different value should discard the old range
    /// entirely rather than leaving fragments.
    #[test]
    fn set_range_completely_covering_existing_range_with_different_value_discards_old_range() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.set_object(a(&space, 0x500), a(&space, 0x3000), 2);

        let mut it = map.get_address_range_iterator();
        let r = it.next().expect("single covering range");
        assert_eq!(r.min_address(), &a(&space, 0x500));
        assert_eq!(r.max_address(), &a(&space, 0x3000));
        assert_eq!(map.get_object(&a(&space, 0x1000)), Some(2));
        assert!(it.next().is_none());
    }

    #[test]
    fn set_single_address_range_in_middle_of_existing_range_splits_it() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);

        map.set_object(a(&space, 0x1500), a(&space, 0x1500), 2);
        let mut it = map.get_address_range_iterator();

        let r1 = it.next().expect("left half");
        assert_eq!(r1.min_address(), &a(&space, 0x1000));
        assert_eq!(r1.max_address(), &a(&space, 0x14ff));
        assert_eq!(map.get_object(&a(&space, 0x1000)), Some(1));

        let r2 = it.next().expect("split point");
        assert_eq!(r2.min_address(), &a(&space, 0x1500));
        assert_eq!(r2.max_address(), &a(&space, 0x1500));
        assert_eq!(map.get_object(&a(&space, 0x1500)), Some(2));

        let r3 = it.next().expect("right half");
        assert_eq!(r3.min_address(), &a(&space, 0x1501));
        assert_eq!(r3.max_address(), &a(&space, 0x2000));
        assert_eq!(map.get_object(&a(&space, 0x1501)), Some(1));

        assert!(it.next().is_none());
    }

    #[test]
    fn remove_sub_range_from_middle_of_existing_range_leaves_two_fragments() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);

        map.clear_range(&a(&space, 0x1500), &a(&space, 0x1600));

        let mut it = map.get_address_range_iterator();
        let r1 = it.next().expect("left fragment");
        assert_eq!(r1.min_address(), &a(&space, 0x1000));
        assert_eq!(r1.max_address(), &a(&space, 0x14ff));

        let r2 = it.next().expect("right fragment");
        assert_eq!(r2.min_address(), &a(&space, 0x1601));
        assert_eq!(r2.max_address(), &a(&space, 0x2000));

        assert!(it.next().is_none());
        assert!(!map.contains(&a(&space, 0x1550)));
        assert_eq!(map.get_object(&a(&space, 0x1550)), None);
    }

    #[test]
    fn clear_range_removes_fully_contained_ranges() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x1010), 1);
        map.set_object(a(&space, 0x1020), a(&space, 0x1030), 2);
        map.set_object(a(&space, 0x1040), a(&space, 0x1050), 3);

        map.clear_range(&a(&space, 0x1000), &a(&space, 0x1050));

        assert!(map.is_empty());
        assert_eq!(map.get_object(&a(&space, 0x1025)), None);
    }

    #[test]
    fn boundary_addresses_are_respected() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x1010), 1);

        assert!(map.contains(&a(&space, 0x1000)));
        assert!(map.contains(&a(&space, 0x1010)));
        assert!(!map.contains(&a(&space, 0x0fff)));
        assert!(!map.contains(&a(&space, 0x1011)));
    }

    #[test]
    fn contains_distinguishes_no_association_from_present_value() {
        let space = space();
        let mut map: AddressRangeObjectMap<i32> = AddressRangeObjectMap::new();
        assert!(!map.contains(&a(&space, 5)));
        map.set_object(a(&space, 0), a(&space, 10), 0);
        assert!(map.contains(&a(&space, 5)));
        assert_eq!(map.get_object(&a(&space, 5)), Some(0));
    }

    #[test]
    fn get_address_range_containing_returns_value_range_or_gap() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.set_object(a(&space, 0x3000), a(&space, 0x4000), 2);

        let value_range = map.get_address_range_containing(&a(&space, 0x1500));
        assert_eq!(value_range.min_address(), &a(&space, 0x1000));
        assert_eq!(value_range.max_address(), &a(&space, 0x2000));

        let gap_range = map.get_address_range_containing(&a(&space, 0x2500));
        assert_eq!(gap_range.min_address(), &a(&space, 0x2001));
        assert_eq!(gap_range.max_address(), &a(&space, 0x2fff));
    }

    #[test]
    fn move_address_range_relocates_values() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x1010), 1);
        map.set_object(a(&space, 0x1020), a(&space, 0x1030), 2);

        let monitor = crate::util::task::DummyMonitor;
        map.move_address_range(&a(&space, 0x1000), &a(&space, 0x5000), 0x40, &monitor)
            .expect("move should not be cancelled");

        assert_eq!(map.get_object(&a(&space, 0x1000)), None);
        assert_eq!(map.get_object(&a(&space, 0x5000)), Some(1));
        assert_eq!(map.get_object(&a(&space, 0x5020)), Some(2));
    }

    #[test]
    fn clear_all_removes_every_association() {
        let space = space();
        let mut map = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x2000), 1);
        map.clear_all();
        assert!(map.is_empty());
        assert_eq!(map.get_object(&a(&space, 0x1500)), None);
    }

    #[test]
    fn content_equal_byte_vectors_from_distinct_allocations_still_coalesce() {
        // Documents this port's deliberate divergence from Java's byte[] reference-identity
        // equality (see the module docs): two distinct Vec<u8> allocations with equal content
        // merge here, whereas real Ghidra's AddressRangeObjectMap<byte[]> would not.
        let space = space();
        let mut map: AddressRangeObjectMap<Vec<u8>> = AddressRangeObjectMap::new();
        map.set_object(a(&space, 0x1000), a(&space, 0x1010), vec![0xAB, 0xCD]);
        map.set_object(a(&space, 0x1011), a(&space, 0x1020), vec![0xAB, 0xCD]);

        let mut it = map.get_address_range_iterator();
        let r = it.next().expect("coalesced range");
        assert_eq!(r.min_address(), &a(&space, 0x1000));
        assert_eq!(r.max_address(), &a(&space, 0x1020));
        assert!(it.next().is_none());
    }
}
