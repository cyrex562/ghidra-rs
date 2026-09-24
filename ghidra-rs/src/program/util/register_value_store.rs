//! Port of `ghidra.program.util.RegisterValueStore`.
//!
//! Generalized storage of register values over address ranges, on top of a [`RangeMapAdapter`].
//! Values carry a mask alongside the value bits; where a newly-set value's mask overlaps an
//! existing stored value, the two are combined bit-by-bit (new bits win, old bits are preserved
//! where the new mask is off) rather than one overwriting the other outright.
//!
//! This is a required, blocking dependency of `AbstractStoredProgramContext` (not itself one of
//! this batch's four assigned classes, but load-bearing infrastructure for all of them): Java's
//! `AbstractStoredProgramContext` stores a `Map<Register, RegisterValueStore>` and delegates
//! essentially all of its value get/set logic to it.
//!
//! Operates on this crate's concrete
//! [`RegisterValue`](crate::program::model::lang::register_value::RegisterValue) throughout
//! (rather than the object-safe `Box<dyn RegisterValueTrait>` seam), since every real caller
//! within this port already has (or can cheaply obtain, via
//! [`RegisterValue::from_trait_object`](crate::program::model::lang::register_value::RegisterValue::from_trait_object))
//! a concrete value by the time it reaches this store; keeping the store itself concrete avoids
//! re-deriving byte<->value conversions the concrete type already owns.

use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::util::{LanguageTranslator, RangeMapAdapter};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Storage of register values over address ranges, backed by a [`RangeMapAdapter`].
///
/// Port of `ghidra.program.util.RegisterValueStore`.
pub struct RegisterValueStore {
    base_register: RegisterRef,
    range_map: Box<dyn RangeMapAdapter>,

    // Write-cache limitations mirror Java's doc comment on the field group of the same name: the
    // cache holds a single memory range to reduce backing-store IO overhead during code block
    // disassembly, and must be flushed before an iterator is used or before a context change that
    // does not extend the current write range.
    range_write_cache_enabled: bool,
    range_write_cache: Option<(Address, Address, RegisterValue)>,
}

impl RegisterValueStore {
    /// Constructs a new store for `register`'s base register, backed by `range_map`.
    pub fn new(register: &RegisterRef, range_map: Box<dyn RangeMapAdapter>, enable_range_write_cache: bool) -> Self {
        Self {
            base_register: register.borrow().get_base_register(),
            range_map,
            range_write_cache_enabled: enable_range_write_cache,
            range_write_cache: None,
        }
    }

    /// Flush any cached context not yet written to the backing store.
    pub fn flush_write_cache(&mut self) {
        if let Some((min, max, value)) = self.range_write_cache.take() {
            self.do_set_value(&min, &max, &value);
        }
    }

    /// Discard any cached context not yet written to the backing store, without persisting it.
    pub fn invalidate_write_cache(&mut self) {
        self.range_write_cache = None;
    }

    /// Move all register values within an address range to a new range.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    pub fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.flush_write_cache();
        self.range_map.move_address_range(from_addr, to_addr, length, monitor)
    }

    /// Sets the given register value (value and mask) across the given address range. Existing
    /// values in the range whose bits are not part of `new_value`'s mask are left unchanged.
    pub fn set_value(&mut self, start: &Address, end: &Address, new_value: &RegisterValue) {
        if self.range_write_cache_enabled {
            if let Some((cache_min, cache_max, cache_value)) = self.range_write_cache.clone() {
                if let Ok(next_addr_in_range) = cache_max.add_no_wrap(1) {
                    if *start == next_addr_in_range && new_value.to_bytes() == cache_value.to_bytes() {
                        self.range_write_cache = Some((cache_min, end.clone(), cache_value));
                        return;
                    }
                }
                self.flush_write_cache();
            } else {
                // Ensure the backing store is in a writable state to avoid a delayed error.
                self.range_map.check_writable_state();
            }
            self.do_set_value(start, end, new_value);
            return;
        }

        self.do_set_value(start, end, new_value);
    }

    fn do_set_value(&mut self, start: &Address, end: &Address, new_value: &RegisterValue) {
        assert!(start.same_address_space(end), "Start and end addresses must be in the same address space.");

        // If `new_value` corresponds to the base register and has a full mask, no merge is
        // needed.
        if same_register(&new_value.register(), &self.base_register) && new_value.has_value() {
            self.range_map.set(start, end, &new_value.to_bytes());
            return;
        }

        // Otherwise, combine bytes where values already exist.
        let list: Vec<AddressRange> = self.range_map.get_address_range_iterator_in_range(start, end).collect();

        let mut cursor: Option<Address> = Some(start.clone());
        for index_range in list {
            let range_start = index_range.min_address().clone();
            let range_end = index_range.max_address().clone();
            let cur = cursor.clone().expect("cursor set at top of every iteration below");

            if range_start > cur {
                if let Ok(prev) = range_start.previous() {
                    self.range_map.set(&cur, &prev, &new_value.to_bytes());
                }
            }
            let current_bytes = self.range_map.get_value(&range_start).unwrap_or_default();
            let current_value = RegisterValue::from_bytes(self.base_register.clone(), &current_bytes);
            let combined_value = current_value.combine_values(new_value);
            self.range_map.set(&range_start, &range_end, &combined_value.to_bytes());

            match range_end.add_no_wrap(1) {
                Ok(next) => cursor = Some(next),
                Err(_) => {
                    cursor = None;
                    break;
                }
            }
        }
        if let Some(cur) = cursor {
            if cur <= *end {
                self.range_map.set(&cur, end, &new_value.to_bytes());
            }
        }
    }

    /// Delete all stored values and free/delete underlying storage.
    pub fn clear_all(&mut self) {
        self.range_write_cache = None;
        self.range_map.clear_all();
    }

    /// Clears the address range of any set bits using the mask from `register`. Existing values
    /// in the range whose bits are not part of the mask are left unchanged. If `register` is
    /// `None`, all values in the range are cleared outright.
    pub fn clear_value(&mut self, start: &Address, end: &Address, register: Option<&RegisterRef>) {
        // Port of `AddressRange.checkValidRange(start, end)`.
        assert!(start.same_address_space(end), "Start and end addresses must be in same address space");
        assert!(start <= end, "Start address must be less than or equal to end address");

        self.flush_write_cache();

        let is_base = register.is_none_or(|r| r.borrow().is_base_register());
        if is_base {
            self.range_map.clear_range(start, end);
            return;
        }
        let register = register.expect("is_base short-circuits above when register is None");

        // Java reassigns its local `start` to `rangeEnd.next()` at the end of each loop
        // iteration below, but never reads it again (in the loop or after) -- dead code in the
        // original, so it is not reproduced here.
        let list: Vec<AddressRange> = self.range_map.get_address_range_iterator_in_range(start, end).collect();
        for index_range in list {
            let range_start = index_range.min_address().clone();
            let range_end = index_range.max_address().clone();

            let mask = register.borrow().base_mask();
            let current_base_bytes = self.range_map.get_value(&range_start).unwrap_or_default();
            let current_base_value = RegisterValue::from_bytes(register.borrow().get_base_register(), &current_base_bytes);
            let new_base_value = current_base_value.clear_bit_values(&mask);

            if !new_base_value.has_any_value() {
                self.range_map.clear_range(&range_start, &range_end);
            } else {
                self.range_map.set(&range_start, &range_end, &new_base_value.to_bytes());
            }
        }
    }

    /// Returns the `RegisterValue` (value and mask) associated with the given address, viewed
    /// through `register` (which may be the base register or a child of it).
    pub fn get_value(&self, register: &RegisterRef, address: &Address) -> Option<RegisterValue> {
        let stored = self.range_map.get_value(address).map(|bytes| RegisterValue::from_bytes(register.clone(), &bytes));

        if let Some((cache_min, cache_max, cache_value)) = &self.range_write_cache {
            if *address >= *cache_min && *address <= *cache_max {
                let combined = match &stored {
                    Some(v) => v.combine_values(cache_value),
                    None => cache_value.clone(),
                };
                return Some(combined.get_register_value(register));
            }
        }
        stored
    }

    /// Returns an iterator over all address ranges within `[start_address, end_address]` that
    /// have an associated register value.
    pub fn get_address_range_iterator_in_range(&mut self, start_address: &Address, end_address: &Address) -> Box<dyn AddressRangeIterator> {
        // Assume we must be in an open transaction if the range cache is active.
        self.flush_write_cache();
        self.range_map.get_address_range_iterator_in_range(start_address, end_address)
    }

    /// Returns an iterator over all address ranges that have an associated register value.
    pub fn get_address_range_iterator(&mut self) -> Box<dyn AddressRangeIterator> {
        self.flush_write_cache();
        self.range_map.get_address_range_iterator()
    }

    /// Returns true if this store has no associated values for any address.
    pub fn is_empty(&self) -> bool {
        self.range_write_cache.is_none() && self.range_map.is_empty()
    }

    /// Preserve register values and handle a register name/size change due to a language
    /// upgrade. Returns `true` if translated successfully, `false` if the register is not mapped
    /// and value storage should be discarded by the caller.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    pub fn set_language(
        &mut self,
        translator: &dyn LanguageTranslator,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledException> {
        let Some(new_reg) = translator.get_new_register(&self.base_register) else {
            return Ok(false);
        };
        self.flush_write_cache();

        // NOTE: mirrors Java's own "// TODO: What should we do if new register is not a
        // base-register? - The code below will not work!" -- ported as-is.
        let needs_update = new_reg.borrow().is_processor_context()
            || !new_reg.borrow().is_base_register()
            || new_reg.borrow().name() != self.base_register.borrow().name()
            || new_reg.borrow().bit_length() != self.base_register.borrow().bit_length();

        if needs_update {
            self.range_map.set_language(translator, &self.base_register, monitor)?;
            self.base_register = new_reg.borrow().get_base_register();
        }
        Ok(true)
    }

    /// Returns the bounding address-range containing `addr` and the same value throughout.
    pub fn get_value_range_containing(&mut self, addr: &Address) -> AddressRange {
        self.flush_write_cache();
        self.range_map.get_value_range_containing(addr)
    }

    /// Notifies the store that something changed that may affect internal caching.
    pub fn invalidate(&mut self) {
        self.range_map.invalidate();
    }
}

fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    crate::program::model::lang::Register::same(a, b) || a.borrow().name() == b.borrow().name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::register::in_memory_range_map_adapter::InMemoryRangeMapAdapter;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    fn base_register(name: &str, num_bytes: i32) -> RegisterRef {
        let space = reg_space();
        Register::new(name, "", Address::new(space, 0), num_bytes, false, 0)
    }

    fn child_register(parent: &mut RegisterRef, name: &str, byte_offset: i64, num_bytes: i32) -> RegisterRef {
        let space = reg_space();
        let child = Register::new(name, "", Address::new(space, byte_offset), num_bytes, false, 0);
        let mut linked = crate::program::model::lang::register::test_support::linked(&[parent, &child], &[(0, &[1])]);
        let child = linked.pop().unwrap();
        *parent = linked.pop().unwrap();
        child
    }

    fn store(register: &RegisterRef) -> RegisterValueStore {
        RegisterValueStore::new(register, Box::new(InMemoryRangeMapAdapter::new()), false)
    }

    #[test]
    fn set_then_get_full_value_over_range() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = store(&reg);
        assert!(s.is_empty());

        let value = RegisterValue::with_value(reg.clone(), 0x1234_5678);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x2000), &value);
        assert!(!s.is_empty());

        let got = s.get_value(&reg, &addr(&space, 0x1500)).expect("value set");
        assert_eq!(got.unsigned_value(), Some(0x1234_5678));
        assert!(s.get_value(&reg, &addr(&space, 0x3000)).is_none());
    }

    #[test]
    fn setting_narrower_value_over_part_of_range_splits_and_combines() {
        let space = space();
        let mut reg = base_register("eax", 4);
        let al = child_register(&mut reg, "al", 0, 1);
        let mut s = store(&reg);

        let full = RegisterValue::with_value(reg.clone(), 0x1111_1111);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x2000), &full);

        // Set just the low byte over a narrower sub-range.
        let byte_val = RegisterValue::with_value(al, 0xAB);
        s.set_value(&addr(&space, 0x1500), &addr(&space, 0x1600), &byte_val);

        // Outside the narrower range: untouched.
        let before = s.get_value(&reg, &addr(&space, 0x1000)).unwrap();
        assert_eq!(before.unsigned_value(), Some(0x1111_1111));

        // Inside the narrower range: low byte replaced, rest preserved (combine semantics).
        let inside = s.get_value(&reg, &addr(&space, 0x1550)).unwrap();
        assert_eq!(inside.unsigned_value(), Some(0x1111_11AB));

        // After the narrower range: back to the original full value.
        let after = s.get_value(&reg, &addr(&space, 0x1700)).unwrap();
        assert_eq!(after.unsigned_value(), Some(0x1111_1111));
    }

    #[test]
    fn clear_value_with_register_mask_only_clears_those_bits() {
        let space = space();
        let mut reg = base_register("eax", 4);
        let al = child_register(&mut reg, "al", 0, 1);
        let mut s = store(&reg);

        let full = RegisterValue::with_value(reg.clone(), 0xFFFF_FFFF);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x2000), &full);

        s.clear_value(&addr(&space, 0x1000), &addr(&space, 0x2000), Some(&al));

        let got = s.get_value(&reg, &addr(&space, 0x1500)).unwrap();
        assert!(!got.has_value()); // low byte no longer known
        assert_eq!(got.unsigned_value_ignore_mask(), 0xFFFF_FF00);
    }

    #[test]
    fn clear_value_without_register_clears_everything_in_range() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = store(&reg);

        let value = RegisterValue::with_value(reg.clone(), 0x42);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x2000), &value);
        s.clear_value(&addr(&space, 0x1000), &addr(&space, 0x2000), None);

        assert!(s.is_empty());
        assert!(s.get_value(&reg, &addr(&space, 0x1500)).is_none());
    }

    #[test]
    fn is_empty_reflects_pending_write_cache() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = RegisterValueStore::new(&reg, Box::new(InMemoryRangeMapAdapter::new()), true);
        assert!(s.is_empty());

        let value = RegisterValue::with_value(reg.clone(), 7);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x1010), &value);
        // The underlying store is empty until the cache is flushed...
        assert!(!s.is_empty()); // ...but is_empty() accounts for the pending cache directly.

        s.flush_write_cache();
        assert!(!s.is_empty());
        let got = s.get_value(&reg, &addr(&space, 0x1005)).unwrap();
        assert_eq!(got.unsigned_value(), Some(7));
    }

    #[test]
    fn adjacent_same_value_writes_extend_the_cached_range() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = RegisterValueStore::new(&reg, Box::new(InMemoryRangeMapAdapter::new()), true);

        let value = RegisterValue::with_value(reg.clone(), 99);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x1010), &value);
        s.set_value(&addr(&space, 0x1011), &addr(&space, 0x1020), &value);
        s.flush_write_cache();

        let got = s.get_value(&reg, &addr(&space, 0x1018)).unwrap();
        assert_eq!(got.unsigned_value(), Some(99));
        let got_start = s.get_value(&reg, &addr(&space, 0x1000)).unwrap();
        assert_eq!(got_start.unsigned_value(), Some(99));
    }

    #[test]
    fn get_address_range_iterator_reports_stored_ranges() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = store(&reg);

        let value = RegisterValue::with_value(reg.clone(), 1);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x1010), &value);
        s.set_value(&addr(&space, 0x2000), &addr(&space, 0x2010), &value);

        let ranges: Vec<AddressRange> = s.get_address_range_iterator().collect();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn move_address_range_relocates_values() {
        let space = space();
        let reg = base_register("r0", 4);
        let mut s = store(&reg);
        let value = RegisterValue::with_value(reg.clone(), 55);
        s.set_value(&addr(&space, 0x1000), &addr(&space, 0x100f), &value);

        let monitor = crate::util::task::DummyMonitor;
        s.move_address_range(&addr(&space, 0x1000), &addr(&space, 0x5000), 0x10, &monitor)
            .expect("move should not be cancelled");

        assert!(s.get_value(&reg, &addr(&space, 0x1000)).is_none());
        let got = s.get_value(&reg, &addr(&space, 0x5000)).unwrap();
        assert_eq!(got.unsigned_value(), Some(55));
    }
}
