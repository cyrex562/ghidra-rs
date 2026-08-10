//! Port of `ghidra.trace.database.memory.InternalTraceMemoryOperations`.
//!
//! Internal (package-private in Java) extension of `TraceMemoryOperations` that supplies the
//! register-taking overloads (`setState(TracePlatform, ...)`, `getValue(TracePlatform, ...)`,
//! etc.) in terms of the plain address-range primitives (`setState(long, AddressRange, ...)`,
//! `putBytes(long, Address, ByteBuffer)`, etc.) declared by the base interface.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! A few adaptations from a literal translation:
//!
//! - Java overloads `setState`/`getState`/`getStates`/`putBytes`/`getBytes`/`getValue`/
//!   `getViewValue`/`removeValue` on whether a `TracePlatform` is given. Rust has no overloading,
//!   so each platform-taking override here is named with the `_on_platform` suffix, the
//!   convention already established by
//!   [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView)
//!   for the same `(long, Register)` vs. `(TracePlatform, long, Register)` overload shape. The
//!   host-platform-only convenience overloads (which Java defaults onto
//!   `getTrace().getPlatformManager().getHostPlatform()`) are declared on the base
//!   [`TraceMemoryOperations`](crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations)
//!   interface in Java, but are reproduced *here* instead: their bodies call the `_on_platform`
//!   counterparts, which Rust can only resolve from this trait. Keeping both halves of each
//!   register overload pair together also keeps exactly one Rust name per Java method across the
//!   crate. See that module's documentation for the full split.
//! - `ByteBuffer` position/limit-bounded parameters become `&mut [u8]` slices, per
//!   [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit)'s
//!   docs. Where Java shrinks the buffer's limit to avoid over-reading/writing past the register's
//!   byte length, this port slices the passed buffer to that same length instead.
//! - `getLock()` returning a plain `java.util.concurrent.locks.ReadWriteLock` becomes just
//!   [`Self::write_lock`], returning an owned `Arc<dyn Lock>` rather than a borrowed `&dyn Lock`:
//!   [`Self::set_value_on_platform`] needs to hold the lock (via [`LockHold`]) across calls to
//!   `&mut self` methods, which a lock reference borrowed from `&self` cannot outlive. This is the
//!   same adaptation, for the same reason, as
//!   [`DBTraceDataSettingsOperations`](crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations).
//!   Only `write_lock` is added (not a `read_lock` counterpart), since none of this interface's own
//!   default methods read under the lock.
//! - The static `TraceRegisterUtils` utility class is exposed as an instance accessor,
//!   [`Self::trace_register_utils`], the same translation
//!   [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
//!   already established for the same static-utility-class shape.
//! - The static `requireOne(AddressRange, Collection, Register)` helper becomes the free function
//!   [`require_one`] below, per the convention established by
//!   [`TraceSymbolManager`](crate::trace::model::symbol::trace_symbol_manager)'s
//!   `primality_compare` for static interface methods. The `TraceMemoryOperations.oneState` static
//!   it delegates to lives with its own interface, as
//!   [`one_state`](crate::trace::model::memory::trace_memory_operations::one_state), and is
//!   re-exported here for convenience.

use std::sync::Arc;

use crate::program::model::address::{AddressRange, AddressSpace};
use crate::program::model::lang::Register;
use crate::program::seam_stubs::RegisterValue;
use crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{TraceRegisterUtils};
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::util::lock_hold::{Lock, LockHold};

pub use crate::trace::model::memory::trace_memory_operations::one_state;

/// Asserts that `states` represents a single state across `range`, panicking if more than one
/// state is present.
///
/// Mirrors `InternalTraceMemoryOperations.requireOne(AddressRange, Collection, Register)`.
///
/// # Panics
/// Panics if `states` does not represent a single uniform state across `range`, mirroring the
/// Java method's `IllegalStateException`.
pub fn require_one(
    range: &AddressRange,
    states: &[(Box<dyn TraceAddressSnapRange>, TraceMemoryState)],
    register: &Register,
) -> TraceMemoryState {
    one_state(range, states)
        .unwrap_or_else(|| panic!("More than one state is present in {}", register.name()))
}

/// Internal extension of [`TraceMemoryOperations`] supplying its register-taking overloads.
///
/// Port of `ghidra.trace.database.memory.InternalTraceMemoryOperations`.
///
/// See the module documentation for the object-safety- and ownership-driven deviations from a
/// literal translation.
pub trait InternalTraceMemoryOperations: TraceMemoryOperations {
    /// The address space this memory operates on, used for register mapping conventions. Mirrors
    /// `getSpace()`.
    fn get_space(&self) -> Arc<AddressSpace>;

    /// The lock guarding writes. Mirrors `getLock().writeLock()`; see the module documentation for
    /// why this is a separate, owned-lock-returning method rather than a `getLock():
    /// ReadWriteLock` accessor.
    fn write_lock(&self) -> Arc<dyn Lock>;

    /// The `TraceRegisterUtils` instance used to convert register values to/from raw bytes.
    /// Mirrors the static `TraceRegisterUtils` calls made by this trait's other defaults; see the
    /// module documentation for why this is an instance accessor.
    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils;

    /// Set the state of a given register at a given time. Mirrors `setState(TracePlatform, long,
    /// Register, TraceMemoryState)`.
    fn set_state_on_platform(
        &mut self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
        state: TraceMemoryState,
    ) {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.set_state(snap, &range, state);
    }

    /// Assert that a register's range has a single state at the given snap and get that state.
    /// Mirrors `getState(TracePlatform, long, Register)`.
    ///
    /// # Panics
    /// Panics if the register is mapped to more than one state, mirroring the Java method's
    /// `IllegalStateException`.
    fn get_state_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> TraceMemoryState {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        let states = self.get_states(snap, &range);
        require_one(&range, &states, register)
    }

    /// Get all the entries covering the given register at the given snap. Mirrors
    /// `getStates(TracePlatform, long, Register)`.
    fn get_states_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.get_states(snap, &range)
    }

    /// Write bytes at the given snap and register address. Mirrors `putBytes(TracePlatform, long,
    /// Register, ByteBuffer)`.
    fn put_bytes_on_platform(
        &mut self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
        buf: &mut [u8],
    ) -> i32 {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        let byte_length = range.length() as usize;
        let n = byte_length.min(buf.len());
        self.put_bytes(snap, range.min_address(), &mut buf[..n])
    }

    /// Set the value of a register at the given snap. Mirrors `setValue(TracePlatform, long,
    /// RegisterValue)`.
    fn set_value_on_platform(
        &mut self,
        platform: &dyn TracePlatform,
        snap: i64,
        value: &dyn RegisterValue,
    ) -> i32 {
        if !value.has_any_value() {
            return 0;
        }
        let lock = self.write_lock();
        let _hold = LockHold::lock(lock.as_ref());
        let register_cell = value.get_register();
        let register = register_cell.borrow();
        let range = platform.get_conventional_register_range(&self.get_space(), &register);
        let combined;
        let effective: &dyn RegisterValue = if !value.has_value()
            || !self.trace_register_utils().is_byte_bound(&register)
        {
            // Don't try to inline to keep range. Base register may have different range.
            let base_cell = register.get_base_register();
            let base = base_cell.borrow();
            // Do not use get_view_value/getRegisterValue, as that would zero unmasked bits;
            // instead pass the original register to buffer_for_value below.
            let old = self.get_value_on_platform(platform, snap, &base);
            combined = old.combine_values(value);
            combined.as_ref()
        } else {
            value
        };
        let mut buf = self
            .trace_register_utils()
            .buffer_for_value(&register, effective);
        self.put_bytes(snap, range.min_address(), &mut buf)
    }

    /// Get the most-recent value of a given register at the given time. Mirrors
    /// `getValue(TracePlatform, long, Register)`.
    fn get_value_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> Box<dyn RegisterValue> {
        let mut buf = self.trace_register_utils().prepare_buffer(register);
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.get_bytes(snap, range.min_address(), &mut buf);
        self.trace_register_utils().finish_buffer(&buf, register)
    }

    /// Get the most-recent value of a given register at the given time, following schedule forks.
    /// Mirrors `getViewValue(TracePlatform, long, Register)`.
    fn get_view_value_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> Box<dyn RegisterValue> {
        let mut buf = self.trace_register_utils().prepare_buffer(register);
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.get_view_bytes(snap, range.min_address(), &mut buf);
        self.trace_register_utils().finish_buffer(&buf, register)
    }

    /// Get the most-recent bytes of a given register at the given time. Mirrors
    /// `getBytes(TracePlatform, long, Register, ByteBuffer)`.
    fn get_bytes_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
        buf: &mut [u8],
    ) -> i32 {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        let byte_length = range.length() as usize;
        let n = byte_length.min(buf.len());
        self.get_bytes(snap, range.min_address(), &mut buf[..n])
    }

    /// Remove a value from the given time and register. Mirrors `removeValue(TracePlatform, long,
    /// Register)`.
    fn remove_value_on_platform(&mut self, platform: &dyn TracePlatform, snap: i64, register: &Register) {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.remove_bytes(snap, range.min_address(), range.length() as i32);
    }

    // ---- host-platform convenience overloads ----
    //
    // Declared by `TraceMemoryOperations` in Java, but hosted here because their bodies call the
    // `_on_platform` counterparts above; see the module documentation.

    /// Set the state of a given register at a given time, on the trace's host platform. Mirrors
    /// `setState(long, Register, TraceMemoryState)`.
    fn set_state_for_register(&mut self, snap: i64, register: &Register, state: TraceMemoryState) {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.set_state_on_platform(platform.as_ref(), snap, register, state);
    }

    /// Assert that a register's range has a single state at the given snap on the host platform,
    /// and get that state. Mirrors `getState(long, Register)`.
    ///
    /// # Panics
    /// Panics if the register is mapped to more than one state, mirroring the Java method's
    /// `IllegalStateException`.
    fn get_state_for_register(&self, snap: i64, register: &Register) -> TraceMemoryState {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_state_on_platform(platform.as_ref(), snap, register)
    }

    /// Get all the entries covering the given host-platform register at the given snap. Mirrors
    /// `getStates(long, Register)`.
    fn get_states_for_register(
        &self,
        snap: i64,
        register: &Register,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_states_on_platform(platform.as_ref(), snap, register)
    }

    /// Set the value of a host-platform register at the given snap, returning the number of bytes
    /// written. Mirrors `setValue(long, RegisterValue)`.
    ///
    /// Note that the trace database tracks state with byte, not bit, precision: assigning even a
    /// single bit marks the whole byte [`TraceMemoryState::Known`].
    fn set_value(&mut self, snap: i64, value: &dyn RegisterValue) -> i32 {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.set_value_on_platform(platform.as_ref(), snap, value)
    }

    /// Write bytes at the given snap and host-platform register address. Mirrors `putBytes(long,
    /// Register, ByteBuffer)`.
    ///
    /// Bit-masked registers are not heeded: to preserve non-masked bits, read the current value
    /// and combine it first (or use [`Self::set_value`]).
    fn put_bytes_for_register(&mut self, snap: i64, register: &Register, buf: &mut [u8]) -> i32 {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.put_bytes_on_platform(platform.as_ref(), snap, register, buf)
    }

    /// Get the most-recent value of a given host-platform register at the given time. Mirrors
    /// `getValue(long, Register)`.
    fn get_value(&self, snap: i64, register: &Register) -> Box<dyn RegisterValue> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_value_on_platform(platform.as_ref(), snap, register)
    }

    /// Get the most-recent value of a given host-platform register at the given time, following
    /// schedule forks. Mirrors `getViewValue(long, Register)`.
    fn get_view_value(&self, snap: i64, register: &Register) -> Box<dyn RegisterValue> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_view_value_on_platform(platform.as_ref(), snap, register)
    }

    /// Get the most-recent bytes of a given host-platform register at the given time. Mirrors
    /// `getBytes(long, Register, ByteBuffer)`.
    fn get_bytes_for_register(&self, snap: i64, register: &Register, buf: &mut [u8]) -> i32 {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_bytes_on_platform(platform.as_ref(), snap, register, buf)
    }

    /// Remove a value from the given time and host-platform register. Mirrors `removeValue(long,
    /// Register)`.
    ///
    /// As for [`Self::set_value`], state is tracked per byte: removing even a single bit's
    /// register marks the whole byte [`TraceMemoryState::Unknown`].
    fn remove_value(&mut self, snap: i64, register: &Register) {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.remove_value_on_platform(platform.as_ref(), snap, register);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;
    use crate::trace::model::lifespan::Lifespan;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// A bare `TraceAddressSnapRange` carrying only an X-axis range, sufficient for [`one_state`]
    /// (which never inspects the Y axis).
    struct MockRange {
        range: AddressRange,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by these tests")
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by these tests")
        }

        fn immutable(
            &self,
            _x1: Address,
            _x2: Address,
            _y1: i64,
            _y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn entry(
        space: &Arc<AddressSpace>,
        min: i64,
        max: i64,
        state: TraceMemoryState,
    ) -> (Box<dyn TraceAddressSnapRange>, TraceMemoryState) {
        (
            Box::new(MockRange {
                range: AddressRange::new(addr(space, min), addr(space, max)),
            }),
            state,
        )
    }

    // --- one_state / require_one ---

    #[test]
    fn one_state_empty_is_implied_unknown() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        assert_eq!(one_state(&range, &[]), Some(TraceMemoryState::IMPLIED_BY_NULL));
    }

    #[test]
    fn one_state_uniform_full_coverage_is_that_state() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        let states = [entry(&space, 0, 10, TraceMemoryState::Known)];
        assert_eq!(one_state(&range, &states), Some(TraceMemoryState::Known));
    }

    #[test]
    fn one_state_partial_coverage_is_none() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        let states = [entry(&space, 0, 4, TraceMemoryState::Known)];
        assert_eq!(one_state(&range, &states), None);
    }

    #[test]
    fn one_state_differing_states_is_none() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        let states = [
            entry(&space, 0, 4, TraceMemoryState::Known),
            entry(&space, 5, 10, TraceMemoryState::Error),
        ];
        assert_eq!(one_state(&range, &states), None);
    }

    #[test]
    #[should_panic(expected = "More than one state is present in r0")]
    fn require_one_panics_when_ambiguous() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        let states = [
            entry(&space, 0, 4, TraceMemoryState::Known),
            entry(&space, 5, 10, TraceMemoryState::Error),
        ];
        let register = Register::new("r0", "", addr(&space, 0), 4, false, 0);
        require_one(&range, &states, &register.borrow());
    }

    // --- InternalTraceMemoryOperations end-to-end ---

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockRegisterValue {
        register: RegisterRef,
        bytes: Vec<u8>,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }

        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
                bytes: self.bytes.clone(),
            })
        }

        fn has_any_value(&self) -> bool {
            true
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            let mut padded = [0u8; 16];
            let start = 16 - self.bytes.len();
            padded[start..].copy_from_slice(&self.bytes);
            u128::from_be_bytes(padded)
        }

        fn has_value(&self) -> bool {
            true
        }

        fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test: our register is always byte-bound")
        }
    }

    /// Ignores the value it's handed and always reports the same fixed byte pattern, since the
    /// `RegisterValue` placeholder doesn't yet expose raw bytes to convert. Sufficient to prove
    /// `InternalTraceMemoryOperations`'s orchestration (range computation, buffer prep/finish,
    /// delegation to `put_bytes`/`get_bytes`) end to end.
    struct MockTraceRegisterUtils;

    impl TraceRegisterUtils for MockTraceRegisterUtils {
        fn get_thread(
            &self,
            _trace: &dyn crate::trace::model::trace::Trace,
            _space: &Arc<AddressSpace>,
        ) -> Box<dyn crate::trace::model::thread::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_frame_level(
            &self,
            _trace: &dyn crate::trace::model::trace::Trace,
            _space: &Arc<AddressSpace>,
        ) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_address_space(
            &self,
            _thread: &dyn crate::trace::model::thread::TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn buffer_for_value(&self, register: &Register, _value: &dyn RegisterValue) -> Vec<u8> {
            let mut bytes = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
            bytes.truncate(register.num_bytes() as usize);
            bytes
        }

        fn finish_buffer(&self, buf: &[u8], register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
                bytes: buf.to_vec(),
            })
        }
    }

    struct MockPlatform;
    impl TracePlatform for MockPlatform {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A single-space, in-memory implementation of both `TraceMemoryOperations` and
    /// `InternalTraceMemoryOperations`, sufficient to prove object-safety and exercise the
    /// register-taking defaults' range computation and byte plumbing end to end. Tracks only
    /// whether *any* write has occurred (not per-address/per-snap state), which is enough to
    /// distinguish "unknown" from "known" for these tests.
    struct MockMemorySpace {
        space: Arc<AddressSpace>,
        bytes: Vec<u8>,
        known: bool,
        utils: MockTraceRegisterUtils,
    }

    impl TraceMemoryOperations for MockMemorySpace {
        fn set_state(&mut self, _snap: i64, _range: &AddressRange, state: TraceMemoryState) {
            self.known = state == TraceMemoryState::Known;
        }

        fn get_states(
            &self,
            _snap: i64,
            range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            if !self.known {
                return Vec::new();
            }
            vec![(
                Box::new(MockRange { range: range.clone() }),
                TraceMemoryState::Known,
            )]
        }

        fn put_bytes(&mut self, _snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            let offset = start.offset() as usize;
            let n = buf.len().min(self.bytes.len() - offset);
            self.bytes[offset..offset + n].copy_from_slice(&buf[..n]);
            self.known = true;
            n as i32
        }

        fn get_bytes(&self, _snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            let offset = start.offset() as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(offset));
            buf[..n].copy_from_slice(&self.bytes[offset..offset + n]);
            n as i32
        }

        fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            self.get_bytes(snap, start, buf)
        }

        fn remove_bytes(&mut self, _snap: i64, _start: &Address, _len: i32) {
            self.bytes.fill(0);
            self.known = false;
        }

        // The remaining members are the base interface's query surface, which this double's
        // register-overload tests never reach; only the six primitives above are exercised.

        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_state(&self, _snap: i64, _address: &Address) -> TraceMemoryState {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_view_state(&self, _snap: i64, _address: &Address) -> (i64, TraceMemoryState) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_view_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_view_most_recent_state_entry_where(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_addresses_with_state_in(
            &self,
            _span: Lifespan,
            _set: &dyn crate::program::model::address::AddressSetView,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_addresses_with_state(
            &self,
            _snap: i64,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_addresses_with_state_over(
            &self,
            _lifespan: Lifespan,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_most_recent_states(
            &self,
            _within: &dyn TraceAddressSnapRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_most_recent_states_in(
            &self,
            _snap: i64,
            _range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_bytes(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _data: &[u8],
            _mask: Option<&[u8]>,
            _forward: bool,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Option<Address> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_buffer_at(
            &self,
            _snap: i64,
            _start: &Address,
            _big_endian: bool,
        ) -> Box<dyn crate::program::model::mem::MemBuffer> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap_of_most_recent_change_to_block(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<i64> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_block_size(&self) -> i32 {
            0
        }

        fn pack(&mut self) {}
    }

    impl InternalTraceMemoryOperations for MockMemorySpace {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn write_lock(&self) -> Arc<dyn Lock> {
            Arc::new(NoopLock)
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.utils
        }
    }

    fn make_mem() -> MockMemorySpace {
        let space = ram_space();
        MockMemorySpace {
            space: space.clone(),
            bytes: vec![0u8; 8],
            known: false,
            utils: MockTraceRegisterUtils,
        }
    }

    fn r0(space: &Arc<AddressSpace>) -> RegisterRef {
        Register::new("r0", "", addr(space, 0), 4, false, 0)
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn InternalTraceMemoryOperations) {}
        let mem = make_mem();
        assert_object_safe(&mem);
    }

    #[test]
    fn state_is_unknown_before_any_write_then_known_after() {
        let mut mem = make_mem();
        let space = mem.space.clone();
        let platform = MockPlatform;
        let register = r0(&space);

        assert_eq!(
            mem.get_state_on_platform(&platform, 0, &register.borrow()),
            TraceMemoryState::Unknown
        );

        let value = MockRegisterValue {
            register: register.clone(),
            bytes: Vec::new(),
        };
        mem.set_value_on_platform(&platform, 0, &value);

        assert_eq!(
            mem.get_state_on_platform(&platform, 0, &register.borrow()),
            TraceMemoryState::Known
        );
    }

    #[test]
    fn set_value_writes_the_utils_provided_bytes_at_the_conventional_range() {
        let mut mem = make_mem();
        let space = mem.space.clone();
        let platform = MockPlatform;
        let register = r0(&space);
        let value = MockRegisterValue {
            register: register.clone(),
            bytes: Vec::new(),
        };

        let written = mem.set_value_on_platform(&platform, 0, &value);

        assert_eq!(written, 4);
        assert_eq!(&mem.bytes[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn get_value_round_trips_through_prepare_and_finish_buffer() {
        let mut mem = make_mem();
        let space = mem.space.clone();
        let platform = MockPlatform;
        let register = r0(&space);
        let value = MockRegisterValue {
            register: register.clone(),
            bytes: Vec::new(),
        };
        mem.set_value_on_platform(&platform, 0, &value);

        let got = mem.get_value_on_platform(&platform, 0, &register.borrow());

        assert_eq!(got.get_unsigned_value_ignore_mask(), 0xDEADBEEFu128);
    }

    #[test]
    fn put_bytes_on_platform_clips_to_the_register_length() {
        let mut mem = make_mem();
        let space = mem.space.clone();
        let platform = MockPlatform;
        let register = r0(&space);
        let mut buf = vec![1u8, 2, 3, 4, 5, 6];

        let written = mem.put_bytes_on_platform(&platform, 0, &register.borrow(), &mut buf);

        assert_eq!(written, 4, "the write is clipped to the register's 4-byte length");
        assert_eq!(&mem.bytes[..4], &[1, 2, 3, 4]);
        assert_eq!(mem.bytes[4], 0, "bytes past the register's length are untouched");
    }

    #[test]
    fn remove_value_on_platform_clears_state() {
        let mut mem = make_mem();
        let space = mem.space.clone();
        let platform = MockPlatform;
        let register = r0(&space);
        let value = MockRegisterValue {
            register: register.clone(),
            bytes: Vec::new(),
        };
        mem.set_value_on_platform(&platform, 0, &value);
        assert_eq!(
            mem.get_state_on_platform(&platform, 0, &register.borrow()),
            TraceMemoryState::Known
        );

        mem.remove_value_on_platform(&platform, 0, &register.borrow());

        assert_eq!(
            mem.get_state_on_platform(&platform, 0, &register.borrow()),
            TraceMemoryState::Unknown
        );
    }
}
