//! A p-code executor state that multiplexes shared and thread-local states for use in a machine
//! that models multi-threading.
//!
//! Corresponds to `ghidra.pcode.emu.ThreadPcodeExecutorState`.
//!
//! Java stores the shared and local delegates behind the `PcodeExecutorState<T>` interface, since
//! any runtime implementation is acceptable there. This port instead makes them generic type
//! parameters `S` and `L`: [`fork`](ThreadPcodeExecutorState::fork) must call
//! [`PcodeExecutorStatePiece::fork`] on each delegate, and that method carries a `where Self:
//! Sized` bound specifically to keep [`PcodeExecutorStatePiece`] itself object-safe (see its
//! module docs) -- which means it is simply not callable through a `Box<dyn PcodeExecutorState<T>>`.
//! Generic delegates, the same approach
//! [`PairedPcodeExecutorState`](crate::pcode::exec::paired_pcode_executor_state::PairedPcodeExecutorState)
//! takes, keep forking possible while still letting any pair of concrete states be composed.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;

/// A p-code executor state that multiplexes shared and thread-local states for use in a machine
/// that models multi-threading.
///
/// `T` is the type of values stored in the states. `S` is the concrete type of the shared
/// (memory) delegate and `L` the concrete type of the thread-local (register/unique) delegate.
pub struct ThreadPcodeExecutorState<T: 'static, S, L>
where
    S: PcodeExecutorState<T>,
    L: PcodeExecutorState<T>,
{
    shared_state: S,
    local_state: L,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
}

impl<T: 'static, S, L> ThreadPcodeExecutorState<T, S, L>
where
    S: PcodeExecutorState<T>,
    L: PcodeExecutorState<T>,
{
    /// Create a multiplexed state.
    ///
    /// Port of `ThreadPcodeExecutorState(PcodeExecutorState<T>, PcodeExecutorState<T>)`. See
    /// `DefaultPcodeThread::new` (not yet ported).
    ///
    /// Java asserts `sharedState.getLanguage().equals(localState.getLanguage())` and
    /// `sharedState.getArithmetic().equals(localState.getArithmetic())` here, but `assert`
    /// statements are compiled out unless the JVM runs with `-ea` (off by default), so this is
    /// not a check callers can generally rely on; it is omitted rather than given a false sense
    /// of enforcement; a mismatch simply manifests as later reads/writes behaving as if under the
    /// wrong language.
    pub fn new(shared_state: S, local_state: L) -> Self {
        let arithmetic = shared_state.get_arithmetic();
        Self { shared_state, local_state, arithmetic }
    }

    /// Decide whether or not access to the given space is directed to thread-local state.
    ///
    /// Port of `isThreadLocalSpace(AddressSpace)`.
    fn is_thread_local_space(space: &AddressSpace) -> bool {
        matches!(space.space_type(), AddressSpaceType::Register | AddressSpaceType::Unique)
    }

    /// Get the shared state.
    ///
    /// Port of `getSharedState()`.
    pub fn get_shared_state(&self) -> &S {
        &self.shared_state
    }

    /// Get the thread-local state.
    ///
    /// Port of `getLocalState()`.
    pub fn get_local_state(&self) -> &L {
        &self.local_state
    }
}

impl<T: 'static, S, L> PcodeExecutorStatePiece<T, T> for ThreadPcodeExecutorState<T, S, L>
where
    S: PcodeExecutorState<T>,
    L: PcodeExecutorState<T>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.shared_state.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    /// This will only include the pieces in the thread's *local* state.
    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.local_state.stream_pieces()
    }

    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        Self::new(self.shared_state.fork(cb), self.local_state.fork(cb))
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, val: &T) {
        if Self::is_thread_local_space(space) {
            self.local_state.set_var_abstract(space, offset, size, quantize, val);
            return;
        }
        self.shared_state.set_var_abstract(space, offset, size, quantize, val);
    }

    // Note: like Java, this does *not* return early after writing the local delegate -- the
    // shared delegate is always also written, even for a thread-local space.
    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &T, size: i32, val: &T) {
        if Self::is_thread_local_space(space) {
            self.local_state.set_var_internal_abstract(space, offset, size, val);
        }
        self.shared_state.set_var_internal_abstract(space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &T) {
        if Self::is_thread_local_space(space) {
            self.local_state.set_var(space, offset, size, quantize, val);
            return;
        }
        self.shared_state.set_var(space, offset, size, quantize, val);
    }

    // See the note on `set_var_internal_abstract`: this also always writes the shared delegate.
    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &T) {
        if Self::is_thread_local_space(space) {
            self.local_state.set_var_internal(space, offset, size, val);
        }
        self.shared_state.set_var_internal(space, offset, size, val);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &T, size: i32, quantize: bool, reason: Reason) -> T {
        if Self::is_thread_local_space(space) {
            return self.local_state.get_var_abstract(space, offset, size, quantize, reason);
        }
        self.shared_state.get_var_abstract(space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &T, size: i32, reason: Reason) -> T {
        if Self::is_thread_local_space(space) {
            return self.local_state.get_var_internal_abstract(space, offset, size, reason);
        }
        self.shared_state.get_var_internal_abstract(space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> T {
        if Self::is_thread_local_space(space) {
            return self.local_state.get_var(space, offset, size, quantize, reason);
        }
        self.shared_state.get_var(space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> T {
        if Self::is_thread_local_space(space) {
            return self.local_state.get_var_internal(space, offset, size, reason);
        }
        self.shared_state.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, T)> {
        let mut result = self.local_state.get_register_values();
        for (register, value) in self.shared_state.get_register_values() {
            result.retain(|(r, _)| *r != register);
            result.push((register, value));
        }
        result
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        debug_assert!(!Self::is_thread_local_space(address.space()));
        self.shared_state.get_concrete_buffer(address, purpose)
    }

    /// This will only clear the thread's local state, lest we invoke clear on the shared state
    /// for every thread. Instead, if necessary, the machine should clear its shared state then
    /// clear each thread's local state.
    fn clear(&mut self) {
        self.local_state.clear();
    }
}

impl<T: 'static, S, L> PcodeExecutorState<T> for ThreadPcodeExecutorState<T, S, L>
where
    S: PcodeExecutorState<T>,
    L: PcodeExecutorState<T>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::AddressSpaceType as AST;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::OpCode;

    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn binary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64, _sizein2: i32, _in2: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn mod_before_store(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }

        fn mod_after_load(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }

        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct FixedMemBuffer {
        address: Address,
    }

    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }

        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }

        fn is_big_endian(&self) -> bool {
            false
        }
    }

    /// A leaf state backed by an in-memory map, keyed by offset, recording every abstract-domain
    /// write and read so tests can check which delegate (shared or local) answered.
    struct MapState {
        cells: RefCell<HashMap<i64, i64>>,
        registers: RefCell<Vec<(RegisterRef, i64)>>,
        writes: RefCell<Vec<i64>>,
        reads: RefCell<Vec<i64>>,
        buffer_address: Address,
    }

    impl MapState {
        fn new(buffer_address: Address) -> Self {
            Self {
                cells: RefCell::new(HashMap::new()),
                registers: RefCell::new(Vec::new()),
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(Vec::new()),
                buffer_address,
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }

        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self
        where
            Self: Sized,
        {
            Self {
                cells: RefCell::new(self.cells.borrow().clone()),
                registers: RefCell::new(self.registers.borrow().clone()),
                writes: RefCell::new(Vec::new()),
                reads: RefCell::new(Vec::new()),
                buffer_address: self.buffer_address.clone(),
            }
        }

        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, val: &i64) {
            self.writes.borrow_mut().push(*offset);
            self.cells.borrow_mut().insert(*offset, *val);
        }

        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            self.set_var_abstract(space, offset, size, false, val);
        }

        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, _reason: Reason) -> i64 {
            self.reads.borrow_mut().push(*offset);
            *self.cells.borrow().get(offset).unwrap_or(&0)
        }

        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            self.registers.borrow().clone()
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            Box::new(FixedMemBuffer { address: self.buffer_address.clone() })
        }

        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AST::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AST::Register, 1)
    }

    fn unique_space() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AST::Unique, 2)
    }

    fn state() -> ThreadPcodeExecutorState<i64, MapState, MapState> {
        ThreadPcodeExecutorState::new(
            MapState::new(ram_space().address(0x1000)),
            MapState::new(ram_space().address(0x2000)),
        )
    }

    /// Java: `isThreadLocalSpace` routes register and unique spaces to the local state.
    #[test]
    fn register_and_unique_spaces_route_to_local_state() {
        let mut state = state();
        let reg = register_space();
        let uniq = unique_space();

        state.set_var(&reg, 0x10, 4, false, &42);
        state.set_var(&uniq, 0x20, 4, false, &43);

        assert_eq!(state.get_var(&reg, 0x10, 4, false, Reason::ExecuteRead), 42);
        assert_eq!(state.get_var(&uniq, 0x20, 4, false, Reason::ExecuteRead), 43);
        assert_eq!(state.local_state.writes.borrow().as_slice(), &[0x10, 0x20]);
        assert!(state.shared_state.writes.borrow().is_empty());
    }

    /// Java: every other space (e.g. `ram`) routes to the shared state.
    #[test]
    fn memory_spaces_route_to_shared_state() {
        let mut state = state();
        let ram = ram_space();

        state.set_var(&ram, 0x3000, 8, false, &99);

        assert_eq!(state.get_var(&ram, 0x3000, 8, false, Reason::ExecuteRead), 99);
        assert_eq!(state.shared_state.writes.borrow().as_slice(), &[0x3000]);
        assert!(state.local_state.writes.borrow().is_empty());
    }

    /// `setVarInternal`/`getVarInternal` for a thread-local space, per Java, write to *both*
    /// delegates (the `if` block has no early return), but read only from local.
    #[test]
    fn set_var_internal_writes_both_delegates_for_a_local_space() {
        let mut state = state();
        let reg = register_space();

        state.set_var_internal(&reg, 0x10, 4, &7);

        assert_eq!(state.local_state.writes.borrow().as_slice(), &[0x10]);
        assert_eq!(state.shared_state.writes.borrow().as_slice(), &[0x10]);
        assert_eq!(state.get_var_internal(&reg, 0x10, 4, Reason::ExecuteRead), 7);
    }

    /// `getConcreteBuffer` always defers to the shared state.
    #[test]
    fn get_concrete_buffer_defers_to_shared_state() {
        let state = state();
        let buf = state.get_concrete_buffer(&ram_space().address(0x9000), Purpose::Other);
        assert_eq!(buf.get_address(), ram_space().address(0x1000));
    }

    /// `clear` only clears the local state.
    #[test]
    fn clear_only_clears_local_state() {
        let mut state = state();
        let ram = ram_space();
        let reg = register_space();
        state.set_var(&ram, 0x3000, 8, false, &1);
        state.set_var(&reg, 0x10, 4, false, &2);

        state.clear();

        assert_eq!(state.get_var(&ram, 0x3000, 8, false, Reason::ExecuteRead), 1);
        assert_eq!(state.get_var(&reg, 0x10, 4, false, Reason::ExecuteRead), 0);
    }

    /// `getRegisterValues` merges both delegates, with the shared delegate's value winning any
    /// conflict -- Java's `result.putAll(local); result.putAll(shared);`.
    #[test]
    fn get_register_values_merges_with_shared_taking_precedence() {
        let state = state();
        let reg = register_space();
        let shared_only = Register::new("R0", "", reg.address(0x0), 4, false, Register::TYPE_NONE);
        let local_only = Register::new("R1", "", reg.address(0x4), 4, false, Register::TYPE_NONE);
        let conflict = Register::new("R2", "", reg.address(0x8), 4, false, Register::TYPE_NONE);

        state.shared_state.registers.borrow_mut().push((std::rc::Rc::clone(&shared_only), 1));
        state.shared_state.registers.borrow_mut().push((std::rc::Rc::clone(&conflict), 100));
        state.local_state.registers.borrow_mut().push((std::rc::Rc::clone(&local_only), 2));
        state.local_state.registers.borrow_mut().push((std::rc::Rc::clone(&conflict), 999));

        let mut values = state.get_register_values();
        values.sort_by_key(|(r, _)| r.borrow().offset());

        assert_eq!(values, vec![(shared_only, 1), (local_only, 2), (conflict, 100)]);
    }

    /// `fork` produces a state whose delegates are independent of the original's.
    #[test]
    fn fork_produces_independent_delegates() {
        let mut state = state();
        let ram = ram_space();
        state.set_var(&ram, 0x100, 8, false, &1);

        let mut forked = state.fork(&NoPcodeStateCallbacks);
        forked.set_var(&ram, 0x100, 8, false, &2);

        assert_eq!(state.get_var(&ram, 0x100, 8, false, Reason::ExecuteRead), 1);
        assert_eq!(forked.get_var(&ram, 0x100, 8, false, Reason::ExecuteRead), 2);
    }

    /// `getSharedState`/`getLocalState` return the original delegates.
    #[test]
    fn get_shared_state_and_get_local_state_return_the_delegates() {
        let mut state = state();
        let ram = ram_space();
        let reg = register_space();
        state.set_var(&ram, 0x100, 8, false, &1);
        state.set_var(&reg, 0x10, 4, false, &2);

        assert_eq!(state.get_shared_state().get_var_abstract(&ram, &0x100, 8, false, Reason::ExecuteRead), 1);
        assert_eq!(state.get_local_state().get_var_abstract(&reg, &0x10, 4, false, Reason::ExecuteRead), 2);
    }
}
