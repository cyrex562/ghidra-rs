//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeThread`.
//!
//! # Deviations from Java
//!
//! Java's `SymZ3PcodeThread extends AuxPcodeThread<SymValueZ3> implements
//! InternalSymZ3RecordsPreconditions`. Its surface splits into two very different kinds of
//! member, and this port treats them very differently:
//!
//! * **Execution-machinery overrides** (`createInstructionDecoder`, `createThreadState`,
//!   `getState()`'s covariant narrowing): these wire the thread into the surrounding emulator
//!   (decoder, machine, counter, injects). `createInstructionDecoder` specifically needs
//!   `SleighInstructionDecoder`, which is not ported (the identical blocker
//!   [`JitPcodeThread`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread)'s own module
//!   docs describe for the same reason). `createThreadState`'s return type,
//!   `SymZ3ThreadPcodeExecutorState`, is Java's covariant-narrowing subclass of the already-ported
//!   generic [`ThreadPcodeExecutorState`] -- since Rust generics do not erase `S`/`L` the way
//!   Java's `PcodeExecutorState<T>` field type does, `ThreadPcodeExecutorState<(Vec<u8>,
//!   SymValueZ3), S, L>` (used directly, with `S`/`L` bounded to
//!   [`SymZ3PairedPcodeExecutorState`]) already **is** the narrowed type Java needs a subclass
//!   for, so no separate `SymZ3ThreadPcodeExecutorState` port or stub is needed at all. None of
//!   this machinery is ported here; see [`Self::with_state`] for what this type builds instead.
//! * **State-touching convenience members** (`getSharedConcreteState`/`getSharedSymbolicState`/
//!   `getLocalConcreteState`/`getLocalSymbolicState`, `addPrecondition`/`getPreconditions`,
//!   `addInstruction`/`addOp`): these only need access to the thread's paired (concrete, symbolic)
//!   state, not the full execution machinery above. This port provides them for real, backed by
//!   [`Self::with_state`] rather than the (blocked) full constructor.
//! * **Register/memory comparison debug tools** (`printRegisterComparison`/`registerComparison`/
//!   `printMemoryComparisonRegPlusOffset`/`memoryComparisonRegPlusOffset`): these additionally need
//!   a live `Language` (for `getRegister`/`getAddressFactory`), a concrete arithmetic, and Z3
//!   simplification, none of which this thread otherwise holds or needs. Not ported; a caller
//!   that already has all of that context can reimplement them inline more simply than this type
//!   could re-expose it.
//!
//! Four other in-repo files ([`RecInstruction`]/[`RecOp`](crate::pcode::emu::symz3::sym_z3_records_execution),
//! [`InternalSymZ3RecordsExecution`](crate::pcode::emu::symz3::internal_sym_z3_records_execution),
//! [`SymZ3PcodeEmulatorTrait`](crate::pcode::emu::symz3::sym_z3_pcode_emulator_trait)) already
//! store or return a bare, non-generic `SymZ3PcodeThread` value (a placeholder, prior to this
//! port, modeling just Java's inherited `getName()`) and clone it freely, standing in for Java's
//! shared-reference semantics. Making this type generic over `S`/`L` -- the straightforward
//! reading of "wrap an `AuxPcodeThread<SymValueZ3, S, L>`" -- would force that genericity onto all
//! four of those already-ported files, `dyn`-hostile since [`AuxPcodeThread`] cannot be boxed
//! (it is not itself object-safe). Instead, this type stays non-generic: its (optional) state is
//! type-erased behind the small local [`SymZ3ThreadState`] trait and shared via `Arc<Mutex<_>>`,
//! so [`Clone`] is cheap (an `Arc` bump) and, faithfully to Java's reference semantics, every
//! clone observes the same mutations.
//!
//! `add_instruction`/`add_op`/`add_precondition` all need to *mutate* the paired state's symbolic
//! side reached through [`SymZ3PairedPcodeExecutorState::get_right`], which only exposes `&self`
//! access; [`ThreadPcodeExecutorState::get_shared_state_mut`]/[`SymZ3PairedPcodeExecutorState::get_right_mut`]
//! are small additive extensions this port made to those already-real types for exactly this need
//! (see their own docs).

use std::sync::{Arc, Mutex};

use crate::pcode::emu::symz3::internal_sym_z3_records_execution::InternalSymZ3RecordsExecution;
use crate::pcode::emu::symz3::internal_sym_z3_records_preconditions::InternalSymZ3RecordsPreconditions;
use crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state::SymZ3PairedPcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece;
use crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions;
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::PcodeOp;

/// Type-erased access to a thread's paired (concrete, symbolic) shared/local state.
///
/// Not a port of any Java type -- see the module docs for why [`SymZ3PcodeThread`] needs this
/// rather than storing `ThreadPcodeExecutorState<(Vec<u8>, SymValueZ3), S, L>` directly.
trait SymZ3ThreadState {
    fn shared_state(&self) -> &dyn SymZ3PairedPcodeExecutorState;
    fn shared_state_mut(&mut self) -> &mut dyn SymZ3PairedPcodeExecutorState;
    fn local_state(&self) -> &dyn SymZ3PairedPcodeExecutorState;
    fn local_state_mut(&mut self) -> &mut dyn SymZ3PairedPcodeExecutorState;
}

impl<S, L> SymZ3ThreadState for ThreadPcodeExecutorState<(Vec<u8>, SymValueZ3), S, L>
where
    S: SymZ3PairedPcodeExecutorState + 'static,
    L: SymZ3PairedPcodeExecutorState + 'static,
{
    fn shared_state(&self) -> &dyn SymZ3PairedPcodeExecutorState {
        self.get_shared_state()
    }
    fn shared_state_mut(&mut self) -> &mut dyn SymZ3PairedPcodeExecutorState {
        self.get_shared_state_mut()
    }
    fn local_state(&self) -> &dyn SymZ3PairedPcodeExecutorState {
        self.get_local_state()
    }
    fn local_state_mut(&mut self) -> &mut dyn SymZ3PairedPcodeExecutorState {
        self.get_local_state_mut()
    }
}

/// A thread of SymZ3 (symbolic Z3) p-code emulation.
///
/// Port of `ghidra.pcode.emu.symz3.SymZ3PcodeThread`. See the module docs for the split between
/// what is and is not ported here.
#[derive(Clone)]
pub struct SymZ3PcodeThread {
    name: String,
    state: Option<Arc<Mutex<dyn SymZ3ThreadState>>>,
}

impl SymZ3PcodeThread {
    /// Construct a thread with only a name, no state.
    ///
    /// This is what [`SymZ3PcodeEmulatorTrait`](crate::pcode::emu::symz3::sym_z3_pcode_emulator_trait::SymZ3PcodeEmulatorTrait)
    /// implementors can build without the unported execution machinery (see the module docs);
    /// most methods below panic on a thread built this way. This mirrors the placeholder this
    /// port replaces and [`JitPcodeThread::named`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread::named)'s
    /// identical accommodation.
    pub fn named(name: impl Into<String>) -> Self {
        Self { name: name.into(), state: None }
    }

    /// Construct a thread backed by real paired shared/local state.
    ///
    /// Not a direct port of any Java constructor (Java's sole constructor is `(String,
    /// AuxPcodeEmulator<SymValueZ3>)`, which derives this same shared/local pairing from the
    /// machine via the unported execution machinery -- see the module docs); this is what a
    /// caller with the pieces `AuxPcodeThread::new` would otherwise need can build today.
    pub fn with_state<S, L>(name: impl Into<String>, shared_state: S, local_state: L) -> Self
    where
        S: SymZ3PairedPcodeExecutorState + 'static,
        L: SymZ3PairedPcodeExecutorState + 'static,
    {
        let state: ThreadPcodeExecutorState<(Vec<u8>, SymValueZ3), S, L> =
            ThreadPcodeExecutorState::new(shared_state, local_state);
        Self { name: name.into(), state: Some(Arc::new(Mutex::new(state))) }
    }

    /// Java: `PcodeThread.getName()`, inherited.
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// The state this thread was built with, or a panic naming what's missing.
    ///
    /// # Panics
    ///
    /// If this thread was built via [`Self::named`] (no state).
    fn require_state(&self) -> &Arc<Mutex<dyn SymZ3ThreadState>> {
        self.state.as_ref().expect(
            "this SymZ3PcodeThread has no state; construct it via SymZ3PcodeThread::with_state \
             (a name-only thread, from SymZ3PcodeThread::named, has none -- see the module docs)",
        )
    }

    /// Run `f` against the shared symbolic state.
    ///
    /// Java: `getSharedSymbolicState()`, but see the module docs for why this cannot simply
    /// return `&SymZ3PcodeExecutorStatePiece` (it would borrow from a lock guard that does not
    /// outlive the call).
    pub fn with_shared_symbolic_state<R>(
        &self,
        f: impl FnOnce(&SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        let guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.shared_state().get_right())
    }

    /// Mutable counterpart to [`Self::with_shared_symbolic_state`].
    pub fn with_shared_symbolic_state_mut<R>(
        &self,
        f: impl FnOnce(&mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        let mut guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.shared_state_mut().get_right_mut())
    }

    /// Run `f` against the local symbolic state.
    ///
    /// Java: `getLocalSymbolicState()`. See [`Self::with_shared_symbolic_state`]'s docs.
    pub fn with_local_symbolic_state<R>(
        &self,
        f: impl FnOnce(&SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        let guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.local_state().get_right())
    }

    /// Mutable counterpart to [`Self::with_local_symbolic_state`].
    pub fn with_local_symbolic_state_mut<R>(
        &self,
        f: impl FnOnce(&mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> R,
    ) -> R {
        let mut guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.local_state_mut().get_right_mut())
    }

    /// Java: `getSharedConcreteState()`.
    pub fn with_shared_concrete_state<R>(
        &self,
        f: impl FnOnce(&dyn crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>) -> R,
    ) -> R {
        let guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.shared_state().get_left())
    }

    /// Java: `getLocalConcreteState()`.
    pub fn with_local_concrete_state<R>(
        &self,
        f: impl FnOnce(&dyn crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>) -> R,
    ) -> R {
        let guard = self.require_state().lock().expect("SymZ3PcodeThread state lock poisoned");
        f(guard.local_state().get_left())
    }

    /// Java: `addInstruction(Instruction)`. Records the instruction against this thread's shared
    /// symbolic state, exactly as `getSharedSymbolicState().addInstruction(this, inst)`.
    pub fn add_instruction(&self, inst: Arc<dyn Instruction>) {
        let recorded_as = self.clone();
        self.with_shared_symbolic_state_mut(|state| {
            InternalSymZ3RecordsExecution::add_instruction(state, &recorded_as, inst)
        });
    }

    /// Java: `addOp(PcodeOp)`.
    pub fn add_op(&self, op: PcodeOp) {
        let recorded_as = self.clone();
        self.with_shared_symbolic_state_mut(|state| {
            InternalSymZ3RecordsExecution::add_op(state, &recorded_as, op)
        });
    }
}

impl InternalSymZ3RecordsPreconditions for SymZ3PcodeThread {
    /// Java: `addPrecondition(String)`, delegating to `getLocalSymbolicState().addPrecondition`.
    fn add_precondition(&mut self, precondition: String) {
        self.with_local_symbolic_state_mut(|state| {
            InternalSymZ3RecordsPreconditions::add_precondition(state, precondition)
        });
    }
}

impl SymZ3RecordsPreconditions for SymZ3PcodeThread {
    /// Java: `getPreconditions()`, delegating to `getLocalSymbolicState().getPreconditions()`.
    fn get_preconditions(&self) -> Vec<String> {
        self.with_local_symbolic_state(|state| SymZ3RecordsPreconditions::get_preconditions(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing::piece;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason};
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::pcode::OpCode;

    /// A `PcodeArithmetic<(Vec<u8>, SymValueZ3)>` that is never actually invoked: `ThreadPcodeExecutorState::new`
    /// eagerly caches `shared_state.get_arithmetic()` at construction (see its own docs), so
    /// `FakePairedState::get_arithmetic` needs *something* to return even though this test never
    /// exercises arithmetic through it.
    struct DummyPairArithmetic;

    impl PcodeArithmetic<(Vec<u8>, SymValueZ3)> for DummyPairArithmetic {
        fn get_endian(&self) -> Option<crate::program::model::lang::endian::Endian> {
            unimplemented!("not exercised by this test")
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &(Vec<u8>, SymValueZ3)) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &(Vec<u8>, SymValueZ3),
            _sizein2: i32,
            _in2: &(Vec<u8>, SymValueZ3),
        ) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, SymValueZ3),
            _sizein_value: i32,
            _in_value: &(Vec<u8>, SymValueZ3),
        ) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, SymValueZ3),
            _sizein_value: i32,
            _in_value: &(Vec<u8>, SymValueZ3),
        ) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn from_const_bytes(&self, _value: &[u8]) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn to_concrete(&self, _value: &(Vec<u8>, SymValueZ3), _purpose: Purpose) -> Result<Vec<u8>, crate::pcode::exec::concretion_error::ConcretionError> {
            unimplemented!("not exercised by this test")
        }
        fn size_of(&self, _value: &(Vec<u8>, SymValueZ3)) -> i64 {
            unimplemented!("not exercised by this test")
        }
    }

    /// A minimal concrete (`Vec<u8>`) left-hand piece, only enough of `PcodeExecutorStatePiece`
    /// to satisfy `SymZ3PairedPcodeExecutorState::get_left`'s trait object -- mirroring
    /// `SymZ3PairedPcodeExecutorState`'s own test module's `FakeLeft`.
    struct FakeLeft;

    impl ErasedPcodeExecutorStatePiece for FakeLeft {}

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for FakeLeft {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this test")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("not exercised by this test")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("not exercised by this test")
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _val: &Vec<u8>) {}
        fn set_var_internal_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _val: &Vec<u8>) {}
        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _reason: Reason) -> Vec<u8> {
            Vec::new()
        }
        fn get_var_internal_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _reason: Reason) -> Vec<u8> {
            Vec::new()
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            Vec::new()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this test")
        }
        fn clear(&mut self) {}
    }

    /// A paired state pairing [`FakeLeft`] with a real
    /// [`SymZ3PcodeExecutorStatePiece`](crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece)
    /// (via [`piece`]), so `SymZ3PcodeThread`'s state-touching methods have something real to
    /// mutate.
    struct FakePairedState {
        left: FakeLeft,
        right: SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>,
    }

    impl ErasedPcodeExecutorStatePiece for FakePairedState {}

    impl PcodeExecutorStatePiece<(Vec<u8>, SymValueZ3), (Vec<u8>, SymValueZ3)> for FakePairedState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this test")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, SymValueZ3)>> {
            unimplemented!("not exercised by this test")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, SymValueZ3)>> {
            Arc::new(DummyPairArithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &(Vec<u8>, SymValueZ3), _size: i32, _quantize: bool, _val: &(Vec<u8>, SymValueZ3)) {}
        fn set_var_internal_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &(Vec<u8>, SymValueZ3), _size: i32, _val: &(Vec<u8>, SymValueZ3)) {}
        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, _offset: &(Vec<u8>, SymValueZ3), _size: i32, _quantize: bool, _reason: Reason) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn get_var_internal_abstract(&self, _space: &Arc<AddressSpace>, _offset: &(Vec<u8>, SymValueZ3), _size: i32, _reason: Reason) -> (Vec<u8>, SymValueZ3) {
            unimplemented!("not exercised by this test")
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, (Vec<u8>, SymValueZ3))> {
            Vec::new()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this test")
        }
        fn clear(&mut self) {}
    }

    impl PcodeExecutorState<(Vec<u8>, SymValueZ3)> for FakePairedState {}

    impl SymZ3PairedPcodeExecutorState for FakePairedState {
        fn get_left(&self) -> &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> {
            &self.left
        }
        fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
            &self.right
        }
        fn get_right_mut(&mut self) -> &mut SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
            &mut self.right
        }
    }

    fn paired() -> FakePairedState {
        FakePairedState { left: FakeLeft, right: piece() }
    }

    fn thread() -> SymZ3PcodeThread {
        SymZ3PcodeThread::with_state("[Threads][0]", paired(), paired())
    }

    #[test]
    fn named_thread_reports_its_name() {
        let t = SymZ3PcodeThread::named("[Threads][7]");
        assert_eq!(t.get_name(), "[Threads][7]");
    }

    #[test]
    #[should_panic(expected = "has no state")]
    fn named_thread_panics_on_state_access() {
        let t = SymZ3PcodeThread::named("[Threads][7]");
        t.with_local_symbolic_state(|_| ());
    }

    #[test]
    fn add_precondition_and_get_preconditions_round_trip() {
        let mut t = thread();
        InternalSymZ3RecordsPreconditions::add_precondition(&mut t, "x > 0".to_string());
        assert_eq!(SymZ3RecordsPreconditions::get_preconditions(&t), vec!["x > 0".to_string()]);
    }

    #[test]
    fn add_instruction_and_add_op_accumulate_on_the_shared_state() {
        use crate::pcode::emu::symz3::sym_z3_records_execution::SymZ3RecordsExecution;

        let t = thread();
        let ram = AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = ram.address(0x400);

        t.add_op(PcodeOp::with_address_no_inputs(addr, 0, OpCode::Copy));

        let ops = t.with_shared_symbolic_state(|s| SymZ3RecordsExecution::get_ops(s));
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].thread.get_name(), "[Threads][0]");
    }

    #[test]
    fn cloned_thread_shares_the_same_underlying_state() {
        let t = thread();
        let mut clone = t.clone();

        InternalSymZ3RecordsPreconditions::add_precondition(&mut clone, "shared".to_string());
        // Adding through the clone must be visible from the original: all clones share one
        // Arc<Mutex<_>>, faithfully standing in for Java's shared object reference.
        assert_eq!(SymZ3RecordsPreconditions::get_preconditions(&t), vec!["shared".to_string()]);
    }
}
