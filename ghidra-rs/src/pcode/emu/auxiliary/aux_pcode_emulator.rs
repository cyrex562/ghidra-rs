//! An emulator whose parts are manufactured by an [`AuxEmulatorPartsFactory`].
//!
//! Corresponds to `ghidra.pcode.emu.auxiliary.AuxPcodeEmulator`.
//!
//! See the parts factory trait: [`AuxEmulatorPartsFactory`]. Also see
//! [`SymZ3PcodeEmulator`](crate::pcode::emu::symz3::state::sym_z3_pcode_emulator::SymZ3PcodeEmulator)
//! for a complete example based on this class.
//!
//! `U` is Java's `AuxPcodeEmulator<U>` type parameter: the type of auxiliary values. As with
//! [`AuxEmulatorPartsFactory`], Java's `Pair<byte[], U>` is rendered as the tuple `(Vec<u8>, U)`.
//!
//! Deviations from the Java source:
//!
//! * Java's sole abstract member, `getPartsFactory()`, is not part of this trait: the factory's
//!   products are associated types (see [`AuxEmulatorPartsFactory`]), so a method returning the
//!   factory polymorphically would make `AuxPcodeEmulator` impossible to use as the `&dyn
//!   AuxPcodeEmulator<U>` the factory's own methods receive. Instead, Java's overridden
//!   `createArithmetic`/`createUseropLibrary`/`createThreadStubLibrary`/`createSharedState`/
//!   `createLocalState`/`createThread` are all free functions below, each taking the concrete
//!   implementer's factory alongside whatever else they need. A concrete implementer stores its
//!   own factory (Java says it "should just be a singleton") and forwards
//!   [`AbstractPcodeMachine`]'s `create_shared_state`/`create_local_state` and
//!   [`AbstractPcodeMachineThreads`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineThreads)'s
//!   `create_thread` to these functions, passing that stored factory.
//! * Java calls `createArithmetic()`/`createUseropLibrary()`/`createThreadStubLibrary()` from
//!   within `super(language, cb)`, on a `this` whose fields do not exist yet. Rust cannot
//!   construct `&self` before `self` exists, so [`create_arithmetic`]/[`create_userop_library`]/
//!   [`create_thread_stub_library`] take the language (and the parts factory) as plain
//!   parameters, matching the deviation
//!   [`AbstractPcodeMachineBase::new`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::new)
//!   already documents for these same three constructor-time factories.
//! * `createSharedState`/`createLocalState`'s Java bodies build a `PcodeStateCallbacks` via
//!   `cb.wrapFor(...)`, adapting the machine's `PcodeEmulationCallbacks` to state callbacks. That
//!   adapter ([`Wrapper`](crate::pcode::emu::pcode_emulation_callbacks::Wrapper)) borrows the
//!   callbacks for a lifetime, so a state cannot keep it; [`create_shared_state`]/
//!   [`create_local_state`] use [`NONE`](crate::pcode::exec::pcode_state_callbacks::NONE) (Java's
//!   own `PcodeStateCallbacks.NONE`) instead, both for the fresh concrete
//!   [`BytesPcodeExecutorStatePiece`] and as the callbacks handed to the parts factory; every
//!   callback the state pieces would receive is simply dropped, as it would be for an emulator
//!   whose callbacks are already the default no-ops. The factory is therefore the one for
//!   [`NoPcodeStateCallbacks`], the default of its `CB` parameter.

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::{AbstractPcodeMachine, AbstractPcodeMachineBase};
use crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory;
use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxThreadParts;
use crate::pcode::emu::default_pcode_thread::PcodeEmulationLibrary;
use crate::pcode::exec::bytes_pcode_arithmetic::BytesPcodeArithmetic;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_state_callbacks::{NoPcodeStateCallbacks, NONE};
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::Language;

/// An emulator whose parts are manufactured by a [`AuxEmulatorPartsFactory`].
///
/// This is a genuine extension point: a concrete implementor supplies its own
/// `AuxEmulatorPartsFactory` and forwards [`AbstractPcodeMachine`]'s abstract methods to the free
/// functions in this module. See the module docs for why `getPartsFactory()` itself is not a
/// method here.
pub trait AuxPcodeEmulator<U: 'static>: AbstractPcodeMachine<(Vec<u8>, U)> {}

/// Port of the overridden `createArithmetic()`: pairs the concrete bytes arithmetic with the
/// parts factory's auxiliary arithmetic.
pub fn create_arithmetic<U: 'static>(
    language: &Arc<dyn Language>,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Arc<dyn PcodeArithmetic<(Vec<u8>, U)>> {
    Arc::new(PairedPcodeArithmetic::new(
        Arc::new(BytesPcodeArithmetic::for_language(language.as_ref())),
        parts_factory.get_arithmetic(language.as_ref()),
    ))
}

/// Port of the overridden `createUseropLibrary()`: composes the machine's default userop library
/// with the parts factory's shared userop library.
pub fn create_userop_library<U: 'static>(
    language: &SleighLanguage,
    arithmetic: &dyn PcodeArithmetic<(Vec<u8>, U)>,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> {
    let base = AbstractPcodeMachineBase::create_userop_library(language, arithmetic, "", &[]);
    base.compose(parts_factory.create_shared_userop_library(language).as_ref())
}

/// Port of the overridden `createThreadStubLibrary()`: composes the machine's default stub
/// library, `new DefaultPcodeThread.PcodeEmulationLibrary<>(null)`, with the parts factory's local
/// userop stub.
pub fn create_thread_stub_library<U: 'static>(
    language: &SleighLanguage,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> {
    let base: Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> = Box::new(PcodeEmulationLibrary::new(None));
    base.compose(parts_factory.create_local_userop_stub(language).as_ref())
}

/// Port of the overridden `createSharedState()`.
///
/// The emulator shares the product with its threads by putting it behind a
/// [`SharedPcodeExecutorState`](crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState)
/// handle, as [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) does.
pub fn create_shared_state<U: 'static, F: AuxEmulatorPartsFactory<U>>(
    emulator: &dyn AuxPcodeEmulator<U>,
    parts_factory: &F,
) -> F::SharedState {
    // Java: `scb = cb.wrapFor(null)`; see the module docs for why this is `NONE`.
    let scb = Arc::new(NONE);
    parts_factory.create_shared_state(emulator, new_concrete_piece(emulator, &scb), scb)
}

/// Port of the overridden `createLocalState(PcodeThread<Pair<byte[], U>>)`, for the thread that
/// will be named `thread_name` (see [`AuxEmulatorPartsFactory::create_local_state`]).
pub fn create_local_state<U: 'static, F: AuxEmulatorPartsFactory<U>>(
    emulator: &dyn AuxPcodeEmulator<U>,
    thread_name: &str,
    parts_factory: &F,
) -> F::LocalState {
    // Java: `scb = cb.wrapFor(thread)`; see the module docs for why this is `NONE`.
    let scb = Arc::new(NONE);
    parts_factory.create_local_state(emulator, thread_name, new_concrete_piece(emulator, &scb), scb)
}

/// Java's `new BytesPcodeExecutorStatePiece(language, scb)`, shared by [`create_shared_state`]
/// and [`create_local_state`].
fn new_concrete_piece<U: 'static>(
    emulator: &dyn AuxPcodeEmulator<U>,
    scb: &Arc<NoPcodeStateCallbacks>,
) -> BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks> {
    let language: Arc<dyn Language> = Arc::clone(emulator.base().language()) as Arc<dyn Language>;
    BytesPcodeExecutorStatePiece::new(language, Arc::clone(scb))
}

/// Port of the overridden `createThread(String)`: `getPartsFactory().createThread(this, name)`.
///
/// `parts` is what the thread's constructor reads off the emulator; see [`AuxThreadParts`].
pub fn create_thread<U: 'static, F: AuxEmulatorPartsFactory<U>>(
    emulator: &dyn AuxPcodeEmulator<U>,
    name: &str,
    parts_factory: &Arc<F>,
    parts: AuxThreadParts<U, F::SharedState, F::LocalState>,
) -> F::Thread {
    Arc::clone(parts_factory).create_thread(emulator, name, parts)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::pcode::emu::abstract_pcode_machine::PcodeMachineShared;
    use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxPcodeThread;
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, PcodeMachine, SwiMode};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::exec::pcode_userop_library::{nil, ErasedPcodeUseropLibrary, PcodeUseropDefinition, UseropMap};
    use crate::pcode::emu::pcode_emulation_callbacks::PcodeEmulationCallbacks;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, PackedDecode};
    use std::collections::HashMap;

    /// Minimal arithmetic over `(Vec<u8>, i64)`, mirroring the fixtures already used by
    /// `abstract_pcode_machine` and `aux_emulator_parts_factory`: just enough of
    /// [`PcodeArithmetic`] to construct a machine, not to compute anything meaningful.
    struct StubArithmetic;

    impl PcodeArithmetic<(Vec<u8>, i64)> for StubArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &(Vec<u8>, i64),
            _sizein2: i32,
            _in2: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sizein_value: i32,
            in_value: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sizein_value: i32,
            in_value: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> (Vec<u8>, i64) {
            (value.to_vec(), 0)
        }
        fn to_concrete(
            &self,
            value: &(Vec<u8>, i64),
            _purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.0.clone())
        }
        fn size_of(&self, value: &(Vec<u8>, i64)) -> i64 {
            value.0.len() as i64
        }
    }

    /// Callbacks that do nothing, so `AbstractPcodeMachineBase::new` has something to hold.
    struct NoCallbacks;

    impl PcodeEmulationCallbacks<(Vec<u8>, i64)> for NoCallbacks {}

    /// A state that does nothing; the free functions under test only need something to hand back,
    /// never to read.
    struct EmptyState;

    impl PcodeExecutorStatePiece<(Vec<u8>, i64), (Vec<u8>, i64)> for EmptyState {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("test should not call this")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            Arc::new(StubArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            Arc::new(StubArithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, i64),
            _size: i32,
            _quantize: bool,
            _val: &(Vec<u8>, i64),
        ) {
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, i64),
            _size: i32,
            _val: &(Vec<u8>, i64),
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, i64),
            size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> (Vec<u8>, i64) {
            (vec![0; size as usize], 0)
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, i64),
            size: i32,
            _reason: Reason,
        ) -> (Vec<u8>, i64) {
            (vec![0; size as usize], 0)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, (Vec<u8>, i64))> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("test should not call this")
        }
        fn clear(&mut self) {}
    }

    impl PcodeExecutorState<(Vec<u8>, i64)> for EmptyState {}

    /// A decoder the threads built by these tests never get to use: they are not stepped.
    struct UnusedDecoder;

    impl crate::pcode::emu::instruction_decoder::InstructionDecoder for UnusedDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unreachable!("the thread is never stepped")
        }
        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn crate::pcode::seam_stubs::RegisterValue>,
        ) -> Result<Box<dyn crate::pcode::seam_stubs::PseudoInstruction>, Box<dyn std::error::Error>> {
            unreachable!("the thread is never stepped")
        }
        fn branched(&mut self, _address: &Address) {}
        fn get_last_instruction(&self) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            None
        }
        fn get_last_length_with_delays(&self) -> i32 {
            0
        }
    }

    /// A named userop that does nothing, just enough to populate a library and be found by name,
    /// mirroring the double `aux_emulator_parts_factory`'s own tests use.
    struct NamedUserop {
        name: String,
    }

    impl PcodeUseropDefinition<(Vec<u8>, i64)> for NamedUserop {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            _executor: &crate::pcode::exec::pcode_executor::PcodeExecutor<(Vec<u8>, i64)>,
            _library: &dyn PcodeUseropLibrary<(Vec<u8>, i64)>,
            _op: &crate::program::model::pcode::PcodeOp,
            _out_var: Option<&crate::program::model::pcode::Varnode>,
            _in_vars: &[crate::program::model::pcode::Varnode],
        ) {
            unimplemented!("test double is never invoked")
        }
        fn is_functional(&self) -> bool {
            true
        }
        fn has_side_effects(&self) -> bool {
            false
        }
        fn modifies_context(&self) -> bool {
            false
        }
        fn can_inline_pcode(&self) -> bool {
            false
        }
        fn get_output_type(&self) -> Option<std::any::TypeId> {
            None
        }
        fn get_java_method(&self) -> Option<()> {
            None
        }
        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    struct NamedUseropLibrary {
        userops: UseropMap<(Vec<u8>, i64)>,
    }

    impl ErasedPcodeUseropLibrary for NamedUseropLibrary {}

    impl PcodeUseropLibrary<(Vec<u8>, i64)> for NamedUseropLibrary {
        fn get_userops(&self) -> &UseropMap<(Vec<u8>, i64)> {
            &self.userops
        }
    }

    fn named_userop_library(name: &str) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
        let mut userops: UseropMap<(Vec<u8>, i64)> = HashMap::new();
        userops.insert(name.to_string(), Arc::new(NamedUserop { name: name.to_string() }));
        Box::new(NamedUseropLibrary { userops })
    }

    /// Proves the concrete piece handed to the parts factory is a real, working
    /// `BytesPcodeExecutorStatePiece` for the emulator's language (Java's
    /// `new BytesPcodeExecutorStatePiece(language, scb)`): it names its default space and
    /// round-trips a write through that space.
    fn describe_piece<CB: PcodeStateCallbacks>(mut piece: BytesPcodeExecutorStatePiece<CB>) -> String {
        let space = piece.get_language().get_default_space();
        piece.set_var(&space, 0x10, 2, false, &vec![0xab, 0xcd]);
        let read = piece.get_var(&space, 0x10, 2, false, Reason::Inspect);
        format!("{}={:02x?}", space.name(), read)
    }

    /// Records every call the free functions under test make into the parts factory, and hands
    /// back distinguishable products.
    #[derive(Default)]
    struct RecordingFactory {
        calls: Mutex<Vec<String>>,
    }

    impl AuxEmulatorPartsFactory<i64> for RecordingFactory {
        type SharedState = EmptyState;
        type LocalState = EmptyState;
        type Thread = AuxPcodeThread<i64, RecordingFactory>;

        fn get_arithmetic(&self, _language: &dyn Language) -> Arc<dyn PcodeArithmetic<i64>> {
            unreachable!("not exercised by these tests")
        }
        fn create_shared_userop_library(
            &self,
            _language: &SleighLanguage,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("shared_userop".into());
            named_userop_library("__shared")
        }
        fn create_local_userop_stub(
            &self,
            _language: &SleighLanguage,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("stub_userop".into());
            named_userop_library("__stub")
        }
        fn create_local_userop_library(
            &self,
            _emulator: &PcodeMachineShared<(Vec<u8>, i64)>,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("local_userop".into());
            named_userop_library("__local")
        }
        fn create_thread(
            self: Arc<Self>,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            name: &str,
            parts: AuxThreadParts<i64, EmptyState, EmptyState>,
        ) -> Self::Thread {
            self.calls.lock().unwrap().push(format!("thread:{name}"));
            AuxPcodeThread::new_aux(name, parts, None, self)
        }
        fn create_shared_state(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
            _cb: Arc<NoPcodeStateCallbacks>,
        ) -> EmptyState {
            self.calls.lock().unwrap().push(format!("shared_state:{}", describe_piece(concrete)));
            EmptyState
        }
        fn create_local_state(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            thread_name: &str,
            concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
            _cb: Arc<NoPcodeStateCallbacks>,
        ) -> EmptyState {
            self.calls
                .lock()
                .unwrap()
                .push(format!("local_state:{thread_name}:{}", describe_piece(concrete)));
            EmptyState
        }
    }

    /// A concrete machine over `(Vec<u8>, i64)`, the shape a real `AuxPcodeEmulator`
    /// implementation takes: it embeds the base and its own parts factory, and forwards
    /// `AbstractPcodeMachine`'s abstract methods to this module's free functions.
    struct TestEmulator {
        base: AbstractPcodeMachineBase<(Vec<u8>, i64)>,
        factory: Arc<RecordingFactory>,
    }

    impl TestEmulator {
        fn new() -> Self {
            let base = AbstractPcodeMachineBase::new(
                Arc::new(test_language()),
                Arc::new(NoCallbacks),
                Arc::new(StubArithmetic),
                Box::new(nil()),
                Box::new(nil()),
                None,
            );
            Self { base, factory: Arc::new(RecordingFactory::default()) }
        }
    }

    impl ErasedPcodeMachine for TestEmulator {}

    impl AbstractPcodeMachine<(Vec<u8>, i64)> for TestEmulator {
        fn base(&self) -> &AbstractPcodeMachineBase<(Vec<u8>, i64)> {
            &self.base
        }
        fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<(Vec<u8>, i64)> {
            &mut self.base
        }
        fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            Box::new(create_shared_state(self, self.factory.as_ref()))
        }
        fn create_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            unreachable!("not exercised by these tests")
        }
    
        /// This machine as a plain [`PcodeMachine`]. Java gets this by subtyping.
        fn as_pcode_machine(&self) -> &dyn PcodeMachine<(Vec<u8>, i64)> {
            self
        }
}

    impl PcodeMachine<(Vec<u8>, i64)> for TestEmulator {
        fn get_language(&self) -> &SleighLanguage {
            self.base.get_language()
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            self.base.get_arithmetic()
        }
        fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
            self.base.set_software_interrupt_mode(mode);
        }
        fn get_software_interrupt_mode(&self) -> SwiMode {
            self.base.get_software_interrupt_mode()
        }
        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<(Vec<u8>, i64)> {
            self.base.get_userop_library()
        }
        fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<(Vec<u8>, i64)> {
            self.base.get_stub_userop_library()
        }
        fn get_shared_state(&self) -> &dyn PcodeExecutorState<(Vec<u8>, i64)> {
            self.base
                .shared_state()
                .expect("shared state not created yet; call get_shared_state_mut first")
        }
        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<(Vec<u8>, i64)> {
            AbstractPcodeMachineBase::get_shared_state(self)
        }
        fn set_suspended(&mut self, suspended: bool) {
            self.base.set_suspended(suspended);
        }
        fn is_suspended(&self) -> bool {
            self.base.is_suspended()
        }
        fn compile_sleigh(
            &self,
            _source_name: &str,
            _source: &str,
        ) -> crate::pcode::exec::pcode_program::PcodeProgram {
            unimplemented!("not exercised by these tests")
        }
        fn inject(&mut self, address: &crate::program::model::address::Address, source: &str) {
            AbstractPcodeMachineBase::inject(self, address, source);
        }
        fn get_inject(
            &self,
            address: &crate::program::model::address::Address,
        ) -> Option<Arc<crate::pcode::exec::pcode_program::PcodeProgram>> {
            self.base.get_inject(address)
        }
        fn clear_inject(&mut self, address: &crate::program::model::address::Address) {
            self.base.clear_inject(address);
        }
        fn clear_all_injects(&mut self) {
            self.base.clear_all_injects();
        }
        fn add_breakpoint(&mut self, address: &crate::program::model::address::Address, sleigh_condition: &str) {
            AbstractPcodeMachineBase::add_breakpoint(self, address, sleigh_condition);
        }
        fn add_access_breakpoint(
            &mut self,
            range: &crate::program::model::address::AddressRange,
            kind: AccessKind,
        ) {
            self.base.add_access_breakpoint(range, kind);
        }
        fn clear_access_breakpoints(&mut self) {
            self.base.clear_access_breakpoints();
        }
    }

    impl AuxPcodeEmulator<i64> for TestEmulator {}

    /// Builds a minimal but real `SleighLanguage`, mirroring the identical helper in
    /// `abstract_pcode_machine`'s and `pcode_userop_library_factory`'s own tests.
    fn test_language() -> SleighLanguage {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
        // <space_unique name="unique" size="4" index="2"/>: every real language has a unique
        // space, and the real bytes state piece needs it.
        data.extend_from_slice(&[0x60, 0xAE]);
        data.extend_from_slice(&[0xCC, 0x71, 6, b'u', b'n', b'i', b'q', b'u', b'e']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 2]);
        data.extend_from_slice(&[0xA0, 0xAE]); // </space_unique>
        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>
        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    /// A language answering from the test language, but declaring a program counter, which a
    /// thread requires.
    fn exec_language() -> Arc<dyn Language> {
        let register = crate::program::model::address::AddressSpace::new(
            "register",
            32,
            1,
            AddressSpaceType::Register,
            3,
        );
        let pc = crate::program::model::lang::register::Register::new(
            "pc",
            "program counter",
            register.address(0),
            4,
            false,
            crate::program::model::lang::register::Register::TYPE_PC,
        );
        Arc::new(crate::pcode::emu::test_support::PcLanguage {
            inner: Arc::new(test_language()) as Arc<dyn Language>,
            pc,
        })
    }

    #[test]
    fn create_thread_delegates_to_the_parts_factory_with_the_given_name() {
        let emulator = TestEmulator::new();
        let parts = AuxThreadParts {
            machine: Arc::clone(emulator.base.shared()),
            exec_language: exec_language(),
            shared_state: crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState::new(EmptyState),
            local_state: EmptyState,
            decoder: Box::new(UnusedDecoder),
        };
        let thread = create_thread(&emulator, "worker", &emulator.factory, parts);

        assert_eq!(crate::pcode::emu::pcode_thread::PcodeThread::get_name(&thread), "worker");
        // Java's AuxPcodeThread constructor asks the factory for the thread's local userops.
        assert_eq!(
            *emulator.factory.calls.lock().unwrap(),
            vec!["thread:worker".to_string(), "local_userop".to_string()]
        );
    }

    #[test]
    fn create_shared_and_local_state_delegate_with_a_concrete_piece_and_no_callbacks() {
        let emulator = TestEmulator::new();

        let _ = create_shared_state(&emulator, emulator.factory.as_ref());
        let _ = create_local_state(&emulator, "t0", emulator.factory.as_ref());

        // Java's createSharedState/createLocalState each call getPartsFactory().createXState
        // exactly once, passing a fresh concrete piece; this crate stands in Java's
        // `cb.wrapFor(...)` with `PcodeStateCallbacks.NONE` (see the module docs).
        assert_eq!(
            *emulator.factory.calls.lock().unwrap(),
            vec![
                "shared_state:ram=[ab, cd]".to_string(),
                "local_state:t0:ram=[ab, cd]".to_string()
            ]
        );
    }

    #[test]
    fn create_userop_library_composes_the_default_library_with_the_factorys_shared_library() {
        let emulator = TestEmulator::new();
        let language = test_language();
        let arithmetic: Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> = Arc::new(StubArithmetic);

        let lib = create_userop_library(&language, arithmetic.as_ref(), emulator.factory.as_ref());

        assert!(lib.get_userops().contains_key("__shared"));
        assert_eq!(*emulator.factory.calls.lock().unwrap(), vec!["shared_userop".to_string()]);
    }

    #[test]
    fn create_thread_stub_library_composes_the_emulation_library_with_the_factorys_local_stub() {
        let emulator = TestEmulator::new();

        let lib = create_thread_stub_library(&test_language(), emulator.factory.as_ref());

        assert!(lib.get_userops().contains_key("__stub"));
        // Java's super.createThreadStubLibrary() is DefaultPcodeThread.PcodeEmulationLibrary.
        assert!(lib.get_userops().contains_key("emu_swi"));
        assert_eq!(*emulator.factory.calls.lock().unwrap(), vec!["stub_userop".to_string()]);
    }
}
