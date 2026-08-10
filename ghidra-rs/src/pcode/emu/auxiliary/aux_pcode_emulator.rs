//! An emulator whose parts are manufactured by an [`AuxEmulatorPartsFactory`].
//!
//! Corresponds to `ghidra.pcode.emu.auxiliary.AuxPcodeEmulator`.
//!
//! See the parts factory trait: [`AuxEmulatorPartsFactory`]. Also see the Taint Analyzer (not yet
//! ported) for a complete example based on this class.
//!
//! `U` is Java's `AuxPcodeEmulator<U>` type parameter: the type of auxiliary values. As with
//! [`AuxEmulatorPartsFactory`], Java's `Pair<byte[], U>` is rendered as the tuple `(Vec<u8>, U)`.
//!
//! Deviations from the Java source, both forced by object-safety:
//!
//! * Java's sole abstract member, `getPartsFactory()`, is not part of this trait.
//!   [`AuxEmulatorPartsFactory::create_shared_state`]/[`AuxEmulatorPartsFactory::create_local_state`]
//!   are generic per Java's `PcodeStateCallbacks`-typed overloads (see that trait's docs), which
//!   makes `AuxEmulatorPartsFactory` itself not object-safe -- there is no valid `&dyn
//!   AuxEmulatorPartsFactory<U>`. But `AuxPcodeEmulator` *does* need to exist as `&dyn
//!   AuxPcodeEmulator<U>` (see [`AuxEmulatorPartsFactory`]'s own erasure convention for the
//!   emulator parameter), so a trait method returning the factory polymorphically is not
//!   expressible either way. Instead, Java's overridden `createArithmetic`/`createUseropLibrary`/
//!   `createThreadStubLibrary`/`createSharedState`/`createLocalState`/`createThread` are all free
//!   functions below, each taking the concrete implementer's factory generically (`impl
//!   AuxEmulatorPartsFactory<U>`) alongside whatever else they need. A concrete implementer stores
//!   its own factory (Java says it "should just be a singleton") and forwards
//!   [`AbstractPcodeMachine`]'s `create_shared_state`/`create_local_state`/`create_thread` to
//!   these functions, passing that stored factory.
//! * Java calls `createArithmetic()`/`createUseropLibrary()`/`createThreadStubLibrary()` from
//!   within `super(language, cb)`, on a `this` whose fields (including those of
//!   `AbstractPcodeMachine`) do not exist yet. Rust cannot construct `&self` before `self` exists,
//!   so [`create_arithmetic`]/[`create_userop_library`]/[`create_thread_stub_library`] take
//!   `language`/`parts_factory` (and, where Java's override also needs `this`, an already-built
//!   `emulator` handle) as plain parameters, matching the deviation
//!   [`AbstractPcodeMachineBase::new`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::new)
//!   already documents for these same three constructor-time factories. Producing that `emulator`
//!   handle before the machine is fully built is left to whichever concrete implementation needs
//!   it, exactly as that constructor already leaves `language`/`arithmetic`/`library` to its
//!   caller.
//! * `createThreadStubLibrary`'s Java default (`super.createThreadStubLibrary()`) is
//!   `DefaultPcodeThread.PcodeEmulationLibrary`, not yet ported (see
//!   `AbstractPcodeMachineBase`'s docs), so [`create_thread_stub_library`] composes the parts
//!   factory's local stub onto an empty library instead of Java's real default.
//! * `createSharedState`/`createLocalState`'s Java bodies build a `PcodeStateCallbacks` via
//!   `cb.wrapFor(...)`, adapting the machine's `PcodeEmulationCallbacks` (not yet ported) to state
//!   callbacks. That adapter class does not exist yet, so [`create_shared_state`]/
//!   [`create_local_state`] pass
//!   [`NONE`](crate::pcode::exec::pcode_state_callbacks::NONE) (Java's own
//!   `PcodeStateCallbacks.NONE`) instead; every callback the state pieces would receive is simply
//!   dropped, as it would be for an emulator whose callbacks are already the default no-ops.

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::{AbstractPcodeMachine, AbstractPcodeMachineBase};
use crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory;
use crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::NONE;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::seam_stubs::{BytesPcodeArithmetic, BytesPcodeExecutorStatePiece};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::Language;

/// A minimal, inert implementor of [`BytesPcodeExecutorStatePiece`], standing in for `new
/// BytesPcodeExecutorStatePiece(SleighLanguage, PcodeStateCallbacks)` until that class is ported.
/// `AuxEmulatorPartsFactory` never calls a method on the concrete piece it receives (the
/// placeholder trait it takes is a bare marker), so an empty marker suffices here too.
struct ConcreteStatePieceStub;

impl BytesPcodeExecutorStatePiece for ConcreteStatePieceStub {}

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
        BytesPcodeArithmetic::for_language(language),
        parts_factory.get_arithmetic(language.as_ref()),
    ))
}

/// Port of the overridden `createUseropLibrary()`: composes the machine's default userop library
/// with the parts factory's shared userop library.
pub fn create_userop_library<U: 'static>(
    language: &SleighLanguage,
    arithmetic: &dyn PcodeArithmetic<(Vec<u8>, U)>,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
    emulator: &dyn AuxPcodeEmulator<U>,
) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> {
    let base = AbstractPcodeMachineBase::create_userop_library(language, arithmetic, "", &[]);
    base.compose(parts_factory.create_shared_userop_library(emulator).as_ref())
}

/// Port of the overridden `createThreadStubLibrary()`: composes an empty library (standing in for
/// Java's not-yet-ported `super.createThreadStubLibrary()`; see the module docs) with the parts
/// factory's local userop stub.
pub fn create_thread_stub_library<U: 'static>(
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
    emulator: &dyn AuxPcodeEmulator<U>,
) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> {
    let base: Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> = Box::new(nil());
    base.compose(parts_factory.create_local_userop_stub(emulator).as_ref())
}

/// Port of the overridden `createSharedState()`.
pub fn create_shared_state<U: 'static>(
    emulator: &dyn AuxPcodeEmulator<U>,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Box<dyn PcodeExecutorState<(Vec<u8>, U)>> {
    parts_factory.create_shared_state(emulator, Box::new(ConcreteStatePieceStub), &NONE)
}

/// Port of the overridden `createLocalState(PcodeThread<Pair<byte[], U>>)`.
pub fn create_local_state<U: 'static>(
    emulator: &dyn AuxPcodeEmulator<U>,
    thread: &dyn ErasedPcodeThread,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Box<dyn PcodeExecutorState<(Vec<u8>, U)>> {
    parts_factory.create_local_state(emulator, thread, Box::new(ConcreteStatePieceStub), &NONE)
}

/// Port of the overridden `createThread(String)`.
pub fn create_thread<U: 'static>(
    emulator: &dyn AuxPcodeEmulator<U>,
    name: &str,
    parts_factory: &impl AuxEmulatorPartsFactory<U>,
) -> Arc<dyn ErasedPcodeThread> {
    parts_factory.create_thread(emulator, name)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, PcodeMachine, SwiMode};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropDefinition, UseropMap};
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
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> (Vec<u8>, i64) {
            (vec![], 0)
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &(Vec<u8>, i64),
            _size: i32,
            _reason: Reason,
        ) -> (Vec<u8>, i64) {
            (vec![], 0)
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

    /// A thread that carries only its name, mirroring `abstract_pcode_machine`'s `NamedThread`.
    struct NamedThread(#[allow(dead_code)] String);

    impl ErasedPcodeThread for NamedThread {}

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

    /// Records every call the free functions under test make into the parts factory, and hands
    /// back distinguishable products.
    #[derive(Default)]
    struct RecordingFactory {
        calls: Mutex<Vec<String>>,
    }

    impl AuxEmulatorPartsFactory<i64> for RecordingFactory {
        fn get_arithmetic(&self, _language: &dyn Language) -> Arc<dyn PcodeArithmetic<i64>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_shared_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("shared_userop".into());
            named_userop_library("__shared")
        }
        fn create_local_userop_stub(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("stub_userop".into());
            named_userop_library("__stub")
        }
        fn create_local_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_thread(&self, _emulator: &dyn AuxPcodeEmulator<i64>, name: &str) -> Arc<dyn ErasedPcodeThread> {
            self.calls.lock().unwrap().push(format!("thread:{name}"));
            Arc::new(NamedThread(name.to_string()))
        }
        fn create_shared_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _concrete: Box<dyn BytesPcodeExecutorStatePiece>,
            _cb: &CB,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("shared_state".into());
            Box::new(EmptyState)
        }
        fn create_local_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _thread: &dyn ErasedPcodeThread,
            _concrete: Box<dyn BytesPcodeExecutorStatePiece>,
            _cb: &CB,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            self.calls.lock().unwrap().push("local_state".into());
            Box::new(EmptyState)
        }
    }

    /// A concrete machine over `(Vec<u8>, i64)`, the shape a real `AuxPcodeEmulator`
    /// implementation takes: it embeds the base and its own parts factory, and forwards
    /// `AbstractPcodeMachine`'s abstract methods to this module's free functions.
    struct TestEmulator {
        base: AbstractPcodeMachineBase<(Vec<u8>, i64)>,
        factory: RecordingFactory,
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
            Self { base, factory: RecordingFactory::default() }
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
            create_shared_state(self, &self.factory)
        }
        fn create_local_state(
            &self,
            thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            create_local_state(self, thread, &self.factory)
        }
        fn create_thread(&self, name: &str) -> Arc<dyn ErasedPcodeThread> {
            create_thread(self, name, &self.factory)
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
        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            AbstractPcodeMachineBase::new_thread(self)
        }
        fn new_thread_named(&mut self, name: &str) -> Arc<dyn ErasedPcodeThread> {
            AbstractPcodeMachineBase::new_thread_named(self, name)
        }
        fn get_thread(&mut self, name: &str, create_if_absent: bool) -> Option<Arc<dyn ErasedPcodeThread>> {
            AbstractPcodeMachineBase::get_thread(self, name, create_if_absent)
        }
        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            self.base.get_all_threads()
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
        ) -> Box<dyn crate::pcode::seam_stubs::PcodeProgram> {
            unimplemented!("not exercised by these tests")
        }
        fn inject(&mut self, address: &crate::program::model::address::Address, source: &str) {
            AbstractPcodeMachineBase::inject(self, address, source);
        }
        fn get_inject(
            &self,
            address: &crate::program::model::address::Address,
        ) -> Option<&dyn crate::pcode::seam_stubs::PcodeProgram> {
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

    #[test]
    fn create_thread_delegates_to_the_parts_factory_with_the_given_name() {
        let emulator = TestEmulator::new();
        let _ = create_thread(&emulator, "worker", &emulator.factory);
        assert_eq!(*emulator.factory.calls.lock().unwrap(), vec!["thread:worker".to_string()]);
    }

    #[test]
    fn create_shared_and_local_state_delegate_with_a_concrete_piece_and_no_callbacks() {
        let emulator = TestEmulator::new();
        let thread = NamedThread("t0".to_string());

        let _ = create_shared_state(&emulator, &emulator.factory);
        let _ = create_local_state(&emulator, &thread, &emulator.factory);

        // Java's createSharedState/createLocalState each call getPartsFactory().createXState
        // exactly once, passing a fresh concrete piece; this crate stands in Java's
        // `cb.wrapFor(...)` with `PcodeStateCallbacks.NONE` (see the module docs).
        assert_eq!(
            *emulator.factory.calls.lock().unwrap(),
            vec!["shared_state".to_string(), "local_state".to_string()]
        );
    }

    #[test]
    fn create_userop_library_composes_the_default_library_with_the_factorys_shared_library() {
        let emulator = TestEmulator::new();
        let language = test_language();
        let arithmetic: Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> = Arc::new(StubArithmetic);

        let lib = create_userop_library(&language, arithmetic.as_ref(), &emulator.factory, &emulator);

        assert!(lib.get_userops().contains_key("__shared"));
        assert_eq!(*emulator.factory.calls.lock().unwrap(), vec!["shared_userop".to_string()]);
    }

    #[test]
    fn create_thread_stub_library_composes_an_empty_library_with_the_factorys_local_stub() {
        let emulator = TestEmulator::new();

        let lib = create_thread_stub_library(&emulator.factory, &emulator);

        assert!(lib.get_userops().contains_key("__stub"));
        assert_eq!(*emulator.factory.calls.lock().unwrap(), vec!["stub_userop".to_string()]);
    }
}
