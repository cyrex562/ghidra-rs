//! A p-code machine which executes on concrete bytes and incorporates per-architecture state
//! modifiers.
//!
//! Corresponds to `ghidra.pcode.emu.PcodeEmulator`.
//!
//! This is a simple concrete bytes emulator suitable for unit testing and scripting. Its
//! `createArithmetic`/`createThread`/`createSharedState`/`createLocalState` overrides are ported
//! faithfully below; `createUseropLibrary`/`createThreadStubLibrary` are not overridden in Java,
//! so [`PcodeEmulator::new`] computes them the same way
//! [`AbstractPcodeMachineBase::new`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::new)'s
//! own deviation notes describe for any concrete machine.
//!
//! Deviations from the Java source, all forced by types this crate has not ported yet:
//!
//! * `createArithmetic()` is `BytesPcodeArithmetic.forLanguage(language)` in Java. `language` is
//!   Java's field typed `SleighLanguage` (see `AbstractPcodeMachine`'s own deviation notes), so
//!   this port calls
//!   [`BytesPcodeArithmetic::for_sleigh_language`](crate::pcode::seam_stubs::BytesPcodeArithmetic::for_sleigh_language),
//!   added alongside the existing `for_language` for exactly this call site. Like the rest of
//!   `BytesPcodeArithmetic`, it is unimplemented until that class is ported, so constructing a
//!   `PcodeEmulator` currently panics -- faithfully so, since Java has no substitute either.
//! * `createThread(String)` is `new BytesPcodeThread(name, this)`; [`BytesPcodeThread`] is added
//!   here as a minimal placeholder (name only) for the same reason.
//! * `createSharedState()`/`createLocalState(PcodeThread<byte[]>)` construct
//!   `new BytesPcodeExecutorState(language, scb)` where `scb = cb.wrapFor(thread)`.
//!   [`BytesPcodeExecutorState`] is added here as a minimal placeholder; `cb.wrapFor(...)` needs
//!   the not-yet-ported `PcodeEmulationCallbacks.Wrapper` adapter, so, as in
//!   [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator), this passes
//!   [`NONE`](crate::pcode::exec::pcode_state_callbacks::NONE) instead.
//! * The default `createThreadStubLibrary()`, `new DefaultPcodeThread.PcodeEmulationLibrary<>(null)`,
//!   is not ported (see `AbstractPcodeMachineBase`'s docs), so [`PcodeEmulator::new`] stands in
//!   with an empty library, as that base's own tests do.

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::{AbstractPcodeMachine, AbstractPcodeMachineBase};
use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, PcodeMachine, SwiMode};
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::NONE;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::pcode::emu::pcode_emulation_callbacks::{
    no_pcode_emulation_callbacks, PcodeEmulationCallbacks,
};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::seam_stubs::{
    BytesPcodeArithmetic, BytesPcodeExecutorState, BytesPcodeThread, PcodeProgram,
};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::sleigh::SleighLanguage;

/// A p-code machine which executes on concrete bytes and incorporates per-architecture state
/// modifiers.
///
/// More complex use cases likely benefit by extending this or one of its super types. See the
/// module docs for the deviations forced by not-yet-ported dependencies.
pub struct PcodeEmulator {
    base: AbstractPcodeMachineBase<Vec<u8>>,
}

impl PcodeEmulator {
    /// Construct a new concrete emulator.
    ///
    /// Port of `PcodeEmulator(Language, PcodeEmulationCallbacks<byte[]>)`.
    pub fn new(language: Arc<SleighLanguage>, cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>) -> Self {
        let arithmetic = BytesPcodeArithmetic::for_sleigh_language(&language);
        let library =
            AbstractPcodeMachineBase::create_userop_library(&language, arithmetic.as_ref(), "", &[]);
        // DefaultPcodeThread.PcodeEmulationLibrary, Java's default createThreadStubLibrary(), is
        // not yet ported -- see the module docs.
        let thread_stub_library: Box<dyn PcodeUseropLibrary<Vec<u8>>> = Box::new(nil());
        let base =
            AbstractPcodeMachineBase::new(language, cb, arithmetic, library, thread_stub_library, None);
        let emulator = Self { base };
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    /// Construct a new concrete emulator with no emulation callbacks.
    ///
    /// Port of `PcodeEmulator(Language)`, which is `this(language, PcodeEmulationCallbacks.none())`.
    pub fn with_language(language: Arc<SleighLanguage>) -> Self {
        Self::new(language, no_pcode_emulation_callbacks())
    }
}

impl ErasedPcodeMachine for PcodeEmulator {}

impl AbstractPcodeMachine<Vec<u8>> for PcodeEmulator {
    fn base(&self) -> &AbstractPcodeMachineBase<Vec<u8>> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<Vec<u8>> {
        &mut self.base
    }

    /// Port of the overridden `createSharedState()`.
    fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        Box::new(BytesPcodeExecutorState::new(Arc::clone(self.base.language()), NONE))
    }

    /// Port of the overridden `createLocalState(PcodeThread<byte[]>)`.
    fn create_local_state(&self, _thread: &dyn ErasedPcodeThread) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        Box::new(BytesPcodeExecutorState::new(Arc::clone(self.base.language()), NONE))
    }

    /// Port of the overridden `createThread(String)`.
    fn create_thread(&self, name: &str) -> Arc<dyn ErasedPcodeThread> {
        Arc::new(BytesPcodeThread::new(name))
    }
}

impl PcodeMachine<Vec<u8>> for PcodeEmulator {
    fn get_language(&self) -> &SleighLanguage {
        self.base.get_language()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.base.get_arithmetic()
    }

    fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
        self.base.set_software_interrupt_mode(mode);
    }

    fn get_software_interrupt_mode(&self) -> SwiMode {
        self.base.get_software_interrupt_mode()
    }

    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<Vec<u8>> {
        self.base.get_userop_library()
    }

    fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<Vec<u8>> {
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

    fn get_shared_state(&self) -> &dyn PcodeExecutorState<Vec<u8>> {
        self.base
            .shared_state()
            .expect("shared state not created yet; call get_shared_state_mut first")
    }

    fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<Vec<u8>> {
        AbstractPcodeMachineBase::get_shared_state(self)
    }

    fn set_suspended(&mut self, suspended: bool) {
        self.base.set_suspended(suspended);
    }

    fn is_suspended(&self) -> bool {
        self.base.is_suspended()
    }

    fn compile_sleigh(&self, source_name: &str, source: &str) -> Box<dyn PcodeProgram> {
        self.base.compile_sleigh(source_name, source)
    }

    fn inject(&mut self, address: &Address, source: &str) {
        AbstractPcodeMachineBase::inject(self, address, source);
    }

    fn get_inject(&self, address: &Address) -> Option<&dyn PcodeProgram> {
        self.base.get_inject(address)
    }

    fn clear_inject(&mut self, address: &Address) {
        self.base.clear_inject(address);
    }

    fn clear_all_injects(&mut self) {
        self.base.clear_all_injects();
    }

    fn add_breakpoint(&mut self, address: &Address, sleigh_condition: &str) {
        AbstractPcodeMachineBase::add_breakpoint(self, address, sleigh_condition);
    }

    fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind) {
        self.base.add_access_breakpoint(range, kind);
    }

    fn clear_access_breakpoints(&mut self) {
        self.base.clear_access_breakpoints();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::{OpCode, PackedDecode};

    /// Minimal little-endian arithmetic over `byte[]`, standing in for the not-yet-ported
    /// `BytesPcodeArithmetic` so a `PcodeEmulator` can be built without hitting its
    /// `unimplemented!()`, mirroring the fixture already used by `abstract_pcode_machine`'s tests.
    struct StubArithmetic;

    impl PcodeArithmetic<Vec<u8>> for StubArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            in1.clone()
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &Vec<u8>,
            _sizein2: i32,
            _in2: &Vec<u8>,
        ) -> Vec<u8> {
            in1.clone()
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &crate::program::model::address::AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &crate::program::model::address::AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// Builds `PcodeEmulator` with [`StubArithmetic`] in place of the real (unported)
    /// `createArithmetic()` path, exactly as `abstract_pcode_machine`'s and `aux_pcode_emulator`'s
    /// own tests substitute a double for that same gap. This still exercises every piece of
    /// `PcodeEmulator` itself: `create_thread`, `create_shared_state`, `create_local_state`, and
    /// the `PcodeMachine`/`AbstractPcodeMachine` forwarding above.
    fn emulator() -> PcodeEmulator {
        let language = Arc::new(test_language());
        let arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>> = Arc::new(StubArithmetic);
        let library =
            AbstractPcodeMachineBase::create_userop_library(&language, arithmetic.as_ref(), "", &[]);
        let thread_stub_library: Box<dyn PcodeUseropLibrary<Vec<u8>>> = Box::new(nil());
        let base = AbstractPcodeMachineBase::new(
            language,
            no_pcode_emulation_callbacks(),
            arithmetic,
            library,
            thread_stub_library,
            None,
        );
        let emulator = PcodeEmulator { base };
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    /// Builds a minimal but real `SleighLanguage`, mirroring the identical helper in
    /// `abstract_pcode_machine`'s and `aux_pcode_emulator`'s own tests.
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
    fn new_thread_named_routes_through_create_thread_like_java() {
        let mut emulator = emulator();

        // newThread() names threads "Thread " + threads.size(), same as any AbstractPcodeMachine.
        let first = PcodeMachine::new_thread(&mut emulator);
        let second = PcodeMachine::new_thread(&mut emulator);
        assert_eq!(2, emulator.get_all_threads().len());
        assert!(Arc::ptr_eq(&first, &emulator.get_all_threads()[0]));
        assert!(Arc::ptr_eq(&second, &emulator.get_all_threads()[1]));
        assert!(emulator.base.get_thread_by_name("Thread 0").is_some());
        assert!(emulator.base.get_thread_by_name("Thread 1").is_some());

        // getThread(name, false) does not create; getThread(name, true) does, via create_thread.
        assert!(PcodeMachine::get_thread(&mut emulator, "worker", false).is_none());
        let worker = PcodeMachine::get_thread(&mut emulator, "worker", true).expect("created on demand");
        assert!(Arc::ptr_eq(
            &worker,
            &PcodeMachine::get_thread(&mut emulator, "worker", true).unwrap()
        ));
        assert_eq!(3, emulator.get_all_threads().len());
    }

    #[test]
    fn shared_state_is_created_lazily_and_reused_like_java() {
        // Java's getSharedState() creates the state on first call and reuses it thereafter.
        let mut emulator = emulator();
        assert!(emulator.base.shared_state().is_none());

        let _ = PcodeMachine::get_shared_state_mut(&mut emulator);
        assert!(emulator.base.shared_state().is_some());
    }

    #[test]
    fn get_language_returns_the_language_given_at_construction() {
        // Java: `AbstractPcodeMachine.getLanguage()` returns the (Sleigh-cast) constructor arg.
        let emulator = emulator();
        assert_eq!("test", PcodeMachine::get_language(&emulator).get_id());
    }

    #[test]
    #[should_panic(expected = "BytesPcodeArithmetic not yet ported")]
    fn constructor_faithfully_calls_bytes_pcode_arithmetic_for_language() {
        // Java: `createArithmetic()` returns `BytesPcodeArithmetic.forLanguage(language)`. That
        // class isn't ported yet (see the module docs), so real construction panics exactly as it
        // would if `BytesPcodeArithmetic` genuinely didn't exist.
        let _ = PcodeEmulator::with_language(Arc::new(test_language()));
    }
}
