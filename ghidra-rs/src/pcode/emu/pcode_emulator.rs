//! A p-code machine which executes on concrete bytes and incorporates per-architecture state
//! modifiers.
//!
//! Corresponds to `ghidra.pcode.emu.PcodeEmulator`.
//!
//! This is a simple concrete bytes emulator suitable for unit testing and scripting. Its
//! `createArithmetic`/`createThread`/`createSharedState`/`createLocalState` overrides are ported
//! below; `createUseropLibrary`/`createThreadStubLibrary` are not overridden in Java, so
//! [`PcodeEmulator::new`] computes them the same way
//! [`AbstractPcodeMachineBase::new`]'s own deviation notes describe for any concrete machine.
//!
//! Deviations from the Java source, all forced by types this crate has not ported yet:
//!
//! * `createArithmetic()` is `BytesPcodeArithmetic.forLanguage(language)` in Java; this port calls
//!   [`BytesPcodeArithmetic::for_sleigh_language`], which selects by the language's endianness
//!   exactly as `forLanguage` does.
//! * `createSharedState()`/`createLocalState(PcodeThread<byte[]>)` construct
//!   `new BytesPcodeExecutorState(language, scb)` where `scb = cb.wrapFor(thread)`. This port
//!   builds the real [`BytesPcodeExecutorState`], but, as in
//!   [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator), passes
//!   [`NONE`] for the state callbacks.
//! * **Threads.** `createThread(String)` is `new BytesPcodeThread(name, this)`, whose constructor
//!   chain builds a [`SleighInstructionDecoder`] over the shared state and reads the program
//!   counter off the language. Only a `.pspec` declares the program counter, and a
//!   [`SleighLanguage`] decoded from a `.sla` alone has none, so, exactly as in Java, a thread of
//!   such a language cannot be created ("Language has no program counter"). A machine can instead
//!   be given [`ThreadDecoding`] naming the language its threads bind to (one declaring a program
//!   counter) and the decoder they use; [`ThreadDecoding::sleigh`] is Java's default decoder. The
//!   shared state a thread holds is the machine's own, via a [`SharedPcodeExecutorState`] handle,
//!   so every thread and the machine see the same memory, as in Java.
//! * The default `createThreadStubLibrary()`, `new DefaultPcodeThread.PcodeEmulationLibrary<>(null)`,
//!   is what [`PcodeEmulator::new`] passes as the thread stub library.

use std::sync::{Arc, OnceLock};

use crate::pcode::emu::abstract_pcode_machine::{
    AbstractPcodeMachine, AbstractPcodeMachineBase, AbstractPcodeMachineThreads, ThreadList,
};
#[allow(unused_imports)]
use crate::pcode::emu::bytes_pcode_thread::{BytesPcodeThread, BytesState};
use crate::pcode::emu::default_pcode_thread::{DefaultPcodeThread, PcodeEmulationLibrary, ThreadHooks};
#[allow(deprecated)]
use crate::pcode::emu::modified_pcode_thread::ModifiedThreadHooks;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::pcode_machine::{
    AccessKind, ErasedPcodeMachine, PcodeMachine, PcodeMachineThreads, SwiMode,
};
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::exec::pcode_state_callbacks::NONE;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::emu::pcode_emulation_callbacks::{
    no_pcode_emulation_callbacks, PcodeEmulationCallbacks,
};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::emu::sleigh_instruction_decoder::SleighInstructionDecoder;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::bytes_pcode_arithmetic::BytesPcodeArithmetic;
use crate::pcode::exec::bytes_pcode_executor_state::BytesPcodeExecutorState;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::SleighLanguage;

/// Builds a thread's instruction decoder over the machine's shared state: Java's
/// `createInstructionDecoder(sharedState)`, given the language the thread binds to.
///
/// `S` is the machine's shared state, as its threads hold it; it defaults to the concrete bytes
/// state of a [`PcodeEmulator`].
pub type InstructionDecoderFactory<S = BytesState> = Arc<
    dyn Fn(&Arc<dyn Language>, &SharedPcodeExecutorState<S>) -> Box<dyn InstructionDecoder>
        + Send
        + Sync,
>;

/// What a machine builds its threads with: the language a thread's executor and register lookups
/// bind to, and the decoder factory. See the module docs. `S` is as for
/// [`InstructionDecoderFactory`].
pub struct ThreadDecoding<S = BytesState> {
    /// The language a thread's executor and decoder bind to; it must declare a program counter.
    pub exec_language: Arc<dyn Language>,
    /// Builds each thread's instruction decoder.
    pub decoder: InstructionDecoderFactory<S>,
}

impl<S> Clone for ThreadDecoding<S> {
    fn clone(&self) -> Self {
        Self { exec_language: Arc::clone(&self.exec_language), decoder: Arc::clone(&self.decoder) }
    }
}

impl<S: 'static> ThreadDecoding<S> {
    /// Threads binding to `exec_language` that decode with Java's default decoder,
    /// `new SleighInstructionDecoder(language, sharedState)`, over the machine's shared state of
    /// `T` values.
    pub fn sleigh<T: 'static>(language: Arc<SleighLanguage>, exec_language: Arc<dyn Language>) -> Self
    where
        SharedPcodeExecutorState<S>: PcodeExecutorStatePiece<T, T>,
    {
        ThreadDecoding {
            exec_language,
            decoder: Arc::new(move |_exec_language, shared_state| {
                Box::new(SleighInstructionDecoder::<T, _>::new(Arc::clone(&language), shared_state.clone()))
            }),
        }
    }
}

/// The factory methods a [`PcodeEmulator`] "subclass" overrides: Java's `createSharedState()`,
/// `createLocalState(PcodeThread)`, and the part of `createThread(String)` a subclass adds to
/// `BytesPcodeThread` (its [`ThreadHooks`]).
///
/// `S` is the concrete bytes state the machine creates for its memory and for each thread's
/// registers, and `H` the overrides its threads carry. [`BytesEmulatorParts`] is `PcodeEmulator`'s
/// own behavior; a Java subclass such as `AdaptedEmulator.AdaptedPcodeEmulator` supplies its own.
pub trait PcodeEmulatorParts<S, H>: Send + Sync {
    /// Port of `createSharedState()`: the machine's memory.
    fn create_shared_state(&self, language: Arc<dyn Language>) -> S;

    /// Port of `createLocalState(PcodeThread<byte[]>)`: a thread's registers.
    fn create_local_state(&self, language: Arc<dyn Language>) -> S;

    /// The overrides of the thread class `createThread(String)` instantiates.
    fn create_thread_hooks(&self) -> H;
}

/// [`PcodeEmulator`]'s own factory methods: `new BytesPcodeExecutorState(language, scb)` for both
/// states (with no state callbacks; see the module docs) and plain `BytesPcodeThread`s.
#[derive(Debug, Default, Clone, Copy)]
pub struct BytesEmulatorParts;

#[allow(deprecated)]
impl PcodeEmulatorParts<BytesState, ModifiedThreadHooks> for BytesEmulatorParts {
    fn create_shared_state(&self, language: Arc<dyn Language>) -> BytesState {
        BytesPcodeExecutorState::new(language, Arc::new(NONE))
    }

    fn create_local_state(&self, language: Arc<dyn Language>) -> BytesState {
        BytesPcodeExecutorState::new(language, Arc::new(NONE))
    }

    fn create_thread_hooks(&self) -> ModifiedThreadHooks {
        ModifiedThreadHooks::new(None)
    }
}

/// The thread type of a [`PcodeEmulator`] over state `S` whose threads carry overrides `H`:
/// [`BytesPcodeThread`] for the defaults.
pub type EmulatorThread<S = BytesState, H = ModifiedThreadHooks> =
    DefaultPcodeThread<Vec<u8>, SharedPcodeExecutorState<S>, S, H>;

/// A p-code machine which executes on concrete bytes and incorporates per-architecture state
/// modifiers.
///
/// More complex use cases likely benefit by extending this or one of its super types. See the
/// module docs for the deviations forced by not-yet-ported dependencies.
///
/// `S` is the concrete state type of the machine's memory and its threads' registers, and `H` the
/// overrides its threads carry; both default to Java's `PcodeEmulator` itself. A Java subclass
/// overriding `createSharedState`/`createLocalState`/`createThread` supplies them through
/// [`PcodeEmulatorParts`].
pub struct PcodeEmulator<S = BytesState, H = ModifiedThreadHooks>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
    base: AbstractPcodeMachineBase<Vec<u8>>,
    threads: ThreadList<EmulatorThread<S, H>>,
    /// The machine's shared state as its threads hold it; set when the shared state is created.
    shared_memory: OnceLock<SharedPcodeExecutorState<S>>,
    thread_decoding: ThreadDecoding<S>,
    parts: Arc<dyn PcodeEmulatorParts<S, H>>,
}

impl PcodeEmulator {
    /// Construct a new concrete emulator.
    ///
    /// Port of `PcodeEmulator(Language, PcodeEmulationCallbacks<byte[]>)`. Its threads bind to
    /// `language` and decode with a [`SleighInstructionDecoder`]; see the module docs.
    pub fn new(language: Arc<SleighLanguage>, cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>) -> Self {
        let exec_language: Arc<dyn Language> = Arc::clone(&language) as Arc<dyn Language>;
        let thread_decoding = ThreadDecoding::sleigh::<Vec<u8>>(Arc::clone(&language), exec_language);
        Self::with_thread_decoding(language, cb, thread_decoding)
    }

    /// Construct a new concrete emulator whose threads bind to and decode with the given parts.
    ///
    /// Port of `PcodeEmulator(Language, PcodeEmulationCallbacks<byte[]>)`; see the module docs on
    /// [`ThreadDecoding`].
    pub fn with_thread_decoding(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>,
        thread_decoding: ThreadDecoding,
    ) -> Self {
        Self::with_parts(language, cb, thread_decoding, Arc::new(BytesEmulatorParts))
    }

    /// Construct a new concrete emulator with no emulation callbacks.
    ///
    /// Port of `PcodeEmulator(Language)`, which is `this(language, PcodeEmulationCallbacks.none())`.
    pub fn with_language(language: Arc<SleighLanguage>) -> Self {
        Self::new(language, no_pcode_emulation_callbacks())
    }
}

impl<S, H> PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
    /// Construct a new concrete emulator whose states and threads come from `parts`: a Java
    /// subclass of `PcodeEmulator` overriding its factory methods.
    ///
    /// Port of `PcodeEmulator(Language, PcodeEmulationCallbacks<byte[]>)` as a subclass invokes
    /// it; see the module docs on [`ThreadDecoding`].
    pub fn with_parts(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>,
        thread_decoding: ThreadDecoding<S>,
        parts: Arc<dyn PcodeEmulatorParts<S, H>>,
    ) -> Self {
        let arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>> =
            Arc::new(BytesPcodeArithmetic::for_sleigh_language(&language));
        Self::with_arithmetic(language, cb, arithmetic, thread_decoding, parts)
    }

    /// The constructor body, given the product of `createArithmetic()`.
    fn with_arithmetic(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>,
        arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>>,
        thread_decoding: ThreadDecoding<S>,
        parts: Arc<dyn PcodeEmulatorParts<S, H>>,
    ) -> Self {
        let library =
            AbstractPcodeMachineBase::create_userop_library(&language, arithmetic.as_ref(), "", &[]);
        // Java's default createThreadStubLibrary().
        let thread_stub_library: Box<dyn PcodeUseropLibrary<Vec<u8>>> =
            Box::new(PcodeEmulationLibrary::new(None));
        let base =
            AbstractPcodeMachineBase::new(language, cb, arithmetic, library, thread_stub_library, None);
        let emulator = Self {
            base,
            threads: ThreadList::new(),
            shared_memory: OnceLock::new(),
            thread_decoding,
            parts,
        };
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    /// The machine's language as the `Language` the real state constructors take.
    fn language_dyn(&self) -> Arc<dyn Language> {
        Arc::clone(self.base.language()) as Arc<dyn Language>
    }

    /// The machine's memory as its threads hold it, creating it if needed. Java reaches the same
    /// object through `getSharedState()`.
    pub fn shared_memory(&mut self) -> SharedPcodeExecutorState<S> {
        AbstractPcodeMachineBase::get_shared_state(self);
        self.shared_memory.get().expect("the shared state was just created").clone()
    }
}

impl<S, H> ErasedPcodeMachine for PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
}

impl<S, H> AbstractPcodeMachine<Vec<u8>> for PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
    fn base(&self) -> &AbstractPcodeMachineBase<Vec<u8>> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<Vec<u8>> {
        &mut self.base
    }

    /// Port of the overridden `createSharedState()`. The machine keeps the handle its threads
    /// will share.
    fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        let memory = self
            .shared_memory
            .get_or_init(|| SharedPcodeExecutorState::new(self.parts.create_shared_state(self.language_dyn())))
            .clone();
        Box::new(memory)
    }

    /// Port of the overridden `createLocalState(PcodeThread<byte[]>)`.
    fn create_local_state(&self, _thread: &dyn ErasedPcodeThread) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        Box::new(self.parts.create_local_state(self.language_dyn()))
    }

    /// This machine as a plain [`PcodeMachine`]. Java gets this by subtyping.
    fn as_pcode_machine(&self) -> &dyn PcodeMachine<Vec<u8>> {
        self
    }
}

impl<S, H> AbstractPcodeMachineThreads<Vec<u8>> for PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
    /// Port of the overridden `createThread(String)`: `new BytesPcodeThread(name, this)`, whose
    /// constructor reads the machine's shared state, creating it if this is the first thread.
    ///
    /// # Panics
    ///
    /// If the language the threads bind to has no program counter, as Java's constructor throws.
    fn create_thread(&mut self, name: &str) -> EmulatorThread<S, H> {
        let decoding = self.thread_decoding.clone();
        let shared = self.shared_memory();
        // Java: `machine.createLocalState(this)`.
        let local = self.parts.create_local_state(self.language_dyn());
        let decoder = (decoding.decoder)(&decoding.exec_language, &shared);
        DefaultPcodeThread::new(
            name,
            Arc::clone(self.base.shared()),
            decoding.exec_language,
            shared,
            local,
            decoder,
            self.parts.create_thread_hooks(),
        )
    }

    fn threads(&self) -> &ThreadList<EmulatorThread<S, H>> {
        &self.threads
    }

    fn threads_mut(&mut self) -> &mut ThreadList<EmulatorThread<S, H>> {
        &mut self.threads
    }
}

impl<S, H> PcodeMachineThreads<Vec<u8>> for PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
    type Thread = EmulatorThread<S, H>;

    fn new_thread(&mut self) -> &mut EmulatorThread<S, H> {
        AbstractPcodeMachineBase::new_thread(self)
    }

    fn new_thread_named(&mut self, name: &str) -> &mut EmulatorThread<S, H> {
        AbstractPcodeMachineBase::new_thread_named(self, name)
    }

    fn get_thread(&mut self, name: &str, create_if_absent: bool) -> Option<&mut EmulatorThread<S, H>> {
        AbstractPcodeMachineBase::get_thread(self, name, create_if_absent)
    }

    fn get_all_threads(&self) -> Vec<&EmulatorThread<S, H>> {
        self.threads.all()
    }
}

impl<S, H> PcodeMachine<Vec<u8>> for PcodeEmulator<S, H>
where
    S: PcodeExecutorState<Vec<u8>> + 'static,
    H: ThreadHooks<Vec<u8>, SharedPcodeExecutorState<S>, S>,
{
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

    fn compile_sleigh(&self, source_name: &str, source: &str) -> PcodeProgram {
        self.base.compile_sleigh(source_name, source)
    }

    fn inject(&mut self, address: &Address, source: &str) {
        AbstractPcodeMachineBase::inject(self, address, source);
    }

    fn get_inject(&self, address: &Address) -> Option<Arc<PcodeProgram>> {
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
    use crate::pcode::emu::pcode_thread::PcodeThread;
    use crate::pcode::emu::test_support::PcLanguage;
    use crate::pcode::exec::pcode_userop_library::nil;
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
        PcodeEmulator::with_arithmetic(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            Arc::new(StubArithmetic),
            thread_decoding(language, register_space()),
            Arc::new(BytesEmulatorParts),
        )
    }

    /// A register space for the test language, which declares none of its own.
    fn register_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            3,
        )
    }

    /// Thread parts for the given Sleigh language: its own semantics, plus a 4-byte `pc` at
    /// `register:0x100` (see `test_support`), decoding with the real `SleighInstructionDecoder`.
    fn thread_decoding(
        language: Arc<SleighLanguage>,
        register: Arc<crate::program::model::address::AddressSpace>,
    ) -> ThreadDecoding {
        let pc = crate::program::model::lang::register::Register::new(
            "pc",
            "program counter",
            register.address(0x100),
            4,
            false,
            crate::program::model::lang::register::Register::TYPE_PC,
        );
        let exec_language: Arc<dyn Language> = Arc::new(PcLanguage {
            inner: Arc::clone(&language) as Arc<dyn Language>,
            pc,
        });
        ThreadDecoding::sleigh::<Vec<u8>>(language, exec_language)
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

    #[test]
    fn new_thread_named_routes_through_create_thread_like_java() {
        let mut emulator = emulator();

        // newThread() names threads "Thread " + threads.size(), same as any AbstractPcodeMachine.
        assert_eq!("Thread 0", emulator.new_thread().get_name());
        assert_eq!("Thread 1", emulator.new_thread().get_name());
        let names = |e: &PcodeEmulator| -> Vec<String> {
            e.get_all_threads().iter().map(|t| t.get_name().to_string()).collect()
        };
        assert_eq!(vec!["Thread 0", "Thread 1"], names(&emulator));

        // getThread(name, false) does not create; getThread(name, true) does, via create_thread.
        assert!(emulator.get_thread("worker", false).is_none());
        assert_eq!("worker", emulator.get_thread("worker", true).expect("created on demand").get_name());
        assert_eq!("worker", emulator.get_thread("worker", true).unwrap().get_name());
        assert_eq!(vec!["Thread 0", "Thread 1", "worker"], names(&emulator));

        // Creating the first thread created the shared state, which every thread refers to.
        assert!(emulator.base.shared_state().is_some());
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
    fn constructor_uses_bytes_pcode_arithmetic_for_language() {
        // Java: `createArithmetic()` returns `BytesPcodeArithmetic.forLanguage(language)`; the
        // test language declares bigendian="false", so that is the little-endian instance.
        let emulator = PcodeEmulator::with_language(Arc::new(test_language()));
        let arithmetic = emulator.base.get_arithmetic();
        assert_eq!(Some(crate::program::model::lang::endian::Endian::Little), arithmetic.get_endian());
        assert_eq!(vec![0x34, 0x12], arithmetic.from_const_u64(0x1234, 2));
    }

    /// Java's threads bind to the machine's language, which must declare a program counter; a
    /// language decoded from a `.sla` alone does not.
    #[test]
    #[should_panic(expected = "Language has no program counter")]
    fn a_thread_needs_a_language_with_a_program_counter() {
        let mut emulator = PcodeEmulator::with_language(Arc::new(test_language()));
        emulator.new_thread();
    }

    /// A `BytesPcodeThread` steps real Sleigh instructions -- decoded from the machine's memory by
    /// the Sleigh language fixture of `SleighInstructionPrototype`'s tests -- through the real bytes
    /// arithmetic and state:
    ///
    /// ```text
    /// 0x1000: 11 2a   mov r1, 0x2a
    /// 0x1002: 20 05   jmp 0x1009
    /// 0x1009: 10 07   mov r0, 7
    /// 0x100b: 31 00   ret           (return [r1])
    /// ```
    #[test]
    fn a_bytes_thread_steps_real_sleigh_instructions() {
        use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
        use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
        use crate::program::model::address::AddressFactory;

        let language = decode_tests::language();
        let register = language
            .get_address_factory()
            .get_address_space_by_name("register")
            .expect("the fixture has a register space");
        let ram = Language::get_default_space(language.as_ref());
        let mut emulator = PcodeEmulator::with_thread_decoding(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            thread_decoding(Arc::clone(&language), Arc::clone(&register)),
        );
        emulator.get_shared_state_mut().set_var(
            &ram,
            0x1000,
            4,
            false,
            &vec![0x11, 0x2a, 0x20, 0x05],
        );
        emulator.get_shared_state_mut().set_var(
            &ram,
            0x1009,
            4,
            false,
            &vec![0x10, 0x07, 0x31, 0x00],
        );

        let thread = emulator.new_thread();
        thread.override_counter(&ram.address(0x1000));
        let r0 = |thread: &BytesPcodeThread| {
            thread.get_state().get_var(&register, 0, 4, false, Reason::Inspect)
        };
        let r1 = |thread: &BytesPcodeThread| {
            thread.get_state().get_var(&register, 4, 4, false, Reason::Inspect)
        };

        // mov r1, 0x2a: falls through by the instruction's 2-byte length.
        thread.step_instruction();
        assert_eq!(vec![0, 0, 0, 0x2a], r1(thread));
        assert_eq!(0x1002, thread.get_counter().offset());
        assert!(thread.get_frame().is_none());

        // jmp: the branch moves the counter to the target, and writes the pc.
        thread.step_instruction();
        assert_eq!(0x1009, thread.get_counter().offset());
        thread.re_initialize();
        assert_eq!(0x1009, thread.get_counter().offset());

        // mov r0, 7, one p-code op at a time: decode, COPY, then resolve the fall-through.
        thread.step_pcode_op();
        assert!(thread.get_frame().is_some());
        assert_eq!(vec![0, 0, 0, 0], r0(thread));
        thread.step_pcode_op();
        assert_eq!(vec![0, 0, 0, 7], r0(thread));
        thread.step_pcode_op();
        assert!(thread.get_frame().is_none());
        assert_eq!(0x100b, thread.get_counter().offset());

        // ret: an indirect branch through r1.
        thread.step_instruction();
        assert_eq!(0x2a, thread.get_counter().offset());

        // The thread's memory is the machine's: a second thread sees the same instructions.
        let other = emulator.new_thread();
        other.override_counter(&ram.address(0x1009));
        other.step_instruction();
        assert_eq!(vec![0, 0, 0, 7], r0(other));
        assert_eq!(0x100b, other.get_counter().offset());
    }

    /// The real decoder weaves a branch's delay slot into its p-code, and the thread steps the
    /// pair as one instruction:
    ///
    /// ```text
    /// 0x1000: 40 04   jd 0x1006
    /// 0x1002: 11 2a     mov r1, 0x2a   (delay slot)
    /// 0x1004: 10 05   mov r0, 5       (jumped over)
    /// 0x1006: 31 00   ret             (return [r1])
    /// ```
    #[test]
    fn a_bytes_thread_steps_a_delay_slotted_branch() {
        use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
        use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};

        let language = decode_tests::language();
        let register = language
            .get_address_factory()
            .get_address_space_by_name("register")
            .expect("the fixture has a register space");
        let ram = Language::get_default_space(language.as_ref());
        let mut emulator = PcodeEmulator::with_thread_decoding(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            thread_decoding(Arc::clone(&language), Arc::clone(&register)),
        );
        emulator.get_shared_state_mut().set_var(
            &ram,
            0x1000,
            8,
            false,
            &vec![0x40, 0x04, 0x11, 0x2a, 0x10, 0x05, 0x31, 0x00],
        );

        let thread = emulator.new_thread();
        thread.override_counter(&ram.address(0x1000));
        thread.step_instruction();
        assert_eq!(0x1006, thread.get_counter().offset());
        assert_eq!(vec![0, 0, 0, 0x2a], thread.get_state().get_var(&register, 4, 4, false, Reason::Inspect));
        assert_eq!(vec![0, 0, 0, 0], thread.get_state().get_var(&register, 0, 4, false, Reason::Inspect));
        thread.step_instruction();
        assert_eq!(0x2a, thread.get_counter().offset());
    }

    /// Undecodable bytes stop the thread with the decoder's error at the counter.
    #[test]
    #[should_panic(expected = "Unknown disassembly error (PC=ram:0x1000)")]
    fn a_bytes_thread_cannot_step_undecodable_bytes() {
        use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;

        let language = decode_tests::language();
        let register = language
            .get_address_factory()
            .get_address_space_by_name("register")
            .expect("the fixture has a register space");
        let ram = Language::get_default_space(language.as_ref());
        let mut emulator = PcodeEmulator::with_thread_decoding(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            thread_decoding(Arc::clone(&language), register),
        );
        emulator.get_shared_state_mut().set_var(&ram, 0x1000, 2, false, &vec![0x00, 0x00]);
        let thread = emulator.new_thread();
        thread.override_counter(&ram.address(0x1000));
        thread.step_instruction();
    }

    /// The Sleigh fixture machine with this program loaded, and one thread at 0x1000:
    ///
    /// ```text
    /// 0x1000: 11 2a   mov r1, 0x2a
    /// 0x1002: 10 07   mov r0, 7
    /// ```
    fn injectable() -> (PcodeEmulator, Arc<crate::program::model::address::AddressSpace>, Arc<crate::program::model::address::AddressSpace>) {
        use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
        use crate::program::model::address::AddressFactory;

        let language = decode_tests::language();
        let register = language.get_address_factory().get_address_space_by_name("register").unwrap();
        let ram = Language::get_default_space(language.as_ref());
        let mut emulator = PcodeEmulator::with_thread_decoding(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            thread_decoding(Arc::clone(&language), Arc::clone(&register)),
        );
        emulator.get_shared_state_mut().set_var(&ram, 0x1000, 4, false, &vec![0x11, 0x2a, 0x10, 0x07]);
        emulator.new_thread().override_counter(&ram.address(0x1000));
        (emulator, ram, register)
    }

    fn reg(thread: &BytesPcodeThread, register: &Arc<crate::program::model::address::AddressSpace>, offset: i64) -> Vec<u8> {
        use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
        thread.get_state().get_var(register, offset, 4, false, Reason::Inspect)
    }

    fn only_thread(emulator: &mut PcodeEmulator) -> &mut BytesPcodeThread {
        let name = emulator.get_all_threads()[0].get_name().to_string();
        emulator.get_thread(&name, false).unwrap()
    }

    #[test]
    fn an_inject_runs_before_the_instruction_it_executes() {
        let (mut emulator, ram, register) = injectable();
        let thread = only_thread(&mut emulator);
        // r1 = 1 runs first; the instruction then overwrites r1; r0 = r1 sees the instruction's 0x2a.
        thread.inject(&ram.address(0x1000), "r1 = 1; r0 = r1 + 1; emu_exec_decoded(); r0 = r0 + r1;");
        thread.step_instruction();
        assert_eq!(vec![0, 0, 0, 0x2a], reg(thread, &register, 4));
        assert_eq!(vec![0, 0, 0, 0x2c], reg(thread, &register, 0));
        // The executed instruction fell through, and the inject's frame is gone.
        assert_eq!(0x1002, thread.get_counter().offset());
        assert!(thread.get_frame().is_none());
        assert!(thread.get_instruction().is_none());

        // No inject at 0x1002: the instruction there executes normally.
        thread.step_instruction();
        assert_eq!(vec![0, 0, 0, 7], reg(thread, &register, 0));
    }

    #[test]
    fn an_inject_steps_op_by_op_through_the_executed_instruction() {
        let (mut emulator, ram, register) = injectable();
        let thread = only_thread(&mut emulator);
        thread.inject(&ram.address(0x1000), "r0 = 5; emu_exec_decoded();");
        thread.step_pcode_op(); // begin the inject
        assert!(thread.get_frame().is_some());
        thread.step_pcode_op(); // r0 = 5
        assert_eq!(vec![0, 0, 0, 5], reg(thread, &register, 0));
        thread.step_pcode_op(); // emu_exec_decoded: the whole instruction, then back to the inject
        assert_eq!(vec![0, 0, 0, 0x2a], reg(thread, &register, 4));
        assert_eq!(0x1002, thread.get_counter().offset());
        assert!(thread.get_frame().is_some_and(|f| f.is_finished()));
        thread.step_pcode_op(); // the finished inject resolves; the counter stays where it went
        assert!(thread.get_frame().is_none());
        assert_eq!(0x1002, thread.get_counter().offset());
    }

    #[test]
    fn an_inject_may_skip_the_instruction() {
        let (mut emulator, ram, register) = injectable();
        let thread = only_thread(&mut emulator);
        thread.inject(&ram.address(0x1000), "r0 = 9; emu_skip_decoded();");
        thread.step_instruction();
        assert_eq!(vec![0, 0, 0, 9], reg(thread, &register, 0));
        assert_eq!(vec![0, 0, 0, 0], reg(thread, &register, 4), "the instruction did not execute");
        assert_eq!(0x1002, thread.get_counter().offset());
    }

    #[test]
    fn an_inject_that_neither_executes_nor_skips_stays_put() {
        let (mut emulator, ram, register) = injectable();
        let thread = only_thread(&mut emulator);
        thread.inject(&ram.address(0x1000), "r0 = r0 + 1;");
        thread.step_instruction();
        thread.step_instruction();
        assert_eq!(vec![0, 0, 0, 2], reg(thread, &register, 0));
        assert_eq!(0x1000, thread.get_counter().offset());
    }

    /// Java's `addBreakpoint`: `emu_swi()` interrupts with the inject's frame recorded, so the
    /// thread resumes by finishing the inject, which executes the instruction.
    #[test]
    fn a_breakpoint_interrupts_and_resumes_into_the_instruction() {
        use crate::pcode::exec::interrupt_pcode_execution_exception::InterruptPcodeExecutionException;
        use std::panic::{self, AssertUnwindSafe};

        let (mut emulator, ram, register) = injectable();
        emulator.add_breakpoint(&ram.address(0x1000), "1:1");
        let thread = only_thread(&mut emulator);
        let hit = panic::catch_unwind(AssertUnwindSafe(|| thread.step_instruction()));
        let message = hit.expect_err("the breakpoint interrupts");
        let message = message.downcast_ref::<String>().cloned().unwrap_or_default();
        assert_eq!(InterruptPcodeExecutionException::MESSAGE, message);
        assert_eq!(0x1000, thread.get_counter().offset());
        assert!(thread.get_frame().is_some(), "the inject's frame is recorded, as in Java");
        assert_eq!(vec![0, 0, 0, 0], reg(thread, &register, 4));

        thread.finish_instruction();
        assert_eq!(vec![0, 0, 0, 0x2a], reg(thread, &register, 4));
        assert_eq!(0x1002, thread.get_counter().offset());
        assert!(thread.get_frame().is_none());
    }

    #[test]
    fn suspension_set_through_the_core_is_the_executors() {
        let (mut emulator, _ram, _register) = injectable();
        let thread = only_thread(&mut emulator);
        thread.core().set_suspended(true);
        assert!(thread.is_suspended());
        thread.set_suspended(false);
        assert!(!thread.core().is_suspended());
    }
}
