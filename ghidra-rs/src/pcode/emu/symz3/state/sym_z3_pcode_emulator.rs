//! An emulator with symbolic Z3 summarization analysis.
//!
//! Port of `ghidra.pcode.emu.symz3.state.SymZ3PcodeEmulator`.
//!
//! Java's class extends `AuxPcodeEmulator<SymValueZ3>` and returns the singleton
//! [`SymZ3PartsFactory`] from `getPartsFactory()`; all the complexity is encapsulated in that
//! factory. Here the emulator holds its factory (see [`SymZ3PartsFactory`]'s module docs on why it
//! is not a no-argument singleton in the default build) and forwards the machine's factory methods
//! to the [`aux_pcode_emulator`] free functions with it, per that module's docs.
//!
//! # Deviations from Java
//!
//! * **Language.** Java takes a `Language` and asserts it is a `SleighLanguage`; the machine base
//!   takes an `Arc<SleighLanguage>` (see
//!   [`abstract_pcode_machine`](crate::pcode::emu::abstract_pcode_machine)'s module docs).
//! * **Threads.** Java's threads build a `SleighInstructionDecoder`, not ported, and read the
//!   program counter off the language, which only a `.pspec` declares. So, as for
//!   [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator), a machine that will
//!   create threads is built with [`ThreadDecoding`], and one built without it panics when asked
//!   for a thread, naming what is missing.
//! * **Covariant getters.** Java narrows `newThread`/`getAllThreads`/`getSharedState` to the
//!   SymZ3 types. The [`PcodeMachineThreads`] methods already return [`SymZ3PcodeThread`]; the
//!   shared state is reached through
//!   [`SymZ3PcodeEmulatorTrait::get_shared_symz3_state`].

use std::sync::{Arc, OnceLock};

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::abstract_pcode_machine::{
    AbstractPcodeMachine, AbstractPcodeMachineBase, AbstractPcodeMachineThreads, ThreadList,
};
use crate::pcode::emu::auxiliary::aux_pcode_emulator::{self, AuxPcodeEmulator};
use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxThreadParts;
use crate::pcode::emu::pcode_emulation_callbacks::{no_pcode_emulation_callbacks, PcodeEmulationCallbacks};
use crate::pcode::emu::pcode_emulator::ThreadDecoding;
use crate::pcode::emu::pcode_machine::{
    AccessKind, ErasedPcodeMachine, PcodeMachine, PcodeMachineThreads, SwiMode,
};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::emu::symz3::sym_z3_parts_factory::SymZ3PartsFactory;
use crate::pcode::emu::symz3::sym_z3_pcode_emulator_trait::SymZ3PcodeEmulatorTrait;
use crate::pcode::emu::symz3::sym_z3_pcode_thread::{SymZ3PcodeThread, SymZ3SharedState, SymZ3State};
use crate::pcode::emu::symz3::sym_z3_records_execution::{RecInstruction, RecOp, SymZ3RecordsExecution};
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::SleighLanguage;

type Pair = (Vec<u8>, SymValueZ3);

/// An emulator with symbolic Z3 summarization analysis.
///
/// Port of `SymZ3PcodeEmulator`. See the module docs.
pub struct SymZ3PcodeEmulator {
    base: AbstractPcodeMachineBase<Pair>,
    parts_factory: Arc<SymZ3PartsFactory>,
    threads: ThreadList<SymZ3PcodeThread>,
    /// The machine's shared state as its threads hold it; set when the shared state is created.
    shared_memory: OnceLock<SymZ3SharedState>,
    thread_decoding: Option<ThreadDecoding<SymZ3State>>,
}

impl SymZ3PcodeEmulator {
    /// Create an emulator.
    ///
    /// Port of `SymZ3PcodeEmulator(Language, PcodeEmulationCallbacks)`, with the emulator's parts
    /// factory (Java's `getPartsFactory()`). The machine cannot create threads; see the module docs
    /// and [`with_thread_decoding`](Self::with_thread_decoding).
    pub fn new(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Pair>>,
        parts_factory: Arc<SymZ3PartsFactory>,
    ) -> Self {
        Self::build(language, cb, parts_factory, None)
    }

    /// Create an emulator with no emulation callbacks.
    ///
    /// Port of `SymZ3PcodeEmulator(Language)`, which is `this(language,
    /// PcodeEmulationCallbacks.none())`.
    pub fn with_language(language: Arc<SleighLanguage>, parts_factory: Arc<SymZ3PartsFactory>) -> Self {
        Self::new(language, no_pcode_emulation_callbacks(), parts_factory)
    }

    /// Create an emulator whose threads decode with the given parts.
    ///
    /// Port of `SymZ3PcodeEmulator(Language, PcodeEmulationCallbacks)`; see the module docs on
    /// `thread_decoding`.
    pub fn with_thread_decoding(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Pair>>,
        parts_factory: Arc<SymZ3PartsFactory>,
        thread_decoding: ThreadDecoding<SymZ3State>,
    ) -> Self {
        Self::build(language, cb, parts_factory, Some(thread_decoding))
    }

    /// The constructor body: Java's `AuxPcodeEmulator(Language, PcodeEmulationCallbacks)`, whose
    /// `super` calls the overridden `createArithmetic`/`createUseropLibrary`/
    /// `createThreadStubLibrary`.
    fn build(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Pair>>,
        parts_factory: Arc<SymZ3PartsFactory>,
        thread_decoding: Option<ThreadDecoding<SymZ3State>>,
    ) -> Self {
        let language_dyn: Arc<dyn Language> = Arc::clone(&language) as Arc<dyn Language>;
        let arithmetic = aux_pcode_emulator::create_arithmetic(&language_dyn, parts_factory.as_ref());
        let library =
            aux_pcode_emulator::create_userop_library(&language, arithmetic.as_ref(), parts_factory.as_ref());
        let thread_stub_library =
            aux_pcode_emulator::create_thread_stub_library(&language, parts_factory.as_ref());
        let base =
            AbstractPcodeMachineBase::new(language, cb, arithmetic, library, thread_stub_library, None);
        let emulator = Self {
            base,
            parts_factory,
            threads: ThreadList::new(),
            shared_memory: OnceLock::new(),
            thread_decoding,
        };
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    /// The emulator's parts factory. Port of `getPartsFactory()`.
    pub fn get_parts_factory(&self) -> &Arc<SymZ3PartsFactory> {
        &self.parts_factory
    }

    /// The machine's shared state as its threads hold it, creating it if this is the first
    /// request. Java: `getSharedState()`, narrowed to `SymZ3PcodeExecutorState`.
    pub fn shared_state_handle(&mut self) -> SymZ3SharedState {
        AbstractPcodeMachineBase::get_shared_state(self);
        self.shared_memory.get().expect("the shared state was just created").clone()
    }
}

impl ErasedPcodeMachine for SymZ3PcodeEmulator {}

impl AbstractPcodeMachine<Pair> for SymZ3PcodeEmulator {
    fn base(&self) -> &AbstractPcodeMachineBase<Pair> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<Pair> {
        &mut self.base
    }

    /// Port of `AuxPcodeEmulator.createSharedState()`. The machine keeps the handle its threads
    /// will share.
    fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<Pair>> {
        let memory = self.shared_memory.get_or_init(|| {
            SharedPcodeExecutorState::new(aux_pcode_emulator::create_shared_state(self, self.parts_factory.as_ref()))
        });
        Box::new(memory.clone())
    }

    /// Port of `AuxPcodeEmulator.createLocalState(PcodeThread)`.
    ///
    /// The type-erased thread carries no name, so the parts factory is given an empty one; the
    /// SymZ3 factory does not read it. Threads created by this machine get their local state
    /// through [`create_thread`](AbstractPcodeMachineThreads::create_thread), which names them.
    fn create_local_state(&self, _thread: &dyn ErasedPcodeThread) -> Box<dyn PcodeExecutorState<Pair>> {
        Box::new(aux_pcode_emulator::create_local_state(self, "", self.parts_factory.as_ref()))
    }

    /// This machine as a plain [`PcodeMachine`]. Java gets this by subtyping.
    fn as_pcode_machine(&self) -> &dyn PcodeMachine<Pair> {
        self
    }
}

impl AuxPcodeEmulator<SymValueZ3> for SymZ3PcodeEmulator {}

impl AbstractPcodeMachineThreads<Pair> for SymZ3PcodeEmulator {
    /// Port of `AuxPcodeEmulator.createThread(String)`: `getPartsFactory().createThread(this,
    /// name)`, whose thread reads the machine's shared state, creating it if this is the first
    /// thread.
    ///
    /// # Panics
    ///
    /// If this machine was built without [`ThreadDecoding`]; see the module docs.
    fn create_thread(&mut self, name: &str) -> SymZ3PcodeThread {
        let Some(decoding) = self.thread_decoding.clone() else {
            panic!(
                "SymZ3PcodeEmulator cannot create threads without ThreadDecoding: \
                 SleighInstructionDecoder is not ported (see SymZ3PcodeEmulator::with_thread_decoding)"
            );
        };
        let shared = self.shared_state_handle();
        // Java: `machine.createLocalState(this)`.
        let local = aux_pcode_emulator::create_local_state(self, name, self.parts_factory.as_ref());
        let decoder = (decoding.decoder)(&decoding.exec_language, &shared);
        let parts = AuxThreadParts {
            machine: Arc::clone(self.base.shared()),
            exec_language: decoding.exec_language,
            shared_state: shared,
            local_state: local,
            decoder,
        };
        aux_pcode_emulator::create_thread(self, name, &self.parts_factory, parts)
    }

    fn threads(&self) -> &ThreadList<SymZ3PcodeThread> {
        &self.threads
    }

    fn threads_mut(&mut self) -> &mut ThreadList<SymZ3PcodeThread> {
        &mut self.threads
    }
}

impl PcodeMachineThreads<Pair> for SymZ3PcodeEmulator {
    type Thread = SymZ3PcodeThread;

    fn new_thread(&mut self) -> &mut SymZ3PcodeThread {
        AbstractPcodeMachineBase::new_thread(self)
    }

    fn new_thread_named(&mut self, name: &str) -> &mut SymZ3PcodeThread {
        AbstractPcodeMachineBase::new_thread_named(self, name)
    }

    fn get_thread(&mut self, name: &str, create_if_absent: bool) -> Option<&mut SymZ3PcodeThread> {
        AbstractPcodeMachineBase::get_thread(self, name, create_if_absent)
    }

    fn get_all_threads(&self) -> Vec<&SymZ3PcodeThread> {
        self.threads.all()
    }
}

impl PcodeMachine<Pair> for SymZ3PcodeEmulator {
    fn get_language(&self) -> &SleighLanguage {
        self.base.get_language()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Pair>> {
        self.base.get_arithmetic()
    }

    fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
        self.base.set_software_interrupt_mode(mode);
    }

    fn get_software_interrupt_mode(&self) -> SwiMode {
        self.base.get_software_interrupt_mode()
    }

    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<Pair> {
        self.base.get_userop_library()
    }

    fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<Pair> {
        self.base.get_stub_userop_library()
    }

    fn get_shared_state(&self) -> &dyn PcodeExecutorState<Pair> {
        self.base
            .shared_state()
            .expect("shared state not created yet; call get_shared_state_mut first")
    }

    fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<Pair> {
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

impl SymZ3RecordsExecution for SymZ3PcodeEmulator {
    /// Java's `SymZ3PcodeEmulatorTrait.getInstructions()`: the shared symbolic state's. Empty
    /// until the shared state exists.
    fn get_instructions(&self) -> Vec<RecInstruction> {
        self.get_shared_symz3_state()
            .map(|shared| shared.with_symbolic(|symbolic| symbolic.get_instructions()))
            .unwrap_or_default()
    }

    /// Java's `SymZ3PcodeEmulatorTrait.getOps()`: the shared symbolic state's. Empty until the
    /// shared state exists.
    fn get_ops(&self) -> Vec<RecOp> {
        self.get_shared_symz3_state()
            .map(|shared| shared.with_symbolic(|symbolic| symbolic.get_ops()))
            .unwrap_or_default()
    }
}

impl SymZ3PcodeEmulatorTrait for SymZ3PcodeEmulator {
    fn get_all_symz3_threads(&self) -> Vec<&SymZ3PcodeThread> {
        self.threads.all()
    }

    fn get_shared_symz3_state(&self) -> Option<SymZ3SharedState> {
        self.shared_memory.get().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::feature::seam_stubs::Z3Context;
    use crate::pcode::emu::pcode_thread::PcodeThread;
    use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
    use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::testing::EvalCtx;
    use crate::pcode::emu::symz3::sym_z3_pcode_emulator_trait::SymZ3PcodeEmulatorTrait;
    use crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions;
    use crate::pcode::emu::test_support::{PcLanguage, SleighTestDecoder};
    use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::lang::register::Register;

    /// The parts factory over the seam's concretely-evaluating test context.
    fn parts_factory() -> Arc<SymZ3PartsFactory> {
        Arc::new(SymZ3PartsFactory::new(Arc::new(|| Arc::new(EvalCtx) as Arc<dyn Z3Context>)))
    }

    /// Thread parts for the Sleigh fixture: its own semantics plus a 4-byte `pc` at
    /// `register:0x100`, and a decoder reading the concrete side of the machine's memory.
    fn thread_decoding(language: &Arc<SleighLanguage>, register: &Arc<AddressSpace>) -> ThreadDecoding<SymZ3State> {
        let pc = Register::new("pc", "program counter", register.address(0x100), 4, false, Register::TYPE_PC);
        let exec_language: Arc<dyn Language> =
            Arc::new(PcLanguage { inner: Arc::clone(language) as Arc<dyn Language>, pc });
        let language = Arc::clone(language);
        ThreadDecoding {
            exec_language,
            decoder: Arc::new(move |_exec_language, memory: &SymZ3SharedState| {
                let memory = memory.clone();
                Box::new(SleighTestDecoder::with_reader(
                    Arc::clone(&language),
                    Box::new(move |address, length| {
                        memory.with_concrete(|concrete| {
                            concrete.get_var(address.space(), address.offset(), length, false, Reason::ExecuteDecode)
                        })
                    }),
                    Arc::new(std::sync::Mutex::new(Vec::new())),
                ))
            }),
        }
    }

    struct Fixture {
        emulator: SymZ3PcodeEmulator,
        ram: Arc<AddressSpace>,
        register: Arc<AddressSpace>,
    }

    /// An emulator over the Sleigh fixture with this program loaded:
    ///
    /// ```text
    /// 0x1000: 11 05   mov r1, 5
    /// 0x1002: 61 00   add r1, r0        (r0 is never written: it stays symbolic)
    /// 0x1004: 70 04   bz r0, 0x100a
    /// ```
    fn fixture() -> Fixture {
        let language = decode_tests::language();
        let register = language
            .get_address_factory()
            .get_address_space_by_name("register")
            .expect("the fixture has a register space");
        let ram = Language::get_default_space(language.as_ref());
        let mut emulator = SymZ3PcodeEmulator::with_thread_decoding(
            Arc::clone(&language),
            no_pcode_emulation_callbacks(),
            parts_factory(),
            thread_decoding(&language, &register),
        );
        let program = emulator.get_arithmetic().from_const_bytes(&[0x11, 0x05, 0x61, 0x00, 0x70, 0x04]);
        emulator.get_shared_state_mut().set_var(&ram, 0x1000, 6, false, &program);
        Fixture { emulator, ram, register }
    }

    /// The symbolic expression of a register, as the seam renders it.
    fn symbolic(thread: &SymZ3PcodeThread, register: &Arc<AddressSpace>, offset: i64) -> String {
        let value = thread.get_state().get_var(register, offset, 4, false, Reason::Inspect).1;
        value.get_bit_vec_expr(&EvalCtx).expect("a bit-vector").as_expr().to_smt_string()
    }

    fn concrete(thread: &SymZ3PcodeThread, register: &Arc<AddressSpace>, offset: i64) -> Vec<u8> {
        thread.with_local_concrete_state(|c| c.get_var(register, offset, 4, false, Reason::Inspect))
    }

    #[test]
    fn a_thread_steps_real_instructions_building_symbolic_values() {
        let Fixture { mut emulator, ram, register } = fixture();
        let thread = emulator.new_thread_named("Threads[0]");
        thread.override_counter(&ram.address(0x1000));

        // mov r1, 5: both sides take the constant.
        thread.step_instruction();
        assert_eq!(concrete(thread, &register, 4), vec![0, 0, 0, 5]);
        assert_eq!(symbolic(thread, &register, 4), "(_ bv5 32)");
        assert_eq!(0x1002, thread.get_counter().offset());

        // add r1, r0: r0 was never written, so the seam names it; the sum is an expression.
        thread.step_instruction();
        assert_eq!(concrete(thread, &register, 4), vec![0, 0, 0, 5]);
        assert_eq!(symbolic(thread, &register, 4), "(bvadd (_ bv5 32) r0)");
        assert_eq!(symbolic(thread, &register, 0), "r0");
        assert_eq!(0x1004, thread.get_counter().offset());
    }

    #[test]
    fn a_conditional_branch_records_its_precondition() {
        let Fixture { mut emulator, ram, .. } = fixture();
        let thread = emulator.new_thread_named("Threads[0]");
        thread.override_counter(&ram.address(0x1004));
        assert!(thread.get_preconditions().is_empty());

        // bz r0: concretely r0 is 0, so the branch is taken, and the precondition is the
        // symbolic condition itself, recorded on the thread's local state.
        thread.step_instruction();
        assert_eq!(0x100a, thread.get_counter().offset());
        // INT_EQUAL yields the 8-bit `ite` Java's SymValueZ3.intEqual builds; CBRANCH reads it as
        // a boolean the way SymValueZ3.getBoolExpr does, as "not zero". Nothing simplifies it.
        assert_eq!(
            thread.get_preconditions(),
            vec!["B:bool;s;(ite (= (ite (= r0 (_ bv0 32)) (_ bv1 8) (_ bv0 8)) (_ bv0 8)) false true)"
                .to_string()]
        );
        // The shared state has none of the thread's preconditions.
        let shared = emulator.get_shared_symz3_state().expect("created with the first thread");
        assert!(shared.with_symbolic(|s| s.get_preconditions()).is_empty());
    }

    #[test]
    fn the_emulator_records_instructions_and_ops_per_thread() {
        let Fixture { mut emulator, ram, .. } = fixture();
        let thread = emulator.new_thread_named("Threads[0]");
        thread.override_counter(&ram.address(0x1000));
        thread.step_instruction();
        thread.step_instruction();

        let instructions = emulator.get_instructions();
        assert_eq!(
            instructions.iter().map(|i| (i.index, i.get_address().offset())).collect::<Vec<_>>(),
            vec![(0, 0x1000), (1, 0x1002)]
        );
        let ops = emulator.get_ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|op| op.thread.get_name() == "Threads[0]"));
        assert_eq!(emulator.format_ops(), "[0] COPY\n[0] INT_ADD");
    }

    #[test]
    fn threads_share_memory_but_not_registers() {
        let Fixture { mut emulator, ram, register } = fixture();
        {
            let first = emulator.new_thread_named("Threads[0]");
            first.override_counter(&ram.address(0x1000));
            first.step_instruction();
        }
        let second = emulator.new_thread_named("Threads[1]");
        // The second thread decodes the same memory, from its own registers.
        second.override_counter(&ram.address(0x1002));
        second.step_instruction();
        assert_eq!(symbolic(second, &register, 4), "(bvadd r1 r0)");

        let names: Vec<_> = emulator.get_all_symz3_threads().iter().map(|t| t.get_name().to_string()).collect();
        assert_eq!(names, vec!["Threads[0]", "Threads[1]"]);
        // Both threads' ops land in the one shared record.
        let threads: Vec<_> = emulator.get_ops().iter().map(|op| op.get_thread_name()).collect();
        assert_eq!(threads, vec![Some("0".to_string()), Some("1".to_string())]);
    }

    #[test]
    fn summaries_fold_in_each_threads_local_state() {
        let Fixture { mut emulator, ram, .. } = fixture();
        let thread = emulator.new_thread_named("Threads[0]");
        thread.override_counter(&ram.address(0x1002));
        thread.step_instruction();
        thread.step_instruction();

        let z3p = Z3InfixPrinter::new(Arc::new(EvalCtx));
        let preconditions = emulator.stream_preconditions(&EvalCtx, &z3p);
        assert_eq!(preconditions.len(), 1);
        let summary = emulator.printable_summary(&EvalCtx, &z3p);
        assert!(summary.contains("Registers that were updated"), "{summary}");
        assert!(summary.contains("r1"), "{summary}");
        let valuations = emulator.stream_valuations(&EvalCtx, &z3p);
        assert!(valuations.iter().any(|(k, _)| k.starts_with("r1")), "{valuations:?}");
    }

    #[test]
    fn the_emulator_uses_the_parts_factorys_libraries_and_arithmetic() {
        let Fixture { emulator, .. } = fixture();
        // Java's createArithmetic(): bytes paired with SymZ3, for the (big-endian) language.
        let (bytes, sym) = emulator.get_arithmetic().from_const_u64(0x1234, 2);
        assert_eq!(bytes, vec![0x12, 0x34]);
        assert_eq!(sym.to_long(&EvalCtx), Some(0x1234));
        // Java's createThreadStubLibrary(): the emulation library composed with the (empty) stub.
        assert!(emulator.get_stub_userop_library().get_userops().contains_key("emu_swi"));
    }

    #[test]
    #[should_panic(expected = "SleighInstructionDecoder is not ported")]
    fn a_machine_without_thread_decoding_cannot_create_threads() {
        let mut emulator = SymZ3PcodeEmulator::with_language(decode_tests::language(), parts_factory());
        emulator.new_thread();
    }
}
