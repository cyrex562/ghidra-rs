//! The parts factory for creating emulators with symbolic summaries using Z3.
//!
//! Port of `ghidra.pcode.emu.symz3.SymZ3PartsFactory`.
//!
//! This is probably the most straightforward means of implementing a concrete-plus-auxiliary
//! emulator. For our case, the auxiliary piece is the [`SymValueZ3`]. For an overview of the parts
//! of a p-code emulator, see [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//! The components, in the order this factory makes them:
//!
//! * P-code Arithmetic: [`SymZ3PcodeArithmetic`]
//! * Userop Library: [`SymZ3PcodeUseropLibrary`]
//! * P-code Executor: [`SymZ3PcodeThreadExecutor`]
//! * Machine State: [`SymZ3PcodeExecutorState`]
//!
//! # Z3 contexts
//!
//! Java's factory is a stateless singleton, and every Z3-touching part opens its own
//! `new Context()` wherever it needs one. The Rust parts hold the
//! [`Z3Context`](crate::feature::seam_stubs::Z3Context) they build expressions with (see
//! [`SymZ3PcodeArithmetic`]'s module docs), so this factory holds the means to open one -- a
//! [`Z3ContextFactory`] -- and opens a fresh context for each part it makes, as Java does. Values
//! carry their expressions as SMT-LIB text (see [`SymValueZ3`]), so parts built over different
//! contexts exchange values freely, again as in Java.
//!
//! The crate's default build has no Z3 binding: the context factory is the caller's, over any
//! implementation of the [`Z3Context`](crate::feature::seam_stubs::Z3Context) seam. With the
//! optional `z3` cargo feature, [`SymZ3PartsFactory::instance`] is Java's `INSTANCE`, opening
//! contexts of the real solver
//! ([`Z3SolverContext`](crate::feature::symz3::z3_solver_context::Z3SolverContext)).
//!
//! # State callbacks
//!
//! The symbolic piece of a [`SymZ3PcodeExecutorState`] is fixed to [`NoPcodeStateCallbacks`] (see
//! [`SymZ3PairedPcodeExecutorState::get_right`](crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state::SymZ3PairedPcodeExecutorState::get_right)),
//! so this factory is the one for those callbacks, which is what
//! [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator)'s states use.

use std::sync::Arc;

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::abstract_pcode_machine::PcodeMachineShared;
use crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory;
use crate::pcode::emu::auxiliary::aux_pcode_emulator::AuxPcodeEmulator;
use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxThreadParts;
use crate::pcode::emu::default_pcode_thread::{PcodeThreadExecutor, ThreadCore};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::emu::symz3::state::sym_z3_pcode_executor_state::SymZ3PcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::SymZ3PcodeArithmetic;
use crate::pcode::emu::symz3::sym_z3_pcode_thread::{SymZ3PcodeThread, SymZ3SharedState, SymZ3State, SymZ3ThreadId};
use crate::pcode::emu::symz3::sym_z3_pcode_thread_executor::SymZ3PcodeThreadExecutor;
use crate::pcode::emu::symz3::sym_z3_pcode_userop_library::SymZ3PcodeUseropLibrary;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::Language;

type Pair = (Vec<u8>, SymValueZ3);

/// Opens a Z3 context: Java's `new Context()`. See the module docs.
pub type Z3ContextFactory = Arc<dyn Fn() -> Arc<dyn Z3Context> + Send + Sync>;

/// The parts factory for creating emulators with symbolic summaries using Z3.
///
/// Port of the enum singleton `SymZ3PartsFactory`. Java's one-constant enum is only its
/// singleton idiom; the Rust factory carries state (its [`Z3ContextFactory`], see the module
/// docs), so it is a struct, and the singleton is [`SymZ3PartsFactory::instance`] where a default
/// context exists.
pub struct SymZ3PartsFactory {
    new_context: Z3ContextFactory,
}

impl SymZ3PartsFactory {
    /// A factory whose parts work in contexts opened by `new_context`.
    pub fn new(new_context: Z3ContextFactory) -> Self {
        Self { new_context }
    }

    /// Open a Z3 context for a new part: Java's `new Context()`.
    pub fn new_context(&self) -> Arc<dyn Z3Context> {
        (self.new_context)()
    }

    /// This singleton factory instance, whose parts use the real Z3 solver.
    ///
    /// Port of `SymZ3PartsFactory.INSTANCE`. Only with the `z3` cargo feature; see the module
    /// docs.
    #[cfg(feature = "z3")]
    pub fn instance() -> Arc<SymZ3PartsFactory> {
        use crate::feature::symz3::z3_solver_context::Z3SolverContext;
        static INSTANCE: std::sync::OnceLock<Arc<SymZ3PartsFactory>> = std::sync::OnceLock::new();
        Arc::clone(INSTANCE.get_or_init(|| {
            Arc::new(SymZ3PartsFactory::new(Arc::new(|| Arc::new(Z3SolverContext) as Arc<dyn Z3Context>)))
        }))
    }

    /// The emulator's language, as the state constructors take it: Java's
    /// `emulator.getLanguage()`.
    fn language_of(emulator: &dyn AuxPcodeEmulator<SymValueZ3>) -> Arc<dyn Language> {
        Arc::clone(emulator.base().language()) as Arc<dyn Language>
    }
}

impl AuxEmulatorPartsFactory<SymValueZ3> for SymZ3PartsFactory {
    type SharedState = SymZ3State;
    type LocalState = SymZ3State;
    type Thread = SymZ3PcodeThread;

    /// Here we simply return the arithmetic for symbolic values for the emulator's language.
    fn get_arithmetic(&self, language: &dyn Language) -> Arc<dyn PcodeArithmetic<SymValueZ3>> {
        Arc::new(SymZ3PcodeArithmetic::for_language(language, self.new_context()))
    }

    /// Java's library for obtaining symbolic values: aside from initializing a trace, or writing
    /// directly to the state, this would let clients quickly place symbolic values in the machine.
    /// We construct and return the library here.
    fn create_shared_userop_library(&self, _language: &SleighLanguage) -> Box<dyn PcodeUseropLibrary<Pair>> {
        Box::new(SymZ3PcodeUseropLibrary::new())
    }

    /// We have no thread-specific userops to add, which means we also have no need for stubs, so
    /// here we just return the empty library.
    fn create_local_userop_stub(&self, _language: &SleighLanguage) -> Box<dyn PcodeUseropLibrary<Pair>> {
        Box::new(nil())
    }

    /// We have no thread-specific userops to add, so here we just return the empty library.
    fn create_local_userop_library(
        &self,
        _emulator: &PcodeMachineShared<Pair>,
        _thread: &dyn ErasedPcodeThread,
    ) -> Box<dyn PcodeUseropLibrary<Pair>> {
        Box::new(nil())
    }

    /// We'd like to instrument conditional branches to record preconditions, so we need a custom
    /// executor: the thread executor, extended by a [`SymZ3PcodeThreadExecutor`].
    fn create_executor(
        &self,
        _emulator: &PcodeMachineShared<Pair>,
        thread: &ThreadCore<Pair, SymZ3SharedState, SymZ3State>,
    ) -> PcodeThreadExecutor<Pair> {
        let extension = SymZ3PcodeThreadExecutor::new(
            SymZ3ThreadId::new(thread.get_name()),
            thread.typed_state_handle(),
            self.new_context(),
        );
        PcodeThreadExecutor::for_thread(thread).with_extension(Box::new(extension))
    }

    /// Port of `createThread`: `new SymZ3PcodeThread(name, emulator)`.
    fn create_thread(
        self: Arc<Self>,
        _emulator: &dyn AuxPcodeEmulator<SymValueZ3>,
        name: &str,
        parts: AuxThreadParts<SymValueZ3, SymZ3State, SymZ3State>,
    ) -> SymZ3PcodeThread {
        SymZ3PcodeThread::new_symz3(name, parts, self)
    }

    /// Port of `createSharedState`: `new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete, cb)`.
    fn create_shared_state(
        &self,
        emulator: &dyn AuxPcodeEmulator<SymValueZ3>,
        concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
        cb: Arc<NoPcodeStateCallbacks>,
    ) -> SymZ3State {
        SymZ3PcodeExecutorState::new(Self::language_of(emulator), concrete, cb, self.new_context())
    }

    /// Port of `createLocalState`: `new SymZ3PcodeExecutorState(emulator.getLanguage(), concrete, cb)`.
    fn create_local_state(
        &self,
        emulator: &dyn AuxPcodeEmulator<SymValueZ3>,
        _thread_name: &str,
        concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
        cb: Arc<NoPcodeStateCallbacks>,
    ) -> SymZ3State {
        SymZ3PcodeExecutorState::new(Self::language_of(emulator), concrete, cb, self.new_context())
    }
}
