//! The default implementation of [`PcodeThread`], suitable for most applications.
//!
//! Corresponds to `ghidra.pcode.emu.DefaultPcodeThread`.
//!
//! This class implements the control-flow logic of the target machine, cooperating with the p-code
//! program flow implemented by [`PcodeExecutor`]. That logic lives primarily in
//! [`DefaultPcodeThread::begin_instruction_or_inject`] and
//! [`DefaultPcodeThread::advance_after_finished`].
//!
//! # Subclassing: [`ThreadHooks`]
//!
//! Java's emulators customize threads by subclassing `DefaultPcodeThread` and overriding its
//! `protected` factory and extension methods (`ModifiedPcodeThread`, `BytesPcodeThread`,
//! `AuxPcodeThread`, the SymZ3 and JIT threads, `AdaptedEmulator.AdaptedPcodeThread`). Here the
//! thread is generic over a [`ThreadHooks`] implementation carrying those overrides; every hook
//! defaults to Java's base behavior, so [`NoThreadHooks`] is a plain `DefaultPcodeThread`. A
//! "subclass of a subclass" is a hooks type that holds its parent's hooks and calls them where Java
//! calls `super` -- see
//! [`ModifiedThreadHooks`](crate::pcode::emu::modified_pcode_thread::ModifiedThreadHooks).
//!
//! The thread's fields -- everything Java's subclasses reach as `protected` state -- live in a
//! [`ThreadCore`], which is what a hook receives in place of Java's `this`. The thread itself is
//! that core plus the executor, the userop library, and the hooks, so a hook can mutate the core
//! while the executor is mid-frame without the two borrows overlapping.
//!
//! The executor's own overrides (Java's `PcodeThreadExecutor extends PcodeExecutor`) are wired
//! through [`PcodeExecutorHooks`]: while stepping, the thread hands the executor a bridge that
//! checks suspension, fires the emulation callbacks, applies access breakpoints, and moves the
//! counter on external branches, exactly as Java's `PcodeThreadExecutor` does. A further executor
//! "subclass" (Java's `createExecutor()` override, e.g. `SymZ3PcodeThreadExecutor`) is a
//! [`PcodeThreadExecutor`] carrying an extension, installed by [`ThreadHooks::create_executor`].
//!
//! # Divergences from Java
//!
//! * **The machine back-reference.** Java's thread holds its `AbstractPcodeMachine<T>` and its
//!   machine holds the thread, a cycle Rust cannot express with plain ownership. The machine owns
//!   its threads, and a thread holds an `Arc<PcodeMachineShared<T>>`: the part of the machine a
//!   thread reads, which the machine shares with all its threads. See
//!   [`abstract_pcode_machine`](crate::pcode::emu::abstract_pcode_machine)'s module docs.
//! * **The factory methods.** Java's constructor calls the overridable `createThreadState`,
//!   `createInstructionDecoder`, `createExecutor`, and (lazily) `createUseropLibrary` on a
//!   half-built `this`. Here the construction-time hooks are called from
//!   [`DefaultPcodeThread::new`] in the same order. `createInstructionDecoder`'s base product (a
//!   [`SleighInstructionDecoder`](crate::pcode::emu::sleigh_instruction_decoder::SleighInstructionDecoder)
//!   over the shared state, which the machine builds; see
//!   [`ThreadDecoding`](crate::pcode::emu::pcode_emulator::ThreadDecoding)) is a constructor
//!   parameter, and [`ThreadHooks::create_instruction_decoder`] receives it to keep or wrap --
//!   which is what every in-tree override does with `super`'s decoder. `createThreadState` needs no hook: the state
//!   delegates' concrete types are type parameters (see [`ThreadPcodeExecutorState`]), which is
//!   the narrowing Java's overrides exist to express.
//! * **Two languages.** [`PcodeThread::get_language`] hands back the machine's
//!   [`SleighLanguage`], while the executor, decoder, and register lookups bind to a separate
//!   `Arc<dyn Language>` constructor parameter, exactly as [`PcodeExecutor`] does. A
//!   `SleighLanguage` built from a `.sla` alone has no program counter (only a `.pspec` declares
//!   one), which this class requires.
//! * **Context.** The decode context is the real [`RegisterValue`], seeded from a real
//!   [`ProgramContextImpl`] over the language's context settings, and re-read from the state by
//!   [`ThreadCore::re_initialize`]. Advancing it after an instruction
//!   ([`DefaultPcodeThread::advance_after_finished`]) combines the language default, the flow
//!   value, and the decoded instruction's `globalset` commits ([`get_context_after_commits`]). A
//!   language without a context register -- Java's `Register.NO_CONTEXT`, rendered here as
//!   `None` -- has no context at all.
//! * **Exceptions.** Java throws from `stepInstruction`, `executeInstruction`, and friends;
//!   [`PcodeThread`]'s documented Rust rendering is to panic, so a `PcodeExecutionException`
//!   escaping the executor is recorded into [`get_frame`](PcodeThread::get_frame) (as Java does)
//!   and then panics with its message.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::pcode::emu::abstract_pcode_machine::PcodeMachineShared;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::pcode_thread::{ErasedPcodeThread, PcodeThread};
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
    PcodeUserop, UseropInputs, UseropValueKind,
};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor::{PcodeExecutor, PcodeExecutorHooks};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::exec::injection_error_pcode_execution_exception::InjectionErrorPcodeExecutionException;
use crate::pcode::exec::interrupt_pcode_execution_exception::InterruptPcodeExecutionException;
use crate::pcode::exec::suspended_pcode_execution_exception::SuspendedPcodeExecutionException;
use crate::pcode::exec::sleigh_program_compiler;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::util::program_context_impl::ProgramContextImpl;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::PcodeOp;
use crate::program::model::lang::disassembler_context_adapter::DisassemblerContextAdapter;
use crate::util::Msg;

/// A userop library exporting some methods for emulated thread control.
///
/// Port of `DefaultPcodeThread.PcodeEmulationLibrary`.
///
/// Java binds one of these to each thread and calls back into it. A Rust userop callback is an
/// `Fn` stored *inside* the library, which is in turn owned by the thread, so it cannot capture
/// that thread. The two userops that only need the machine -- `emu_swi` and `emu_injection_err` --
/// act on the machine directly. The two that drive the owning thread -- `emu_exec_decoded` and
/// `emu_skip_decoded` -- post a [`ThreadRequest`] to the thread's [`ThreadRequests`], which the
/// thread services as soon as the userop returns, before the next p-code op, exactly where Java's
/// call into the thread would have run. A library bound to no thread (the machine's *stub* library,
/// which only ever needs to declare the userops so Sleigh compiled against it links) panics if one
/// of those two is actually executed, as Java's would dereferencing its `null` thread.
pub struct PcodeEmulationLibrary<T: 'static> {
    base: AnnotatedPcodeUseropLibraryBase<T>,
    machine: Option<Arc<PcodeMachineShared<T>>>,
    thread: Option<Arc<ThreadRequests>>,
}

impl<T: 'static> PcodeEmulationLibrary<T> {
    /// Construct a library controlling the given machine's threads.
    ///
    /// Port of `PcodeEmulationLibrary(DefaultPcodeThread<T>)`, with the machine standing in for the
    /// thread -- see the struct docs. `None` is Java's `new PcodeEmulationLibrary<>(null)`, i.e.
    /// the declaration-only library a machine uses as its thread stub library.
    pub fn new(machine: Option<Arc<PcodeMachineShared<T>>>) -> Self {
        Self::bound(machine, None)
    }

    /// Construct the library of one thread: `requests` is that thread's
    /// [`ThreadCore::thread_requests`], through which `emu_exec_decoded` and `emu_skip_decoded`
    /// drive it. Port of `PcodeEmulationLibrary(DefaultPcodeThread<T>)` for a real thread.
    pub fn for_thread(machine: Arc<PcodeMachineShared<T>>, requests: Arc<ThreadRequests>) -> Self {
        Self::bound(Some(machine), Some(requests))
    }

    fn bound(machine: Option<Arc<PcodeMachineShared<T>>>, thread: Option<Arc<ThreadRequests>>) -> Self {
        let mut library = Self { base: AnnotatedPcodeUseropLibraryBase::new(), machine, thread };
        library.init();
        library
    }

    /// The machine whose threads this library controls, if it is bound to one.
    pub fn machine(&self) -> Option<&Arc<PcodeMachineShared<T>>> {
        self.machine.as_ref()
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for PcodeEmulationLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for PcodeEmulationLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        self.base.get_userops()
    }
}

impl<T: 'static> AnnotatedPcodeUseropLibrary<T> for PcodeEmulationLibrary<T> {
    fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<T> {
        &mut self.base
    }

    fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<T>> {
        let swi_machine = self.machine.clone();
        let exec_thread = self.thread.clone();
        let skip_thread = self.thread.clone();
        let swi_thread = self.thread.clone();
        let err_thread = self.thread.clone();
        vec![
            // Execute the actual machine instruction at the current program counter. Because
            // "injects" override the machine instruction, injects which need to defer to the
            // machine instruction must invoke this userop.
            AnnotatedPcodeUseropDefinition::new(
                "emu_exec_decoded",
                PcodeUserop::default(),
                UseropInputs::Fixed(vec![]),
                UseropValueKind::Void,
                Box::new(move |_ctx, _args| {
                    exec_thread
                        .as_ref()
                        .expect("emu_exec_decoded invoked on a library bound to no thread")
                        .post(ThreadRequest::ExecDecoded);
                    None
                }),
            ),
            // Advance the program counter beyond the current machine instruction, without
            // executing it. Because "injects" override the machine instruction, they must specify
            // the effect on the program counter, lest the thread be caught in an infinite loop on
            // the inject.
            AnnotatedPcodeUseropDefinition::new(
                "emu_skip_decoded",
                PcodeUserop::default(),
                UseropInputs::Fixed(vec![]),
                UseropValueKind::Void,
                Box::new(move |_ctx, _args| {
                    skip_thread
                        .as_ref()
                        .expect("emu_skip_decoded invoked on a library bound to no thread")
                        .post(ThreadRequest::SkipDecoded);
                    None
                }),
            ),
            // Interrupt execution. To implement out-of-band breakpoints, inject an invocation of
            // this userop at the desired address.
            AnnotatedPcodeUseropDefinition::new(
                "emu_swi",
                PcodeUserop { functional: true, ..PcodeUserop::default() },
                UseropInputs::Fixed(vec![]),
                UseropValueKind::Void,
                Box::new(move |_ctx, _args| {
                    let machine = swi_machine
                        .as_ref()
                        .expect("emu_swi invoked on a library bound to no machine");
                    if let Err(e) = machine.swi() {
                        raise(swi_thread.as_deref(), e.message());
                    }
                    None
                }),
            ),
            // Notify the client of a failed Sleigh inject compilation. To avoid pestering the
            // client during emulator set-up, a service may defer notifying the user of Sleigh
            // compilation errors by replacing the erroneous injects with calls to this userop.
            AnnotatedPcodeUseropDefinition::new(
                "emu_injection_err",
                PcodeUserop { functional: true, ..PcodeUserop::default() },
                UseropInputs::Fixed(vec![]),
                UseropValueKind::Void,
                Box::new(move |_ctx, _args| {
                    let e = InjectionErrorPcodeExecutionException::new_without_frame();
                    raise(err_thread.as_deref(), e.message());
                    None
                }),
            ),
        ]
    }
}

/// Throw `message` out of a userop: through the thread, which fails the op with it (so the frame
/// is recorded, as Java records it for any exception escaping an op), or, for a library bound to no
/// thread, as a panic.
fn raise(thread: Option<&ThreadRequests>, message: &str) {
    match thread {
        Some(thread) => thread.post(ThreadRequest::Raise(message.to_string())),
        None => panic!("{message}"),
    }
}

/// Something a userop asked of the thread executing it.
///
/// Java's userops that control a thread call its methods directly (`thread.executeInstruction()`).
/// A Rust userop cannot reach the thread that owns its library (see [`PcodeEmulationLibrary`]), so
/// it posts one of these to the thread's [`ThreadRequests`] instead; the thread services it as
/// soon as the userop returns, before the next op, and an error from servicing fails the userop's
/// op as the Java call would have thrown out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadRequest {
    /// `emu_exec_decoded()`: execute the decoded machine instruction at the counter, as
    /// `thread.dropInstruction(); thread.executeInstruction();` with the frame restored after.
    ExecDecoded,
    /// `emu_skip_decoded()`: advance the counter past the machine instruction without executing
    /// it, as `thread.dropInstruction(); thread.skipInstruction();` with the frame restored after.
    SkipDecoded,
    /// Fail the userop's op with this message: the userop threw. `emu_swi` and
    /// `emu_injection_err` raise their interrupts this way, so the thread records its frame and
    /// can resume after them, as in Java.
    Raise(String),
    /// A request for the thread's [`ThreadHooks`], by name, serviced by
    /// [`ThreadHooks::on_thread_request`]: what a userop of a subclass's library does when Java's
    /// body reaches into the subclass (e.g. `AdaptedEmulator`'s `__addr_cb`).
    Hooks(String),
}

/// The requests posted by the userops of one thread's libraries; see [`ThreadRequest`].
///
/// Shared (by `Arc`) between the thread and the userop callbacks, which are `'static` closures
/// stored in libraries the thread owns.
#[derive(Debug, Default)]
pub struct ThreadRequests {
    pending: Mutex<Vec<ThreadRequest>>,
}

impl ThreadRequests {
    /// Ask the thread to act once the current userop returns.
    pub fn post(&self, request: ThreadRequest) {
        self.pending.lock().expect("thread requests poisoned").push(request);
    }

    /// Take every pending request, in the order posted.
    pub fn take(&self) -> Vec<ThreadRequest> {
        std::mem::take(&mut *self.pending.lock().expect("thread requests poisoned"))
    }
}

/// An executor for a p-code thread.
///
/// Port of `DefaultPcodeThread.PcodeThreadExecutor`.
///
/// Java's subclass checks for thread suspension and updates the program counter register upon
/// execution of (external) branches. Here it wraps the [`PcodeExecutor`] it would otherwise extend
/// and carries the `suspended` flag Java's subclass adds; the overriding behavior is applied by
/// the owning thread, which reaches its own state through a [`PcodeExecutorHooks`] bridge while
/// stepping (see the module docs).
///
/// A further subclass of Java's `PcodeThreadExecutor` -- what a `createExecutor()` override
/// returns, e.g. `SymZ3PcodeThreadExecutor` -- is this type carrying an *extension*: a
/// [`PcodeExecutorHooks`] whose points run inside the thread executor's own, the way a Java
/// subclass does its work and calls `super`. Its `before_*` points run ahead of the thread
/// executor's and its `after_*` points behind them; see [`with_extension`](Self::with_extension).
pub struct PcodeThreadExecutor<T: 'static> {
    /// Java declares this `volatile`, for a thread suspending another that is stepping -- or a
    /// userop or breakpoint suspending its own thread mid-step. The flag is shared with the owning
    /// thread's [`ThreadCore`] (see [`ThreadCore::set_suspended`]), which is how the latter reaches
    /// it while the executor is busy.
    suspended: Arc<AtomicBool>,
    executor: PcodeExecutor<T>,
    /// The executor "subclass", if any. `()` is Java's plain `PcodeThreadExecutor`.
    extension: Box<dyn PcodeExecutorHooks<T>>,
}

impl<T: 'static> PcodeThreadExecutor<T> {
    /// Construct the executor over the bindings a thread supplies.
    ///
    /// Port of `PcodeThreadExecutor(DefaultPcodeThread<T>)`, which reads exactly these three off
    /// the thread. As Java notes, the executor itself is not decoding, so its reads are in fact
    /// data reads: [`Reason::ExecuteRead`].
    pub fn new(
        language: Arc<dyn Language>,
        arithmetic: Arc<dyn PcodeArithmetic<T>>,
        state: Arc<Mutex<dyn PcodeExecutorState<T>>>,
    ) -> Self {
        Self {
            suspended: Arc::new(AtomicBool::new(false)),
            executor: PcodeExecutor::new(language, arithmetic, state, Reason::ExecuteRead),
            extension: Box::new(()),
        }
    }

    /// Construct the executor for the given thread, as Java's constructor does.
    pub fn for_thread<S, L>(thread: &ThreadCore<T, S, L>) -> Self
    where
        S: PcodeExecutorState<T> + 'static,
        L: PcodeExecutorState<T> + 'static,
    {
        Self::new(
            Arc::clone(thread.exec_language()),
            thread.get_arithmetic(),
            thread.state_handle(),
        )
    }

    /// Install an executor extension -- the body of a Java `PcodeThreadExecutor` subclass --
    /// replacing any installed before.
    ///
    /// Its [`before_step_op`](PcodeExecutorHooks::before_step_op), `before_load`, `before_store`,
    /// and [`before_conditional_branch`](PcodeExecutorHooks::before_conditional_branch) run before
    /// the thread executor's own behavior; its `after_*` points and
    /// [`branch_to_address`](PcodeExecutorHooks::branch_to_address) run after it; and its
    /// [`on_missing_userop_def`](PcodeExecutorHooks::on_missing_userop_def) is consulted only when
    /// neither the callbacks nor the thread handled the userop, taking the place of the base
    /// class's link error.
    pub fn with_extension(mut self, extension: Box<dyn PcodeExecutorHooks<T>>) -> Self {
        self.extension = extension;
        self
    }

    /// Whether this executor is refusing to step.
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Set whether this executor refuses to step.
    pub fn set_suspended(&mut self, suspended: bool) {
        self.suspended.store(suspended, Ordering::SeqCst);
    }
}

impl<T: 'static> Deref for PcodeThreadExecutor<T> {
    type Target = PcodeExecutor<T>;

    fn deref(&self) -> &PcodeExecutor<T> {
        &self.executor
    }
}

/// The overridable behavior of a [`DefaultPcodeThread`]: Java's `protected` factory and extension
/// methods, which its subclasses override.
///
/// Every method defaults to `DefaultPcodeThread`'s own behavior, so an implementation overrides
/// only what its Java subclass does. The run-time hooks receive the thread's [`ThreadCore`] in
/// place of Java's `this`; the construction-time `create_*` hooks are called from
/// [`DefaultPcodeThread::new`] in the order Java's constructor calls their counterparts.
///
/// A hooks type standing for a subclass of another subclass holds its parent's hooks and calls
/// them where Java calls `super`.
pub trait ThreadHooks<T: 'static, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    /// Port of `createInstructionDecoder(PcodeExecutorState)`.
    ///
    /// `decoder` is the base class's product -- see the module docs on why it is a constructor
    /// parameter. Return it, or a decoder wrapping it, as Java's overrides do with `super`'s.
    fn create_instruction_decoder(
        &mut self,
        decoder: Box<dyn InstructionDecoder>,
    ) -> Box<dyn InstructionDecoder> {
        decoder
    }

    /// Port of `createUseropLibrary()`.
    ///
    /// `library` is the base class's product: [`PcodeEmulationLibrary`] composed with the
    /// machine's library. Return it, or a composition over it.
    fn create_userop_library(
        &mut self,
        _thread: &ThreadCore<T, S, L>,
        library: Box<dyn PcodeUseropLibrary<T>>,
    ) -> Box<dyn PcodeUseropLibrary<T>> {
        library
    }

    /// Port of `createExecutor()`. The default is Java's `new PcodeThreadExecutor<>(this)`.
    fn create_executor(&mut self, thread: &ThreadCore<T, S, L>) -> PcodeThreadExecutor<T> {
        PcodeThreadExecutor::for_thread(thread)
    }

    /// Port of `preExecuteInstruction()`: extra behavior before executing an instruction.
    ///
    /// Java's base implementation does nothing; it exists for incorporating state modifiers from
    /// the older `Emulator` framework.
    fn pre_execute_instruction(&mut self, _thread: &mut ThreadCore<T, S, L>) {}

    /// Port of `postExecuteInstruction()`: extra behavior after executing an instruction. Java's
    /// base implementation does nothing.
    ///
    /// It is called while the finished instruction's frame and instruction are still current,
    /// as in Java.
    fn post_execute_instruction(&mut self, _thread: &mut ThreadCore<T, S, L>) {}

    /// Port of `onMissingUseropDef(PcodeOp, String)`: behavior when a p-code userop definition is
    /// not found. Returns true if handled, false if still undefined. Java's base implementation
    /// returns false.
    fn on_missing_userop_def(
        &mut self,
        _thread: &mut ThreadCore<T, S, L>,
        _op: &PcodeOp,
        _op_name: &str,
    ) -> bool {
        false
    }

    /// Service a [`ThreadRequest::Hooks`] request, posted by a userop of a library these hooks
    /// installed (see [`create_userop_library`](Self::create_userop_library)). An error fails the
    /// userop's op. The base thread installs no such userops, so the default refuses the request.
    fn on_thread_request(
        &mut self,
        _thread: &mut ThreadCore<T, S, L>,
        request: &str,
    ) -> Result<(), LowlevelError> {
        Err(LowlevelError::with_message(format!("No thread hooks service the request '{request}'")))
    }

    /// Port of `overrideCounter(Address)`: set the counter and write the pc register of the
    /// thread's state. Java's base implementation is [`ThreadCore::write_counter`].
    ///
    /// Every caller of Java's virtual `overrideCounter` -- the public API and `skipInstruction`
    /// alike -- reaches this hook.
    fn override_counter(&mut self, thread: &mut ThreadCore<T, S, L>, counter: &Address) {
        thread.write_counter(counter);
    }
}

/// The hooks of a plain [`DefaultPcodeThread`]: every behavior is the base class's own.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoThreadHooks;

impl<T: 'static, S, L> ThreadHooks<T, S, L> for NoThreadHooks
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
}

/// The state of a [`DefaultPcodeThread`]: everything Java's class keeps in fields, which its
/// subclasses reach as `protected` members.
///
/// This is what a [`ThreadHooks`] method receives in place of Java's `this`. It also stands for
/// the thread in the emulation callbacks fired while the executor is mid-frame; see the module
/// docs.
pub struct ThreadCore<T: 'static, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    name: String,
    machine: Arc<PcodeMachineShared<T>>,
    language: Arc<SleighLanguage>,
    /// The language the executor, decoder, and register lookups bind to. See the module docs.
    exec_language: Arc<dyn Language>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    state: Arc<Mutex<ThreadPcodeExecutorState<T, S, L>>>,
    decoder: Box<dyn InstructionDecoder>,
    pc: RegisterRef,
    /// The language's context register, or `None` for Java's `Register.NO_CONTEXT`.
    contextreg: Option<RegisterRef>,
    counter: Address,
    context: Option<RegisterValue>,
    instruction: Option<Arc<dyn Instruction>>,
    frame: Option<PcodeFrame>,
    default_context: Option<ProgramContextImpl>,
    injects: HashMap<Address, Arc<PcodeProgram>>,
    /// The executor's suspension flag, shared with it; see [`PcodeThreadExecutor`].
    suspended: Arc<AtomicBool>,
    /// What this thread's userops asked of it; see [`ThreadRequest`].
    requests: Arc<ThreadRequests>,
    /// The frame of an instruction executed by `emu_exec_decoded` that failed. Java records it as
    /// the thread's frame on the way out (`frame = e.getFrame()` in `executeInstruction`), where
    /// the enclosing inject's handler must not overwrite it; see [`ThreadCore::settle_frame`].
    nested_frame: Option<PcodeFrame>,
}

impl<T: 'static, S, L> ThreadCore<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    /// Get the name of this thread. Port of `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Whether the thread's executor is refusing to step. Port of `isSuspended()`, reachable while
    /// the executor is mid-step.
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Set whether the thread's executor refuses to step. Port of `setSuspended(boolean)`,
    /// reachable while the executor is mid-step (e.g. from a breakpoint), when Java's `volatile`
    /// write is seen by the executor's very next op.
    pub fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Ordering::SeqCst);
    }

    /// The channel through which the userops of this thread's libraries drive it. A hooks type
    /// installing a library of its own (see [`ThreadHooks::create_userop_library`]) gives it this
    /// to post [`ThreadRequest::Hooks`] requests.
    pub fn thread_requests(&self) -> &Arc<ThreadRequests> {
        &self.requests
    }

    /// Settle the frame after a failed step: the frame of a failed nested instruction (see
    /// `nested_frame`) wins over `frame`, the one the failing call itself was running.
    fn settle_frame(&mut self, frame: Option<PcodeFrame>) {
        self.frame = self.nested_frame.take().or(frame);
    }

    /// The machine this thread executes within, as its threads share it. Port of the `machine`
    /// field.
    pub fn machine(&self) -> &Arc<PcodeMachineShared<T>> {
        &self.machine
    }

    /// The thread's Sleigh language. Port of the `language` field.
    pub fn get_language(&self) -> &SleighLanguage {
        &self.language
    }

    /// The language bound to this thread's executor and decoder. See the module docs.
    pub fn exec_language(&self) -> &Arc<dyn Language> {
        &self.exec_language
    }

    /// The thread's arithmetic. Port of the `arithmetic` field.
    pub fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    /// A handle to this thread's multiplexed state, as the executor holds it.
    pub fn state_handle(&self) -> Arc<Mutex<dyn PcodeExecutorState<T>>> {
        self.state.clone()
    }

    /// A handle to this thread's multiplexed state, typed: the same state the executor holds
    /// through [`state_handle`](Self::state_handle). An executor extension (see
    /// [`PcodeThreadExecutor::with_extension`]) keeps one to reach the state's delegates, as a Java
    /// `PcodeThreadExecutor` subclass does through `getThread().getState()`.
    pub fn typed_state_handle(&self) -> Arc<Mutex<ThreadPcodeExecutorState<T, S, L>>> {
        Arc::clone(&self.state)
    }

    /// This thread's multiplexed state, typed. Port of the `state` field.
    pub fn get_state(&self) -> MutexGuard<'_, ThreadPcodeExecutorState<T, S, L>> {
        self.state.lock().expect("thread state lock poisoned")
    }

    /// This thread's instruction decoder. Port of the `decoder` field.
    pub fn decoder(&self) -> &dyn InstructionDecoder {
        self.decoder.as_ref()
    }

    /// This thread's instruction decoder, for writing.
    pub fn decoder_mut(&mut self) -> &mut dyn InstructionDecoder {
        self.decoder.as_mut()
    }

    /// The program counter register. Port of the `pc` field.
    pub fn program_counter(&self) -> &RegisterRef {
        &self.pc
    }

    /// Get the value of the program counter of this thread. Port of `getCounter()`.
    pub fn get_counter(&self) -> Address {
        self.counter.clone()
    }

    /// Set the counter without writing the state. Port of `setCounter(Address)`.
    pub fn set_counter(&mut self, counter: &Address) {
        self.counter = counter.clone();
    }

    /// The thread's decoding context. Port of `getContext()`.
    pub fn get_context(&self) -> Option<&RegisterValue> {
        self.context.as_ref()
    }

    /// The current frame, if present. Port of the `frame` field.
    pub fn get_frame(&self) -> Option<&PcodeFrame> {
        self.frame.as_ref()
    }

    /// The instruction being executed, if any. Port of the `instruction` field.
    pub fn get_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.instruction.clone()
    }

    /// Port of `branchToAddress(Address)`: write the counter and tell the decoder we branched.
    pub fn branch_to_address(&mut self, target: &Address) {
        self.write_counter(target);
        let counter = self.counter.clone();
        self.decoder.branched(&counter);
    }

    /// Port of the final `writeCounter(Address)`: set the counter *and* write the pc register of
    /// this thread's state.
    pub fn write_counter(&mut self, counter: &Address) {
        self.counter = counter.clone();
        let size = self.pc.minimum_byte_size();
        let value = self
            .arithmetic
            .from_const_u64(counter.addressable_word_offset() as u64, size);
        self.state
            .lock()
            .expect("thread state lock poisoned")
            .set_var_register(&self.pc, &value);
    }

    /// Port of the final `writeContext(RegisterValue)`: adjust the context and write the contextreg
    /// of this thread's state.
    pub fn write_context(&mut self, context: Option<&RegisterValue>) {
        if self.contextreg.is_none() && context.is_none() {
            return;
        }
        let context = context.expect("context must be the contextreg value");
        self.assign_context(context);
        let Some(current) = self.context.as_ref() else {
            debug_assert!(self.contextreg.is_none());
            return;
        };
        let contextreg = self
            .contextreg
            .clone()
            .expect("a context value implies a context register");
        let size = contextreg.minimum_byte_size();
        let value = self.arithmetic.from_const_big_int(
            current.unsigned_value_ignore_mask() as i128,
            size,
            true,
        );
        self.state
            .lock()
            .expect("thread state lock poisoned")
            .set_var_register(&contextreg, &value);
    }

    /// Port of `assignContext(RegisterValue)`.
    ///
    /// # Panics
    ///
    /// If the value is not the contextreg's, as Java throws `IllegalArgumentException`.
    pub fn assign_context(&mut self, context: &RegisterValue) {
        let register = context.register();
        let base = register.get_base_register();
        let is_contextreg = match &self.contextreg {
            Some(contextreg) => same_register(&base, contextreg),
            // `None` is Java's `Register.NO_CONTEXT`, which only a NO_CONTEXT value matches.
            None => base.name() == "NO_CONTEXT",
        };
        assert!(is_contextreg, "context must be the contextreg value");
        let Some(current) = self.context.as_ref() else {
            // Java asserts contextreg == NO_CONTEXT and returns, leaving the context null.
            debug_assert!(self.contextreg.is_none());
            return;
        };
        self.context = Some(current.assign(&register, context));
    }

    /// Port of `overrideContextWithDefault()`.
    pub fn override_context_with_default(&mut self) {
        let (Some(contextreg), Some(default_context)) =
            (self.contextreg.clone(), self.default_context.as_ref())
        else {
            return;
        };
        let default_value =
            DefaultProgramContext::get_default_value(default_context, &contextreg, &self.counter);
        if let Some(default_value) = default_value {
            self.write_context(Some(&default_value));
        }
    }

    /// Port of `doPluggableInitialization()`: execute the machine's initializer upon this thread,
    /// if applicable.
    #[deprecated(note = "Java marks the initializer mechanism for removal since 12.0")]
    pub fn do_pluggable_initialization(&self) {
        if let Some(initializer) = self.machine.initializer.clone() {
            initializer.initialize_thread(self);
        }
    }

    /// Port of `reInitialize()`: re-sync the counter and decode context from the machine state.
    pub fn re_initialize(&mut self) {
        let value = self
            .state
            .lock()
            .expect("thread state lock poisoned")
            .get_var_register(&self.pc, Reason::ReInit);
        let offset = self
            .arithmetic
            .to_long(&value, Purpose::Branch)
            .unwrap_or_else(|e| panic!("{e}"));
        self.counter = self
            .exec_language
            .get_default_space()
            .address_from_word_offset(offset)
            .unwrap_or_else(|e| panic!("{e:?}"));

        if let Some(contextreg) = self.contextreg.clone() {
            // Java catches an `AccessPcodeExecutionException` from `getVar` here ("contextreg not
            // recorded in trace"); state reads in this port do not report access failures, so the
            // value read is always assigned.
            let value = self
                .state
                .lock()
                .expect("thread state lock poisoned")
                .get_var_register(&contextreg, Reason::ReInit);
            let ctx = self
                .arithmetic
                .to_big_integer(&value, Purpose::Context)
                .unwrap_or_else(|e| panic!("{e}"));
            self.assign_context(&RegisterValue::with_value(contextreg, ctx as u128));
        }

        #[allow(deprecated)]
        self.do_pluggable_initialization();
    }

    /// Port of `assertCompletedInstruction()`: cannot start a new instruction while one is still
    /// being executed.
    ///
    /// # Panics
    ///
    /// If a frame is present, as Java throws `IllegalStateException`.
    pub fn assert_completed_instruction(&self) {
        assert!(
            self.frame.is_none(),
            "The current instruction or inject has not finished."
        );
    }

    /// Port of `assertMidInstruction()`: cannot finish an instruction unless one is currently being
    /// executed.
    ///
    /// # Panics
    ///
    /// If no frame is present, as Java throws `IllegalStateException`.
    pub fn assert_mid_instruction(&self) {
        assert!(self.frame.is_some(), "There is no current instruction to finish.");
    }

    /// Port of `getInject(Address)`: check the callbacks, then this thread's injects, then the
    /// machine's.
    ///
    /// Java hands back a bare `PcodeProgram` reference; every source holds a shared handle here.
    pub fn get_inject(&self, address: &Address) -> Option<Arc<PcodeProgram>> {
        if let Some(inject) = self.machine.callbacks().get_inject(self, address) {
            return Some(inject);
        }
        if let Some(inject) = self.injects.get(address) {
            return Some(Arc::clone(inject));
        }
        self.machine.get_inject(address)
    }

    /// Record the given compiled p-code as this thread's inject at the given address, replacing any
    /// inject already there. This is Java's `injects.put(address, pcode)`, which
    /// [`inject`](PcodeThread::inject) reaches only after compiling the source.
    pub fn put_inject(&mut self, address: Address, pcode: Arc<PcodeProgram>) {
        self.injects.insert(address, pcode);
    }

    /// Port of `checkLoad(AddressSpace, T, int)`: perform checks on a requested `LOAD`, returning
    /// the interrupt it should cause, if any.
    pub fn check_load(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.check_load(space, offset, size)
    }

    /// Port of `checkStore(AddressSpace, T, int)`: perform checks on a requested `STORE`, returning
    /// the interrupt it should cause, if any.
    pub fn check_store(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.check_store(space, offset, size)
    }

    /// Port of `swi()`: return a software interrupt if those interrupts are active.
    pub fn swi(&self) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.swi()
    }

    /// Port of `stepped()`: notify the machine a thread has stepped a p-code op, so that it may
    /// re-enable software interrupts, if applicable.
    pub fn stepped(&self) {
        self.machine.stepped();
    }

    /// Decode the instruction at the given address into [`instruction`](Self::get_instruction),
    /// which is Java's `instruction = decoder.decodeInstruction(counter, context)`.
    ///
    /// This crate's decoder hands back a `PseudoInstruction`, which is not (yet) an
    /// [`Instruction`], so the decoded instruction is recovered from the decoder itself.
    fn decode_instruction(&mut self, address: &Address) {
        let context = self.context.as_ref();
        self.decoder
            .decode_instruction(address, context)
            .unwrap_or_else(|e| panic!("{e}"));
        self.instruction = self.decoder.get_last_instruction();
    }

    /// The instruction just decoded. Java's decoder "cannot return null."
    fn require_instruction(&self) -> Arc<dyn Instruction> {
        self.instruction
            .clone()
            .expect("decoder reported no instruction")
    }
}

/// The core stands for its thread in the emulation callbacks fired while the executor is
/// mid-frame. It cannot step itself -- the executor that would do so is busy -- so the type-erased
/// stepping methods keep their panicking defaults.
impl<T: 'static, S, L> ErasedPcodeThread for ThreadCore<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
}

/// The overrides of Java's `PcodeThreadExecutor`, applied while a thread steps its executor.
///
/// Built afresh for each call into the executor from the thread's disjoint parts: its core, its
/// hooks, and its executor's extension (the executor "subclass"). See [`PcodeThreadExecutor`] for
/// the order in which the extension's points run relative to these.
struct ThreadExecutorBridge<'a, T: 'static, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    core: &'a mut ThreadCore<T, S, L>,
    hooks: &'a mut H,
    extension: &'a mut dyn PcodeExecutorHooks<T>,
}

/// Carry an interrupt out of an executor hook, which reports errors as [`LowlevelError`]s.
fn interrupt_error(e: InterruptPcodeExecutionException) -> LowlevelError {
    LowlevelError::with_message(e.message().to_string())
}

impl<T: 'static, S, L, H> PcodeExecutorHooks<T> for ThreadExecutorBridge<'_, T, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    fn before_step_op(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        frame: &PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.extension.before_step_op(executor, op, frame)?;
        if self.core.is_suspended() || self.core.machine.is_suspended() {
            // Java: `throw new SuspendedPcodeExecutionException(frame, null)`.
            return Err(LowlevelError::with_message(
                SuspendedPcodeExecutionException::new(frame.clone()).message().to_string(),
            ));
        }
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.before_step_op(&*self.core, op, frame);
        Ok(())
    }

    fn after_step_op(&mut self, executor: &PcodeExecutor<T>, op: &PcodeOp, frame: &PcodeFrame) {
        self.core.stepped();
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.after_step_op(&*self.core, op, frame);
        self.extension.after_step_op(executor, op, frame);
    }

    fn before_load(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), LowlevelError> {
        self.extension.before_load(executor, op, space, offset, size)?;
        self.core.check_load(space, offset, size).map_err(interrupt_error)?;
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.before_load(&*self.core, op, space, offset, size);
        Ok(())
    }

    fn after_load(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
        value: &T,
    ) {
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.after_load(&*self.core, op, space, offset, size, value);
        self.extension.after_load(executor, op, space, offset, size, value);
    }

    fn before_store(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
        value: &T,
    ) -> Result<(), LowlevelError> {
        self.extension.before_store(executor, op, space, offset, size, value)?;
        self.core.check_store(space, offset, size).map_err(interrupt_error)?;
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.before_store(&*self.core, op, space, offset, size, value);
        Ok(())
    }

    fn after_store(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
        value: &T,
    ) {
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.after_store(&*self.core, op, space, offset, size, value);
        self.extension.after_store(executor, op, space, offset, size, value);
    }

    fn branch_to_address(&mut self, executor: &PcodeExecutor<T>, op: &PcodeOp, target: &Address) {
        self.core.branch_to_address(target);
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.after_branch(&*self.core, op, target);
        self.extension.branch_to_address(executor, op, target);
    }

    fn before_conditional_branch(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        frame: &PcodeFrame,
    ) -> Result<(), LowlevelError> {
        self.extension.before_conditional_branch(executor, op, frame)
    }

    /// Service what the userop asked of this thread (see [`ThreadRequest`]), then the extension's
    /// own advice.
    fn after_userop(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        frame: &PcodeFrame,
        op_name: &str,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        for request in self.core.requests.take() {
            match request {
                ThreadRequest::ExecDecoded => self.exec_decoded(executor, library)?,
                ThreadRequest::SkipDecoded => self.skip_decoded(),
                ThreadRequest::Raise(message) => return Err(LowlevelError::with_message(message)),
                ThreadRequest::Hooks(name) => self.hooks.on_thread_request(self.core, &name)?,
            }
        }
        self.extension.after_userop(executor, op, frame, op_name, library)
    }

    fn on_missing_userop_def(
        &mut self,
        executor: &PcodeExecutor<T>,
        op: &PcodeOp,
        frame: &PcodeFrame,
        op_name: &str,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        let cb = Arc::clone(self.core.machine.callbacks());
        if cb.handle_missing_userop(&*self.core, op, frame, op_name, library) {
            return Ok(());
        }
        if self.hooks.on_missing_userop_def(self.core, op, op_name) {
            return Ok(());
        }
        self.extension.on_missing_userop_def(executor, op, frame, op_name, library)
    }
}

impl<T: 'static, S, L, H> ThreadExecutorBridge<'_, T, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    /// The body of `PcodeEmulationLibrary.emu_exec_decoded()`: set the current frame aside,
    /// execute the decoded instruction at the counter (Java's `executeInstruction()`, run through
    /// this same bridge), then restore the frame. As in Java, the frame is restored only on
    /// success; a failure leaves the instruction's own frame to be recorded (see
    /// [`ThreadCore::settle_frame`]).
    fn exec_decoded(
        &mut self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), LowlevelError> {
        let saved = self.core.frame.take();
        let cb = Arc::clone(self.core.machine.callbacks());
        let counter = self.core.counter.clone();
        cb.before_decode_instruction(&*self.core, &counter, self.core.context.as_ref());
        self.core.decode_instruction(&counter);
        let instruction = self.core.require_instruction();
        let ins_prog = PcodeProgram::from_instruction(instruction.as_ref());
        self.hooks.pre_execute_instruction(self.core);
        cb.before_execute_instruction(&*self.core, instruction.as_ref(), &ins_prog);
        match executor.execute_hooked(&ins_prog, library, self) {
            Ok(frame) => self.core.frame = Some(frame),
            Err(e) => {
                let message = e.message().to_string();
                self.core.nested_frame = e.into_frame().map(|frame| *frame);
                return Err(LowlevelError::with_message(message));
            }
        }
        advance_after_finished(self.core, self.hooks);
        self.core.frame = saved;
        Ok(())
    }

    /// The body of `PcodeEmulationLibrary.emu_skip_decoded()`: set the current frame aside, skip
    /// the decoded instruction at the counter (Java's `skipInstruction()`), then restore the frame.
    fn skip_decoded(&mut self) {
        let saved = self.core.frame.take();
        let cb = Arc::clone(self.core.machine.callbacks());
        let counter = self.core.counter.clone();
        cb.before_decode_instruction(&*self.core, &counter, self.core.context.as_ref());
        self.core.decode_instruction(&counter);
        let advanced = counter.add_wrap(self.core.decoder.get_last_length_with_delays() as i64);
        self.hooks.override_counter(self.core, &advanced);
        self.core.frame = saved;
    }
}

/// The default implementation of [`PcodeThread`], suitable for most applications.
///
/// `T` is the type of variables in the emulator, `S` the concrete type of the machine's shared
/// (memory) state, and `L` that of this thread's local (register/unique) state -- see
/// [`ThreadPcodeExecutorState`] on why the delegates are named rather than boxed. `H` carries the
/// overrides of whichever Java subclass this thread stands for; see [`ThreadHooks`].
pub struct DefaultPcodeThread<T: 'static, S, L, H = NoThreadHooks>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    core: ThreadCore<T, S, L>,
    executor: PcodeThreadExecutor<T>,
    library: Box<dyn PcodeUseropLibrary<T>>,
    hooks: H,
}

impl<T: 'static, S, L, H> DefaultPcodeThread<T, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    /// Construct a new thread.
    ///
    /// Port of `DefaultPcodeThread(String, AbstractPcodeMachine<T>)`, with `machine` the handle a
    /// machine's threads hold on it (see the module docs). `shared_state` and
    /// `local_state` are what Java reads from `machine.getSharedState()` and
    /// `machine.createLocalState(this)`, `decoder` is the base product of
    /// `createInstructionDecoder`, and `exec_language` is the machine's language as a
    /// [`Language`]; see the module docs on why all four are parameters. `hooks` carries the
    /// subclass's overrides; its construction-time hooks are called here, in Java's order.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as Java's `Objects.requireNonNull` throws.
    pub fn new(
        name: impl Into<String>,
        machine: Arc<PcodeMachineShared<T>>,
        exec_language: Arc<dyn Language>,
        shared_state: S,
        local_state: L,
        decoder: Box<dyn InstructionDecoder>,
        mut hooks: H,
    ) -> Self {
        let language = Arc::clone(machine.language());
        let arithmetic = machine.get_arithmetic();
        let state = Arc::new(Mutex::new(ThreadPcodeExecutorState::new(shared_state, local_state)));
        let decoder = hooks.create_instruction_decoder(decoder);
        let pc = exec_language
            .get_program_counter()
            .expect("Language has no program counter");
        let contextreg = context_base_register(exec_language.as_ref());

        // Java: if the language has a context register, build its default context store and seed
        // the thread's context from it.
        let (default_context, context) = match &contextreg {
            Some(_) => {
                let mut default_context = ProgramContextImpl::new(Arc::clone(&exec_language));
                exec_language.apply_context_settings(&mut default_context);
                let context = default_context.get_default_disassembly_context();
                (Some(default_context), Some(context))
            }
            None => (None, None),
        };

        let core = ThreadCore {
            name: name.into(),
            machine,
            language,
            // Java's counter is null until reInitialize(); an Address cannot be, so it starts at
            // the base of the default space and is immediately overwritten below.
            counter: exec_language.get_default_space().address(0),
            exec_language,
            arithmetic,
            state,
            decoder,
            pc,
            contextreg,
            context,
            instruction: None,
            frame: None,
            default_context,
            injects: HashMap::new(),
            suspended: Arc::new(AtomicBool::new(false)),
            requests: Arc::new(ThreadRequests::default()),
            nested_frame: None,
        };

        // Java's default `createUseropLibrary()`.
        let base_library =
            PcodeEmulationLibrary::for_thread(Arc::clone(&core.machine), Arc::clone(&core.requests))
                .compose(core.machine.get_userop_library());
        let library = hooks.create_userop_library(&core, base_library);
        let mut executor = hooks.create_executor(&core);
        executor.suspended = Arc::clone(&core.suspended);

        let mut thread = Self { core, executor, library, hooks };
        thread.core.re_initialize();
        thread
    }

    /// This thread's state, as its hooks see it.
    pub fn core(&self) -> &ThreadCore<T, S, L> {
        &self.core
    }

    /// This thread's state, as its hooks see it, for writing.
    pub fn core_mut(&mut self) -> &mut ThreadCore<T, S, L> {
        &mut self.core
    }

    /// The overrides this thread was built with.
    pub fn hooks(&self) -> &H {
        &self.hooks
    }

    /// The overrides this thread was built with, for writing.
    pub fn hooks_mut(&mut self) -> &mut H {
        &mut self.hooks
    }

    /// The language bound to this thread's executor and decoder. See the module docs.
    pub fn exec_language(&self) -> &Arc<dyn Language> {
        self.core.exec_language()
    }

    /// A handle to this thread's multiplexed state, as the executor holds it.
    pub fn state_handle(&self) -> Arc<Mutex<dyn PcodeExecutorState<T>>> {
        self.core.state_handle()
    }

    /// This thread's executor, including the suspension flag Java's `PcodeThreadExecutor` adds.
    pub fn thread_executor(&self) -> &PcodeThreadExecutor<T> {
        &self.executor
    }

    /// Port of `branchToAddress(Address)`: write the counter and tell the decoder we branched.
    pub fn branch_to_address(&mut self, target: &Address) {
        self.core.branch_to_address(target);
    }

    /// Port of the final `writeCounter(Address)`. See [`ThreadCore::write_counter`].
    pub fn write_counter(&mut self, counter: &Address) {
        self.core.write_counter(counter);
    }

    /// Port of the final `writeContext(RegisterValue)`. See [`ThreadCore::write_context`].
    pub fn write_context(&mut self, context: Option<&RegisterValue>) {
        self.core.write_context(context);
    }

    /// Port of `assertCompletedInstruction()`. See [`ThreadCore::assert_completed_instruction`].
    pub fn assert_completed_instruction(&self) {
        self.core.assert_completed_instruction();
    }

    /// Port of `assertMidInstruction()`. See [`ThreadCore::assert_mid_instruction`].
    pub fn assert_mid_instruction(&self) {
        self.core.assert_mid_instruction();
    }

    /// Port of `getInject(Address)`. See [`ThreadCore::get_inject`].
    pub fn get_inject(&self, address: &Address) -> Option<Arc<PcodeProgram>> {
        self.core.get_inject(address)
    }

    /// Record the given compiled p-code as this thread's inject. See [`ThreadCore::put_inject`].
    pub fn put_inject(&mut self, address: Address, pcode: Arc<PcodeProgram>) {
        self.core.put_inject(address, pcode);
    }

    /// Port of `checkLoad(AddressSpace, T, int)`. See [`ThreadCore::check_load`].
    pub fn check_load(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.core.check_load(space, offset, size)
    }

    /// Port of `checkStore(AddressSpace, T, int)`. See [`ThreadCore::check_store`].
    pub fn check_store(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.core.check_store(space, offset, size)
    }

    /// Port of `swi()`. See [`ThreadCore::swi`].
    pub fn swi(&self) -> Result<(), InterruptPcodeExecutionException> {
        self.core.swi()
    }

    /// Port of `stepped()`. See [`ThreadCore::stepped`].
    pub fn stepped(&self) {
        self.core.stepped();
    }

    /// Port of `beginInstructionOrInject()`: start execution of the instruction or inject at the
    /// program counter.
    pub fn begin_instruction_or_inject(&mut self) {
        let counter = self.core.counter.clone();
        match self.core.get_inject(&counter) {
            Some(inject) => {
                self.core.instruction = None;
                self.core.frame = Some(self.executor.begin(&inject));
            }
            None => {
                self.core.decode_instruction(&counter);
                let instruction = self.core.require_instruction();
                let pcode = PcodeProgram::from_instruction(instruction.as_ref());
                self.core.frame = Some(self.executor.begin(&pcode));
            }
        }
    }

    /// Port of `advanceAfterFinished()`: resolve a finished instruction, advancing the program
    /// counter if necessary.
    pub fn advance_after_finished(&mut self) {
        advance_after_finished(&mut self.core, &mut self.hooks);
    }

    /// Run `f` against the executor, with this thread's executor overrides bridged in. This is
    /// every entry into Java's `PcodeThreadExecutor`.
    fn with_executor<R>(
        &mut self,
        f: impl FnOnce(
            &PcodeExecutor<T>,
            &dyn PcodeUseropLibrary<T>,
            &mut dyn PcodeExecutorHooks<T>,
        ) -> R,
    ) -> R {
        let Self { core, executor, library, hooks } = self;
        let mut bridge = ThreadExecutorBridge { core, hooks, extension: executor.extension.as_mut() };
        f(&executor.executor, library.as_ref(), &mut bridge)
    }

    /// Run the executor over `program` to completion, through the bridged executor.
    fn execute_program(
        &mut self,
        program: &PcodeProgram,
    ) -> Result<PcodeFrame, PcodeExecutionException> {
        self.with_executor(|executor, library, hooks| executor.execute_hooked(program, library, hooks))
    }

    /// Record the frame of a failed execution as Java does (`frame = e.getFrame()`), then rethrow.
    fn record_and_rethrow(&mut self, e: PcodeExecutionException) -> ! {
        let message = e.message().to_string();
        self.core.settle_frame(e.into_frame().map(|frame| *frame));
        panic!("{message}");
    }
}

/// Port of `advanceAfterFinished()` over a thread's disjoint parts, so the thread and a nested
/// `emu_exec_decoded` (which runs while the executor is busy) share it. The core stands for the
/// thread in the callbacks, as it does in every callback fired mid-step.
fn advance_after_finished<T: 'static, S, L, H>(core: &mut ThreadCore<T, S, L>, hooks: &mut H)
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    let cb = Arc::clone(core.machine.callbacks());
    let counter = core.counter.clone();
    let Some(instruction) = core.instruction.clone() else {
        // The frame resulted from an inject.
        cb.after_execute_inject(&*core, &counter);
        core.frame = None;
        return;
    };
    if core.frame.as_ref().is_some_and(PcodeFrame::is_fall_through) {
        let advanced =
            counter.add_wrap(core.decoder.get_last_length_with_delays() as i64);
        core.write_counter(&advanced);
    }
    if let Some(contextreg) = core.contextreg.clone() {
        let counter = core.counter.clone();
        let default_context =
            core.default_context.as_ref().expect("a context register implies a default context");
        let mut ctx = RegisterValue::with_value(contextreg.clone(), 0);
        if let Some(default_value) =
            DefaultProgramContext::get_default_value(default_context, &contextreg, &counter)
        {
            ctx = ctx.combine_values(&default_value);
        }
        if let Some(context) = core.context.clone() {
            ctx = ctx.combine_values(&ProgramContext::get_flow_value(default_context, context));
        }
        if let Some(committed) = get_context_after_commits(instruction.as_ref(), counter.offset()) {
            ctx = ctx.combine_values(&committed);
        }
        core.write_context(Some(&ctx));
    }
    hooks.post_execute_instruction(core);
    cb.after_execute_instruction(&*core, instruction.as_ref());
    core.frame = None;
    core.instruction = None;
}

/// Port of the static `getContextAfterCommits(Instruction, long)`: the context the decoded
/// instruction's constructors committed (`globalset`) at the given counter.
///
/// Java casts the instruction to `PseudoInstruction` and applies the commits of its cached
/// `SleighParserContext` to a `DisassemblerContextAdapter` collecting the processor-context values
/// placed at the counter (or at the instruction itself). Here the parser context is rebuilt from the
/// instruction's prototype, bytes, and input context, which re-applies the same constructor context
/// changes and so records the same commits. Returns `None` for a language without a context
/// register, or an instruction whose prototype is not Sleigh's (neither has commits to apply).
///
/// # Panics
///
/// If the instruction's bytes cannot be re-read, as Java throws `AssertionError`.
pub fn get_context_after_commits(instruction: &dyn Instruction, counter: i64) -> Option<RegisterValue> {
    use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::lang::processor_context_view::ProcessorContextView;

    let prototype = instruction.get_prototype();
    let contextreg = prototype.get_language().get_context_base_register()?;
    let buf: &dyn MemBuffer = instruction;
    let view: &dyn ProcessorContextView = instruction;
    let parser_ctx = prototype
        .get_parser_context(buf, view)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let parser_ctx = parser_ctx.as_any()?.downcast_ref::<SleighParserContext>()?;
    let mut collector = CommitCollector {
        ctx_val: RegisterValue::new(contextreg),
        counter,
        instruction_address: instruction.get_min_address(),
    };
    parser_ctx
        .apply_commits(&mut collector, &RegisterValueFromBytes)
        .unwrap_or_else(|e| panic!("{e}"));
    Some(collector.ctx_val)
}

/// Builds the `RegisterValue`s context commits produce: Java's `new RegisterValue(register, bytes)`.
pub(crate) struct RegisterValueFromBytes;

impl crate::app::seam_stubs::RegisterValueBuilder for RegisterValueFromBytes {
    fn build_register_value(&self, register: RegisterRef, bytes: Vec<u8>) -> RegisterValue {
        RegisterValue::from_bytes(register, &bytes)
    }
}

/// The anonymous `DisassemblerContextAdapter` of `getContextAfterCommits`: it keeps only the
/// processor-context values committed at the counter (or the instruction's own address).
struct CommitCollector {
    ctx_val: RegisterValue,
    counter: i64,
    instruction_address: Address,
}

impl crate::program::model::lang::processor_context_view::ProcessorContextView for CommitCollector {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_base_context_register(self)
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_registers(self)
    }
    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        <Self as DisassemblerContextAdapter>::get_register(self, name)
    }
    fn get_value(&self, register: &crate::program::model::lang::register::Register, signed: bool) -> Option<i128> {
        <Self as DisassemblerContextAdapter>::get_value(self, register, signed)
    }
    fn get_register_value(&self, register: &crate::program::model::lang::register::Register) -> Option<RegisterValue> {
        <Self as DisassemblerContextAdapter>::get_register_value(self, register)
    }
    fn has_value(&self, register: &crate::program::model::lang::register::Register) -> bool {
        <Self as DisassemblerContextAdapter>::has_value(self, register)
    }
}

impl crate::program::model::lang::processor_context::ProcessorContext for CommitCollector {
    fn set_value(
        &mut self,
        register: &crate::program::model::lang::register::Register,
        value: i128,
    ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
        <Self as DisassemblerContextAdapter>::set_value(self, register, value)
    }
    fn set_register_value(
        &mut self,
        value: RegisterValue,
    ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
        <Self as DisassemblerContextAdapter>::set_register_value(self, value)
    }
    fn clear_register(
        &mut self,
        register: &crate::program::model::lang::register::Register,
    ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
        <Self as DisassemblerContextAdapter>::clear_register(self, register)
    }
}

impl crate::program::model::lang::disassembler_context::DisassemblerContext for CommitCollector {
    fn set_future_register_value(&mut self, address: Address, value: RegisterValue) {
        <Self as DisassemblerContextAdapter>::set_future_register_value(self, address, value)
    }
    fn set_future_register_value_for_flow(&mut self, from_addr: Address, to_addr: Address, value: RegisterValue) {
        <Self as DisassemblerContextAdapter>::set_future_register_value_for_flow(self, from_addr, to_addr, value)
    }
}

impl DisassemblerContextAdapter for CommitCollector {
    fn set_future_register_value(&mut self, address: Address, value: RegisterValue) {
        let register = value.register();
        if !register.is_processor_context() {
            return;
        }
        if address.offset() != self.counter && address != self.instruction_address {
            Msg::warn("DefaultPcodeThread", &"Context applied somewhere other than the counter.");
            return;
        }
        self.ctx_val = self.ctx_val.assign(&register, &value);
    }
}

/// Whether two register handles denote the same register. Java compares `Register` identity; these
/// are separately built handles, so they are compared by where they live.
fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    let (a, b) = (a, b);
    a.name() == b.name() && a.address() == b.address() && a.num_bytes() == b.num_bytes()
}

/// The language's context base register, mapping Java's `Register.NO_CONTEXT` sentinel onto `None`
/// so callers have one "no context" case rather than two.
fn context_base_register(language: &dyn Language) -> Option<RegisterRef> {
    let contextreg = language.get_context_base_register()?;
    let is_no_context = contextreg.name() == "NO_CONTEXT";
    (!is_no_context).then_some(contextreg)
}

impl<T: 'static, S, L, H> ErasedPcodeThread for DefaultPcodeThread<T, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    fn erased_step_instruction(&mut self) {
        <Self as PcodeThread<T>>::step_instruction(self);
    }

    fn erased_skip_instruction(&mut self) {
        <Self as PcodeThread<T>>::skip_instruction(self);
    }

    fn erased_step_pcode_op(&mut self) {
        <Self as PcodeThread<T>>::step_pcode_op(self);
    }

    fn erased_skip_pcode_op(&mut self) {
        <Self as PcodeThread<T>>::skip_pcode_op(self);
    }
}

impl<T: 'static, S, L, H> PcodeThread<T> for DefaultPcodeThread<T, S, L, H>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
    H: ThreadHooks<T, S, L>,
{
    type SharedState = S;
    type LocalState = L;

    fn get_name(&self) -> &str {
        self.core.get_name()
    }

    fn get_machine(&self) -> &PcodeMachineShared<T> {
        &self.core.machine
    }

    fn set_counter(&mut self, counter: &Address) {
        self.core.set_counter(counter);
    }

    fn get_counter(&self) -> Address {
        self.core.get_counter()
    }

    fn override_counter(&mut self, counter: &Address) {
        self.hooks.override_counter(&mut self.core, counter);
    }

    fn assign_context(&mut self, context: &RegisterValue) {
        self.core.assign_context(context);
    }

    fn get_context(&self) -> Option<&RegisterValue> {
        self.core.get_context()
    }

    fn override_context(&mut self, context: &RegisterValue) {
        self.core.write_context(Some(context));
    }

    fn override_context_with_default(&mut self) {
        self.core.override_context_with_default();
    }

    fn re_initialize(&mut self) {
        self.core.re_initialize();
    }

    fn step_instruction(&mut self) {
        self.core.assert_completed_instruction();
        let counter = self.core.counter.clone();
        let Some(inject) = self.core.get_inject(&counter) else {
            self.execute_instruction();
            return;
        };
        self.core.instruction = None;
        let cb = Arc::clone(self.core.machine.callbacks());
        cb.before_execute_inject(&*self, &counter, &inject);
        if let Err(e) = self.execute_program(&inject) {
            self.record_and_rethrow(e);
        }
        cb.after_execute_inject(&*self, &counter);
    }

    fn step_pcode_op(&mut self) {
        let Some(mut frame) = self.core.frame.take() else {
            self.begin_instruction_or_inject();
            return;
        };
        if frame.is_finished() {
            self.core.frame = Some(frame);
            self.advance_after_finished();
            return;
        }
        let result =
            self.with_executor(|executor, library, hooks| executor.step_hooked(&mut frame, library, hooks));
        match result {
            Ok(()) => self.core.frame = Some(frame),
            Err(e) => {
                self.core.settle_frame(Some(frame));
                panic!("{}", e.message());
            }
        }
    }

    fn skip_pcode_op(&mut self) {
        let Some(mut frame) = self.core.frame.take() else {
            self.begin_instruction_or_inject();
            return;
        };
        if frame.is_finished() {
            self.core.frame = Some(frame);
            self.advance_after_finished();
            return;
        }
        self.executor.skip(&mut frame);
        self.core.frame = Some(frame);
    }

    fn step_patch(&mut self, sleigh: &str) {
        let program = self.core.machine.compile_sleigh("patch", &format!("{sleigh};"));
        if let Err(e) = self.execute_program(&program) {
            panic!("{}", e.message());
        }
    }

    fn get_frame(&self) -> Option<&PcodeFrame> {
        self.core.get_frame()
    }

    fn get_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.core.get_instruction()
    }

    fn execute_instruction(&mut self) {
        let cb = Arc::clone(self.core.machine.callbacks());
        let counter = self.core.counter.clone();
        cb.before_decode_instruction(&*self, &counter, self.core.context.as_ref());
        self.core.decode_instruction(&counter);
        let instruction = self.core.require_instruction();
        let ins_prog = PcodeProgram::from_instruction(instruction.as_ref());
        self.hooks.pre_execute_instruction(&mut self.core);
        cb.before_execute_instruction(&*self, instruction.as_ref(), &ins_prog);
        match self.execute_program(&ins_prog) {
            Ok(frame) => self.core.frame = Some(frame),
            Err(e) => self.record_and_rethrow(e),
        }
        self.advance_after_finished();
    }

    fn finish_instruction(&mut self) {
        self.core.assert_mid_instruction();
        let mut frame = self.core.frame.take().expect("frame present per assert");
        let result = self
            .with_executor(|executor, library, hooks| executor.finish_hooked(&mut frame, library, hooks));
        match result {
            Ok(()) => self.core.frame = Some(frame),
            Err(e) => {
                self.core.settle_frame(Some(frame));
                panic!("{}", e.message());
            }
        }
        self.advance_after_finished();
    }

    fn skip_instruction(&mut self) {
        self.core.assert_completed_instruction();
        let cb = Arc::clone(self.core.machine.callbacks());
        let counter = self.core.counter.clone();
        cb.before_decode_instruction(&*self, &counter, self.core.context.as_ref());
        self.core.decode_instruction(&counter);
        let advanced = counter.add_wrap(self.core.decoder.get_last_length_with_delays() as i64);
        self.override_counter(&advanced);
    }

    fn drop_instruction(&mut self) {
        self.core.frame = None;
    }

    fn run(&mut self) {
        self.executor.set_suspended(false);
        if self.core.frame.is_some() {
            self.finish_instruction();
        }
        loop {
            self.step_instruction();
        }
    }

    fn set_suspended(&mut self, suspended: bool) {
        self.executor.set_suspended(suspended);
    }

    fn is_suspended(&self) -> bool {
        self.executor.is_suspended()
    }

    fn get_language(&self) -> &SleighLanguage {
        self.core.get_language()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        self.core.get_arithmetic()
    }

    fn get_executor(&self) -> &PcodeExecutor<T> {
        &self.executor
    }

    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T> {
        self.library.as_ref()
    }

    fn get_state(&self) -> MutexGuard<'_, ThreadPcodeExecutorState<T, S, L>> {
        self.core.get_state()
    }

    fn inject(&mut self, address: &Address, source: &str) {
        let pcode = sleigh_program_compiler::compile_program(
            &self.core.language,
            &format!("thread_inject:{address}"),
            source,
            self.library.as_ref(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        self.core.put_inject(address.clone(), Arc::new(pcode));
    }

    fn clear_inject(&mut self, address: &Address) {
        self.core.injects.remove(address);
    }

    fn clear_all_injects(&mut self) {
        self.core.injects.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine;
    use crate::pcode::emu::pcode_machine::PcodeMachine;
    use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase;
    use crate::pcode::emu::pcode_emulation_callbacks::PcodeEmulationCallbacks;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, SwiMode};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece;
    use crate::pcode::exec::pcode_program::testing::empty_program;
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::pcode::seam_stubs::PseudoInstruction;
    use crate::program::model::address::{
        AddressRange, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::{
        LanguageDescription, LanguageID, ParallelInstructionLanguageHelper, ParseError,
    };
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, PackedDecode, SequenceNumber, Varnode};

    /// Little-endian arithmetic over `byte[]`, as the sibling machine and state tests use.
    struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
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
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(
            &self,
            value: &Vec<u8>,
            _purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// A leaf state backed by a map keyed by (space name, offset).
    #[derive(Default)]
    struct MapState {
        cells: RefCell<HashMap<(String, i64), Vec<u8>>>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self {
            Self { cells: RefCell::new(self.cells.borrow().clone()) }
        }
        fn set_var_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            quantize: bool,
            val: &Vec<u8>,
        ) {
            let offset = i64::from_le_bytes(pad8(offset));
            self.set_var(space, offset, size, quantize, val);
        }
        fn set_var(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: i64,
            _size: i32,
            _quantize: bool,
            val: &Vec<u8>,
        ) {
            self.cells
                .borrow_mut()
                .insert((space.name().to_string(), offset), val.clone());
        }
        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            val: &Vec<u8>,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            quantize: bool,
            reason: Reason,
        ) -> Vec<u8> {
            let offset = i64::from_le_bytes(pad8(offset));
            self.get_var(space, offset, size, quantize, reason)
        }
        fn get_var(
            &self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> Vec<u8> {
            self.cells
                .borrow()
                .get(&(space.name().to_string(), offset))
                .cloned()
                .unwrap_or_else(|| vec![0; size as usize])
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            reason: Reason,
        ) -> Vec<u8> {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    impl PcodeExecutorState<Vec<u8>> for MapState {}

    fn pad8(bytes: &[u8]) -> [u8; 8] {
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf
    }

    /// A decoder that reports fixed-length instructions and records every call, standing in for
    /// `SleighInstructionDecoder`.
    struct CountingDecoder {
        length: i32,
        decoded: Arc<Mutex<Vec<i64>>>,
        branched: Arc<Mutex<Vec<i64>>>,
    }

    struct NoInstruction;
    impl PseudoInstruction for NoInstruction {}

    impl InstructionDecoder for CountingDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn decode_instruction(
            &mut self,
            address: &Address,
            _context: Option<&RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            self.decoded.lock().unwrap().push(address.offset());
            Ok(Box::new(NoInstruction))
        }
        fn branched(&mut self, address: &Address) {
            self.branched.lock().unwrap().push(address.offset());
        }
        fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
            // A real decoder yields the decoded instruction; nothing here needs one, and every
            // test path that would consume it stops at `PcodeProgram::from_instruction`.
            None
        }
        fn get_last_length_with_delays(&self) -> i32 {
            self.length
        }
    }

    #[derive(Default)]
    struct RecordingCallbacks {
        events: Mutex<Vec<String>>,
    }

    impl PcodeEmulationCallbacks<Vec<u8>> for RecordingCallbacks {
        fn before_decode_instruction(
            &self,
            _thread: &dyn ErasedPcodeThread,
            counter: &Address,
            _context: Option<&RegisterValue>,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("beforeDecodeInstruction@{:x}", counter.offset()));
        }
    }

    /// The machine a thread is created in, cut down to what the thread reads off it.
    struct TestMachine {
        base: AbstractPcodeMachineBase<Vec<u8>>,
    }

    impl ErasedPcodeMachine for TestMachine {}

    impl AbstractPcodeMachine<Vec<u8>> for TestMachine {
        fn base(&self) -> &AbstractPcodeMachineBase<Vec<u8>> {
            &self.base
        }
        fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<Vec<u8>> {
            &mut self.base
        }
        fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
            Box::new(MapState::default())
        }
        fn create_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
            Box::new(MapState::default())
        }
        fn as_pcode_machine(&self) -> &dyn PcodeMachine<Vec<u8>> {
            self
        }
    }

    impl PcodeMachine<Vec<u8>> for TestMachine {
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
            unimplemented!("not exercised by these tests")
        }
        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<Vec<u8>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_suspended(&mut self, suspended: bool) {
            self.base.set_suspended(suspended);
        }
        fn is_suspended(&self) -> bool {
            self.base.is_suspended()
        }
        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> PcodeProgram {
            empty_program()
        }
        fn inject(&mut self, _address: &Address, _source: &str) {
            unimplemented!("not exercised by these tests")
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
        fn add_breakpoint(&mut self, _address: &Address, _sleigh_condition: &str) {
            unimplemented!("not exercised by these tests")
        }
        fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind) {
            self.base.add_access_breakpoint(range, kind);
        }
        fn clear_access_breakpoints(&mut self) {
            self.base.clear_access_breakpoints();
        }
    }

    /// A `.sla`-only Sleigh language, built the way the sibling machine tests build one.
    fn sleigh_language() -> SleighLanguage {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" .../>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>
        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table .../>
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    /// The 8-byte program counter of [`ExecLanguage`], at register offset 0.
    fn pc_register() -> RegisterRef {
        Register::new("pc", "", register_space().address(0), 8, false, Register::TYPE_PC)
    }

    /// A [`Language`] answering just what the thread reads off it: a default space, a program
    /// counter, and -- as many emulated languages do -- no context register. Everything else is
    /// out of reach here, exactly as in the sibling `MockLanguage` doubles.
    struct ExecLanguage;

    impl Language for ExecLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram()
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            Some(pc_register())
        }
        /// Java's `Register.NO_CONTEXT`, i.e. a language with no context register.
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_language_id(&self) -> LanguageID {
            unimplemented!("test should not call this")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("test should not call this")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            unimplemented!("test should not call this")
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("test should not call this")
        }
        fn get_version(&self) -> i32 {
            unimplemented!("test should not call this")
        }
        fn get_minor_version(&self) -> i32 {
            unimplemented!("test should not call this")
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("test should not call this")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("test should not call this")
        }
        fn get_instruction_alignment(&self) -> i32 {
            unimplemented!("test should not call this")
        }
        fn supports_pcode(&self) -> bool {
            unimplemented!("test should not call this")
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            unimplemented!("test should not call this")
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn crate::program::model::lang::InstructionPrototype>, ParseError> {
            unimplemented!("test should not call this")
        }
        /// One language-declared userop, which no library in these tests defines.
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            1
        }
        fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
            (index == 0).then(|| "missing_op".to_string())
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("test should not call this")
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            unimplemented!("test should not call this")
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            unimplemented!("test should not call this")
        }
        fn get_segmented_space(&self) -> String {
            unimplemented!("test should not call this")
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("test should not call this")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext,
        ) {
            unimplemented!("test should not call this")
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            unimplemented!("test should not call this")
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            unimplemented!("test should not call this")
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
            unimplemented!("test should not call this")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("test should not call this")
        }
        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("test should not call this")
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("test should not call this")
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("test should not call this")
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("test should not call this")
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("test should not call this")
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("test should not call this")
        }
        fn has_manual(&self) -> bool {
            unimplemented!("test should not call this")
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            unimplemented!("test should not call this")
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("test should not call this")
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            unimplemented!("test should not call this")
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("test should not call this")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("test should not call this")
        }
    }

    struct Fixture {
        thread: DefaultPcodeThread<Vec<u8>, MapState, MapState>,
        machine: Arc<TestMachine>,
        cb: Arc<RecordingCallbacks>,
        decoded: Arc<Mutex<Vec<i64>>>,
        branched: Arc<Mutex<Vec<i64>>>,
    }

    /// Build a thread whose state already holds `pc = counter`, as a freshly initialized emulator's
    /// would; Java's constructor ends by reading exactly that back through `reInitialize()`.
    fn fixture(counter: i64) -> Fixture {
        let cb = Arc::new(RecordingCallbacks::default());
        let machine = Arc::new(TestMachine {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                Arc::clone(&cb) as Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>,
                Arc::new(BytesArithmetic),
                Box::new(nil::<Vec<u8>>()),
                Box::new(nil::<Vec<u8>>()),
                None,
            ),
        });
        let mut shared = MapState::default();
        let local = MapState::default();
        // The pc lives in the register space, which the thread state routes to the local delegate;
        // seed both so either routing reads the same counter.
        let mut seeded_local = local;
        seeded_local.set_var_register(&pc_register(), &counter.to_le_bytes().to_vec());
        shared.set_var_register(&pc_register(), &counter.to_le_bytes().to_vec());

        let decoded = Arc::new(Mutex::new(Vec::new()));
        let branched = Arc::new(Mutex::new(Vec::new()));
        let decoder = CountingDecoder {
            length: 4,
            decoded: Arc::clone(&decoded),
            branched: Arc::clone(&branched),
        };
        let thread = DefaultPcodeThread::new(
            "Thread 0",
            Arc::clone(machine.base().shared()),
            Arc::new(ExecLanguage),
            shared,
            seeded_local,
            Box::new(decoder),
            NoThreadHooks,
        );
        Fixture { thread, machine, cb, decoded, branched }
    }

    /// Java's constructor names the thread, binds it to the machine's language and arithmetic, and
    /// ends with `reInitialize()`, which sets the counter from the pc register in the state.
    #[test]
    fn constructor_re_initializes_the_counter_from_state() {
        let f = fixture(0x400000);
        assert_eq!("Thread 0", f.thread.get_name());
        assert_eq!(0x400000, f.thread.get_counter().offset());
        assert_eq!("ram", f.thread.get_counter().space().name());
        assert_eq!("test", f.thread.get_language().get_id());
        assert!(!f.thread.is_suspended());
        assert!(f.thread.get_frame().is_none());
        assert!(f.thread.get_instruction().is_none());
        assert!(f.thread.get_context().is_none());
        // The machine is reachable back through the thread, as Java's `getMachine()` promises.
        assert!(!f.thread.get_machine().is_suspended());
    }

    /// `setCounter` records the counter without touching the state; `overrideCounter` writes the pc
    /// register too, so a re-initialize agrees with it.
    #[test]
    fn set_counter_does_not_write_state_but_override_counter_does() {
        let mut f = fixture(0x400000);
        let space = ram();

        f.thread.set_counter(&space.address(0x1000));
        assert_eq!(0x1000, f.thread.get_counter().offset());
        // Nothing was written, so re-initializing restores the counter the state still holds.
        f.thread.re_initialize();
        assert_eq!(0x400000, f.thread.get_counter().offset());

        f.thread.override_counter(&space.address(0x1000));
        assert_eq!(0x1000, f.thread.get_counter().offset());
        f.thread.re_initialize();
        assert_eq!(0x1000, f.thread.get_counter().offset());
        // Neither path tells the decoder we branched; only branchToAddress does.
        assert!(f.branched.lock().unwrap().is_empty());
        f.thread.branch_to_address(&space.address(0x2000));
        assert_eq!(vec![0x2000], *f.branched.lock().unwrap());
    }

    /// `skipInstruction` decodes at the counter, notifies the callbacks, and advances the counter by
    /// the decoded length including delay slots.
    #[test]
    fn skip_instruction_decodes_then_advances_by_the_decoded_length() {
        let mut f = fixture(0x400000);
        f.thread.skip_instruction();

        assert_eq!(vec![0x400000], *f.decoded.lock().unwrap());
        assert_eq!(
            vec!["beforeDecodeInstruction@400000"],
            *f.cb.events.lock().unwrap()
        );
        // CountingDecoder reports 4-byte instructions.
        assert_eq!(0x400004, f.thread.get_counter().offset());
        // It advanced via overrideCounter, so the state agrees.
        f.thread.re_initialize();
        assert_eq!(0x400004, f.thread.get_counter().offset());
    }

    /// The type-erased `ErasedPcodeThread::erased_skip_instruction` (added for
    /// [`crate::trace::model::time::schedule::step_kind::StepKind`]) must behave identically to
    /// calling `PcodeThread::skip_instruction` directly -- it exists purely to route through a
    /// `&mut dyn ErasedPcodeThread`, not to do anything different.
    #[test]
    fn erased_skip_instruction_matches_calling_skip_instruction_directly() {
        let mut f = fixture(0x400000);
        let erased: &mut dyn ErasedPcodeThread = &mut f.thread;
        erased.erased_skip_instruction();

        assert_eq!(vec![0x400000], *f.decoded.lock().unwrap());
        assert_eq!(0x400004, f.thread.get_counter().offset());
    }

    /// Java's `getInject` checks the callbacks, then the thread's own injects, then the machine's.
    #[test]
    fn thread_injects_take_precedence_over_the_machines() {
        let mut f = fixture(0x400000);
        let space = ram();
        let address = space.address(0x400000);
        let other = space.address(0x400010);

        // With nothing installed anywhere, there is no inject.
        assert!(f.thread.get_inject(&address).is_none());

        // A machine-level inject is found through the thread...
        f.machine.base().put_inject(address.clone(), empty_program());
        let machine_inject = f.thread.get_inject(&address).expect("the machine's inject");
        assert!(Arc::ptr_eq(&machine_inject, &f.machine.base().get_inject(&address).unwrap()));
        assert!(f.thread.get_inject(&other).is_none());

        // ... and a thread-level one at the same address wins.
        let thread_inject = Arc::new(empty_program());
        f.thread.put_inject(address.clone(), Arc::clone(&thread_inject));
        assert!(Arc::ptr_eq(&thread_inject, &f.thread.get_inject(&address).unwrap()));
        assert!(f.thread.get_inject(&other).is_none());

        // clearInject only affects this thread; the machine's inject is still effective.
        f.thread.clear_inject(&address);
        assert!(Arc::ptr_eq(&machine_inject, &f.thread.get_inject(&address).unwrap()));

        f.thread.put_inject(other.clone(), Arc::new(empty_program()));
        f.thread.clear_all_injects();
        assert!(f.thread.get_inject(&other).is_none());
    }

    /// Suspension is carried by the executor, as Java's `PcodeThreadExecutor.suspended`.
    #[test]
    fn suspension_lives_on_the_executor() {
        let mut f = fixture(0x400000);
        assert!(!f.thread.thread_executor().is_suspended());

        f.thread.set_suspended(true);
        assert!(f.thread.is_suspended());
        assert!(f.thread.thread_executor().is_suspended());

        f.thread.set_suspended(false);
        assert!(!f.thread.is_suspended());
    }

    /// "Cannot finish an instruction unless one is currently being executed."
    #[test]
    #[should_panic(expected = "There is no current instruction to finish.")]
    fn finishing_without_an_instruction_is_rejected() {
        let mut f = fixture(0x400000);
        f.thread.finish_instruction();
    }

    /// `dropInstruction` clears the frame without advancing the counter.
    #[test]
    fn drop_instruction_clears_the_frame_and_leaves_the_counter() {
        let mut f = fixture(0x400000);
        f.thread.drop_instruction();
        assert!(f.thread.get_frame().is_none());
        assert_eq!(0x400000, f.thread.get_counter().offset());
        // With no frame, a fresh instruction may start.
        f.thread.assert_completed_instruction();
    }

    /// The thread's library composes `PcodeEmulationLibrary` over the machine's, so all four
    /// emulation userops are declared.
    #[test]
    fn userop_library_exports_the_four_emulation_userops() {
        let f = fixture(0x400000);
        let userops = f.thread.get_userop_library().get_userops();
        let mut names: Vec<&str> = userops.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            vec!["emu_exec_decoded", "emu_injection_err", "emu_skip_decoded", "emu_swi"],
            names
        );
        // Java marks emu_swi and emu_injection_err functional, the other two not.
        assert!(userops["emu_swi"].is_functional());
        assert!(userops["emu_injection_err"].is_functional());
        assert!(!userops["emu_exec_decoded"].is_functional());
        assert_eq!(0, userops["emu_swi"].get_input_count());
    }

    /// `swi()` and the access checks defer to the machine, as Java's do.
    #[test]
    fn interrupt_checks_defer_to_the_machine() {
        let f = fixture(0x400000);
        // The machine's default SWI mode is ACTIVE, so emu_swi interrupts.
        assert_eq!(
            "Execution hit breakpoint",
            f.thread.swi().expect_err("swi is active").message()
        );
        // With no access breakpoints, loads and stores pass.
        let space = ram();
        let offset = 0x1234u64.to_le_bytes().to_vec();
        assert!(f.thread.check_load(&space, &offset, 4).is_ok());
        assert!(f.thread.check_store(&space, &offset, 4).is_ok());
    }

    /// A machine's stub library is Java's `new PcodeEmulationLibrary<>(null)`: the userops are
    /// declared, but invoking one is a programming error.
    #[test]
    fn a_machine_less_library_still_declares_the_userops() {
        let library = PcodeEmulationLibrary::<Vec<u8>>::new(None);
        assert!(library.machine().is_none());
        assert_eq!(4, library.get_userops().len());
    }

    // ---- Hooks: the overrides of Java's subclasses ----

    /// A decoded instruction with fixed p-code, standing in for the `PseudoInstruction` a
    /// `SleighInstructionDecoder` yields, so these tests can script p-code the toy language
    /// cannot express. Only what `DefaultPcodeThread` reads is answered: the address, the p-code,
    /// and the prototype's language.
    struct ScriptedInstruction {
        address: Address,
        pcode: Vec<PcodeOp>,
    }

    impl crate::program::model::listing::instruction_stub::InstructionStub for ScriptedInstruction {
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_prototype(&self) -> Arc<dyn crate::program::model::lang::InstructionPrototype> {
            Arc::new(crate::program::model::lang::invalid_prototype::DefaultInvalidPrototype::new(
                Arc::new(ExecLanguage),
            ))
        }
        fn get_pcode(&self) -> Vec<PcodeOp> {
            self.pcode.clone()
        }
        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            self.pcode.clone()
        }
    }

    /// A decoder whose "instructions" are 4 bytes long and carry the p-code scripted for their
    /// address.
    struct ScriptedDecoder {
        program: HashMap<i64, Vec<PcodeOp>>,
        last: Option<Arc<ScriptedInstruction>>,
        branched: Arc<Mutex<Vec<i64>>>,
    }

    impl InstructionDecoder for ScriptedDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            Arc::new(ExecLanguage)
        }
        fn decode_instruction(
            &mut self,
            address: &Address,
            _context: Option<&RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            let pcode = self
                .program
                .get(&address.offset())
                .cloned()
                .ok_or_else(|| format!("no instruction scripted at {address}"))?;
            self.last = Some(Arc::new(ScriptedInstruction { address: address.clone(), pcode }));
            Ok(Box::new(NoInstruction))
        }
        fn branched(&mut self, address: &Address) {
            self.branched.lock().unwrap().push(address.offset());
        }
        fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
            self.last.clone().map(|i| i as Arc<dyn Instruction>)
        }
        fn get_last_length_with_delays(&self) -> i32 {
            4
        }
    }

    fn scripted_op(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        PcodeOp::new(opcode, SequenceNumber::new(ram().address(0x400000), 0), inputs, output)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 2)
    }

    /// `r1` -- an 8-byte register the scripted p-code writes.
    fn r1() -> Varnode {
        Varnode::new(register_space().address(8), 8)
    }

    /// Build a thread over a machine with the given callbacks, seeded with `pc = counter` and a
    /// value at `ram:0x100`, decoding the given script, with the given hooks.
    fn scripted_thread<H>(
        counter: i64,
        program: HashMap<i64, Vec<PcodeOp>>,
        hooks: H,
    ) -> (DefaultPcodeThread<Vec<u8>, MapState, MapState, H>, Arc<Mutex<Vec<i64>>>)
    where
        H: ThreadHooks<Vec<u8>, MapState, MapState>,
    {
        let machine = Arc::new(TestMachine {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                Arc::new(RecordingCallbacks::default()),
                Arc::new(BytesArithmetic),
                Box::new(nil::<Vec<u8>>()),
                Box::new(nil::<Vec<u8>>()),
                None,
            ),
        });
        let mut shared = MapState::default();
        let mut local = MapState::default();
        local.set_var_register(&pc_register(), &counter.to_le_bytes().to_vec());
        shared.set_var(&ram(), 0x100, 8, false, &0x1122334455667788u64.to_le_bytes().to_vec());
        let branched = Arc::new(Mutex::new(Vec::new()));
        let decoder = ScriptedDecoder { program, last: None, branched: Arc::clone(&branched) };
        let thread = DefaultPcodeThread::new(
            "Thread 0",
            Arc::clone(machine.base().shared()),
            Arc::new(ExecLanguage),
            shared,
            local,
            Box::new(decoder),
            hooks,
        );
        (thread, branched)
    }

    /// Records what Java's `preExecuteInstruction()` and `onMissingUseropDef()` overrides see.
    #[derive(Default)]
    struct RecordingHooks {
        pre_executed: Vec<(i64, Option<i64>)>,
        missing: Vec<String>,
        handle_missing: bool,
    }

    impl ThreadHooks<Vec<u8>, MapState, MapState> for RecordingHooks {
        fn pre_execute_instruction(&mut self, thread: &mut ThreadCore<Vec<u8>, MapState, MapState>) {
            let instruction = thread.get_instruction().map(|i| i.get_min_address().offset());
            self.pre_executed.push((thread.get_counter().offset(), instruction));
        }

        fn on_missing_userop_def(
            &mut self,
            _thread: &mut ThreadCore<Vec<u8>, MapState, MapState>,
            op: &PcodeOp,
            op_name: &str,
        ) -> bool {
            assert_eq!(OpCode::CallOther, op.opcode);
            self.missing.push(op_name.to_string());
            self.handle_missing
        }
    }

    /// A single instruction: copy `ram:0x100` into `r1`, then call the undefined userop 0.
    fn copy_then_missing_userop() -> HashMap<i64, Vec<PcodeOp>> {
        let ram_100 = Varnode::new(ram().address(0x100), 8);
        HashMap::from([(
            0x400000,
            vec![
                scripted_op(OpCode::Copy, vec![ram_100], Some(r1())),
                scripted_op(OpCode::CallOther, vec![Varnode::new(const_space().address(0), 4)], None),
            ],
        )])
    }

    /// Java's `executeInstruction()` calls `preExecuteInstruction()` once the instruction is
    /// decoded, before its p-code runs; a userop the library lacks reaches `onMissingUseropDef()`,
    /// and a hook that handles it lets the instruction fall through.
    #[test]
    fn hooks_intercept_pre_execute_and_missing_userops() {
        let hooks = RecordingHooks { handle_missing: true, ..RecordingHooks::default() };
        let (mut thread, _) = scripted_thread(0x400000, copy_then_missing_userop(), hooks);

        thread.step_instruction();

        assert_eq!(vec![(0x400000, Some(0x400000))], thread.hooks().pre_executed);
        assert_eq!(vec!["missing_op".to_string()], thread.hooks().missing);
        // The COPY ran, and the instruction fell through by its 4-byte length.
        assert_eq!(
            0x1122334455667788u64.to_le_bytes().to_vec(),
            thread.get_state().get_var_varnode(&r1(), Reason::Inspect)
        );
        assert_eq!(0x400004, thread.get_counter().offset());
        assert!(thread.get_frame().is_none());
    }

    /// When no hook handles the userop, the base class's link error escapes, naming the userop.
    #[test]
    fn an_unhandled_missing_userop_is_the_base_link_error() {
        let (mut thread, _) =
            scripted_thread(0x400000, copy_then_missing_userop(), RecordingHooks::default());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread.step_instruction();
        }));
        let message = match result.expect_err("the userop is undefined") {
            payload => payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default(),
        };
        assert!(message.contains("Sleigh userop 'missing_op' is not in the library"), "{message}");
        assert_eq!(vec!["missing_op".to_string()], thread.hooks().missing);
        // Java records the failed frame: the instruction is mid-flight, at the failing op.
        assert!(thread.get_frame().is_some());
        assert_eq!(0x400000, thread.get_counter().offset());
    }

    /// An executor extension, standing in for a `PcodeThreadExecutor` subclass such as
    /// `SymZ3PcodeThreadExecutor`: it records every op stepped and every branch taken.
    struct RecordingExtension {
        stepped: Arc<Mutex<Vec<OpCode>>>,
        branches: Arc<Mutex<Vec<i64>>>,
    }

    impl PcodeExecutorHooks<Vec<u8>> for RecordingExtension {
        fn before_step_op(
            &mut self,
            _executor: &PcodeExecutor<Vec<u8>>,
            op: &PcodeOp,
            _frame: &PcodeFrame,
        ) -> Result<(), LowlevelError> {
            self.stepped.lock().unwrap().push(op.opcode);
            Ok(())
        }

        fn branch_to_address(&mut self, _executor: &PcodeExecutor<Vec<u8>>, _op: &PcodeOp, target: &Address) {
            self.branches.lock().unwrap().push(target.offset());
        }
    }

    /// Java's `createExecutor()` override: the thread executes through the executor it returns.
    struct SwappedExecutorHooks {
        stepped: Arc<Mutex<Vec<OpCode>>>,
        branches: Arc<Mutex<Vec<i64>>>,
    }

    impl ThreadHooks<Vec<u8>, MapState, MapState> for SwappedExecutorHooks {
        fn create_executor(
            &mut self,
            thread: &ThreadCore<Vec<u8>, MapState, MapState>,
        ) -> PcodeThreadExecutor<Vec<u8>> {
            PcodeThreadExecutor::for_thread(thread).with_extension(Box::new(RecordingExtension {
                stepped: Arc::clone(&self.stepped),
                branches: Arc::clone(&self.branches),
            }))
        }
    }

    /// The executor `createExecutor()` returns is the one that runs the thread's p-code, for
    /// whole instructions and single p-code steps alike; the thread still moves its counter (and
    /// tells the decoder) when that p-code branches, as Java's `PcodeThreadExecutor` does.
    #[test]
    fn a_swapped_executor_runs_the_threads_pcode() {
        let stepped = Arc::new(Mutex::new(Vec::new()));
        let branches = Arc::new(Mutex::new(Vec::new()));
        let hooks = SwappedExecutorHooks {
            stepped: Arc::clone(&stepped),
            branches: Arc::clone(&branches),
        };
        let ram_100 = Varnode::new(ram().address(0x100), 8);
        let program = HashMap::from([
            (
                0x400000,
                vec![
                    scripted_op(OpCode::Copy, vec![ram_100.clone()], Some(r1())),
                    scripted_op(OpCode::Branch, vec![Varnode::new(ram().address(0x500000), 8)], None),
                ],
            ),
            (0x500000, vec![scripted_op(OpCode::Copy, vec![ram_100], Some(r1()))]),
        ]);
        let (mut thread, decoder_branched) = scripted_thread(0x400000, program, hooks);

        thread.step_instruction();
        assert_eq!(vec![OpCode::Copy, OpCode::Branch], *stepped.lock().unwrap());
        assert_eq!(vec![0x500000], *branches.lock().unwrap());
        // The branch moved the counter, wrote the pc, and told the decoder.
        assert_eq!(0x500000, thread.get_counter().offset());
        assert_eq!(vec![0x500000], *decoder_branched.lock().unwrap());
        thread.re_initialize();
        assert_eq!(0x500000, thread.get_counter().offset());

        // Stepping by p-code op goes through the same executor: decode, step the COPY, then
        // resolve the fall-through.
        thread.step_pcode_op();
        assert!(thread.get_frame().is_some());
        thread.step_pcode_op();
        assert_eq!(vec![OpCode::Copy, OpCode::Branch, OpCode::Copy], *stepped.lock().unwrap());
        thread.step_pcode_op();
        assert!(thread.get_frame().is_none());
        assert_eq!(0x500004, thread.get_counter().offset());
    }

    /// A suspended thread refuses to step an op, leaving its frame at the op it refused.
    #[test]
    fn a_suspended_thread_refuses_to_step() {
        let (mut thread, _) = scripted_thread(0x400000, copy_then_missing_userop(), NoThreadHooks);
        thread.set_suspended(true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread.step_instruction();
        }));
        let message = result
            .expect_err("a suspended thread cannot step")
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert_eq!(SuspendedPcodeExecutionException::new_without_frame().message(), message);
        // The COPY never ran.
        assert_eq!(vec![0u8; 8], thread.get_state().get_var_varnode(&r1(), Reason::Inspect));
        assert!(thread.get_frame().is_some());
    }
}
