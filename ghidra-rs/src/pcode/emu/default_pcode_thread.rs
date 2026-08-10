//! The default implementation of [`PcodeThread`], suitable for most applications.
//!
//! Corresponds to `ghidra.pcode.emu.DefaultPcodeThread`.
//!
//! This class implements the control-flow logic of the target machine, cooperating with the p-code
//! program flow implemented by [`PcodeExecutor`]. That logic lives primarily in
//! [`DefaultPcodeThread::begin_instruction_or_inject`] and
//! [`DefaultPcodeThread::advance_after_finished`].
//!
//! # Divergences from Java
//!
//! * **The machine back-reference.** Java's thread holds its `AbstractPcodeMachine<T>` and its
//!   machine holds the thread, a cycle Rust cannot express with plain ownership. The thread holds
//!   an `Arc<dyn AbstractPcodeMachine<T>>`, so a machine must be `Arc`-owned before it can create a
//!   thread that refers back to it. Consequently the machine is reachable only through `&`, which
//!   is why [`AbstractPcodeMachineBase::stepped`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::stepped)
//!   takes `&self`.
//! * **The factory methods.** Java's constructor calls the overridable `createThreadState`,
//!   `createInstructionDecoder`, `createExecutor`, and (lazily) `createUseropLibrary` on a
//!   half-built `this`. Rust has no such call, so the state delegates and the decoder are
//!   parameters of [`DefaultPcodeThread::new`], following the convention
//!   [`AbstractPcodeMachineBase::new`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::new)
//!   already uses. The userop library is built eagerly there too: Java delays it only because
//!   `createUseropLibrary` needs `this`, and this port's [`PcodeEmulationLibrary`] binds to the
//!   machine instead (see below).
//! * **Two languages.** [`PcodeThread::get_language`] hands back the machine's
//!   [`SleighLanguage`], but this crate's `SleighLanguage` is a partial, `.sla`-only port that
//!   neither implements [`Language`] nor exposes the program counter, context register, or default
//!   space -- all of which this class needs, and all of which are on [`Language`]. So the executor,
//!   decoder, and register lookups bind to a separate `Arc<dyn Language>` constructor parameter,
//!   exactly as [`PcodeExecutor`] does for the same reason.
//! * **The executor's overrides.** Java's `PcodeThreadExecutor` overrides `stepOp`, `beforeLoad`,
//!   `branchToAddress`, and friends, all of which call back into the thread that owns it. A Rust
//!   field cannot refer to its owner, and [`PcodeExecutor`]'s hooks are inherent methods with no
//!   override seam (see its module docs), so [`PcodeThreadExecutor`] carries only the state Java's
//!   subclass adds -- the `suspended` flag -- and the override *bodies* live on the thread, as
//!   [`DefaultPcodeThread::step_op`], [`DefaultPcodeThread::check_load`], and so on. Until
//!   `PcodeExecutor` grows that seam, the executor cannot invoke them mid-frame; the thread invokes
//!   the ones on its own control-flow path.
//! * **Context.** `RegisterValue` is still a bare seam stub in this crate (two of them, in fact --
//!   see [`ProgramContextImpl`]), and cannot be constructed, so the paths that build a context
//!   value panic. A language without a context register -- Java's `Register.NO_CONTEXT`, rendered
//!   here as `None` -- is fully supported, and that is what the tests exercise.
//! * **Exceptions.** Java throws from `stepInstruction`, `executeInstruction`, and friends;
//!   [`PcodeThread`]'s documented Rust rendering is to panic, so a `PcodeExecutionException`
//!   escaping the executor is recorded into [`get_frame`](PcodeThread::get_frame) (as Java does)
//!   and then panics with its message.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::pcode_thread::{ErasedPcodeThread, PcodeThread};
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
    PcodeUserop, UseropInputs, UseropValueKind,
};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::seam_stubs::{
    InjectionErrorPcodeExecutionException, InterruptPcodeExecutionException, ProgramContextImpl,
    RegisterValue, SleighProgramCompiler, SuspendedPcodeExecutionException,
};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::PcodeOp;

/// A userop library exporting some methods for emulated thread control.
///
/// Port of `DefaultPcodeThread.PcodeEmulationLibrary`.
///
/// Java binds one of these to each thread and calls back into it. A Rust userop callback is an
/// `Fn` stored *inside* the library, which is in turn owned by the thread, so it cannot capture
/// that thread; this library binds to the machine instead. The two userops that only need the
/// machine -- `emu_swi` and `emu_injection_err` -- are therefore faithful, while the two that drive
/// the owning thread -- `emu_exec_decoded` and `emu_skip_decoded` -- are declared (so Sleigh
/// compiled against this library still links, which is all the machine's *stub* library ever needs)
/// but panic if actually executed.
pub struct PcodeEmulationLibrary<T: 'static> {
    base: AnnotatedPcodeUseropLibraryBase<T>,
    machine: Option<Arc<dyn AbstractPcodeMachine<T>>>,
}

impl<T: 'static> PcodeEmulationLibrary<T> {
    /// Construct a library controlling the given machine's threads.
    ///
    /// Port of `PcodeEmulationLibrary(DefaultPcodeThread<T>)`, with the machine standing in for the
    /// thread -- see the struct docs. `None` is Java's `new PcodeEmulationLibrary<>(null)`, i.e.
    /// the declaration-only library a machine uses as its thread stub library.
    pub fn new(machine: Option<Arc<dyn AbstractPcodeMachine<T>>>) -> Self {
        let mut library = Self { base: AnnotatedPcodeUseropLibraryBase::new(), machine };
        library.init();
        library
    }

    /// The machine whose threads this library controls, if it is bound to one.
    pub fn machine(&self) -> Option<&Arc<dyn AbstractPcodeMachine<T>>> {
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
        vec![
            // Execute the actual machine instruction at the current program counter. Because
            // "injects" override the machine instruction, injects which need to defer to the
            // machine instruction must invoke this userop.
            AnnotatedPcodeUseropDefinition::new(
                "emu_exec_decoded",
                PcodeUserop::default(),
                UseropInputs::Fixed(vec![]),
                UseropValueKind::Void,
                Box::new(|_ctx, _args| {
                    unimplemented!(
                        "emu_exec_decoded must drive the thread that owns this library; \
                         see PcodeEmulationLibrary's docs"
                    )
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
                Box::new(|_ctx, _args| {
                    unimplemented!(
                        "emu_skip_decoded must drive the thread that owns this library; \
                         see PcodeEmulationLibrary's docs"
                    )
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
                    if let Err(e) = machine.base().swi() {
                        panic!("{}", e.message());
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
                Box::new(|_ctx, _args| {
                    panic!("{}", InjectionErrorPcodeExecutionException::new(None).message())
                }),
            ),
        ]
    }
}

/// An executor for a p-code thread.
///
/// Port of `DefaultPcodeThread.PcodeThreadExecutor`.
///
/// Java's subclass checks for thread suspension and updates the program counter register upon
/// execution of (external) branches. Here it carries only the `suspended` flag Java's subclass
/// adds, wrapping the [`PcodeExecutor`] it would otherwise extend; the overriding behavior lives on
/// the thread. See this module's docs.
pub struct PcodeThreadExecutor<T: 'static> {
    /// Java declares this `volatile`, for a thread suspending another that is stepping.
    /// [`PcodeThread::set_suspended`] takes `&mut self`, so exclusive access is already required to
    /// write it and a plain `bool` suffices.
    suspended: bool,
    executor: PcodeExecutor<T>,
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
            suspended: false,
            executor: PcodeExecutor::new(language, arithmetic, state, Reason::ExecuteRead),
        }
    }

    /// Construct the executor for the given thread, as Java's constructor does.
    pub fn for_thread<S, L>(thread: &DefaultPcodeThread<T, S, L>) -> Self
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

    /// Whether this executor is refusing to step.
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Set whether this executor refuses to step.
    pub fn set_suspended(&mut self, suspended: bool) {
        self.suspended = suspended;
    }
}

impl<T: 'static> Deref for PcodeThreadExecutor<T> {
    type Target = PcodeExecutor<T>;

    fn deref(&self) -> &PcodeExecutor<T> {
        &self.executor
    }
}

/// A p-code program overriding the instruction at some address, from whichever of the three
/// sources [`DefaultPcodeThread::get_inject`] consults.
///
/// Java hands back a bare `PcodeProgram` reference, since every source holds one. Here the
/// callbacks and the thread hold shared handles while the machine owns its injects outright, so the
/// lookup yields one or the other; both deref to the program.
pub enum Inject<'a> {
    /// An inject from the emulation callbacks or from the thread itself.
    Shared(Arc<PcodeProgram>),
    /// An inject owned by the machine.
    Borrowed(&'a PcodeProgram),
}

impl Deref for Inject<'_> {
    type Target = PcodeProgram;

    fn deref(&self) -> &PcodeProgram {
        match self {
            Self::Shared(program) => program,
            Self::Borrowed(program) => program,
        }
    }
}

/// The default implementation of [`PcodeThread`], suitable for most applications.
///
/// `T` is the type of variables in the emulator, `S` the concrete type of the machine's shared
/// (memory) state, and `L` that of this thread's local (register/unique) state -- see
/// [`ThreadPcodeExecutorState`] on why the delegates are named rather than boxed.
pub struct DefaultPcodeThread<T: 'static, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    name: String,
    machine: Arc<dyn AbstractPcodeMachine<T>>,
    language: Arc<SleighLanguage>,
    /// The language the executor, decoder, and register lookups bind to. See the module docs.
    exec_language: Arc<dyn Language>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    state: Arc<Mutex<ThreadPcodeExecutorState<T, S, L>>>,
    decoder: Box<dyn InstructionDecoder>,
    library: Box<dyn PcodeUseropLibrary<T>>,
    executor: PcodeThreadExecutor<T>,
    pc: RegisterRef,
    /// The language's context register, or `None` for Java's `Register.NO_CONTEXT`.
    contextreg: Option<RegisterRef>,
    counter: Address,
    context: Option<Box<dyn RegisterValue>>,
    instruction: Option<Arc<dyn Instruction>>,
    frame: Option<PcodeFrame>,
    default_context: Option<ProgramContextImpl>,
    injects: HashMap<Address, Arc<PcodeProgram>>,
}

impl<T: 'static, S, L> DefaultPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    /// Construct a new thread.
    ///
    /// Port of `DefaultPcodeThread(String, AbstractPcodeMachine<T>)`. `shared_state` and
    /// `local_state` are what Java reads from `machine.getSharedState()` and
    /// `machine.createLocalState(this)`, `decoder` is the product of `createInstructionDecoder`,
    /// and `exec_language` is the machine's language as a [`Language`]; see the module docs on why
    /// all four are parameters.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as Java's `Objects.requireNonNull` throws.
    pub fn new(
        name: impl Into<String>,
        machine: Arc<dyn AbstractPcodeMachine<T>>,
        exec_language: Arc<dyn Language>,
        shared_state: S,
        local_state: L,
        decoder: Box<dyn InstructionDecoder>,
    ) -> Self {
        let language = Arc::clone(machine.base().language());
        let arithmetic = machine.base().get_arithmetic();
        let state = Arc::new(Mutex::new(ThreadPcodeExecutorState::new(shared_state, local_state)));
        let executor = PcodeThreadExecutor::new(
            Arc::clone(&exec_language),
            Arc::clone(&arithmetic),
            state.clone(),
        );
        let library = PcodeEmulationLibrary::new(Some(Arc::clone(&machine)))
            .compose(machine.base().get_userop_library());
        let pc = exec_language
            .get_program_counter()
            .expect("Language has no program counter");
        let contextreg = context_base_register(exec_language.as_ref());

        // Java: if the language has a context register, build its default context store and seed
        // the thread's context from it.
        let (default_context, context) = match &contextreg {
            Some(_) => {
                let mut default_context = ProgramContextImpl::new();
                exec_language.apply_context_settings(&mut default_context);
                let context = default_context.get_default_disassembly_context();
                (Some(default_context), Some(context))
            }
            None => (None, None),
        };

        let mut thread = Self {
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
            library,
            executor,
            pc,
            contextreg,
            context,
            instruction: None,
            frame: None,
            default_context,
            injects: HashMap::new(),
        };
        thread.re_initialize();
        thread
    }

    /// The language bound to this thread's executor and decoder. See the module docs.
    pub fn exec_language(&self) -> &Arc<dyn Language> {
        &self.exec_language
    }

    /// A handle to this thread's multiplexed state, as the executor holds it.
    pub fn state_handle(&self) -> Arc<Mutex<dyn PcodeExecutorState<T>>> {
        self.state.clone()
    }

    /// This thread's executor, including the suspension flag Java's `PcodeThreadExecutor` adds.
    pub fn thread_executor(&self) -> &PcodeThreadExecutor<T> {
        &self.executor
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
        let size = self.pc.borrow().minimum_byte_size();
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
    pub fn write_context(&mut self, context: Option<&dyn RegisterValue>) {
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
        let size = contextreg.borrow().minimum_byte_size();
        let value = self.arithmetic.from_const_big_int(
            current.get_unsigned_value_ignore_mask() as i128,
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
    pub fn assign_context(&mut self, context: &dyn RegisterValue) {
        let register = context.get_register();
        let base = register.borrow().get_base_register();
        let is_contextreg = match &self.contextreg {
            Some(contextreg) => same_register(&base, contextreg),
            // `None` is Java's `Register.NO_CONTEXT`, which only a NO_CONTEXT value matches.
            None => base.borrow().name() == "NO_CONTEXT",
        };
        assert!(is_contextreg, "context must be the contextreg value");
        let Some(current) = self.context.as_ref() else {
            // Java asserts contextreg == NO_CONTEXT and returns, leaving the context null.
            debug_assert!(self.contextreg.is_none());
            return;
        };
        self.context = Some(current.assign(&register, context));
    }

    /// Port of `doPluggableInitialization()`: execute the machine's initializer upon this thread,
    /// if applicable.
    #[deprecated(note = "Java marks the initializer mechanism for removal since 12.0")]
    pub fn do_pluggable_initialization(&self) {
        if let Some(initializer) = self.machine.base().initializer.clone() {
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

        if self.contextreg.is_some() {
            // Java reads the contextreg from the state and assigns `new RegisterValue(contextreg,
            // ctx)`. RegisterValue is still a seam stub here and cannot be constructed.
            unimplemented!(
                "re-initializing the decode context needs the real RegisterValue port"
            );
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

    /// Port of `getInject(Address)`: check this thread's injects, then the machine's.
    ///
    /// The machine is taken as a parameter, rather than read off `self`, so the returned borrow
    /// outlives the `&self` one; callers clone the [`Arc`] first and then mutate the thread while
    /// holding the inject, as Java does.
    pub fn get_inject<'m>(
        &self,
        machine: &'m dyn AbstractPcodeMachine<T>,
        address: &Address,
    ) -> Option<Inject<'m>> {
        if let Some(inject) = machine.base().callbacks().get_inject(self, address) {
            return Some(Inject::Shared(inject));
        }
        if let Some(inject) = self.injects.get(address) {
            return Some(Inject::Shared(Arc::clone(inject)));
        }
        machine.get_inject(address).map(Inject::Borrowed)
    }

    /// Record the given compiled p-code as this thread's inject at the given address, replacing any
    /// inject already there. This is Java's `injects.put(address, pcode)`, which
    /// [`inject`](PcodeThread::inject) reaches only after compiling the source.
    pub fn put_inject(&mut self, address: Address, pcode: Arc<PcodeProgram>) {
        self.injects.insert(address, pcode);
    }

    /// Port of `beginInstructionOrInject()`: start execution of the instruction or inject at the
    /// program counter.
    pub fn begin_instruction_or_inject(&mut self) {
        let machine = Arc::clone(&self.machine);
        let counter = self.counter.clone();
        match self.get_inject(machine.as_ref(), &counter) {
            Some(inject) => {
                self.instruction = None;
                self.frame = Some(self.executor.begin(&inject));
            }
            None => {
                self.decode_instruction(&counter);
                let instruction = self.require_instruction();
                let pcode = PcodeProgram::from_instruction(instruction.as_ref());
                self.frame = Some(self.executor.begin(&pcode));
            }
        }
    }

    /// Port of `advanceAfterFinished()`: resolve a finished instruction, advancing the program
    /// counter if necessary.
    pub fn advance_after_finished(&mut self) {
        let machine = Arc::clone(&self.machine);
        let cb = Arc::clone(machine.base().callbacks());
        let counter = self.counter.clone();
        let Some(instruction) = self.instruction.clone() else {
            // The frame resulted from an inject.
            cb.after_execute_inject(self, &counter);
            self.frame = None;
            return;
        };
        if self.frame.as_ref().is_some_and(PcodeFrame::is_fall_through) {
            let advanced = counter.add_wrap(self.decoder.get_last_length_with_delays() as i64);
            self.write_counter(&advanced);
        }
        if self.contextreg.is_some() {
            // Java combines the language default, the flow value, and the context committed while
            // decoding, then writes the result. Each of those is a RegisterValue, still a seam stub.
            unimplemented!("advancing the decode context needs the real RegisterValue port");
        }
        self.post_execute_instruction();
        cb.after_execute_instruction(self, instruction.as_ref());
        self.frame = None;
        self.instruction = None;
    }

    /// Extension point: extra behavior before executing an instruction.
    ///
    /// Java's `preExecuteInstruction()` is an empty `protected` method, used for incorporating
    /// state modifiers from the older `Emulator` framework.
    pub fn pre_execute_instruction(&mut self) {}

    /// Extension point: extra behavior after executing an instruction. See
    /// [`pre_execute_instruction`](Self::pre_execute_instruction).
    pub fn post_execute_instruction(&mut self) {}

    /// Extension point: behavior when a p-code userop definition is not found. Returns true if
    /// handled, false if still undefined. Java's base implementation returns false.
    pub fn on_missing_userop_def(&mut self, op: &PcodeOp, op_name: &str) -> bool {
        let _ = (op, op_name);
        false
    }

    /// Port of `PcodeThreadExecutor.stepOp`: check for suspension, notify the callbacks, step the
    /// op, and let the machine re-enable software interrupts.
    ///
    /// See the module docs: this is the executor's override, hosted on the thread because it needs
    /// the thread.
    ///
    /// # Panics
    ///
    /// If this thread's executor or its machine is suspended, as Java throws
    /// `SuspendedPcodeExecutionException`.
    pub fn step_op(&mut self, op: &PcodeOp, frame: &mut PcodeFrame) {
        let machine = Arc::clone(&self.machine);
        if self.executor.is_suspended() || machine.is_suspended() {
            panic!("{}", SuspendedPcodeExecutionException::new(None).message());
        }
        let cb = Arc::clone(machine.base().callbacks());
        cb.before_step_op(self, op, frame);
        if let Err(e) = self.executor.step_op(op, frame, self.library.as_ref()) {
            panic!("{e}");
        }
        self.stepped();
        cb.after_step_op(self, op, frame);
    }

    /// Port of `checkLoad(AddressSpace, T, int)`: perform checks on a requested `LOAD`, returning
    /// the interrupt it should cause, if any.
    pub fn check_load(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.base().check_load(space, offset, size)
    }

    /// Port of `checkStore(AddressSpace, T, int)`: perform checks on a requested `STORE`, returning
    /// the interrupt it should cause, if any.
    pub fn check_store(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.base().check_store(space, offset, size)
    }

    /// Port of `swi()`: return a software interrupt if those interrupts are active.
    pub fn swi(&self) -> Result<(), InterruptPcodeExecutionException> {
        self.machine.base().swi()
    }

    /// Port of `stepped()`: notify the machine a thread has stepped a p-code op, so that it may
    /// re-enable software interrupts, if applicable.
    pub fn stepped(&self) {
        self.machine.base().stepped();
    }

    /// Decode the instruction at the given address into [`instruction`](Self::get_instruction),
    /// which is Java's `instruction = decoder.decodeInstruction(counter, context)`.
    ///
    /// This crate's decoder hands back a `PseudoInstruction`, which is not (yet) an
    /// [`Instruction`], so the decoded instruction is recovered from the decoder itself.
    fn decode_instruction(&mut self, address: &Address) {
        let context = self.context.as_deref();
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

    /// Run the executor over `program`, recording the frame of a failed execution as Java does
    /// before rethrowing.
    fn execute_program(&mut self, program: &PcodeProgram) {
        match self.executor.execute(program, self.library.as_ref()) {
            Ok(_) => {}
            Err(e) => {
                let message = e.message().to_string();
                self.frame = e.into_frame().map(|frame| *frame);
                panic!("{message}");
            }
        }
    }
}

/// Whether two register handles denote the same register. Java compares `Register` identity; these
/// are separately built handles, so they are compared by where they live.
fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    let (a, b) = (a.borrow(), b.borrow());
    a.name() == b.name() && a.address() == b.address() && a.num_bytes() == b.num_bytes()
}

/// The language's context base register, mapping Java's `Register.NO_CONTEXT` sentinel onto `None`
/// so callers have one "no context" case rather than two.
fn context_base_register(language: &dyn Language) -> Option<RegisterRef> {
    let contextreg = language.get_context_base_register()?;
    let is_no_context = contextreg.borrow().name() == "NO_CONTEXT";
    (!is_no_context).then_some(contextreg)
}

impl<T: 'static, S, L> ErasedPcodeThread for DefaultPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
}

impl<T: 'static, S, L> PcodeThread<T> for DefaultPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    type SharedState = S;
    type LocalState = L;

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_machine(&self) -> &dyn PcodeMachine<T> {
        self.machine.as_pcode_machine()
    }

    fn set_counter(&mut self, counter: &Address) {
        self.counter = counter.clone();
    }

    fn get_counter(&self) -> Address {
        self.counter.clone()
    }

    fn override_counter(&mut self, counter: &Address) {
        self.write_counter(counter);
    }

    fn assign_context(&mut self, context: &dyn RegisterValue) {
        DefaultPcodeThread::assign_context(self, context);
    }

    fn get_context(&self) -> Option<&dyn RegisterValue> {
        self.context.as_deref()
    }

    fn override_context(&mut self, context: &dyn RegisterValue) {
        self.write_context(Some(context));
    }

    fn override_context_with_default(&mut self) {
        let (Some(contextreg), Some(default_context)) =
            (self.contextreg.clone(), self.default_context.as_ref())
        else {
            return;
        };
        let default_value = default_context.get_default_value(&contextreg, &self.counter);
        if let Some(default_value) = default_value {
            self.write_context(Some(default_value.as_ref()));
        }
    }

    fn re_initialize(&mut self) {
        DefaultPcodeThread::re_initialize(self);
    }

    fn step_instruction(&mut self) {
        self.assert_completed_instruction();
        let machine = Arc::clone(&self.machine);
        let counter = self.counter.clone();
        let Some(inject) = self.get_inject(machine.as_ref(), &counter) else {
            self.execute_instruction();
            return;
        };
        self.instruction = None;
        let cb = Arc::clone(machine.base().callbacks());
        cb.before_execute_inject(self, &counter, &inject);
        self.execute_program(&inject);
        cb.after_execute_inject(self, &counter);
    }

    fn step_pcode_op(&mut self) {
        let Some(mut frame) = self.frame.take() else {
            self.begin_instruction_or_inject();
            return;
        };
        if frame.is_finished() {
            self.frame = Some(frame);
            self.advance_after_finished();
            return;
        }
        let result = self.executor.step(&mut frame, self.library.as_ref());
        self.frame = Some(frame);
        if let Err(e) = result {
            panic!("{}", e.message());
        }
    }

    fn skip_pcode_op(&mut self) {
        let Some(mut frame) = self.frame.take() else {
            self.begin_instruction_or_inject();
            return;
        };
        if frame.is_finished() {
            self.frame = Some(frame);
            self.advance_after_finished();
            return;
        }
        self.executor.skip(&mut frame);
        self.frame = Some(frame);
    }

    fn step_patch(&mut self, sleigh: &str) {
        let program = self.machine.compile_sleigh("patch", &format!("{sleigh};"));
        self.execute_program(&program);
    }

    fn get_frame(&self) -> Option<&PcodeFrame> {
        self.frame.as_ref()
    }

    fn get_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.instruction.clone()
    }

    fn execute_instruction(&mut self) {
        let machine = Arc::clone(&self.machine);
        let cb = Arc::clone(machine.base().callbacks());
        let counter = self.counter.clone();
        cb.before_decode_instruction(self, &counter, self.context.as_deref());
        self.decode_instruction(&counter);
        let instruction = self.require_instruction();
        let ins_prog = PcodeProgram::from_instruction(instruction.as_ref());
        self.pre_execute_instruction();
        cb.before_execute_instruction(self, instruction.as_ref(), &ins_prog);
        self.execute_program(&ins_prog);
        self.advance_after_finished();
    }

    fn finish_instruction(&mut self) {
        self.assert_mid_instruction();
        let mut frame = self.frame.take().expect("frame present per assert");
        let result = self.executor.finish(&mut frame, self.library.as_ref());
        self.frame = Some(frame);
        if let Err(e) = result {
            panic!("{}", e.message());
        }
        self.advance_after_finished();
    }

    fn skip_instruction(&mut self) {
        self.assert_completed_instruction();
        let machine = Arc::clone(&self.machine);
        let cb = Arc::clone(machine.base().callbacks());
        let counter = self.counter.clone();
        cb.before_decode_instruction(self, &counter, self.context.as_deref());
        self.decode_instruction(&counter);
        let advanced = counter.add_wrap(self.decoder.get_last_length_with_delays() as i64);
        self.override_counter(&advanced);
    }

    fn drop_instruction(&mut self) {
        self.frame = None;
    }

    fn run(&mut self) {
        self.executor.set_suspended(false);
        if self.frame.is_some() {
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
        &self.language
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    fn get_executor(&self) -> &PcodeExecutor<T> {
        &self.executor
    }

    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T> {
        self.library.as_ref()
    }

    fn get_state(&self) -> MutexGuard<'_, ThreadPcodeExecutorState<T, S, L>> {
        self.state.lock().expect("thread state lock poisoned")
    }

    fn inject(&mut self, address: &Address, source: &str) {
        let pcode = SleighProgramCompiler::compile_program(
            &self.language,
            &format!("thread_inject:{address}"),
            source,
            self.library.as_ref(),
        );
        self.put_inject(address.clone(), Arc::new(pcode));
    }

    fn clear_inject(&mut self, address: &Address) {
        self.injects.remove(address);
    }

    fn clear_all_injects(&mut self) {
        self.injects.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
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
    use crate::program::model::pcode::{OpCode, PackedDecode};

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
            _context: Option<&dyn RegisterValue>,
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
            _context: Option<&dyn RegisterValue>,
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
        fn create_thread(&self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
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
        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn new_thread_named(&mut self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread(
            &mut self,
            _name: &str,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn ErasedPcodeThread>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            self.base.get_all_threads()
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
        fn get_inject(&self, address: &Address) -> Option<&PcodeProgram> {
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
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            unimplemented!("test should not call this")
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            unimplemented!("test should not call this")
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
            Arc::clone(&machine) as Arc<dyn AbstractPcodeMachine<Vec<u8>>>,
            Arc::new(ExecLanguage),
            shared,
            seeded_local,
            Box::new(decoder),
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

    /// Java's `getInject` checks the callbacks, then the thread's own injects, then the machine's.
    #[test]
    fn thread_injects_take_precedence_over_the_machines() {
        let mut f = fixture(0x400000);
        let space = ram();
        let address = space.address(0x400000);
        let other = space.address(0x400010);

        // With nothing installed anywhere, there is no inject.
        assert!(f.thread.get_inject(f.machine.as_ref(), &address).is_none());

        // A machine-level inject is found through the thread...
        let mut machine = TestMachine {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                Arc::new(RecordingCallbacks::default()),
                Arc::new(BytesArithmetic),
                Box::new(nil::<Vec<u8>>()),
                Box::new(nil::<Vec<u8>>()),
                None,
            ),
        };
        machine.base_mut().put_inject(address.clone(), empty_program());
        assert!(f.thread.get_inject(&machine, &address).is_some());
        assert!(f.thread.get_inject(&machine, &other).is_none());

        // ... and a thread-level one at the same address wins.
        f.thread.put_inject(address.clone(), Arc::new(empty_program()));
        assert!(matches!(
            f.thread.get_inject(&machine, &address),
            Some(Inject::Shared(_))
        ));
        assert!(matches!(
            f.thread.get_inject(&machine, &other),
            None
        ));

        // clearInject only affects this thread; the machine's inject is still effective.
        f.thread.clear_inject(&address);
        assert!(matches!(
            f.thread.get_inject(&machine, &address),
            Some(Inject::Borrowed(_))
        ));

        f.thread.put_inject(other.clone(), Arc::new(empty_program()));
        f.thread.clear_all_injects();
        assert!(f.thread.get_inject(&machine, &other).is_none());
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
}
