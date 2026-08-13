//! A JIT-accelerated thread of p-code emulation.
//!
//! Port of `ghidra.pcode.emu.jit.JitPcodeThread`.
//!
//! This type implements the actual JIT-accelerated execution loop. In contrast to the normal
//! per-instruction Fetch-Execute-Store loop inherited from
//! [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread), this
//! thread's [`run`](JitPcodeThread::run) method implements a per-*passage*
//! Fetch-Decode-Translate-Execute loop.
//!
//! # Fetch
//!
//! The Fetch step involves checking the code cache for an existing translation at the thread's
//! current counter and decode context. Cache entries are keyed by *passage entry point*, that is
//! an address (and context reg value, if applicable) within a passage where execution is permitted
//! to enter. This typically consists of the passage's seed as well as each branch target in the
//! same passage. If one is found, we skip the Decode and Translate steps, and proceed directly to
//! Execute.
//!
//! # Decode
//!
//! The Decode step involves decoding and selecting several instructions into a *passage*. A passage
//! may comprise several instructions connected by control flow. Often it is a few long strides of
//! instructions connected by a few branches. The decoder will avoid selecting instructions that are
//! already included in an existing translated passage. For more details, see [`JitPassageDecoder`].
//!
//! # Translate
//!
//! The Translate step involves translating the selected passage of instructions. The result of that
//! translation implements `JitCompiledPassage`. The compiled passage provides a list of its entry
//! points. Each is added to the emulator's code cache. Among those should be the seed required by
//! this iteration of the execution loop, and so that entry point is chosen.
//!
//! # Execute
//!
//! The chosen entry point is then executed. This step is as simple as invoking
//! [`EntryPoint::run`]. That, in turn, invokes the compiled passage's `run(int)`, providing the
//! entry point's index as an argument. The index identifies to the translated passage the desired
//! address of entry, and so it jumps directly to the corresponding translation. When control flow
//! exits the passage, the method returns, and the loop repeats.
//!
//! # Deviations from the Java source
//!
//! * Java `extends BytesPcodeThread`, and so inherits the whole
//!   [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread) machinery:
//!   the counter, context, suspension flag, injects map, interpretation frame, and multiplexed
//!   thread state. This crate's [`BytesPcodeThread`](crate::pcode::emu::bytes_pcode_thread) is
//!   presently a name-only marker, and `DefaultPcodeThread` cannot be embedded here, since building
//!   one demands an `Arc<dyn AbstractPcodeMachine<_>>` plus both executor states -- neither of
//!   which [`JitPcodeEmulator::create_thread`](crate::pcode::emu::jit::jit_pcode_emulator) can hand
//!   a thread it constructs from a bare name. This type therefore carries the few inherited members
//!   its own methods read or write (name, machine, counter, context, suspension, injects) directly.
//!   Two consequences are visible in the API:
//!   * [`write_counter`](JitPcodeThread::write_counter) and
//!     [`write_context`](JitPcodeThread::write_context) record the value but do not write the pc and
//!     contextreg of the thread's machine state, because this thread does not yet own one. They are
//!     thus presently indistinguishable from [`set_counter`](JitPcodeThread::set_counter) and its
//!     context counterpart; the two names are kept apart because the callers Java distinguishes --
//!     `writeCounterAndContext` versus `setCounterAndContext` -- are ported as written.
//!   * The interpretation frame is not modeled, so [`run`](JitPcodeThread::run) has nothing to
//!     answer Java's opening `if (frame != null) { finishInstruction(); }` with.
//! * Java's constructor takes the machine, from which it derives everything else. Nothing in this
//!   crate can produce an `Arc<JitPcodeEmulator>` from the `&self` that `createThread` is handed, so
//!   the machine is optional: [`with_machine`](JitPcodeThread::with_machine) is the port of Java's
//!   constructor, and [`named`](JitPcodeThread::named) is what `create_thread` can actually build.
//!   [`new`](JitPcodeThread::new) takes the pieces [`JitPassageDecoder`] reads, for the same reason:
//!   the real `createInstructionDecoder` needs the unported `SleighInstructionDecoder`.
//! * Java's `passageDecoder` is built in the constructor. Here it is built on first use, because
//!   [`JitPassageDecoder::new`] requires an [`InstructionDecoder`], which a thread built by
//!   [`named`](JitPcodeThread::named) does not have.
//! * Java's decoder holds a reference back to the very thread that owns it. Rust has no such
//!   ownership cycle, so this type's state lives behind shared handles and [`Clone`] yields another
//!   reference to the *same* thread, exactly as copying a Java reference does. The only field not
//!   shared is the lazily built passage decoder, which a clone rebuilds on demand -- that is what
//!   keeps the cycle from closing.
//! * `getMachine()` and `getState()` are covariant-return narrowings in Java. Rust has no covariant
//!   return: [`get_machine`](JitPcodeThread::get_machine) is ported because this type is where the
//!   machine is actually stored, while `getState()` is not, since the state it would narrow
//!   (`JitThreadBytesPcodeExecutorState`) is not yet owned by any thread. The factory that produces
//!   it, [`create_thread_state`](JitPcodeThread::create_thread_state), is ported: Java's override
//!   exists to assert both halves are `JitDefaultBytesPcodeExecutorState`, which this port states in
//!   the parameter types instead of by a cast.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine;
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder;
use crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator;
use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::pcode::seam_stubs::{
    AddrCtx, EntryPoint, JitDefaultBytesPcodeExecutorState, JitThreadBytesPcodeExecutorState,
    RegisterValue, SleighProgramCompiler, SuspendedPcodeExecutionException,
};
use crate::program::model::address::Address;
use crate::program::model::address::AddressFactory;
use crate::program::model::listing::program_context::ProgramContext;

/// Copy a p-code program, which [`PcodeProgram`] does not itself implement.
///
/// Java hands out the very same `PcodeProgram` object an inject was compiled into. Here the inject
/// is owned by the thread (or the machine), so the caller gets an equivalent program: same
/// language, same code, same userop names.
fn copy_program(program: &PcodeProgram) -> PcodeProgram {
    PcodeProgram::from_program(program, program.code().to_vec())
}

/// A JIT-accelerated thread of p-code emulation.
///
/// Port of `ghidra.pcode.emu.jit.JitPcodeThread`. See the module docs for the loop it implements
/// and for how it stands in for the state Java inherits from `BytesPcodeThread`.
pub struct JitPcodeThread {
    /// The thread's name, as `BytesPcodeThread` inherits it from `DefaultPcodeThread`.
    name: String,
    /// The machine that created this thread. Port of the inherited `machine` field, narrowed by
    /// Java's `getMachine()` override. `None` for a thread built without one; see the module docs.
    machine: Option<Arc<JitPcodeEmulator>>,
    /// This thread's instruction decoder, as `getDecoder()` exposes it to the passage decoder. Port
    /// of the inherited `decoder` field. `None` until `SleighInstructionDecoder` is ported.
    decoder: Option<Arc<Mutex<dyn InstructionDecoder>>>,
    /// The language's default program context, as `getDefaultContext()` exposes it to the passage
    /// decoder. Port of the inherited `defaultContext` field.
    default_context: Option<Arc<dyn ProgramContext>>,
    /// This thread's userop library. Port of the inherited `library` field.
    userop_library: Arc<dyn PcodeUseropLibrary<Vec<u8>>>,
    /// This thread's p-code injections, keyed by address. Port of the inherited `injects` field.
    injects: Arc<Mutex<HashMap<Address, Arc<PcodeProgram>>>>,
    /// This thread's cache of translations instantiated for this thread. Port of the `codeCache`
    /// field.
    ///
    /// As an optimization, the translator generates classes which pre-fetch portions of the
    /// thread's state. Thus, the class must be instantiated for each particular thread needing to
    /// execute it.
    ///
    /// Entries are never invalidated, matching Java. Expiration, eviction, and invalidation of an
    /// `EntryPointPrototype` from the emulator would all be reasons to want it.
    code_cache: Arc<Mutex<HashMap<AddrCtx, EntryPoint>>>,
    /// The program counter. Port of the inherited `counter` field, which Java initializes from the
    /// language's default space; a thread built without a machine has no language, hence `None`.
    counter: Arc<Mutex<Option<Address>>>,
    /// The decode context. Port of the inherited `context` field.
    context: Arc<Mutex<Option<Arc<dyn RegisterValue>>>>,
    /// Whether execution is suspended. Port of the inherited executor's suspension flag, which
    /// `setSuspended`/`isSuspended` reach.
    suspended: Arc<AtomicBool>,
    /// This thread's passage decoder, which is based on its [`get_decoder`](Self::get_decoder)
    /// instruction decoder. Port of the `passageDecoder` field; built on first use, and
    /// deliberately not shared by [`Clone`]. See the module docs.
    passage_decoder: OnceLock<Box<JitPassageDecoder>>,
}

impl JitPcodeThread {
    /// Construct a thread from the pieces the passage decoder reads.
    ///
    /// Java's sole constructor derives all of these from the machine; this one is for the callers
    /// that have an [`InstructionDecoder`] but no [`JitPcodeEmulator`] -- notably any test standing
    /// a [`JitPassageDecoder`] up on its own. The thread has no machine, so it can neither look up
    /// entry points nor [`run`](Self::run).
    pub fn new(
        decoder: Arc<Mutex<dyn InstructionDecoder>>,
        default_context: Option<Arc<dyn ProgramContext>>,
        userop_library: Arc<dyn PcodeUseropLibrary<Vec<u8>>>,
    ) -> Self {
        Self {
            name: String::new(),
            machine: None,
            decoder: Some(decoder),
            default_context,
            userop_library,
            ..Self::empty()
        }
    }

    /// Construct a thread with only a name.
    ///
    /// This is what
    /// [`JitPcodeEmulator::create_thread`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator)
    /// can build: it holds no `Arc` of itself to pass on, and the decoder Java's constructor would
    /// build needs the unported `SleighInstructionDecoder`. See
    /// [`with_machine`](Self::with_machine) for the full port of Java's constructor.
    pub fn named(name: &str) -> Self {
        Self { name: name.to_string(), ..Self::empty() }
    }

    /// Create a thread.
    ///
    /// This should only be called by the emulator and its test suites.
    ///
    /// # Arguments
    /// * `name` - the name of the thread
    /// * `machine` - the machine creating the thread
    ///
    /// Port of `JitPcodeThread(String, JitPcodeEmulator)`. What Java's `super(name, machine)`
    /// computes and this cannot -- the decoder (`SleighInstructionDecoder`), the composed userop
    /// library, and the thread's multiplexed state -- is left absent; see the module docs. The
    /// counter is seeded from the machine's language exactly as `DefaultPcodeThread`'s constructor
    /// seeds it.
    pub fn with_machine(name: &str, machine: Arc<JitPcodeEmulator>) -> Self {
        let counter = PcodeMachine::get_language(machine.as_ref())
            .get_address_factory()
            .get_default_address_space()
            .expect("language has no default address space")
            .address(0);
        Self {
            name: name.to_string(),
            machine: Some(machine),
            counter: Arc::new(Mutex::new(Some(counter))),
            ..Self::empty()
        }
    }

    /// The shared shape every constructor starts from: no machine, no decoder, no context, an empty
    /// userop library, and empty caches.
    fn empty() -> Self {
        Self {
            name: String::new(),
            machine: None,
            decoder: None,
            default_context: None,
            userop_library: Arc::new(nil()),
            injects: Arc::new(Mutex::new(HashMap::new())),
            code_cache: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(Mutex::new(None)),
            context: Arc::new(Mutex::new(None)),
            suspended: Arc::new(AtomicBool::new(false)),
            passage_decoder: OnceLock::new(),
        }
    }

    /// Port of the inherited `PcodeThread.getName()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The machine that created this thread, if it was created by one.
    ///
    /// Port of `getMachine()`, which in Java is the inherited getter narrowed to
    /// [`JitPcodeEmulator`].
    pub fn get_machine(&self) -> Option<&Arc<JitPcodeEmulator>> {
        self.machine.as_ref()
    }

    /// The machine, or a panic naming what is missing. Every Java call site reaches the machine
    /// through the constructor's non-null argument.
    fn require_machine(&self) -> &Arc<JitPcodeEmulator> {
        self.machine
            .as_ref()
            .expect("this thread was not created by a JitPcodeEmulator, so it has no machine")
    }

    /// An accessor so the passage decoder can retrieve its thread's instruction decoder.
    ///
    /// Port of `getDecoder()`.
    ///
    /// # Panics
    ///
    /// If this thread has no decoder, i.e. it was not built by [`new`](Self::new). Java's
    /// constructor always builds a `SleighInstructionDecoder`, which is not ported.
    pub fn get_decoder(&self) -> Arc<Mutex<dyn InstructionDecoder>> {
        Arc::clone(
            self.decoder
                .as_ref()
                .expect("SleighInstructionDecoder is not ported, so a named thread has no decoder"),
        )
    }

    /// An accessor so the passage decoder can query the language's default program context.
    ///
    /// Port of `getDefaultContext()`.
    pub fn get_default_context(&self) -> Option<Arc<dyn ProgramContext>> {
        self.default_context.clone()
    }

    /// Port of the inherited `PcodeThread.getUseropLibrary()`.
    pub fn get_userop_library(&self) -> Arc<dyn PcodeUseropLibrary<Vec<u8>>> {
        Arc::clone(&self.userop_library)
    }

    /// Multiplex the machine's shared state and this thread's local state.
    ///
    /// Port of the overridden `createThreadState(PcodeExecutorState<byte[]>,
    /// PcodeExecutorState<byte[]>)`, whose whole content is a cast of both halves to
    /// [`JitDefaultBytesPcodeExecutorState`] -- stated here in the parameter types. It reads no
    /// instance state, so it is an associated function.
    pub fn create_thread_state(
        shared_state: JitDefaultBytesPcodeExecutorState,
        local_state: JitDefaultBytesPcodeExecutorState,
    ) -> JitThreadBytesPcodeExecutorState {
        JitThreadBytesPcodeExecutorState::new(shared_state, local_state)
    }

    /// Create the passage decoder.
    ///
    /// This is an extension point in case the decoder needs to be replaced with a further
    /// extension.
    ///
    /// Port of `createPassageDecoder()`. The decoder is handed another reference to this thread;
    /// see the module docs on [`Clone`].
    ///
    /// # Panics
    ///
    /// If this thread has no [`InstructionDecoder`]; see [`get_decoder`](Self::get_decoder).
    pub fn create_passage_decoder(&self) -> JitPassageDecoder {
        JitPassageDecoder::new(self.clone())
    }

    /// This thread's passage decoder, built on first use.
    ///
    /// Port of reading the `passageDecoder` field, which Java assigns in its constructor.
    ///
    /// # Panics
    ///
    /// If this thread has no [`InstructionDecoder`]; see [`get_decoder`](Self::get_decoder).
    pub fn passage_decoder(&self) -> &JitPassageDecoder {
        self.passage_decoder.get_or_init(|| Box::new(self.create_passage_decoder()))
    }

    /// Get the p-code injected at the given address, if any.
    ///
    /// Port of the `@Internal` override of `getInject(Address)`, whose body is `super.getInject`:
    /// the callbacks are consulted first, then this thread's injects, then the machine's.
    pub fn get_inject(&self, address: &Address) -> Option<PcodeProgram> {
        if let Some(machine) = &self.machine {
            if let Some(inject) = machine.base().callbacks().get_inject(self, address) {
                return Some(copy_program(&inject));
            }
        }
        if let Some(inject) = self.injects.lock().expect("injects poisoned").get(address) {
            return Some(copy_program(inject));
        }
        self.machine.as_ref().and_then(|m| m.get_inject(address).map(copy_program))
    }

    /// Inject p-code, compiled from the given Sleigh source, at the given address.
    ///
    /// Port of the override of `inject(Address, String)`, whose body is `super.inject`. Java's
    /// javadoc leaves open whether the code cache ought to be flushed here; it is not, on the
    /// reasoning that only the passages containing the address would need to go, and that the
    /// caching algorithm can work out the new entries an inject may introduce.
    ///
    /// # Panics
    ///
    /// If this thread has no machine, since the source is compiled against its language.
    pub fn inject(&self, address: &Address, source: &str) {
        let machine = self.require_machine();
        let program = SleighProgramCompiler::compile_program(
            PcodeMachine::get_language(machine.as_ref()),
            &format!("thread_inject:{address}"),
            source,
            self.userop_library.as_ref(),
        );
        self.injects
            .lock()
            .expect("injects poisoned")
            .insert(address.clone(), Arc::new(program));
    }

    /// Check if the *emulator* has an entry prototype for the given address and contextreg value.
    ///
    /// This simply passes through to the emulator. It does not matter whether or not this thread
    /// has instantiated the prototype. If any thread has caused the emulator to translate the given
    /// entry, this will return true.
    ///
    /// # Arguments
    /// * `pc_ctx` - the address and contextreg to check
    ///
    /// # Returns
    /// true if the emulator has a translation which can be entered at the given `pc_ctx`. A thread
    /// with no machine has no translations at all, so it answers false.
    ///
    /// Port of `hasEntry(AddrCtx)`. See
    /// [`JitPcodeEmulator::has_entry_prototype`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator::has_entry_prototype).
    pub fn has_entry(&self, pc_ctx: &AddrCtx) -> bool {
        self.machine.as_ref().is_some_and(|m| m.has_entry_prototype(pc_ctx))
    }

    /// Get the translated and instantiated entry point for the given address and contextreg value.
    ///
    /// An **entry point** is an instance of a class representing a translated passage and an index
    /// identifying the point at which to enter the passage. In essence, it is an instance of an
    /// **entry prototype** for this thread.
    ///
    /// This will first check the cache for an existing instance. Then, it will delegate to the
    /// emulator. The emulator will check its cache for an existing translation. If one is found, we
    /// simply take it and instantiate it for this thread. Otherwise, the emulator translates a new
    /// passage at the given seed, and we instantiate it for this thread.
    ///
    /// Placeholders are not needed at the thread level, but at the machine level.
    ///
    /// # Arguments
    /// * `pc_ctx` - the counter and decoder context
    ///
    /// # Panics
    ///
    /// If this thread has no machine to translate the passage.
    ///
    /// Port of `getEntry(AddrCtx)`. Java's `computeIfAbsent` holds the map while the emulator
    /// translates; this releases it, since a compiled passage may ask its own thread for a chained
    /// entry point, which would otherwise deadlock. The re-check on insert keeps the first instance
    /// to land, so all callers still share one instance per entry point.
    pub fn get_entry(&self, pc_ctx: &AddrCtx) -> EntryPoint {
        if let Some(entry) = self.code_cache.lock().expect("code cache poisoned").get(pc_ctx) {
            return entry.clone();
        }
        let prototype =
            self.require_machine().get_entry_prototype(pc_ctx, self.passage_decoder());
        let entry = prototype.create_instance(self);
        self.code_cache
            .lock()
            .expect("code cache poisoned")
            .entry(pc_ctx.clone())
            .or_insert(entry)
            .clone()
    }

    /// Run this thread, translating passages as needed.
    ///
    /// Only this method is overridden to accelerate execution using JIT translation. Implementing
    /// single stepping via JIT doesn't make much sense from an efficiency standpoint. However, this
    /// thread still supports stepping via interpretation (as inherited). Mixing the two execution
    /// paradigms is permitted; however, using JIT after a few single steps will incur some waste as
    /// the JIT translates an otherwise uncommon entry point.
    ///
    /// # Panics
    ///
    /// If this thread has no machine, i.e. as soon as it needs an entry point.
    ///
    /// Port of the overridden `run()`. Java first finishes any partially executed instruction; this
    /// port models no interpretation frame, so there is never one to finish -- see the module docs.
    pub fn run(&self) {
        self.set_suspended(false);
        let mut next: Option<EntryPoint> = None;
        while !self.is_suspended() && !self.is_machine_suspended() {
            if next.is_none() {
                let counter = self.get_counter().expect("thread has no program counter");
                next = Some(self.get_entry(&AddrCtx::new(self.get_context(), counter)));
            }
            match next.as_ref().expect("an entry point was just fetched").run() {
                Ok(entry) => next = Some(entry),
                // Cool. Java's `catch (SuspendedPcodeExecutionException e)` leaves `next` as it
                // was, since the assignment never happened.
                Err(_suspended) => {}
            }
        }
    }

    /// This is called before each basic block is executed.
    ///
    /// This gives the thread an opportunity to track and control execution, if desired. It provides
    /// the number of instructions and additional p-code ops about to be completed. If the counts
    /// exceed a desired schedule, or if the thread is suspended, this interrupts execution. This can
    /// be toggled in the emulator's configuration -- see `JitConfiguration::emit_counters`.
    ///
    /// # Arguments
    /// * `instructions` - the number of instructions about to be completed
    /// * `trailing_ops` - the number of ops of a final partial instruction about to be completed. If
    ///   the block does not complete any instruction, this is the number of ops continuing in the
    ///   current (partial) instruction.
    ///
    /// Port of `count(int, int)`, whose thrown `SuspendedPcodeExecutionException` is an `Err` here.
    pub fn count(
        &self,
        _instructions: i32,
        _trailing_ops: i32,
    ) -> Result<(), SuspendedPcodeExecutionException> {
        if self.is_suspended() || self.is_machine_suspended() {
            return Err(SuspendedPcodeExecutionException::new(None));
        }
        Ok(())
    }

    /// Write the given counter and context to the emulator and its machine state.
    ///
    /// # Arguments
    /// * `counter` - the counter
    /// * `context` - the context
    ///
    /// Port of `writeCounterAndContext(Address, RegisterValue)`. Note this is deliberately not
    /// `overrideCounter`/`overrideContext`: things can override those.
    pub fn write_counter_and_context(
        &self,
        counter: &Address,
        context: Option<Arc<dyn RegisterValue>>,
    ) {
        self.write_counter(counter);
        if let Some(context) = context {
            self.write_context(context);
        }
    }

    /// Set the emulator's counter and context without affecting its machine state.
    ///
    /// The reasons for doing this are a bit nuanced and they deal in the setting of the pc by p-code
    /// ops whilst it also makes hazardous userop invocations. The intended value of the pc may not
    /// survive if it gets clobbered with the current counter before execution reaches the "goto pc".
    ///
    /// # Arguments
    /// * `counter` - the counter
    /// * `context` - the context
    ///
    /// Port of `setCounterAndContext(Address, RegisterValue)`. As in Java, the context is *written*
    /// rather than assigned: state modifiers expect the contextreg to be in the machine state.
    pub fn set_counter_and_context(
        &self,
        counter: &Address,
        context: Option<Arc<dyn RegisterValue>>,
    ) {
        self.set_counter(counter);
        if let Some(context) = context {
            self.write_context(context);
        }
    }

    /// Port of the inherited `PcodeThread.setCounter(Address)`: set the counter field alone.
    pub fn set_counter(&self, counter: &Address) {
        *self.counter.lock().expect("counter poisoned") = Some(counter.clone());
    }

    /// Port of the inherited `PcodeThread.getCounter()`. `None` before any counter is set; see the
    /// module docs.
    pub fn get_counter(&self) -> Option<Address> {
        self.counter.lock().expect("counter poisoned").clone()
    }

    /// Port of the inherited `DefaultPcodeThread.writeCounter(Address)`: set the counter, and write
    /// the pc register of this thread's state -- which this port cannot yet do; see the module docs.
    pub fn write_counter(&self, counter: &Address) {
        self.set_counter(counter);
    }

    /// Port of the inherited `PcodeThread.getContext()`.
    pub fn get_context(&self) -> Option<Arc<dyn RegisterValue>> {
        self.context.lock().expect("context poisoned").clone()
    }

    /// Port of the inherited `DefaultPcodeThread.writeContext(RegisterValue)`: adjust the context,
    /// and write the contextreg of this thread's state -- which this port cannot yet do; see the
    /// module docs.
    pub fn write_context(&self, context: Arc<dyn RegisterValue>) {
        *self.context.lock().expect("context poisoned") = Some(context);
    }

    /// Port of the inherited `PcodeThread.setSuspended(boolean)`.
    pub fn set_suspended(&self, suspended: bool) {
        self.suspended.store(suspended, Ordering::SeqCst);
    }

    /// Port of the inherited `PcodeThread.isSuspended()`.
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Port of `getMachine().isSuspended()`. A thread with no machine has nothing to suspend it.
    fn is_machine_suspended(&self) -> bool {
        self.machine.as_ref().is_some_and(|m| PcodeMachine::is_suspended(m.as_ref()))
    }
}

/// Another reference to the *same* thread: all state is shared, exactly as copying a Java reference
/// shares it. The lazily built passage decoder is the one exception -- a clone builds its own on
/// demand -- which is what keeps the thread/decoder cycle from closing. See the module docs.
impl Clone for JitPcodeThread {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            machine: self.machine.clone(),
            decoder: self.decoder.clone(),
            default_context: self.default_context.clone(),
            userop_library: Arc::clone(&self.userop_library),
            injects: Arc::clone(&self.injects),
            code_cache: Arc::clone(&self.code_cache),
            counter: Arc::clone(&self.counter),
            context: Arc::clone(&self.context),
            suspended: Arc::clone(&self.suspended),
            passage_decoder: OnceLock::new(),
        }
    }
}

/// Java reaches this through `JitPcodeThread extends BytesPcodeThread ... implements
/// PcodeThread<byte[]>`; here it is what
/// [`JitPcodeEmulator::create_thread`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator)
/// must return, exactly as [`BytesPcodeThread`](crate::pcode::emu::bytes_pcode_thread) does for
/// [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
impl ErasedPcodeThread for JitPcodeThread {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, UseropMap};
    use crate::program::model::lang::language::Language;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct DummyDecoder;

    impl InstructionDecoder for DummyDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn crate::pcode::seam_stubs::PseudoInstruction>, Box<dyn std::error::Error>>
        {
            unimplemented!("not exercised by these tests")
        }

        fn branched(&mut self, _address: &Address) {
            unimplemented!("not exercised by these tests")
        }

        fn get_last_instruction(
            &self,
        ) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            unimplemented!("not exercised by these tests")
        }

        fn get_last_length_with_delays(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockUseropLibrary {
        userops: UseropMap<Vec<u8>>,
    }
    impl ErasedPcodeUseropLibrary for MockUseropLibrary {}
    impl PcodeUseropLibrary<Vec<u8>> for MockUseropLibrary {
        fn get_userops(&self) -> &UseropMap<Vec<u8>> {
            &self.userops
        }
    }

    /// A contextreg value, as `AddrCtx` reduces it.
    struct Ctx(i128);
    impl RegisterValue for Ctx {
        fn get_unsigned_value(&self) -> i128 {
            self.0
        }
    }

    fn ram(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    fn thread_with_decoder() -> JitPcodeThread {
        let library: Arc<dyn PcodeUseropLibrary<Vec<u8>>> =
            Arc::new(MockUseropLibrary { userops: UseropMap::new() });
        JitPcodeThread::new(Arc::new(Mutex::new(DummyDecoder)), None, library)
    }

    #[test]
    fn a_thread_with_no_machine_knows_of_no_entry_points() {
        // Java: `hasEntry(pcCtx)` is `getMachine().hasEntryPrototype(pcCtx)`, and a machine that has
        // translated nothing answers false. Neither can a thread with no machine at all.
        let thread = JitPcodeThread::named("Thread 0");
        assert_eq!("Thread 0", thread.name());
        assert!(thread.get_machine().is_none());
        assert!(!thread.has_entry(&AddrCtx::new(None, ram(0x400))));
        assert!(thread.get_inject(&ram(0x400)).is_none());
    }

    #[test]
    fn count_interrupts_a_suspended_thread() {
        // Java: `count` throws SuspendedPcodeExecutionException iff the thread or its machine is
        // suspended; otherwise it returns normally, whatever the counts.
        let thread = JitPcodeThread::named("t");
        assert!(thread.count(3, 0).is_ok());
        assert!(thread.count(0, 12).is_ok());

        thread.set_suspended(true);
        let interrupted = thread.count(3, 0).expect_err("a suspended thread must not proceed");
        assert_eq!("Execution suspended by user", interrupted.message());

        thread.set_suspended(false);
        assert!(thread.count(3, 0).is_ok());
    }

    #[test]
    fn write_counter_and_context_keeps_the_context_when_given_none() {
        // Java: both writeCounterAndContext and setCounterAndContext guard with
        // `if (context != null)`, so a null context leaves the thread's context as it was.
        let thread = JitPcodeThread::named("t");
        assert!(thread.get_counter().is_none());
        assert!(thread.get_context().is_none());

        thread.write_counter_and_context(&ram(0x1000), Some(Arc::new(Ctx(7))));
        assert_eq!(Some(ram(0x1000)), thread.get_counter());
        assert_eq!(7, thread.get_context().expect("context was written").get_unsigned_value());

        thread.write_counter_and_context(&ram(0x1004), None);
        assert_eq!(Some(ram(0x1004)), thread.get_counter());
        assert_eq!(7, thread.get_context().expect("context is unchanged").get_unsigned_value());

        thread.set_counter_and_context(&ram(0x2000), Some(Arc::new(Ctx(9))));
        assert_eq!(Some(ram(0x2000)), thread.get_counter());
        assert_eq!(9, thread.get_context().expect("context was written").get_unsigned_value());
    }

    #[test]
    fn run_unsuspends_the_thread_before_fetching_an_entry_point() {
        // Java: `run()` opens with `setSuspended(false)`, so a thread suspended by an earlier run
        // resumes rather than returning immediately. It then needs an entry point, which this
        // machine-less thread cannot get.
        let thread = JitPcodeThread::named("t");
        thread.set_suspended(true);
        thread.set_counter(&ram(0x400));

        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| thread.run()))
            .expect_err("a thread with no machine cannot translate a passage");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(message.contains("no machine"), "unexpected failure: {message}");
        assert!(!thread.is_suspended(), "run() must clear the suspension flag first");
    }

    #[test]
    fn the_passage_decoder_reads_this_threads_decoder_and_shares_its_state() {
        // Java: `createPassageDecoder()` is `new JitPassageDecoder(this)`, and the decoder reads the
        // thread's own instruction decoder and asks it about entry points. Here the decoder holds
        // another reference to the same thread, so what it sees must track the original.
        let thread = thread_with_decoder();
        assert!(!thread.passage_decoder().thread_has_entry(&AddrCtx::new(None, ram(0x400))));
        assert!(thread.passage_decoder().thread_get_inject(&ram(0x400)).is_none());

        let same_thread = thread.clone();
        same_thread.set_counter(&ram(0x800));
        assert_eq!(Some(ram(0x800)), thread.get_counter());
        same_thread.set_suspended(true);
        assert!(thread.is_suspended());
    }
}
