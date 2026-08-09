//! An abstract implementation of [`PcodeMachine`] suitable as a base for most implementations.
//!
//! Corresponds to `ghidra.pcode.emu.AbstractPcodeMachine`.
//!
//! A note regarding terminology: a p-code "machine" refers to any p-code-based machine simulator,
//! whether or not it operates on abstract or concrete values. The term "emulator" is reserved for
//! machines whose values always include a concrete piece. That piece doesn't necessarily have to
//! be a (derivative of) `BytesPcodeExecutorStatePiece`, but it usually is. To be called an
//! "emulator" implies that [`PcodeArithmetic::to_concrete`] never fails for any value in its
//! state.
//!
//! Java's abstract class carries both state and behavior, so this port splits it in two, following
//! the convention already used by
//! [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece):
//!
//! * [`AbstractPcodeMachineBase`] holds the fields and the concrete behavior. Behavior that Java
//!   expresses with a virtual call on `this` (e.g. `newThread` calling `createThread`) appears as
//!   an associated function taking the machine itself, since the base alone cannot dispatch to the
//!   subclass.
//! * [`AbstractPcodeMachine`] declares only the operations Java leaves abstract (or overridable
//!   after construction), plus accessors for the embedded base.
//!
//! A concrete machine embeds the base, implements this trait, and implements [`PcodeMachine`] by
//! forwarding each method to the base field method or associated function of the same name.
//!
//! Deviations from the Java source, all forced by construction order or by types this crate has
//! not ported yet:
//!
//! * `assertSleigh(Language)` has no Rust analogue: `SleighLanguage` is not an implementor of
//!   [`Language`] here, so there is nothing to downcast. The check it performs -- "Emulation
//!   requires a sleigh language" -- is instead enforced by [`AbstractPcodeMachineBase::new`]
//!   taking an `Arc<SleighLanguage>`, i.e. at compile time.
//! * Java's constructor calls the overridable factories `createArithmetic`,
//!   `createUseropLibrary`, and `createThreadStubLibrary` on a half-built `this`. Rust has no
//!   such call, so those three products are parameters of [`AbstractPcodeMachineBase::new`]; the
//!   concrete machine computes them before constructing its base. The default
//!   `createUseropLibrary` is available as
//!   [`AbstractPcodeMachineBase::create_userop_library`]. There is no default
//!   `createThreadStubLibrary`, because Java's is
//!   `DefaultPcodeThread.PcodeEmulationLibrary`, which is not ported yet.
//! * Likewise, `cb.emulatorCreated(this)` cannot run inside the constructor, since `this` does not
//!   exist yet; the machine calls [`AbstractPcodeMachineBase::notify_emulator_created`] once it is
//!   whole.
//! * Java's `getSharedState()` creates the state on first call. Creating it mutates the machine,
//!   so the lazy path is [`AbstractPcodeMachineBase::get_shared_state`], which takes `&mut`;
//!   [`AbstractPcodeMachineBase::shared_state`] is the read-only view, empty until then.
//! * `threadsView`, Java's unmodifiable wrapper around the thread map, has no purpose here: the
//!   base's `threads` field is private and [`AbstractPcodeMachineBase::get_all_threads`] hands
//!   back handles, not the collection.
//! * `checkLoad`/`checkStore`/`swi` throw `InterruptPcodeExecutionException`; here they return it
//!   as an `Err`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::emu::pcode_machine::{AccessKind, PcodeMachine, SwiMode};
use crate::pcode::emu::pcode_state_initializer::PcodeStateInitializer;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::exec::pcode_userop_library_factory::{
    create_userop_library_for_language, PcodeUseropLibraryFactory,
};
use crate::pcode::emu::pcode_emulation_callbacks::PcodeEmulationCallbacks;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::seam_stubs::{
    InterruptPcodeExecutionException, PcodeProgram, SleighProgramCompiler, SparseAddressRangeMap,
};
use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::SleighLanguage;

/// Search the given initializers for one applicable to the given language.
///
/// Port of the static `getPluggableInitializer(Language)`. If found, the initializer is executed
/// immediately upon creating the machine's shared state and upon creating each thread.
///
/// Java discovers the candidates with `ClassSearcher`, a classpath scan. Rust has no such scan;
/// following the convention already used for
/// [`PcodeUseropLibraryFactory`](crate::pcode::exec::pcode_userop_library_factory), the candidates
/// arrive as an explicit slice.
///
/// Deprecated in Java for removal since 12.0: the mechanism is not really used anymore.
#[deprecated(note = "Java marks this for removal since 12.0; it is not really used")]
pub fn get_pluggable_initializer(
    language: &dyn Language,
    initializers: &[Arc<dyn PcodeStateInitializer>],
) -> Option<Arc<dyn PcodeStateInitializer>> {
    initializers
        .iter()
        .find(|init| init.is_applicable(language))
        .cloned()
}

/// The shared state and concrete behavior of a p-code machine.
///
/// `T` is the type of objects in the machine's state.
pub struct AbstractPcodeMachineBase<T: 'static> {
    language: Arc<SleighLanguage>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    library: Box<dyn PcodeUseropLibrary<T>>,
    stub_library: Box<dyn PcodeUseropLibrary<T>>,
    swi_mode: SwiMode,
    /// The pluggable initializer, if any, found for this machine's language. Java gives this
    /// package-private visibility "for abstract thread access"; threads live in the same module
    /// tree here, so it is public.
    pub initializer: Option<Arc<dyn PcodeStateInitializer>>,
    shared_state: Option<Box<dyn PcodeExecutorState<T>>>,
    /// Java uses a `LinkedHashMap`, i.e. keyed by name but iterated in insertion order. Machines
    /// hold a handful of threads, so a vector of pairs gives the same two behaviors without a
    /// second collection.
    threads: Vec<(String, Arc<dyn ErasedPcodeThread>)>,
    /// Java declares this `volatile`, for a thread suspending a machine another thread is
    /// stepping. [`PcodeMachine::set_suspended`] takes `&mut self`, so exclusive access is already
    /// required to write it and a plain `bool` suffices.
    suspended: bool,
    injects: HashMap<Address, Box<dyn PcodeProgram>>,
    access_breakpoints: SparseAddressRangeMap<AccessKind>,
    cb: Arc<dyn PcodeEmulationCallbacks<T>>,
}

impl<T: 'static> AbstractPcodeMachineBase<T> {
    /// Construct the base of a p-code machine with the given language and arithmetic.
    ///
    /// Port of `AbstractPcodeMachine(Language, PcodeEmulationCallbacks)`. `arithmetic`, `library`,
    /// and `thread_stub_library` are the products of Java's `createArithmetic()`,
    /// `createUseropLibrary()`, and `createThreadStubLibrary()`, which it calls on `this` from
    /// within the constructor; `initializer` is the product of
    /// [`get_pluggable_initializer`]. The stub library exposed by
    /// [`get_stub_userop_library`](Self::get_stub_userop_library) is `thread_stub_library`
    /// composed with `library`, exactly as in Java.
    ///
    /// The machine must call [`notify_emulator_created`](Self::notify_emulator_created) once it is
    /// fully constructed; that is Java's `cb.emulatorCreated(this)`.
    ///
    /// The shared state is deliberately *not* created here. See
    /// [`get_shared_state`](Self::get_shared_state).
    pub fn new(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<T>>,
        arithmetic: Arc<dyn PcodeArithmetic<T>>,
        library: Box<dyn PcodeUseropLibrary<T>>,
        thread_stub_library: Box<dyn PcodeUseropLibrary<T>>,
        initializer: Option<Arc<dyn PcodeStateInitializer>>,
    ) -> Self {
        let stub_library = thread_stub_library.compose(library.as_ref());
        Self {
            language,
            arithmetic,
            library,
            stub_library,
            swi_mode: SwiMode::Active,
            initializer,
            shared_state: None,
            threads: Vec::new(),
            suspended: false,
            injects: HashMap::new(),
            access_breakpoints: SparseAddressRangeMap::new(),
            cb,
        }
    }

    /// Create the userop library shared by all threads in a machine of the given language.
    ///
    /// Port of the default `createUseropLibrary()`. `useroplib_ids` and `factories` stand in for
    /// what Java reads from the language's pspec and discovers on the classpath -- see
    /// [`create_userop_library_for_language`].
    pub fn create_userop_library(
        language: &SleighLanguage,
        arithmetic: &dyn PcodeArithmetic<T>,
        useroplib_ids: &str,
        factories: &[&dyn PcodeUseropLibraryFactory<T>],
    ) -> Box<dyn PcodeUseropLibrary<T>> {
        create_userop_library_for_language(language, arithmetic, useroplib_ids, factories)
    }

    /// Get the machine's language. Port of `getLanguage()`.
    pub fn get_language(&self) -> &SleighLanguage {
        &self.language
    }

    /// Get the machine's language as a shared handle, for the threads and states that must retain
    /// it beyond a borrow of the machine.
    pub fn language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }

    /// Get the arithmetic applied by the machine. Port of `getArithmetic()`.
    pub fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    /// Get the userop library common to all threads in the machine. Port of `getUseropLibrary()`.
    pub fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T> {
        self.library.as_ref()
    }

    /// Get the library declaring all userops available in each thread's library. Port of
    /// `getStubUseropLibrary()`.
    pub fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<T> {
        self.stub_library.as_ref()
    }

    /// Change the efficacy of p-code breakpoints. Port of `setSoftwareInterruptMode(SwiMode)`.
    pub fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
        self.swi_mode = mode;
    }

    /// Get the current software interrupt mode. Port of `getSoftwareInterruptMode()`.
    pub fn get_software_interrupt_mode(&self) -> SwiMode {
        self.swi_mode
    }

    /// Get the callbacks receiving this machine's emulation events.
    pub fn callbacks(&self) -> &Arc<dyn PcodeEmulationCallbacks<T>> {
        &self.cb
    }

    /// Collect all threads present in the machine, in creation order. Port of `getAllThreads()`.
    pub fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
        self.threads.iter().map(|(_, t)| Arc::clone(t)).collect()
    }

    /// Get the thread with the given name, if it is present. This is Java's `threads.get(name)`,
    /// i.e. `getThread(name, false)`.
    pub fn get_thread_by_name(&self, name: &str) -> Option<Arc<dyn ErasedPcodeThread>> {
        self.threads
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| Arc::clone(t))
    }

    /// Get the machine's shared (memory) state, if it has been created.
    ///
    /// Java's `getSharedState()` creates the state on demand; that path is
    /// [`get_shared_state`](Self::get_shared_state), which needs `&mut`. This is the read-only
    /// view, which is `None` until then.
    pub fn shared_state(&self) -> Option<&dyn PcodeExecutorState<T>> {
        self.shared_state.as_deref()
    }

    /// Set the suspension state of the machine. Port of `setSuspended(boolean)`.
    pub fn set_suspended(&mut self, suspended: bool) {
        self.suspended = suspended;
    }

    /// Check the suspension state of the machine. Port of `isSuspended()`.
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Check for a p-code injection (override) at the given address. Port of `getInject(Address)`.
    pub fn get_inject(&self, address: &Address) -> Option<&dyn PcodeProgram> {
        self.injects.get(address).map(|p| p.as_ref())
    }

    /// Record the given compiled p-code as the inject at the given address, replacing and
    /// forgetting any inject already there. This is Java's `injects.put(address, pcode)`, shared
    /// by `inject` and `addBreakpoint`.
    pub fn put_inject(&mut self, address: Address, pcode: Box<dyn PcodeProgram>) {
        self.injects.insert(address, pcode);
    }

    /// Remove the inject, if present, at the given address. Port of `clearInject(Address)`.
    pub fn clear_inject(&mut self, address: &Address) {
        self.injects.remove(address);
    }

    /// Remove all injects from this machine. Port of `clearAllInjects()`. This clears execution
    /// breakpoints, but not access breakpoints.
    pub fn clear_all_injects(&mut self) {
        self.injects.clear();
    }

    /// Add an access breakpoint over the given range. Port of
    /// `addAccessBreakpoint(AddressRange, AccessKind)`.
    pub fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind) {
        self.access_breakpoints.put(range.clone(), kind);
    }

    /// Remove all access breakpoints from this machine. Port of `clearAccessBreakpoints()`.
    pub fn clear_access_breakpoints(&mut self) {
        self.access_breakpoints.clear();
    }

    /// Compile the given Sleigh code for execution by a thread of this machine, linking it against
    /// the stub library. Port of `compileSleigh(String, String)`.
    pub fn compile_sleigh(&self, source_name: &str, source: &str) -> Box<dyn PcodeProgram> {
        SleighProgramCompiler::compile_program(
            &self.language,
            source_name,
            source,
            self.stub_library.as_ref(),
        )
    }

    /// The source name Java gives an inject compiled for the given address: `"machine_inject:"`
    /// followed by the address.
    pub fn inject_source_name(address: &Address) -> String {
        format!("machine_inject:{address}")
    }

    /// The source name Java gives a breakpoint compiled for the given address: `"breakpoint:"`
    /// followed by the address.
    pub fn breakpoint_source_name(address: &Address) -> String {
        format!("breakpoint:{address}")
    }

    /// The Sleigh source Java compiles for a conditional execution breakpoint: swi when the
    /// condition holds, then execute the overridden instruction either way.
    pub fn breakpoint_source(sleigh_condition: &str) -> String {
        format!(
            "if (!({sleigh_condition})) goto <nobreak>;\n\temu_swi();\n<nobreak>\n\temu_exec_decoded();\n"
        )
    }

    /// Perform checks on a requested `LOAD`, returning the interrupt the `LOAD` should cause, if
    /// any. Port of `checkLoad(AddressSpace, T, int)`.
    pub fn check_load(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        _size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.check_access(space, offset, AccessKind::traps_read)
    }

    /// Perform checks on a requested `STORE`, returning the interrupt the `STORE` should cause, if
    /// any. Port of `checkStore(AddressSpace, T, int)`.
    pub fn check_store(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        _size: i32,
    ) -> Result<(), InterruptPcodeExecutionException> {
        self.check_access(space, offset, AccessKind::traps_write)
    }

    /// The body shared by [`check_load`](Self::check_load) and [`check_store`](Self::check_store),
    /// which differ in Java only by the trapping predicate.
    fn check_access(
        &self,
        space: &Arc<AddressSpace>,
        offset: &T,
        traps: fn(AccessKind) -> bool,
    ) -> Result<(), InterruptPcodeExecutionException> {
        if self.access_breakpoints.is_empty() {
            return Ok(());
        }
        // Java uses Purpose.LOAD for the store check too.
        let Ok(concrete) = self.arithmetic.to_long(offset, Purpose::Load) else {
            // Consider a value that cannot be made concrete as not hitting any breakpoint.
            return Ok(());
        };
        let Ok(address) = space.checked_address(concrete) else {
            // Likewise for an offset that isn't an address in this space at all: no breakpoint
            // range can contain it. (Java lets the AddressOutOfBoundsException propagate.)
            return Ok(());
        };
        if self.access_breakpoints.has_entry(&address, |kind| traps(*kind)) {
            return Err(InterruptPcodeExecutionException::new(None));
        }
        Ok(())
    }

    /// Return a software interrupt if those interrupts are active. Port of `swi()`.
    pub fn swi(&self) -> Result<(), InterruptPcodeExecutionException> {
        if self.swi_mode == SwiMode::Active {
            return Err(InterruptPcodeExecutionException::new(None));
        }
        Ok(())
    }

    /// Notify the machine a thread has been stepped a p-code op, so that it may re-enable software
    /// interrupts, if applicable. Port of `stepped()`.
    pub fn stepped(&mut self) {
        if self.swi_mode == SwiMode::IgnoreStep {
            self.swi_mode = SwiMode::Active;
        }
    }

    /// Notify the callbacks that the machine has been created. This is the
    /// `cb.emulatorCreated(this)` of Java's constructor, which cannot run until the machine is
    /// whole -- see [`new`](Self::new).
    pub fn notify_emulator_created<M: AbstractPcodeMachine<T>>(machine: &M) {
        let cb = Arc::clone(&machine.base().cb);
        cb.emulator_created(machine);
    }

    /// Execute the initializer upon the given machine, if applicable. Port of
    /// `doPluggableInitialization()`.
    #[deprecated(note = "Java marks this for removal since 12.0; it is not really used")]
    pub fn do_pluggable_initialization<M: AbstractPcodeMachine<T>>(machine: &M) {
        if let Some(initializer) = machine.base().initializer.clone() {
            initializer.initialize_machine(machine);
        }
    }

    /// Get the machine's shared (memory) state, creating it if this is the first request.
    ///
    /// Port of `getSharedState()`. On creation, the machine runs its pluggable initialization and
    /// notifies its callbacks, in that order.
    pub fn get_shared_state<M: AbstractPcodeMachine<T>>(
        machine: &mut M,
    ) -> &mut dyn PcodeExecutorState<T> {
        if machine.base().shared_state.is_none() {
            let state = machine.create_shared_state();
            machine.base_mut().shared_state = Some(state);
            #[allow(deprecated)]
            Self::do_pluggable_initialization(machine);
            let cb = Arc::clone(&machine.base().cb);
            cb.shared_state_created(&*machine);
        }
        machine
            .base_mut()
            .shared_state
            .as_deref_mut()
            .expect("shared state was just created if it was absent")
    }

    /// Create a new thread with a default name in this machine. Port of `newThread()`.
    pub fn new_thread<M: AbstractPcodeMachine<T>>(machine: &mut M) -> Arc<dyn ErasedPcodeThread> {
        let name = format!("Thread {}", machine.base().threads.len());
        Self::new_thread_named(machine, &name)
    }

    /// Create a new thread with the given name in this machine. Port of `newThread(String)`.
    ///
    /// # Panics
    ///
    /// If a thread with the given name already exists, as Java throws `IllegalStateException`.
    pub fn new_thread_named<M: AbstractPcodeMachine<T>>(
        machine: &mut M,
        name: &str,
    ) -> Arc<dyn ErasedPcodeThread> {
        if machine.base().get_thread_by_name(name).is_some() {
            panic!("Thread with name '{name}' already exists");
        }
        let thread = machine.create_thread(name);
        machine
            .base_mut()
            .threads
            .push((name.to_string(), Arc::clone(&thread)));
        let cb = Arc::clone(&machine.base().cb);
        cb.thread_created(&thread);
        thread
    }

    /// Get the thread, if present, with the given name, creating it if `create_if_absent`. Port of
    /// `getThread(String, boolean)`.
    pub fn get_thread<M: AbstractPcodeMachine<T>>(
        machine: &mut M,
        name: &str,
        create_if_absent: bool,
    ) -> Option<Arc<dyn ErasedPcodeThread>> {
        match machine.base().get_thread_by_name(name) {
            Some(thread) => Some(thread),
            None if create_if_absent => Some(Self::new_thread_named(machine, name)),
            None => None,
        }
    }

    /// Override the p-code at the given address with the given Sleigh source. Port of
    /// `inject(Address, String)`.
    pub fn inject<M: AbstractPcodeMachine<T>>(machine: &mut M, address: &Address, source: &str) {
        let pcode = machine.compile_sleigh(&Self::inject_source_name(address), source);
        machine.base_mut().put_inject(address.clone(), pcode);
    }

    /// Add a conditional execution breakpoint at the given address. Port of
    /// `addBreakpoint(Address, String)`. Breakpoints are implemented as injects, so this replaces
    /// any inject already at the address.
    pub fn add_breakpoint<M: AbstractPcodeMachine<T>>(
        machine: &mut M,
        address: &Address,
        sleigh_condition: &str,
    ) {
        let source = Self::breakpoint_source(sleigh_condition);
        let pcode = machine.compile_sleigh(&Self::breakpoint_source_name(address), &source);
        machine.base_mut().put_inject(address.clone(), pcode);
    }
}

/// The operations `AbstractPcodeMachine` leaves to its subclasses, plus accessors for the embedded
/// [`AbstractPcodeMachineBase`].
///
/// `T` is the type of objects in the machine's state.
pub trait AbstractPcodeMachine<T: 'static>: PcodeMachine<T> {
    /// Get the machine's shared state and concrete behavior.
    fn base(&self) -> &AbstractPcodeMachineBase<T>;

    /// Get the machine's shared state and concrete behavior, for writing.
    fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<T>;

    /// A factory method to create the (memory) state shared by all threads in this machine.
    ///
    /// Port of the abstract `createSharedState()`. It is called at most once per machine, by
    /// [`AbstractPcodeMachineBase::get_shared_state`].
    fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<T>>;

    /// A factory method to create the (register) state local to the given thread.
    ///
    /// Port of the abstract `createLocalState(PcodeThread<T>)`.
    fn create_local_state(&self, thread: &dyn ErasedPcodeThread) -> Box<dyn PcodeExecutorState<T>>;

    /// A factory method to create a new thread in this machine.
    ///
    /// Port of `createThread(String)`. Java defaults it to `new DefaultPcodeThread<>(name, this)`;
    /// that class is not ported yet, so every machine must supply its own for now.
    fn create_thread(&self, name: &str) -> Arc<dyn ErasedPcodeThread>;
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::program::model::address::{
        AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::{OpCode, PackedDecode};

    /// Minimal little-endian arithmetic over `byte[]`, implementing only what `PcodeArithmetic`
    /// leaves abstract (mirroring the fixtures in `pcode_arithmetic` and
    /// `pcode_userop_library_factory`). The default `to_long` built on `to_concrete` is what the
    /// access-breakpoint checks exercise.
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

    /// An arithmetic whose values are never concrete, standing in for an abstract (e.g. symbolic)
    /// domain. Java treats a `ConcretionError` from an access check as "no breakpoint hit".
    struct AbstractArithmetic;

    impl PcodeArithmetic<Vec<u8>> for AbstractArithmetic {
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
            _value: &Vec<u8>,
            purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Err(ConcretionError::new("Value is not concrete", purpose))
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// A thread that carries only its name, which is all the machine itself observes.
    struct NamedThread(String);

    impl ErasedPcodeThread for NamedThread {}

    /// The product of the machine's stand-in compiler; opaque, as `PcodeProgram` is here.
    struct CompiledProgram;

    impl PcodeProgram for CompiledProgram {}

    /// Records every callback the machine fires, in order.
    #[derive(Default)]
    struct RecordingCallbacks {
        events: Mutex<Vec<String>>,
    }

    impl PcodeEmulationCallbacks<Vec<u8>> for RecordingCallbacks {
        fn emulator_created(&self, _machine: &dyn ErasedPcodeMachine) {
            self.events.lock().unwrap().push("emulatorCreated".into());
        }

        fn shared_state_created(&self, _machine: &dyn ErasedPcodeMachine) {
            self.events.lock().unwrap().push("sharedStateCreated".into());
        }

        fn thread_created(&self, _thread: &Arc<dyn ErasedPcodeThread>) {
            self.events.lock().unwrap().push("threadCreated".into());
        }
    }

    /// A state that does nothing; `createSharedState` must return something, and no test reads it.
    struct EmptyState;

    impl crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>
        for EmptyState
    {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("test should not call this")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(BytesArithmetic)
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
            vec![]
        }
        fn get_register_values(
            &self,
        ) -> Vec<(crate::program::model::lang::register::RegisterRef, Vec<u8>)> {
            vec![]
        }
        fn get_concrete_buffer(
            &self,
            _address: &Address,
            _purpose: Purpose,
        ) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
            unimplemented!("test should not call this")
        }
        fn clear(&mut self) {}
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            _val: &Vec<u8>,
        ) {
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            _size: i32,
            _val: &Vec<u8>,
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            size: i32,
            _quantize: bool,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> Vec<u8> {
            vec![0; size as usize]
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &Vec<u8>,
            size: i32,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> Vec<u8> {
            vec![0; size as usize]
        }
    }

    impl PcodeExecutorState<Vec<u8>> for EmptyState {}

    /// A concrete machine over `byte[]`: the shape a real subclass takes, cut down to what these
    /// tests observe. It counts `createSharedState` calls, so the lazy creation Java documents is
    /// visible, and "compiles" Sleigh by logging the request.
    struct TestMachine {
        base: AbstractPcodeMachineBase<Vec<u8>>,
        shared_states_created: Mutex<u32>,
        compiled: Mutex<Vec<(String, String)>>,
    }

    impl TestMachine {
        fn new(arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>>, cb: Arc<RecordingCallbacks>) -> Self {
            let machine = Self {
                base: AbstractPcodeMachineBase::new(
                    Arc::new(test_language()),
                    cb,
                    arithmetic,
                    Box::new(nil::<Vec<u8>>()),
                    Box::new(nil::<Vec<u8>>()),
                    None,
                ),
                shared_states_created: Mutex::new(0),
                compiled: Mutex::new(Vec::new()),
            };
            AbstractPcodeMachineBase::notify_emulator_created(&machine);
            machine
        }

        /// The (source name, source) of the most recent compile request.
        fn last_compiled(&self) -> (String, String) {
            self.compiled.lock().unwrap().last().cloned().expect("nothing compiled")
        }
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
            *self.shared_states_created.lock().unwrap() += 1;
            Box::new(EmptyState)
        }

        fn create_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
            Box::new(EmptyState)
        }

        fn create_thread(&self, name: &str) -> Arc<dyn ErasedPcodeThread> {
            Arc::new(NamedThread(name.to_string()))
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
            AbstractPcodeMachineBase::new_thread(self)
        }
        fn new_thread_named(&mut self, name: &str) -> Arc<dyn ErasedPcodeThread> {
            AbstractPcodeMachineBase::new_thread_named(self, name)
        }
        fn get_thread(
            &mut self,
            name: &str,
            create_if_absent: bool,
        ) -> Option<Arc<dyn ErasedPcodeThread>> {
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
        /// Stands in for `SleighProgramCompiler.compileProgram`, which is not ported yet: record
        /// the request instead of compiling it.
        fn compile_sleigh(&self, source_name: &str, source: &str) -> Box<dyn PcodeProgram> {
            self.compiled
                .lock()
                .unwrap()
                .push((source_name.to_string(), source.to_string()));
            Box::new(CompiledProgram)
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

    /// Builds a minimal but real `SleighLanguage` by feeding a hand-assembled packed-binary
    /// `<sleigh>` document through the crate's real `PackedDecode`, as the sibling
    /// `pcode_userop_library_factory` tests do; `SleighLanguage`'s fields are private outside its
    /// module, so a literal construction isn't available here.
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

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn machine() -> (TestMachine, Arc<RecordingCallbacks>) {
        let cb = Arc::new(RecordingCallbacks::default());
        (TestMachine::new(Arc::new(BytesArithmetic), Arc::clone(&cb)), cb)
    }

    /// Little-endian bytes for an offset, the shape an arithmetic over `byte[]` yields for a
    /// `LOAD`/`STORE` offset in a 64-bit space.
    fn offset_bytes(offset: u64) -> Vec<u8> {
        offset.to_le_bytes().to_vec()
    }

    #[test]
    fn constructor_notifies_callbacks_and_defaults_match_java() {
        let (machine, cb) = machine();
        // Java's constructor ends with cb.emulatorCreated(this); nothing else has fired yet.
        assert_eq!(*cb.events.lock().unwrap(), vec!["emulatorCreated"]);
        // Field initializers: swiMode = ACTIVE, suspended = false, no threads, no injects.
        assert_eq!(SwiMode::Active, machine.base.get_software_interrupt_mode());
        assert!(!machine.base.is_suspended());
        assert!(machine.base.get_all_threads().is_empty());
        assert!(machine.base.shared_state().is_none());
        // "Do not initialize memoryState here" -- createSharedState has not run.
        assert_eq!(0, *machine.shared_states_created.lock().unwrap());
    }

    #[test]
    fn breakpoint_compiles_javas_conditional_swi_source() {
        let (mut machine, _cb) = machine();
        let address = ram().address(0x400000);
        machine.add_breakpoint(&address, "RAX == 0");

        // The breakpoint is installed as an inject at that address...
        assert!(machine.get_inject(&address).is_some());
        let (source_name, source) = machine.last_compiled();
        assert_eq!(format!("breakpoint:{address}"), source_name);
        // ... compiled from the Java text block, with its incidental indentation stripped.
        assert_eq!(
            "if (!(RAX == 0)) goto <nobreak>;\n\temu_swi();\n<nobreak>\n\temu_exec_decoded();\n",
            source
        );
    }

    #[test]
    fn injects_are_replaced_not_chained_and_cleared_separately() {
        let (mut machine, _cb) = machine();
        let space = ram();
        let address = space.address(0x400000);
        let other = space.address(0x400010);

        assert!(machine.get_inject(&address).is_none());

        machine.inject(&address, "emu_exec_decoded();");
        assert_eq!(
            (format!("machine_inject:{address}"), "emu_exec_decoded();".to_string()),
            machine.last_compiled()
        );

        // "Each address can have at most a single inject... the old inject completely forgotten."
        machine.inject(&address, "emu_swi();");
        // A breakpoint is just an inject, so it replaces this one too.
        machine.add_breakpoint(&address, "1");
        assert!(machine.get_inject(&address).is_some());
        assert!(machine.get_inject(&other).is_none());

        machine.inject(&other, "emu_exec_decoded();");
        machine.clear_inject(&address);
        assert!(machine.get_inject(&address).is_none());
        assert!(machine.get_inject(&other).is_some());

        // clearAllInjects clears execution breakpoints, but not access breakpoints.
        machine.add_access_breakpoint(
            &AddressRange::new(space.address(0x1000), space.address(0x1fff)),
            AccessKind::Rw,
        );
        machine.clear_all_injects();
        assert!(machine.get_inject(&other).is_none());
        assert!(machine
            .base
            .check_load(&space, &offset_bytes(0x1234), 4)
            .is_err());
    }

    #[test]
    fn access_breakpoints_trap_only_their_kind_and_range() {
        let (mut machine, _cb) = machine();
        let space = ram();

        // With no breakpoints at all, every access passes.
        assert!(machine.base.check_load(&space, &offset_bytes(0x1234), 4).is_ok());
        assert!(machine.base.check_store(&space, &offset_bytes(0x1234), 4).is_ok());

        machine.add_access_breakpoint(
            &AddressRange::new(space.address(0x1000), space.address(0x1fff)),
            AccessKind::W,
        );

        // W traps writes only...
        let err = machine
            .base
            .check_store(&space, &offset_bytes(0x1234), 4)
            .expect_err("store in range should interrupt");
        assert_eq!("Execution hit breakpoint", err.message());
        assert!(machine.base.check_load(&space, &offset_bytes(0x1234), 4).is_ok());
        // ... and only within its range.
        assert!(machine.base.check_store(&space, &offset_bytes(0x2000), 4).is_ok());

        machine.clear_access_breakpoints();
        assert!(machine.base.check_store(&space, &offset_bytes(0x1234), 4).is_ok());
    }

    #[test]
    fn access_breakpoints_ignore_offsets_that_cannot_be_made_concrete() {
        let cb = Arc::new(RecordingCallbacks::default());
        let mut machine = TestMachine::new(Arc::new(AbstractArithmetic), cb);
        let space = ram();
        machine.add_access_breakpoint(
            &AddressRange::new(space.address(0x1000), space.address(0x1fff)),
            AccessKind::Rw,
        );

        // Java catches ConcretionError and considers it "not hitting any breakpoint".
        assert!(machine.base.check_load(&space, &offset_bytes(0x1234), 4).is_ok());
        assert!(machine.base.check_store(&space, &offset_bytes(0x1234), 4).is_ok());
    }

    #[test]
    fn swi_follows_mode_and_a_step_re_enables_it() {
        let (mut machine, _cb) = machine();
        // ACTIVE: emu_swi() interrupts.
        assert!(machine.base.swi().is_err());

        machine.set_software_interrupt_mode(SwiMode::IgnoreAll);
        assert!(machine.base.swi().is_ok());
        machine.base.stepped();
        // IGNORE_ALL survives a step.
        assert_eq!(SwiMode::IgnoreAll, machine.get_software_interrupt_mode());
        assert!(machine.base.swi().is_ok());

        machine.set_software_interrupt_mode(SwiMode::IgnoreStep);
        assert!(machine.base.swi().is_ok());
        // IGNORE_STEP reverts to ACTIVE after one p-code step, hit or not.
        machine.base.stepped();
        assert_eq!(SwiMode::Active, machine.get_software_interrupt_mode());
        assert!(machine.base.swi().is_err());
    }

    #[test]
    fn threads_are_named_and_ordered_like_java() {
        let (mut machine, cb) = machine();

        let first = machine.new_thread();
        let second = machine.new_thread();
        // newThread() names threads "Thread " + threads.size().
        assert_eq!(2, machine.get_all_threads().len());
        assert!(Arc::ptr_eq(&first, &machine.get_all_threads()[0]));
        assert!(Arc::ptr_eq(&second, &machine.get_all_threads()[1]));
        assert!(machine.get_thread("Thread 0", false).is_some());
        assert!(machine.get_thread("Thread 1", false).is_some());

        // getThread(name, false) does not create; getThread(name, true) does.
        assert!(machine.get_thread("worker", false).is_none());
        let worker = machine.get_thread("worker", true).expect("created on demand");
        assert!(Arc::ptr_eq(&worker, &machine.get_thread("worker", true).unwrap()));
        assert_eq!(3, machine.get_all_threads().len());

        assert_eq!(
            *cb.events.lock().unwrap(),
            vec!["emulatorCreated", "threadCreated", "threadCreated", "threadCreated"]
        );
    }

    #[test]
    #[should_panic(expected = "Thread with name 'Thread 0' already exists")]
    fn duplicate_thread_names_are_rejected() {
        let (mut machine, _cb) = machine();
        machine.new_thread();
        machine.new_thread_named("Thread 0");
    }

    #[test]
    fn shared_state_is_created_once_on_demand() {
        let (mut machine, cb) = machine();
        assert_eq!(0, *machine.shared_states_created.lock().unwrap());

        let _ = machine.get_shared_state_mut();
        assert_eq!(1, *machine.shared_states_created.lock().unwrap());
        assert_eq!(
            *cb.events.lock().unwrap(),
            vec!["emulatorCreated", "sharedStateCreated"]
        );

        // Subsequent requests reuse it: no second createSharedState, no second callback.
        let _ = machine.get_shared_state_mut();
        let _ = machine.get_shared_state();
        assert_eq!(1, *machine.shared_states_created.lock().unwrap());
        assert_eq!(
            *cb.events.lock().unwrap(),
            vec!["emulatorCreated", "sharedStateCreated"]
        );
    }

    #[test]
    fn machine_language_and_arithmetic_are_the_ones_given() {
        let (machine, _cb) = machine();
        // assertSleigh's job, done by the type system: the machine's language is the Sleigh one.
        assert_eq!("test", machine.get_language().get_id());
        // Java's getArithmetic() hands back the very arithmetic createArithmetic() produced.
        let arithmetic = machine.get_arithmetic();
        assert_eq!(0x1234, arithmetic.to_long(&offset_bytes(0x1234), Purpose::Load).unwrap());
        // The stub library composes the thread stub library over the machine's library; both are
        // empty here, so the composition is too, but it is a distinct library.
        assert!(machine.get_userop_library().get_userops().is_empty());
        assert!(machine.get_stub_userop_library().get_userops().is_empty());
    }
}
