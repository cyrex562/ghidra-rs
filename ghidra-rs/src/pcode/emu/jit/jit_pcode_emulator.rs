//! An extension of [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) that applies Just-in-Time (JIT) translation to accelerate
//! execution.
//!
//! Port of `ghidra.pcode.emu.jit.JitPcodeEmulator`.
//!
//! This is meant as a near drop-in replacement for the type it extends. Aside from some additional
//! configuration, and some annotations you might add to a
//! [`PcodeUseropLibrary`](crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary), you can
//! simply replace `PcodeEmulator::new(..)` with [`JitPcodeEmulator::new`].
//!
//! # Terminology
//!
//! * **Basic block**: a block of *p-code* ops for which there are no branches into or from, except
//!   at its top and bottom. This definition pertains only to p-code ops in the same passage.
//! * **Decode context**: the input contextreg value for decoding an instruction, usually paired
//!   with an address to seed passages and identify entry points -- see [`AddrCtx`].
//! * **Emulation target**: the machine being emulated, as opposed to the *translation target*.
//! * **Entry point**: an address (and contextreg value) by which execution may enter a passage. In
//!   addition to the decode seed, the translator may expose many entries into a given passage.
//! * **Passage**: a collection of strides connected by branches.
//! * **Stride**: a contiguous sequence of instructions (and their emitted p-code) connected by
//!   fall-through.
//! * **Varnode**: the triple (space, offset, size) giving the address and size of a variable in the
//!   emulation target's machine state. Distinct from a variable node
//!   ([`JitVal`](crate::pcode::emu::jit::var::JitVal)) in the use-def graph.
//!
//! # Translation cache
//!
//! This type, aside from replacing the state and thread objects with respective extensions, manages
//! a part of the translation cache. There are two levels of caching: once a passage is translated
//! into a class, it must be instantiated for the thread executing it. Thus, at the machine level,
//! each translated passage's class is cached; then each thread caches its instance of that class.
//! When a thread encounters an address (and contextreg value) that it has not yet translated, it
//! requests that the emulator perform that translation. See
//! [`get_entry_prototype`](JitPcodeEmulator::get_entry_prototype).
//!
//! # Deviations from the Java source
//!
//! * Java `extends PcodeEmulator`. This port embeds an [`AbstractPcodeMachineBase`] and implements
//!   [`PcodeMachine`]/[`AbstractPcodeMachine`] directly, which is the convention
//!   [`AbstractPcodeMachineBase`]'s own docs set out for a concrete machine and which
//!   [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) itself follows. Nothing is lost by not composing a [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator): its
//!   only field is that same base, and its only behavior is the three factory overrides
//!   (`createSharedState`, `createLocalState`, `createThread`) that this type overrides again.
//!   What Java's `super(language, cb)` computes -- the arithmetic, userop library, and stub library
//!   -- [`JitPcodeEmulator::with_callbacks`] therefore computes the same way [`PcodeEmulator::new`](crate::pcode::emu::pcode_emulator::PcodeEmulator::new)
//!   does. The forwarding to the base is not blind: the methods Java's `AbstractPcodeMachine`
//!   implements in terms of overridable factories (`newThread`, `getThread`, `getSharedState`,
//!   `inject`, `addBreakpoint`) go through [`AbstractPcodeMachineBase`]'s associated functions with
//!   `self` -- this emulator -- so they dispatch to *this* type's factories, as virtual dispatch
//!   does in Java.
//! * Java's `newThread()`/`newThread(String)` overrides exist only to narrow the return type from
//!   `PcodeThread<byte[]>` to `JitPcodeThread`. Rust has no covariant return, so they are not
//!   ported; [`PcodeMachine::new_thread`] and [`PcodeMachine::new_thread_named`] are the whole
//!   behavior. Likewise `createUseropLibrary()`, whose Java override is a bare `super` call added
//!   only to carry javadoc.
//! * The `lookup` field (a JVM `MethodHandles.Lookup`) and the `Lookup` parameter of
//!   `JitCompiler.compilePassage` are dropped. They exist to define the generated classfile as a
//!   hidden class and to reach non-public elements reflectively; this crate has no JVM, as
//!   [`JitCompiledPassageClass`] already documents for the same reason.
//! * Java's `codeCache` maps to a `CompletableFuture` per entry, guarded by `synchronized`. Here
//!   the map lives behind a [`Mutex`] and each entry is an [`EntryFuture`], a minimal
//!   complete-once cell with the two operations Java uses: `isDone` and a blocking `get`.
//! * Java completes a future exceptionally when translation throws, so the failure is rethrown to
//!   the requester and to anyone later awaiting the same entry. Here a translation failure is a
//!   panic, which propagates to the requester by itself; a drop guard removes the still-pending
//!   entry from the cache during the unwind, so a later requester retries rather than blocking
//!   forever on a future nobody will ever complete.
//! * `compilePassage` throws `MethodTooLargeException`, which the backoff loop catches; here
//!   [`JitCompiler::compile_passage`] returns it as an `Err`.
//! * `createSharedState`/`createLocalState` call `cb.wrapFor(thread)`. That adapter is not ported,
//!   so, as in [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) itself, this passes
//!   [`NONE`](crate::pcode::exec::pcode_state_callbacks::NONE).
//! * [`JitCompiler`], [`JitConfiguration`], [`JitDefaultBytesPcodeExecutorState`], and
//!   [`JitPcodeThread`] are still placeholders in
//!   [`seam_stubs`](crate::pcode::seam_stubs); in particular the compiler cannot yet translate
//!   anything, so [`get_entry_prototype`](JitPcodeEmulator::get_entry_prototype) panics on a cache
//!   miss.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use crate::pcode::emu::abstract_pcode_machine::{AbstractPcodeMachine, AbstractPcodeMachineBase};
use crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder;
use crate::pcode::emu::jit::gen::tgt::JitCompiledPassageClass;
use crate::pcode::emu::pcode_emulation_callbacks::{
    no_pcode_emulation_callbacks, PcodeEmulationCallbacks,
};
use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, PcodeMachine, SwiMode};
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_state_callbacks::NONE;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::pcode::emu::jit::jit_configuration::JitConfiguration;
use crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread;
use crate::pcode::seam_stubs::{
    AddrCtx, BytesPcodeArithmetic, EntryPointPrototype, JitCompiler,
    JitDefaultBytesPcodeExecutorState,
};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::util::msg::Msg;

/// A translation that one thread is producing and any number of threads may be awaiting.
///
/// Stands in for the `CompletableFuture<EntryPointPrototype>` Java stores in its code cache. Only
/// the two operations Java uses are provided: [`is_done`](Self::is_done), which
/// [`JitPcodeEmulator::has_entry_prototype`] tests without waiting, and [`get`](Self::get), which
/// blocks until the translation lands.
struct EntryFuture {
    proto: Mutex<Option<EntryPointPrototype>>,
    completed: Condvar,
}

impl EntryFuture {
    /// A future nobody has completed yet. Port of `new CompletableFuture<>()`.
    fn new() -> Self {
        Self { proto: Mutex::new(None), completed: Condvar::new() }
    }

    /// An already-completed future. Port of `CompletableFuture.completedFuture(v)`.
    fn completed(proto: EntryPointPrototype) -> Self {
        Self { proto: Mutex::new(Some(proto)), completed: Condvar::new() }
    }

    /// Port of `CompletableFuture.isDone()`.
    fn is_done(&self) -> bool {
        self.proto.lock().expect("code cache entry poisoned").is_some()
    }

    /// Port of `CompletableFuture.complete(v)`, waking everyone blocked in [`get`](Self::get).
    fn complete(&self, proto: EntryPointPrototype) {
        *self.proto.lock().expect("code cache entry poisoned") = Some(proto);
        self.completed.notify_all();
    }

    /// Port of `CompletableFuture.get()`: block until some thread completes this translation.
    fn get(&self) -> EntryPointPrototype {
        let mut guard = self.proto.lock().expect("code cache entry poisoned");
        while guard.is_none() {
            guard = self.completed.wait(guard).expect("code cache entry poisoned");
        }
        guard.as_ref().expect("waited until completed").clone()
    }
}

/// Removes a still-pending cache entry if translation unwinds.
///
/// Java's `catch (Throwable t) { proto.completeExceptionally(t); }` leaves the entry in the cache
/// so the failure is rethrown from `proto.get()`, both here and for anyone who later requests the
/// same entry point. A Rust panic already carries the failure back to the requester, but it would
/// leave behind a future no thread will ever complete -- so this drops the entry instead, which
/// makes a later request retry the translation.
struct PendingEntry<'a> {
    cache: &'a Mutex<HashMap<AddrCtx, Arc<EntryFuture>>>,
    pc_ctx: &'a AddrCtx,
    armed: bool,
}

impl PendingEntry<'_> {
    /// Translation completed; leave the cache alone.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for PendingEntry<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut cache) = self.cache.lock() {
            if cache.get(self.pc_ctx).is_some_and(|f| !f.is_done()) {
                cache.remove(self.pc_ctx);
            }
        }
    }
}

/// A p-code emulator that translates passages of the emulation target's machine code ahead of
/// executing them.
///
/// Port of `ghidra.pcode.emu.jit.JitPcodeEmulator`.
pub struct JitPcodeEmulator {
    /// The state and concrete behavior Java inherits through `extends PcodeEmulator`; see the
    /// module docs.
    base: AbstractPcodeMachineBase<Vec<u8>>,
    /// The compiler which translates passages into classes. Port of the `compiler` field.
    compiler: JitCompiler,
    /// This emulator's cache of passage translations, incl. all entry points. Port of the
    /// `codeCache` field together with the `synchronized (codeCache)` blocks guarding it.
    ///
    /// Entries are never invalidated, matching Java. Invalidation is complicated by any thread
    /// still holding -- and possibly executing -- an instance of a translation; self-modifying
    /// code, changes to the memory map, and injects added after execution starts would all be
    /// reasons to want it.
    code_cache: Mutex<HashMap<AddrCtx, Arc<EntryFuture>>>,
}

impl JitPcodeEmulator {
    /// Create a JIT-accelerated p-code emulator.
    ///
    /// Port of the private `JitPcodeEmulator(Language, PcodeEmulationCallbacks<byte[]>,
    /// JitConfiguration, Lookup)`. It is private in Java because callbacks are not completely
    /// implemented, and so are not recommended yet; it is likewise module-private here.
    ///
    /// The body of Java's `super(language, cb)` is inlined; see the module docs.
    ///
    /// # Arguments
    /// * `language` - the emulation target language
    /// * `cb` - callbacks to receive emulation events
    /// * `config` - configuration options for this emulator
    fn with_callbacks(
        language: Arc<SleighLanguage>,
        cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>>,
        config: JitConfiguration,
    ) -> Self {
        let arithmetic = BytesPcodeArithmetic::for_sleigh_language(&language);
        let library =
            AbstractPcodeMachineBase::create_userop_library(&language, arithmetic.as_ref(), "", &[]);
        // DefaultPcodeThread.PcodeEmulationLibrary, Java's default createThreadStubLibrary(), is
        // not yet ported -- see `PcodeEmulator`'s module docs.
        let thread_stub_library: Box<dyn PcodeUseropLibrary<Vec<u8>>> = Box::new(nil());
        let base = AbstractPcodeMachineBase::new(
            language,
            cb,
            arithmetic,
            library,
            thread_stub_library,
            None,
        );
        let emulator = Self {
            base,
            compiler: JitCompiler::new(config),
            code_cache: Mutex::new(HashMap::new()),
        };
        // Java's `cb.emulatorCreated(this)`, which its constructor cannot run on a half-built
        // `this`.
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    /// Create a JIT-accelerated p-code emulator.
    ///
    /// Port of `JitPcodeEmulator(Language, JitConfiguration, Lookup)`, which is
    /// `this(language, PcodeEmulationCallbacks.none(), config, lookup)`.
    ///
    /// # Arguments
    /// * `language` - the emulation target language
    /// * `config` - configuration options for this emulator
    pub fn new(language: Arc<SleighLanguage>, config: JitConfiguration) -> Self {
        Self::with_callbacks(language, no_pcode_emulation_callbacks(), config)
    }

    /// Check if the emulator has already translated a given entry point.
    ///
    /// This is used by the decoder to detect if it should end a stride before reaching its natural
    /// end (i.e., a non-fall-through instruction.) This was a design decision to reduce
    /// re-translation of the same machine code. Terminating the stride will cause execution to exit
    /// the translated passage, but it will then immediately enter the existing translated passage.
    ///
    /// # Arguments
    /// * `pc_ctx` - the program counter and contextreg value to check
    ///
    /// # Returns
    /// true if the emulator has a translation which can be entered at the given `pc_ctx`.
    ///
    /// Port of `hasEntryPrototype(AddrCtx)`.
    pub fn has_entry_prototype(&self, pc_ctx: &AddrCtx) -> bool {
        let cache = self.code_cache.lock().expect("code cache poisoned");
        cache.get(pc_ctx).is_some_and(|proto| proto.is_done())
    }

    /// Translate a new passage starting at the given seed.
    ///
    /// Note the compiler must provide an entry to the resulting passage at the requested seed. It
    /// and any additional entry points are placed into the code cache by
    /// [`get_entry_prototype`](Self::get_entry_prototype). Each thread executing the passage must
    /// still create (and ought to cache) an instance of the translation.
    ///
    /// # Arguments
    /// * `pc_ctx` - the seed address and contextreg value for decoding and selecting a passage
    /// * `decoder` - the passage decoder, provided by the thread
    ///
    /// # Returns
    /// the class that is the translation of the passage, and information about its entry points.
    ///
    /// # Panics
    ///
    /// If the op budget is exhausted without a translation small enough to emit, which Java
    /// reports as an `AssertionError`. It would be caused by an exceptionally large stride, perhaps
    /// with a good bit of instrumentation.
    ///
    /// Port of `compileWithMaxOpsBackoff(AddrCtx, JitPassageDecoder)`.
    fn compile_with_max_ops_backoff(
        &self,
        pc_ctx: &AddrCtx,
        decoder: &JitPassageDecoder,
    ) -> JitCompiledPassageClass {
        let mut max_ops = self.get_configuration().max_passage_ops;
        while max_ops > 0 {
            let decoded = decoder.decode_passage(pc_ctx.clone(), max_ops);
            match self.compiler.compile_passage(decoded) {
                Ok(compiled) => return compiled,
                Err(_too_large) => {
                    Msg::warn(
                        "JitPcodeEmulator",
                        &format!(
                            "Method too large for {pc_ctx} with maxOps={max_ops}. \
                             Retrying with half."
                        ),
                    );
                    max_ops >>= 1;
                }
            }
        }
        panic!("could not translate {pc_ctx} within any op budget");
    }

    /// Get the entry prototype for a given address and contextreg value.
    ///
    /// An **entry prototype** is a class representing a translated passage and an index identifying
    /// the point at which to enter the passage. The compiler numbers each entry point it generates.
    /// Those entry point indices are entered into the code cache for each translated passage. If no
    /// entry point exists for the requested address and contextreg value, the emulator will decode
    /// and translate a new passage at the requested seed.
    ///
    /// It's a bit odd to take the thread's decoder for a machine-level thing; however, all thread
    /// decoders ought to have the same behavior. The particular thread's decoder will have better
    /// cached instruction block state for decoding in the vicinity of its past execution, though.
    ///
    /// # Arguments
    /// * `pc_ctx` - the counter and decoder context
    /// * `decoder` - the thread's decoder needing this entry point prototype
    ///
    /// # Panics
    ///
    /// If translation fails, which Java reports by rethrowing the compiler's exception -- and,
    /// currently, on any cache miss at all, since [`JitCompiler`] is not ported. Also if the
    /// compiler produces a passage with no entry at `pc_ctx`, violating the contract
    /// [`compile_with_max_ops_backoff`](Self::compile_with_max_ops_backoff) documents; Java instead
    /// blocks forever on a future it then never completes.
    ///
    /// Port of `getEntryPrototype(AddrCtx, JitPassageDecoder)`.
    pub fn get_entry_prototype(
        &self,
        pc_ctx: &AddrCtx,
        decoder: &JitPassageDecoder,
    ) -> EntryPointPrototype {
        // It is still possible for a race condition if (very likely) the passage provides multiple
        // entry points. It's not ideal, but still correct, if this happens.
        let (proto, was_absent) = {
            let mut cache = self.code_cache.lock().expect("code cache poisoned");
            match cache.get(pc_ctx) {
                Some(proto) => (Arc::clone(proto), false),
                None => {
                    // Won't know to put other entry points, yet.
                    let proto = Arc::new(EntryFuture::new());
                    cache.insert(pc_ctx.clone(), Arc::clone(&proto));
                    (proto, true)
                }
            }
        };

        if was_absent {
            // Go ahead and use this thread instead of spawning another, because this one can't
            // proceed until compilation is completed, anyway. Note the lock is not held across
            // compilation, which lets threads stall only on translations for the same entry point.
            let pending =
                PendingEntry { cache: &self.code_cache, pc_ctx, armed: true };
            let compiled = self.compile_with_max_ops_backoff(pc_ctx, decoder);
            {
                let mut cache = self.code_cache.lock().expect("code cache poisoned");
                for (entry, prototype) in compiled.get_block_entries() {
                    if &entry == pc_ctx {
                        proto.complete(prototype);
                    } else {
                        cache.insert(entry, Arc::new(EntryFuture::completed(prototype)));
                    }
                }
            }
            assert!(
                proto.is_done(),
                "translation of {pc_ctx} provided no entry at the requested seed"
            );
            pending.disarm();
        }
        proto.get()
    }

    /// Get the configuration for this emulator.
    ///
    /// Port of `getConfiguration()`, i.e. `compiler.getConfiguration()`.
    pub fn get_configuration(&self) -> &JitConfiguration {
        self.compiler.get_configuration()
    }
}

impl ErasedPcodeMachine for JitPcodeEmulator {}

impl AbstractPcodeMachine<Vec<u8>> for JitPcodeEmulator {
    fn base(&self) -> &AbstractPcodeMachineBase<Vec<u8>> {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<Vec<u8>> {
        &mut self.base
    }

    /// Port of the overridden `createSharedState()`.
    fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        Box::new(JitDefaultBytesPcodeExecutorState::new(
            Arc::clone(self.base().language()),
            NONE,
        ))
    }

    /// Port of the overridden `createLocalState(PcodeThread<byte[]>)`.
    fn create_local_state(
        &self,
        _thread: &dyn ErasedPcodeThread,
    ) -> Box<dyn PcodeExecutorState<Vec<u8>>> {
        Box::new(JitDefaultBytesPcodeExecutorState::new(
            Arc::clone(self.base().language()),
            NONE,
        ))
    }

    /// Port of the overridden `createThread(String)`, i.e. `new JitPcodeThread(name, this)`.
    fn create_thread(&self, name: &str) -> Arc<dyn ErasedPcodeThread> {
        Arc::new(JitPcodeThread::named(name))
    }

    /// This machine as a plain [`PcodeMachine`]. Java gets this by subtyping.
    fn as_pcode_machine(&self) -> &dyn PcodeMachine<Vec<u8>> {
        self
    }
}

impl PcodeMachine<Vec<u8>> for JitPcodeEmulator {
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

    fn compile_sleigh(&self, source_name: &str, source: &str) -> PcodeProgram {
        self.base.compile_sleigh(source_name, source)
    }

    fn inject(&mut self, address: &Address, source: &str) {
        AbstractPcodeMachineBase::inject(self, address, source);
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

    fn add_breakpoint(&mut self, address: &Address, sleigh_condition: &str) {
        AbstractPcodeMachineBase::add_breakpoint(self, address, sleigh_condition);
    }

    /// The JIT-accelerated emulator does not currently implement access breakpoints. Furthermore,
    /// because JIT generated code is granted direct access to the emulator's state internals, it is
    /// not sufficient to override
    /// [`PcodeExecutorStatePiece::get_var`](crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece::get_var)
    /// and related.
    ///
    /// # Panics
    ///
    /// Always. Port of the override that throws `UnsupportedOperationException`.
    fn add_access_breakpoint(&mut self, _range: &AddressRange, _kind: AccessKind) {
        unimplemented!("the JIT-accelerated emulator does not implement access breakpoints")
    }

    fn clear_access_breakpoints(&mut self) {
        self.base.clear_access_breakpoints();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::instruction_decoder::InstructionDecoder;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::pcode::seam_stubs::JitCompiledPassage;
    use crate::program::model::address::{
        Address, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::{OpCode, PackedDecode};

    /// Minimal little-endian arithmetic over `byte[]`, standing in for the not-yet-ported
    /// `BytesPcodeArithmetic`, mirroring the identical fixture in
    /// [`crate::pcode::emu::pcode_emulator`]'s own tests.
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

    /// Builds a minimal but real `SleighLanguage`, mirroring the identical helper in
    /// [`crate::pcode::emu::pcode_emulator`]'s own tests.
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

    /// Builds a `JitPcodeEmulator` around a hand-built [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator) carrying
    /// [`StubArithmetic`], since the real `createArithmetic()` path
    /// (`BytesPcodeArithmetic.forLanguage`) is not ported and panics -- the same substitution
    /// [`crate::pcode::emu::pcode_emulator`]'s own tests make.
    fn emulator_with(config: JitConfiguration) -> JitPcodeEmulator {
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
        let emulator = JitPcodeEmulator {
            base,
            compiler: JitCompiler::new(config),
            code_cache: Mutex::new(HashMap::new()),
        };
        AbstractPcodeMachineBase::notify_emulator_created(&emulator);
        emulator
    }

    fn emulator() -> JitPcodeEmulator {
        emulator_with(JitConfiguration::default())
    }

    fn ram(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    struct FakePassage;
    impl JitCompiledPassage for FakePassage {}

    /// A decoder that is never asked to decode anything: the tests below either hit the cache or
    /// stop at the unported compiler, both before the decoder is consulted. Mirrors the same
    /// fixture in [`crate::pcode::emu::jit::gen::tgt::jit_compiled_passage_class`]'s tests.
    struct DummyDecoder;

    impl InstructionDecoder for DummyDecoder {
        fn get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by these tests")
        }

        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn crate::pcode::seam_stubs::RegisterValue>,
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

    /// The decoder a thread would hand the emulator when it needs an entry prototype.
    fn passage_decoder() -> JitPassageDecoder {
        let library: Arc<dyn PcodeUseropLibrary<Vec<u8>>> = Arc::new(nil::<Vec<u8>>());
        JitPassageDecoder::new(JitPcodeThread::new(
            Arc::new(Mutex::new(DummyDecoder)),
            None,
            library,
        ))
    }

    fn fake_class(entries: Vec<AddrCtx>) -> JitCompiledPassageClass {
        JitCompiledPassageClass::new(
            Arc::new(|_thread: &JitPcodeThread| {
                Box::new(FakePassage) as Box<dyn JitCompiledPassage>
            }),
            entries,
        )
    }

    #[test]
    fn get_configuration_returns_the_compilers_configuration() {
        // Java: `getConfiguration()` is `compiler.getConfiguration()`, and the no-arg
        // `JitConfiguration()` is `this(1000, 5000, 10, true, true, false)`.
        let emulator = emulator();
        let config = emulator.get_configuration();
        assert_eq!(1000, config.max_passage_instructions);
        assert_eq!(5000, config.max_passage_ops);
        assert_eq!(10, config.max_passage_strides);
        assert!(config.remove_unused_operations);
        assert!(config.emit_counters);
        assert!(!config.log_stack_traces);

        // ...and a non-default configuration is carried through, not reset.
        let custom = JitConfiguration { max_passage_ops: 64, ..JitConfiguration::default() };
        assert_eq!(64, emulator_with(custom).get_configuration().max_passage_ops);
    }

    #[test]
    fn has_entry_prototype_is_false_until_the_translation_completes() {
        // Java: `proto != null && proto.isDone()`. A pending translation -- one another thread is
        // still compiling -- must read as absent, not as present.
        let emulator = emulator();
        let pc_ctx = AddrCtx::new(None, ram(0x400));
        assert!(!emulator.has_entry_prototype(&pc_ctx));

        let pending = Arc::new(EntryFuture::new());
        emulator
            .code_cache
            .lock()
            .unwrap()
            .insert(pc_ctx.clone(), Arc::clone(&pending));
        assert!(!emulator.has_entry_prototype(&pc_ctx));

        pending.complete(EntryPointPrototype::new(fake_class(vec![pc_ctx.clone()]), 0));
        assert!(emulator.has_entry_prototype(&pc_ctx));

        // The cache is keyed by (contextreg value, address): a different context at the same
        // address is a different entry point. Java: `AddrCtx.equals` compares `biCtx` and
        // `address`.
        struct Ctx(i128);
        impl crate::pcode::seam_stubs::RegisterValue for Ctx {
            fn get_unsigned_value(&self) -> i128 {
                self.0
            }
        }
        let other_ctx = AddrCtx::new(Some(Arc::new(Ctx(7))), ram(0x400));
        assert!(!emulator.has_entry_prototype(&other_ctx));
    }

    #[test]
    fn get_entry_prototype_returns_a_cached_translation_without_compiling() {
        // Java: when `codeCache.get(pcCtx)` is present, `getEntryPrototype` never calls
        // `compileWithMaxOpsBackoff`. That matters here, since this crate's `JitCompiler` panics.
        let emulator = emulator();
        let pc_ctx = AddrCtx::new(None, ram(0x1000));
        let other = AddrCtx::new(None, ram(0x2000));
        let cls = fake_class(vec![pc_ctx.clone(), other.clone()]);
        for (entry, prototype) in cls.get_block_entries() {
            emulator
                .code_cache
                .lock()
                .unwrap()
                .insert(entry, Arc::new(EntryFuture::completed(prototype)));
        }

        // Block ids come from each entry's position in the passage's entry list.
        let decoder = passage_decoder();
        assert_eq!(0, emulator.get_entry_prototype(&pc_ctx, &decoder).block_id);
        assert_eq!(1, emulator.get_entry_prototype(&other, &decoder).block_id);
    }

    #[test]
    fn create_thread_makes_jit_threads_named_like_java() {
        // Java: `createThread(name)` is `new JitPcodeThread(name, this)`, and the inherited
        // `newThread()` names threads "Thread " + threads.size().
        let mut emulator = emulator();
        let first = PcodeMachine::new_thread(&mut emulator);
        let named = PcodeMachine::new_thread_named(&mut emulator, "worker");
        assert_eq!(2, emulator.get_all_threads().len());
        assert!(Arc::ptr_eq(&first, &emulator.get_all_threads()[0]));
        assert!(Arc::ptr_eq(&named, &emulator.get_all_threads()[1]));
        assert!(emulator.base.get_thread_by_name("Thread 0").is_some());
        assert!(emulator.base.get_thread_by_name("worker").is_some());
    }

    #[test]
    fn shared_state_is_created_lazily_and_reused() {
        // Java: `getSharedState()` creates the state on first call and reuses it thereafter.
        let mut emulator = emulator();
        assert!(emulator.base.shared_state().is_none());

        let _ = PcodeMachine::get_shared_state_mut(&mut emulator);
        assert!(emulator.base.shared_state().is_some());
    }

    #[test]
    #[should_panic(expected = "JitDefaultBytesPcodeExecutorState not yet ported")]
    fn shared_state_is_the_jit_state_not_the_plain_bytes_one() {
        // Java: the override returns `new JitDefaultBytesPcodeExecutorState(language, scb)`, where
        // `PcodeEmulator` would have returned a `BytesPcodeExecutorState`. Neither is ported, and
        // each names itself in the panic its `getLanguage()` raises, so which one was built is
        // exactly what this distinguishes.
        let mut emulator = emulator();
        let _ = PcodeMachine::get_shared_state_mut(&mut emulator).get_language();
    }

    #[test]
    #[should_panic(expected = "JitDefaultBytesPcodeExecutorState not yet ported")]
    fn local_state_is_the_jit_state_too() {
        // Java: `createLocalState(PcodeThread<byte[]>)` returns the same kind of state.
        let emulator = emulator();
        let thread: Arc<dyn ErasedPcodeThread> = Arc::new(JitPcodeThread::named("t"));
        let _ = emulator.create_local_state(thread.as_ref()).get_language();
    }

    #[test]
    #[should_panic(expected = "does not implement access breakpoints")]
    fn add_access_breakpoint_is_unsupported() {
        // Java: the override throws UnsupportedOperationException.
        let mut emulator = emulator();
        let range = AddressRange::new(ram(0x1000), ram(0x1fff));
        emulator.add_access_breakpoint(&range, AccessKind::R);
    }

    #[test]
    fn get_entry_prototype_translates_on_a_cache_miss_and_does_not_strand_the_entry() {
        // Java: an absent entry point sends `getEntryPrototype` through
        // `compileWithMaxOpsBackoff` -> `decoder.decodePassage` -> `compiler.compilePassage`. The
        // decoder's inner `DecoderForOnePassage` isn't ported, so translation fails there.
        let emulator = emulator();
        let pc_ctx = AddrCtx::new(None, ram(0x3000));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emulator.get_entry_prototype(&pc_ctx, &passage_decoder());
        }));
        let failure =
            result.expect_err("translation cannot succeed until the decoder and compiler are ported");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(message.contains("DecoderForOnePassage"), "unexpected failure: {message}");

        // Java would leave an exceptionally-completed future behind, whose failure it rethrows to
        // every later requester. A panic already reached this caller, so the pending entry is
        // dropped instead -- otherwise the next requester would block on it forever.
        assert!(!emulator.has_entry_prototype(&pc_ctx));
        assert!(emulator.code_cache.lock().unwrap().is_empty());
    }
}
