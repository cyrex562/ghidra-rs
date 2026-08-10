//! A p-code thread which incorporates per-architecture state modifiers.
//!
//! Port of `ghidra.pcode.emu.ModifiedPcodeThread`.
//!
//! All machines that include a concrete state piece, i.e., all emulators, should use threads
//! derived from this one. This implementation assumes that the modified state can be concretized.
//! This doesn't necessarily require the machine to be a concrete emulator, but an abstract machine
//! must avoid or handle `ConcretionError`s arising from state modifiers.
//!
//! For a complete example of a p-code emulator, see
//! [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//!
//! "State modifiers" are a feature of the older `Emulator`. They are crudely incorporated into
//! threads built from this module, so that they do not yet need to be ported to this emulator.
//!
//! # Divergences from Java
//!
//! * **No subclassing.** Java's `ModifiedPcodeThread<T> extends DefaultPcodeThread<T>`, overriding
//!   `createUseropLibrary()`, `overrideCounter(Address)`, and `postExecuteInstruction()`. Rust has
//!   no inheritance, so [`ModifiedPcodeThread`] wraps a [`DefaultPcodeThread`] by composition.
//!   `override_counter` is a trait method this type implements itself, so it is free to add the
//!   modifier callback after delegating -- but only for *external* calls; `DefaultPcodeThread`'s
//!   own internal call to `overrideCounter` from `skipInstruction` is monomorphized to itself and
//!   cannot reach this override. `createUseropLibrary()` and `postExecuteInstruction()` have no
//!   trait-level seam at all (Java calls them as protected virtual methods from deep inside
//!   `DefaultPcodeThread`'s control flow), so [`DefaultPcodeThread`] grew two narrow, additive
//!   extension points for them: [`DefaultPcodeThread::replace_library`] and
//!   [`DefaultPcodeThread::set_post_execute_hook`]/[`PostExecuteHook`]. See that module's docs.
//! * **No reflection.** Java's `createModifier()` looks up the language's
//!   `EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS` property and instantiates it via
//!   `ClassSearcher`/reflection over a `Constructor<? extends EmulateInstructionStateModifier>`.
//!   Rust has no dynamic class loading, so the modifier is a constructor parameter of
//!   [`ModifiedPcodeThread::new`] instead: the caller resolves it however it likes (e.g. from the
//!   same language property, via its own registry) and hands over an already-constructed
//!   [`PcodeStateModifier`].
//! * **`GlueEmulate` is minimal.** Java's inner `GlueEmulate` overrides five `Emulate` methods
//!   (`getLanguage`, `setExecuteAddress`/`getExecuteAddress`,
//!   `setContextRegisterValue`/`getContextRegisterValue`) so that a state modifier can drive the
//!   thread's counter and context through the legacy `Emulate` API. This crate's [`Emulate`] seam
//!   stub (see `crate::pcode::seam_stubs`) exposes only `dispose`/`get_language`, since nothing here
//!   calls the other three -- the modifier hooks this type *does* wire
//!   ([`PcodeStateModifier::initial_execute_callback`]/`post_execute_callback`) only ever receive
//!   `&dyn Emulate` opaquely, they never call back into it. `get_language` itself is unreachable
//!   for the same reason and panics if invoked.

use std::any::TypeId;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine;
use crate::pcode::emu::default_pcode_thread::{DefaultPcodeThread, PostExecuteHook};
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::pcode_thread::{ErasedPcodeThread, PcodeThread};
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
#[allow(deprecated)]
use crate::pcode::emulate::emulate_instruction_state_modifier::{
    EmulateInstructionStateModifier, EmulateInstructionStateModifierBase,
};
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::seam_stubs::{Emulate, RegisterValue};
use crate::program::model::address::Address;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Instruction;
use crate::program::model::pcode::{PcodeOp, Varnode};
use std::collections::HashMap;
use std::sync::MutexGuard;

/// The combination Java's abstract `EmulateInstructionStateModifier` class provides to a subclass:
/// the CALLOTHER dispatch table
/// ([`EmulateInstructionStateModifierBase`]) plus the two overridable callbacks
/// ([`EmulateInstructionStateModifier`]). A concrete, language-specific modifier passed to
/// [`ModifiedPcodeThread::new`] implements both, exactly as Java's doc for
/// `EmulateInstructionStateModifierBase` anticipates.
#[allow(deprecated)]
pub trait PcodeStateModifier: EmulateInstructionStateModifier {
    /// The shared CALLOTHER dispatch table this modifier registered against.
    fn base(&self) -> &EmulateInstructionStateModifierBase;
}

/// Glue for incorporating state modifiers.
///
/// Port of `ModifiedPcodeThread.GlueEmulate`. This allows the modifiers to change the context and
/// counter of the thread in Java; here it is passed opaquely to the modifier's callbacks and
/// nothing calls back into it -- see the module docs.
struct GlueEmulate;

impl Emulate for GlueEmulate {
    fn dispose(&self) {}

    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!(
            "GlueEmulate::get_language is unreachable: nothing in this port's \
             ModifiedPcodeThread calls back into the Emulate it hands to a modifier"
        )
    }
}

/// A wrapper around `OpBehaviorOther`.
///
/// Port of `ModifiedPcodeThread.ModifierUseropLibrary.ModifierUseropDefinition`. Java's inner class
/// closes over its enclosing `ModifiedPcodeThread` for `emulate`; here that is an explicit `Arc`,
/// and the behavior is looked up by index from the modifier's dispatch table at call time rather
/// than held directly, since [`EmulateInstructionStateModifierBase::get_pcode_op_map`] only lends a
/// borrow.
#[allow(deprecated)]
struct ModifierUseropDefinition<T: 'static> {
    name: String,
    op_index: i32,
    modifier: Arc<dyn PcodeStateModifier>,
    emulate: Arc<dyn Emulate>,
    _t: PhantomData<fn() -> T>,
}

#[allow(deprecated)]
impl<T: 'static> PcodeUseropDefinition<T> for ModifierUseropDefinition<T> {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_input_count(&self) -> i32 {
        -1
    }

    fn execute(
        &self,
        _executor: &PcodeExecutor<T>,
        _library: &dyn PcodeUseropLibrary<T>,
        _op: &PcodeOp,
        out_var: Option<&Varnode>,
        in_vars: &[Varnode],
    ) {
        let behavior = self
            .modifier
            .base()
            .get_pcode_op_map()
            .get(&self.op_index)
            .expect("this definition's own registration outlives it");
        behavior.evaluate(self.emulate.as_ref(), out_var, in_vars);
    }

    fn is_functional(&self) -> bool {
        false
    }

    fn has_side_effects(&self) -> bool {
        true
    }

    fn modifies_context(&self) -> bool {
        true
    }

    fn can_inline_pcode(&self) -> bool {
        false
    }

    fn get_output_type(&self) -> Option<TypeId> {
        None
    }

    fn get_java_method(&self) -> Option<()> {
        None
    }

    fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
        // Java returns `ModifierUseropLibrary.this`. A back-reference to the owning library would
        // be a cycle -- and isn't expressible from `&self` anyway -- so, as with
        // `AnnotatedPcodeUseropDefinition`, this is always `None`.
        None
    }
}

/// For incorporating the state modifier's userop behaviors.
///
/// Port of `ModifiedPcodeThread.ModifierUseropLibrary`. Java computes and caches `userops` lazily
/// on first access; this builds the (small, fixed) map eagerly at construction instead, which is
/// observably equivalent since the modifier's dispatch table does not change afterward.
#[allow(deprecated)]
struct ModifierUseropLibrary<T: 'static> {
    userops: UseropMap<T>,
}

#[allow(deprecated)]
impl<T: 'static> ModifierUseropLibrary<T> {
    /// Port of `computeUserops()`, run eagerly rather than lazily (see the struct docs).
    fn new(
        modifier: Option<Arc<dyn PcodeStateModifier>>,
        exec_language: &dyn Language,
        emulate: &Arc<dyn Emulate>,
    ) -> Self {
        let mut userops: UseropMap<T> = HashMap::new();
        if let Some(modifier) = modifier {
            for &op_index in modifier.base().get_pcode_op_map().keys() {
                let Some(name) = exec_language.get_user_defined_op_name(op_index) else {
                    continue;
                };
                let definition = ModifierUseropDefinition {
                    name: name.clone(),
                    op_index,
                    modifier: Arc::clone(&modifier),
                    emulate: Arc::clone(emulate),
                    _t: PhantomData,
                };
                userops.insert(name, Arc::new(definition));
            }
        }
        Self { userops }
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for ModifierUseropLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for ModifierUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        &self.userops
    }
}

/// Adapts a [`PcodeStateModifier`] to the [`PostExecuteHook`] seam, forwarding
/// [`DefaultPcodeThread`]'s post-execute notification to the modifier's `postExecuteCallback`.
///
/// Port of the body of `ModifiedPcodeThread.postExecuteInstruction()`.
#[allow(deprecated)]
struct ModifierPostExecuteHook {
    modifier: Arc<dyn PcodeStateModifier>,
    emulate: Arc<dyn Emulate>,
}

#[allow(deprecated)]
impl<T: 'static> PostExecuteHook<T> for ModifierPostExecuteHook {
    fn post_execute_instruction(
        &self,
        last_execute_address: &Address,
        last_execute_pcode: &[PcodeOp],
        last_pcode_index: i32,
        current_address: &Address,
    ) {
        if let Err(e) = self.modifier.post_execute_callback(
            self.emulate.as_ref(),
            last_execute_address,
            last_execute_pcode,
            last_pcode_index,
            current_address,
        ) {
            panic!("{e}");
        }
    }
}

/// A p-code thread which incorporates per-architecture state modifiers.
///
/// `T` is the type of variables in the emulator, `S` the concrete type of the machine's shared
/// (memory) state, and `L` that of this thread's local (register/unique) state -- see
/// [`DefaultPcodeThread`], which this type wraps.
#[allow(deprecated)]
pub struct ModifiedPcodeThread<T: 'static, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    inner: DefaultPcodeThread<T, S, L>,
    /// Part of the glue that makes existing state modifiers work in this emulation framework.
    ///
    /// Java instantiates one per thread, rather than sharing one across the machine, because some
    /// modifiers are stateful and assume a single-threaded model. `None` if the language declares
    /// no `EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS` (or the caller otherwise has none to supply).
    modifier: Option<Arc<dyn PcodeStateModifier>>,
    /// Glue for incorporating state modifiers. See [`GlueEmulate`].
    #[allow(dead_code)]
    emulate: Arc<dyn Emulate>,
}

#[allow(deprecated)]
impl<T: 'static, S, L> ModifiedPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    /// Construct a new thread with the given name belonging to the given machine.
    ///
    /// Port of `ModifiedPcodeThread(String, AbstractPcodeMachine<T>)`. `exec_language`,
    /// `shared_state`, `local_state`, and `decoder` are exactly what
    /// [`DefaultPcodeThread::new`] needs from a machine, matching that constructor's own
    /// divergence from Java (see its module docs). `modifier` stands in for Java's reflective
    /// `createModifier()` -- see this module's docs.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as [`DefaultPcodeThread::new`] requires.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        machine: Arc<dyn AbstractPcodeMachine<T>>,
        exec_language: Arc<dyn Language>,
        shared_state: S,
        local_state: L,
        decoder: Box<dyn InstructionDecoder>,
        modifier: Option<Arc<dyn PcodeStateModifier>>,
    ) -> Self {
        let mut inner = DefaultPcodeThread::new(
            name,
            machine,
            Arc::clone(&exec_language),
            shared_state,
            local_state,
            decoder,
        );

        let emulate: Arc<dyn Emulate> = Arc::new(GlueEmulate);

        // Port of `createUseropLibrary()`: `new ModifierUseropLibrary().compose(super.createUseropLibrary(), true)`.
        let modifier_library =
            ModifierUseropLibrary::<T>::new(modifier.clone(), exec_language.as_ref(), &emulate);
        let composed = modifier_library.compose_with_override(inner.get_userop_library(), true);
        inner.replace_library(composed);

        // Wires `postExecuteInstruction()`'s override; see `PostExecuteHook`'s docs.
        if let Some(modifier) = &modifier {
            let hook: Arc<dyn PostExecuteHook<T>> = Arc::new(ModifierPostExecuteHook {
                modifier: Arc::clone(modifier),
                emulate: Arc::clone(&emulate),
            });
            inner.set_post_execute_hook(hook);
        }

        Self { inner, modifier, emulate }
    }

    /// The wrapped [`DefaultPcodeThread`], for access to members this type does not otherwise
    /// re-expose.
    pub fn inner(&self) -> &DefaultPcodeThread<T, S, L> {
        &self.inner
    }

    /// This thread's state modifier, if the language specifies one.
    pub fn modifier(&self) -> Option<&Arc<dyn PcodeStateModifier>> {
        self.modifier.as_ref()
    }
}

#[allow(deprecated)]
impl<T: 'static, S, L> ErasedPcodeThread for ModifiedPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
}

#[allow(deprecated)]
impl<T: 'static, S, L> PcodeThread<T> for ModifiedPcodeThread<T, S, L>
where
    S: PcodeExecutorState<T> + 'static,
    L: PcodeExecutorState<T> + 'static,
{
    type SharedState = S;
    type LocalState = L;

    fn get_name(&self) -> &str {
        self.inner.get_name()
    }

    fn get_machine(&self) -> &dyn PcodeMachine<T> {
        self.inner.get_machine()
    }

    fn set_counter(&mut self, counter: &Address) {
        self.inner.set_counter(counter);
    }

    fn get_counter(&self) -> Address {
        self.inner.get_counter()
    }

    /// Port of the override: writes through, then (if a modifier is installed) runs its
    /// `initialExecuteCallback`. Only reaches modifier-driven internal callers of
    /// `overrideCounter` (e.g. `skipInstruction`) when they go through this type -- see the module
    /// docs on why `DefaultPcodeThread`'s own internal call cannot be intercepted.
    fn override_counter(&mut self, counter: &Address) {
        self.inner.override_counter(counter);
        if let Some(modifier) = &self.modifier {
            if let Err(e) = modifier.initial_execute_callback(
                self.emulate.as_ref(),
                counter,
                self.inner.get_context(),
            ) {
                panic!("{e}");
            }
        }
    }

    fn assign_context(&mut self, context: &dyn RegisterValue) {
        self.inner.assign_context(context);
    }

    fn get_context(&self) -> Option<&dyn RegisterValue> {
        self.inner.get_context()
    }

    fn override_context(&mut self, context: &dyn RegisterValue) {
        self.inner.override_context(context);
    }

    fn override_context_with_default(&mut self) {
        self.inner.override_context_with_default();
    }

    fn re_initialize(&mut self) {
        self.inner.re_initialize();
    }

    fn step_instruction(&mut self) {
        self.inner.step_instruction();
    }

    fn step_pcode_op(&mut self) {
        self.inner.step_pcode_op();
    }

    fn skip_pcode_op(&mut self) {
        self.inner.skip_pcode_op();
    }

    fn step_patch(&mut self, sleigh: &str) {
        self.inner.step_patch(sleigh);
    }

    fn get_frame(&self) -> Option<&PcodeFrame> {
        self.inner.get_frame()
    }

    fn get_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.inner.get_instruction()
    }

    fn execute_instruction(&mut self) {
        self.inner.execute_instruction();
    }

    fn finish_instruction(&mut self) {
        self.inner.finish_instruction();
    }

    fn skip_instruction(&mut self) {
        self.inner.skip_instruction();
    }

    fn drop_instruction(&mut self) {
        self.inner.drop_instruction();
    }

    fn run(&mut self) {
        self.inner.run();
    }

    fn set_suspended(&mut self, suspended: bool) {
        self.inner.set_suspended(suspended);
    }

    fn is_suspended(&self) -> bool {
        self.inner.is_suspended()
    }

    fn get_language(&self) -> &SleighLanguage {
        self.inner.get_language()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        self.inner.get_arithmetic()
    }

    fn get_executor(&self) -> &PcodeExecutor<T> {
        self.inner.get_executor()
    }

    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T> {
        self.inner.get_userop_library()
    }

    fn get_state(&self) -> MutexGuard<'_, ThreadPcodeExecutorState<T, S, L>> {
        self.inner.get_state()
    }

    fn inject(&mut self, address: &Address, source: &str) {
        self.inner.inject(address, source);
    }

    fn clear_inject(&mut self, address: &Address) {
        self.inner.clear_inject(address);
    }

    fn clear_all_injects(&mut self) {
        self.inner.clear_all_injects();
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase;
    use crate::pcode::opbehavior::OpBehaviorOther;
    use crate::pcode::emu::pcode_emulation_callbacks::PcodeEmulationCallbacks;
    use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
    use crate::pcode::error::lowlevel_error::LowlevelError;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_program::testing::empty_program;
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::pcode::seam_stubs::PseudoInstruction;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{
        LanguageDescription, LanguageID, ParallelInstructionLanguageHelper, ParseError,
    };
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, PackedDecode};
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex;

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
        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    #[derive(Default)]
    struct MapState {
        cells: RefCell<StdHashMap<(String, i64), Vec<u8>>>,
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
            self.cells.borrow_mut().insert((space.name().to_string(), offset), val.clone());
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

    struct FixedLengthDecoder {
        length: i32,
    }

    struct NoInstruction;
    impl PseudoInstruction for NoInstruction {}

    impl InstructionDecoder for FixedLengthDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            Ok(Box::new(NoInstruction))
        }
        fn branched(&mut self, _address: &Address) {}
        fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_last_length_with_delays(&self) -> i32 {
            self.length
        }
    }

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
        fn set_software_interrupt_mode(&mut self, mode: crate::pcode::emu::pcode_machine::SwiMode) {
            self.base.set_software_interrupt_mode(mode);
        }
        fn get_software_interrupt_mode(&self) -> crate::pcode::emu::pcode_machine::SwiMode {
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
        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> crate::pcode::exec::pcode_program::PcodeProgram {
            empty_program()
        }
        fn inject(&mut self, _address: &Address, _source: &str) {
            unimplemented!("not exercised by these tests")
        }
        fn get_inject(&self, address: &Address) -> Option<&crate::pcode::exec::pcode_program::PcodeProgram> {
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
        fn add_access_breakpoint(
            &mut self,
            range: &crate::program::model::address::AddressRange,
            kind: crate::pcode::emu::pcode_machine::AccessKind,
        ) {
            self.base.add_access_breakpoint(range, kind);
        }
        fn clear_access_breakpoints(&mut self) {
            self.base.clear_access_breakpoints();
        }
    }

    struct ExecLanguage {
        user_ops: Vec<&'static str>,
    }

    impl Language for ExecLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram()
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            Some(pc_register())
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            self.user_ops.len() as i32
        }
        fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
            self.user_ops.get(index as usize).map(|s| s.to_string())
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

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    fn pc_register() -> RegisterRef {
        Register::new("pc", "", register_space().address(0), 8, false, Register::TYPE_PC)
    }

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

    /// A recording [`PcodeStateModifier`], registering a single CALLOTHER behavior under
    /// `"my_modifier_op"` and recording every `initialExecuteCallback`/`postExecuteCallback`
    /// invocation.
    struct RecordingModifier {
        base: EmulateInstructionStateModifierBase,
        initial_calls: Mutex<Vec<i64>>,
        post_calls: Mutex<Vec<(i64, i32, i64)>>,
    }

    impl RecordingModifier {
        fn new(emu: Box<dyn Emulate>) -> Arc<Self> {
            let mut base = EmulateInstructionStateModifierBase::new(emu);
            struct RecordingBehavior;
            impl OpBehaviorOther for RecordingBehavior {
                fn evaluate(&self, _emu: &dyn Emulate, _out: Option<&Varnode>, _inputs: &[Varnode]) {}
            }
            base.register_pcode_op_behavior("my_modifier_op", Box::new(RecordingBehavior))
                .expect("my_modifier_op is declared by ExecLanguage");
            Arc::new(Self {
                base,
                initial_calls: Mutex::new(Vec::new()),
                post_calls: Mutex::new(Vec::new()),
            })
        }
    }

    /// `EmulateInstructionStateModifierBase::new` reads `emu.getLanguage()` up front (to resolve
    /// user-defined op names for `registerPcodeOpBehavior`), so this cannot be a bare no-op.
    struct NoopEmulate;
    impl Emulate for NoopEmulate {
        fn dispose(&self) {}
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(ExecLanguage { user_ops: vec!["my_modifier_op"] })
        }
    }

    impl EmulateInstructionStateModifier for RecordingModifier {
        fn initial_execute_callback(
            &self,
            _emulate: &dyn Emulate,
            current_address: &Address,
            _context_register_value: Option<&dyn RegisterValue>,
        ) -> Result<(), LowlevelError> {
            self.initial_calls.lock().unwrap().push(current_address.offset());
            Ok(())
        }

        fn post_execute_callback(
            &self,
            _emulate: &dyn Emulate,
            last_execute_address: &Address,
            last_execute_pcode: &[PcodeOp],
            last_pcode_index: i32,
            current_address: &Address,
        ) -> Result<(), LowlevelError> {
            self.post_calls.lock().unwrap().push((
                last_execute_address.offset(),
                last_pcode_index,
                current_address.offset(),
            ));
            let _ = last_execute_pcode;
            Ok(())
        }
    }

    impl PcodeStateModifier for RecordingModifier {
        fn base(&self) -> &EmulateInstructionStateModifierBase {
            &self.base
        }
    }

    struct Fixture {
        thread: ModifiedPcodeThread<Vec<u8>, MapState, MapState>,
        modifier: Arc<RecordingModifier>,
    }

    fn fixture(counter: i64) -> Fixture {
        let cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>> =
            crate::pcode::emu::pcode_emulation_callbacks::no_pcode_emulation_callbacks::<Vec<u8>>();
        let machine = Arc::new(TestMachine {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                cb,
                Arc::new(BytesArithmetic),
                Box::new(nil::<Vec<u8>>()),
                Box::new(nil::<Vec<u8>>()),
                None,
            ),
        });

        let mut shared = MapState::default();
        let mut local = MapState::default();
        local.set_var_register(&pc_register(), &counter.to_le_bytes().to_vec());
        shared.set_var_register(&pc_register(), &counter.to_le_bytes().to_vec());

        let modifier = RecordingModifier::new(Box::new(NoopEmulate));

        let thread = ModifiedPcodeThread::new(
            "Thread 0",
            Arc::clone(&machine) as Arc<dyn AbstractPcodeMachine<Vec<u8>>>,
            Arc::new(ExecLanguage { user_ops: vec!["my_modifier_op"] }),
            shared,
            local,
            Box::new(FixedLengthDecoder { length: 4 }),
            Some(Arc::clone(&modifier) as Arc<dyn PcodeStateModifier>),
        );
        Fixture { thread, modifier }
    }

    /// The composed library exports both the standard `DefaultPcodeThread` userops and the
    /// modifier's, matching Java's `createUseropLibrary()` override.
    #[test]
    fn userop_library_exports_the_modifiers_op_alongside_the_standard_ones() {
        let f = fixture(0x400000);
        let userops = f.thread.get_userop_library().get_userops();
        let mut names: Vec<&str> = userops.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            vec!["emu_exec_decoded", "emu_injection_err", "emu_skip_decoded", "emu_swi", "my_modifier_op"],
            names
        );
        assert_eq!(-1, userops["my_modifier_op"].get_input_count());
    }

    /// `overrideCounter` writes through to the wrapped thread and runs the modifier's
    /// `initialExecuteCallback` with the new counter.
    #[test]
    fn override_counter_writes_through_and_notifies_the_modifier() {
        let mut f = fixture(0x400000);
        let target = ram().address(0x1000);

        f.thread.override_counter(&target);

        assert_eq!(0x1000, f.thread.get_counter().offset());
        assert_eq!(vec![0x1000], *f.modifier.initial_calls.lock().unwrap());
    }

    /// `ModifiedPcodeThread::new` wires a [`ModifierPostExecuteHook`] into the wrapped thread's
    /// `PostExecuteHook` seam; this exercises that adapter directly (in isolation from
    /// `DefaultPcodeThread::advance_after_finished`, which needs a fully decoded `Instruction` --
    /// infrastructure no test in this crate builds yet, see `default_pcode_thread`'s own tests),
    /// confirming it forwards to the modifier's `postExecuteCallback` faithfully.
    #[test]
    fn post_execute_hook_forwards_to_the_modifiers_callback() {
        let modifier = RecordingModifier::new(Box::new(NoopEmulate));
        let hook = ModifierPostExecuteHook {
            modifier: Arc::clone(&modifier) as Arc<dyn PcodeStateModifier>,
            emulate: Arc::new(NoopEmulate) as Arc<dyn Emulate>,
        };
        let space = ram();
        let last = space.address(0x400000);
        let code = vec![];
        let current = space.address(0x400004);

        <ModifierPostExecuteHook as PostExecuteHook<Vec<u8>>>::post_execute_instruction(
            &hook, &last, &code, -1, &current,
        );

        assert_eq!(vec![(0x400000, -1, 0x400004)], *modifier.post_calls.lock().unwrap());
    }

    /// With no modifier installed, the thread behaves exactly like a plain `DefaultPcodeThread`:
    /// only the standard userops are declared, and `overrideCounter` triggers no callback.
    #[test]
    fn with_no_modifier_the_thread_behaves_like_the_default() {
        let cb: Arc<dyn PcodeEmulationCallbacks<Vec<u8>>> =
            crate::pcode::emu::pcode_emulation_callbacks::no_pcode_emulation_callbacks::<Vec<u8>>();
        let machine = Arc::new(TestMachine {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                cb,
                Arc::new(BytesArithmetic),
                Box::new(nil::<Vec<u8>>()),
                Box::new(nil::<Vec<u8>>()),
                None,
            ),
        });
        let mut shared = MapState::default();
        let mut local = MapState::default();
        local.set_var_register(&pc_register(), &0x400000i64.to_le_bytes().to_vec());
        shared.set_var_register(&pc_register(), &0x400000i64.to_le_bytes().to_vec());

        let mut thread = ModifiedPcodeThread::new(
            "Thread 0",
            Arc::clone(&machine) as Arc<dyn AbstractPcodeMachine<Vec<u8>>>,
            Arc::new(ExecLanguage { user_ops: vec![] }),
            shared,
            local,
            Box::new(FixedLengthDecoder { length: 4 }),
            None,
        );

        let mut names: Vec<&str> =
            thread.get_userop_library().get_userops().keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(vec!["emu_exec_decoded", "emu_injection_err", "emu_skip_decoded", "emu_swi"], names);

        thread.override_counter(&ram().address(0x2000));
        assert_eq!(0x2000, thread.get_counter().offset());
        assert!(thread.modifier().is_none());
    }
}
