//! The default thread for [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::AuxPcodeEmulator).
//!
//! Corresponds to `ghidra.pcode.emu.auxiliary.AuxPcodeThread`.
//!
//! Generally, wrapping this type should not be necessary, as it already defers to the emulator's
//! parts factory.
//!
//! `U` is Java's `AuxPcodeThread<U>` type parameter: the type of auxiliary values. As with
//! [`AuxPcodeEmulator`] and [`AuxEmulatorPartsFactory`], Java's `Pair<byte[], U>` is rendered as
//! the tuple `(Vec<u8>, U)`.
//!
//! # Shape
//!
//! Java's `AuxPcodeThread<U> extends ModifiedPcodeThread<Pair<byte[], U>>`, overriding
//! `createUseropLibrary()` and `createExecutor()` to defer to the emulator's parts factory. Those
//! overrides are [`AuxThreadHooks`], which holds the [`ModifiedThreadHooks`] of its superclass and
//! calls them where Java calls `super`; the thread itself is [`AuxPcodeThread`] =
//! [`DefaultPcodeThread`] over those hooks.
//!
//! # Deviations from Java
//!
//! * **No `getMachine()` override.** Java's override narrows `super.getMachine()` back down to
//!   `AuxPcodeEmulator<U>` via an unchecked cast. The hooks hold the narrow emulator handle
//!   themselves (see [`AuxThreadHooks::emulator`]), which is where the two overrides need it.
//! * **The parts factory is held by the hooks.** Java recovers it from the emulator via
//!   `getPartsFactory()`, which cannot be a method of the object-safe [`AuxPcodeEmulator`] (see
//!   that module's docs), so the thread's creator supplies it alongside the emulator.

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine;
use crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory;
use crate::pcode::emu::auxiliary::aux_pcode_emulator::AuxPcodeEmulator;
use crate::pcode::emu::default_pcode_thread::{
    DefaultPcodeThread, PcodeThreadExecutor, ThreadCore, ThreadHooks,
};
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
#[allow(deprecated)]
use crate::pcode::emu::modified_pcode_thread::{ModifiedThreadHooks, PcodeStateModifier};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::program::model::address::Address;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::PcodeOp;

/// The overrides of Java's `AuxPcodeThread`, over those of its superclass `ModifiedPcodeThread`.
///
/// `U` is the type of auxiliary values and `F` the emulator's parts factory.
pub struct AuxThreadHooks<U: 'static, F> {
    parent: ModifiedThreadHooks,
    emulator: Arc<dyn AuxPcodeEmulator<U>>,
    parts_factory: Arc<F>,
}

impl<U: 'static, F: AuxEmulatorPartsFactory<U>> AuxThreadHooks<U, F> {
    /// The overrides for a thread of the given emulator, whose parts come from the given factory.
    ///
    /// `modifier` is what [`ModifiedThreadHooks::new`] takes for the superclass.
    #[allow(deprecated)]
    pub fn new(
        emulator: Arc<dyn AuxPcodeEmulator<U>>,
        parts_factory: Arc<F>,
        modifier: Option<Arc<dyn PcodeStateModifier>>,
    ) -> Self {
        Self { parent: ModifiedThreadHooks::new(modifier), emulator, parts_factory }
    }

    /// The emulator this thread belongs to. Port of the narrowed `getMachine()`.
    pub fn emulator(&self) -> &Arc<dyn AuxPcodeEmulator<U>> {
        &self.emulator
    }

    /// The emulator's parts factory. Port of `getPartsFactory()`.
    pub fn parts_factory(&self) -> &Arc<F> {
        &self.parts_factory
    }

    /// The superclass's overrides.
    pub fn modified(&self) -> &ModifiedThreadHooks {
        &self.parent
    }
}

impl<U: 'static, F, S, L> ThreadHooks<(Vec<u8>, U), S, L> for AuxThreadHooks<U, F>
where
    F: AuxEmulatorPartsFactory<U>,
    S: PcodeExecutorState<(Vec<u8>, U)> + 'static,
    L: PcodeExecutorState<(Vec<u8>, U)> + 'static,
{
    fn create_instruction_decoder(
        &mut self,
        decoder: Box<dyn InstructionDecoder>,
    ) -> Box<dyn InstructionDecoder> {
        ThreadHooks::<(Vec<u8>, U), S, L>::create_instruction_decoder(&mut self.parent, decoder)
    }

    /// Port of the override:
    /// `super.createUseropLibrary().compose(getPartsFactory().createLocalUseropLibrary(getMachine(), this))`.
    fn create_userop_library(
        &mut self,
        thread: &ThreadCore<(Vec<u8>, U), S, L>,
        library: Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>> {
        let library = self.parent.create_userop_library(thread, library);
        let local = self
            .parts_factory
            .create_local_userop_library(self.emulator.as_ref(), thread);
        library.compose(local.as_ref())
    }

    /// Port of the override: `getPartsFactory().createExecutor(getMachine(), this)`.
    fn create_executor(
        &mut self,
        thread: &ThreadCore<(Vec<u8>, U), S, L>,
    ) -> PcodeThreadExecutor<(Vec<u8>, U)> {
        self.parts_factory.create_executor(self.emulator.as_ref(), thread)
    }

    fn pre_execute_instruction(&mut self, thread: &mut ThreadCore<(Vec<u8>, U), S, L>) {
        self.parent.pre_execute_instruction(thread);
    }

    fn post_execute_instruction(&mut self, thread: &mut ThreadCore<(Vec<u8>, U), S, L>) {
        self.parent.post_execute_instruction(thread);
    }

    fn on_missing_userop_def(
        &mut self,
        thread: &mut ThreadCore<(Vec<u8>, U), S, L>,
        op: &PcodeOp,
        op_name: &str,
    ) -> bool {
        self.parent.on_missing_userop_def(thread, op, op_name)
    }

    fn override_counter(&mut self, thread: &mut ThreadCore<(Vec<u8>, U), S, L>, counter: &Address) {
        self.parent.override_counter(thread, counter);
    }
}

/// The default thread for `AuxPcodeEmulator`.
///
/// `S` and `L` are the concrete types of the machine's shared (memory) and this thread's local
/// (register/unique) state, and `F` the emulator's parts factory. See the module docs.
pub type AuxPcodeThread<U, S, L, F> = DefaultPcodeThread<(Vec<u8>, U), S, L, AuxThreadHooks<U, F>>;

impl<U: 'static, S, L, F> DefaultPcodeThread<(Vec<u8>, U), S, L, AuxThreadHooks<U, F>>
where
    F: AuxEmulatorPartsFactory<U>,
    S: PcodeExecutorState<(Vec<u8>, U)> + 'static,
    L: PcodeExecutorState<(Vec<u8>, U)> + 'static,
{
    /// Construct a new thread with the given name belonging to the given emulator.
    ///
    /// Port of `AuxPcodeThread(String, AuxPcodeEmulator<U>)`. `exec_language`, `shared_state`,
    /// `local_state`, and `decoder` are what [`DefaultPcodeThread::new`] needs from a machine;
    /// `modifier` is what [`ModifiedThreadHooks::new`] takes; `parts_factory` is Java's
    /// `getPartsFactory()` -- see the module docs.
    ///
    /// # Panics
    ///
    /// If the language has no program counter, as [`DefaultPcodeThread::new`] requires.
    #[allow(clippy::too_many_arguments, deprecated)]
    pub fn new_aux(
        name: impl Into<String>,
        emulator: Arc<dyn AuxPcodeEmulator<U>>,
        exec_language: Arc<dyn Language>,
        shared_state: S,
        local_state: L,
        decoder: Box<dyn InstructionDecoder>,
        modifier: Option<Arc<dyn PcodeStateModifier>>,
        parts_factory: Arc<F>,
    ) -> Self {
        let machine: Arc<dyn AbstractPcodeMachine<(Vec<u8>, U)>> = emulator.clone();
        DefaultPcodeThread::new(
            name,
            machine,
            exec_language,
            shared_state,
            local_state,
            decoder,
            AuxThreadHooks::new(emulator, parts_factory, modifier),
        )
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_thread::{ErasedPcodeThread, PcodeThread};
    use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase;
    use crate::pcode::emu::pcode_emulation_callbacks::{
        no_pcode_emulation_callbacks, PcodeEmulationCallbacks,
    };
    use crate::pcode::emu::pcode_machine::{
        AccessKind, ErasedPcodeMachine, PcodeMachine, SwiMode,
    };
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_program::PcodeProgram;
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::exec::pcode_userop_library::{
        nil, ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
    };
    use crate::pcode::seam_stubs::PseudoInstruction;
    use crate::program::model::address::{
        Address, AddressRange, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::lang::{
        LanguageDescription, LanguageID, ParallelInstructionLanguageHelper, ParseError,
    };
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, PackedDecode, PcodeOp, Varnode};
    use std::any::TypeId;
    use std::collections::HashMap;

    struct BytesArithmetic;

    impl PcodeArithmetic<(Vec<u8>, i64)> for BytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _o: OpCode, _so: i32, _si: i32, in1: &(Vec<u8>, i64)) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn binary_op(
            &self,
            _o: OpCode,
            _so: i32,
            _si1: i32,
            in1: &(Vec<u8>, i64),
            _si2: i32,
            _in2: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn mod_before_store(
            &self,
            _so: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sv: i32,
            in_value: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _so: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sv: i32,
            in_value: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> (Vec<u8>, i64) {
            (value.to_vec(), 0)
        }
        fn to_concrete(
            &self,
            value: &(Vec<u8>, i64),
            _purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.0.clone())
        }
        fn size_of(&self, value: &(Vec<u8>, i64)) -> i64 {
            value.0.len() as i64
        }
    }

    #[derive(Default)]
    struct MapState {
        cells: std::cell::RefCell<HashMap<(String, i64), Vec<u8>>>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<(Vec<u8>, i64), (Vec<u8>, i64)> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            Arc::new(BytesArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            Arc::new(BytesArithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self {
            Self { cells: std::cell::RefCell::new(self.cells.borrow().clone()) }
        }
        fn set_var_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &(Vec<u8>, i64),
            _size: i32,
            _quantize: bool,
            val: &(Vec<u8>, i64),
        ) {
            let offset = i64::from_le_bytes(pad8(&offset.0));
            self.cells.borrow_mut().insert((space.name().to_string(), offset), val.0.clone());
        }
        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &(Vec<u8>, i64),
            size: i32,
            val: &(Vec<u8>, i64),
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &(Vec<u8>, i64),
            size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> (Vec<u8>, i64) {
            let offset = i64::from_le_bytes(pad8(&offset.0));
            let bytes = self
                .cells
                .borrow()
                .get(&(space.name().to_string(), offset))
                .cloned()
                .unwrap_or_else(|| vec![0; size as usize]);
            (bytes, 0)
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &(Vec<u8>, i64),
            size: i32,
            reason: Reason,
        ) -> (Vec<u8>, i64) {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, (Vec<u8>, i64))> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    impl PcodeExecutorState<(Vec<u8>, i64)> for MapState {}

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
            _context: Option<&dyn crate::pcode::seam_stubs::RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            Ok(Box::new(NoInstruction))
        }
        fn branched(&mut self, _address: &Address) {}
        fn get_last_instruction(&self) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            None
        }
        fn get_last_length_with_delays(&self) -> i32 {
            self.length
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
        data.extend_from_slice(&[0x60, 0xA1]);
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]);
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]);
        data.extend_from_slice(&[0x60, 0xA2]);
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        data.extend_from_slice(&[0x60, 0xA5]);
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]);
        data.extend_from_slice(&[0xA0, 0xA2]);
        data.extend_from_slice(&[0x60, 0xA6]);
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0xA6]);
        data.extend_from_slice(&[0xA0, 0xA1]);
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    struct ExecLanguage;

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
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("test should not call this")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("test should not call this")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
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
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext) {
            unimplemented!("test should not call this")
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            unimplemented!("test should not call this")
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            unimplemented!("test should not call this")
        }
        fn get_compiler_spec_by_id(
            &self,
            _id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::CompilerSpec>, crate::program::model::lang::CompilerSpecNotFoundException> {
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
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
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

    struct NamedUserop {
        name: String,
    }

    impl PcodeUseropDefinition<(Vec<u8>, i64)> for NamedUserop {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            _executor: &crate::pcode::exec::pcode_executor::PcodeExecutor<(Vec<u8>, i64)>,
            _library: &dyn PcodeUseropLibrary<(Vec<u8>, i64)>,
            _op: &PcodeOp,
            _out_var: Option<&Varnode>,
            _in_vars: &[Varnode],
        ) {
            unimplemented!("test double is never invoked")
        }
        fn is_functional(&self) -> bool {
            true
        }
        fn has_side_effects(&self) -> bool {
            false
        }
        fn modifies_context(&self) -> bool {
            false
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
            None
        }
    }

    struct NamedUseropLibrary {
        userops: UseropMap<(Vec<u8>, i64)>,
    }

    impl ErasedPcodeUseropLibrary for NamedUseropLibrary {}

    impl PcodeUseropLibrary<(Vec<u8>, i64)> for NamedUseropLibrary {
        fn get_userops(&self) -> &UseropMap<(Vec<u8>, i64)> {
            &self.userops
        }
    }

    fn named_userop_library(name: &str) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
        let mut userops: UseropMap<(Vec<u8>, i64)> = HashMap::new();
        userops.insert(name.to_string(), Arc::new(NamedUserop { name: name.to_string() }));
        Box::new(NamedUseropLibrary { userops })
    }

    /// A minimal `AuxEmulatorPartsFactory<i64>` whose only exercised method is
    /// `create_local_userop_library`, recording that it was called and handing back a
    /// distinguishable library.
    struct RecordingFactory;

    impl AuxEmulatorPartsFactory<i64> for RecordingFactory {
        fn get_arithmetic(&self, _language: &dyn Language) -> Arc<dyn PcodeArithmetic<i64>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_shared_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_local_userop_stub(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_local_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__local")
        }
        fn create_shared_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _concrete: crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece<CB>,
            _cb: Arc<CB>,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_local_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _thread: &dyn ErasedPcodeThread,
            _concrete: crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece<CB>,
            _cb: Arc<CB>,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct TestEmulator {
        base: AbstractPcodeMachineBase<(Vec<u8>, i64)>,
    }

    impl ErasedPcodeMachine for TestEmulator {}

    impl AbstractPcodeMachine<(Vec<u8>, i64)> for TestEmulator {
        fn base(&self) -> &AbstractPcodeMachineBase<(Vec<u8>, i64)> {
            &self.base
        }
        fn base_mut(&mut self) -> &mut AbstractPcodeMachineBase<(Vec<u8>, i64)> {
            &mut self.base
        }
        fn create_shared_state(&self) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            Box::new(MapState::default())
        }
        fn create_local_state(&self, _thread: &dyn ErasedPcodeThread) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            Box::new(MapState::default())
        }
        fn create_thread(&self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn as_pcode_machine(&self) -> &dyn PcodeMachine<(Vec<u8>, i64)> {
            self
        }
    }

    impl PcodeMachine<(Vec<u8>, i64)> for TestEmulator {
        fn get_language(&self) -> &SleighLanguage {
            self.base.get_language()
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            self.base.get_arithmetic()
        }
        fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
            self.base.set_software_interrupt_mode(mode);
        }
        fn get_software_interrupt_mode(&self) -> SwiMode {
            self.base.get_software_interrupt_mode()
        }
        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<(Vec<u8>, i64)> {
            self.base.get_userop_library()
        }
        fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<(Vec<u8>, i64)> {
            self.base.get_stub_userop_library()
        }
        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn new_thread_named(&mut self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread(&mut self, _name: &str, _create_if_absent: bool) -> Option<Arc<dyn ErasedPcodeThread>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            self.base.get_all_threads()
        }
        fn get_shared_state(&self) -> &dyn PcodeExecutorState<(Vec<u8>, i64)> {
            unimplemented!("not exercised by these tests")
        }
        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<(Vec<u8>, i64)> {
            unimplemented!("not exercised by these tests")
        }
        fn set_suspended(&mut self, suspended: bool) {
            self.base.set_suspended(suspended);
        }
        fn is_suspended(&self) -> bool {
            self.base.is_suspended()
        }
        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> PcodeProgram {
            unimplemented!("not exercised by these tests")
        }
        fn inject(&mut self, address: &Address, source: &str) {
            crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::inject(self, address, source);
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
            crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::add_breakpoint(self, address, sleigh_condition);
        }
        fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind) {
            self.base.add_access_breakpoint(range, kind);
        }
        fn clear_access_breakpoints(&mut self) {
            self.base.clear_access_breakpoints();
        }
    }

    impl AuxPcodeEmulator<i64> for TestEmulator {}

    struct NoCallbacks;
    impl PcodeEmulationCallbacks<(Vec<u8>, i64)> for NoCallbacks {}

    fn test_emulator() -> Arc<TestEmulator> {
        Arc::new(TestEmulator {
            base: AbstractPcodeMachineBase::new(
                Arc::new(sleigh_language()),
                Arc::new(NoCallbacks),
                Arc::new(BytesArithmetic),
                Box::new(nil::<(Vec<u8>, i64)>()),
                Box::new(nil::<(Vec<u8>, i64)>()),
                None,
            ),
        })
    }

    /// The composed library exports both the machine's default userops and the parts factory's
    /// local library, matching Java's `createUseropLibrary()` override.
    #[test]
    fn userop_library_composes_the_base_library_with_the_factorys_local_library() {
        let emulator = test_emulator();
        let machine = Arc::clone(&emulator) as Arc<dyn AbstractPcodeMachine<(Vec<u8>, i64)>>;
        let mut shared = MapState::default();
        let mut local = MapState::default();
        shared.set_var_register(&pc_register(), &(0x400000i64.to_le_bytes().to_vec(), 0));
        local.set_var_register(&pc_register(), &(0x400000i64.to_le_bytes().to_vec(), 0));

        let _ = machine;
        let thread = AuxPcodeThread::new_aux(
            "Thread 0",
            emulator as Arc<dyn AuxPcodeEmulator<i64>>,
            Arc::new(ExecLanguage),
            shared,
            local,
            Box::new(FixedLengthDecoder { length: 4 }),
            None,
            Arc::new(RecordingFactory),
        );

        let userops = PcodeThread::get_userop_library(&thread).get_userops();
        assert!(userops.contains_key("__local"));
        // The base library's own userops (from `DefaultPcodeThread`) are still present alongside
        // the composed-in local one.
        assert!(userops.contains_key("emu_exec_decoded"));
    }
}
