//! A factory that manufactures all the parts needed for an emulator with concrete and some
//! implementation-defined auxiliary state.
//!
//! Corresponds to `ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory`.
//!
//! More capable emulators may also use many of these parts. Usually, the additional capabilities
//! deal with how state is loaded and stored or otherwise made available to the user.
//!
//! This "parts factory" pattern aims to flatten the extension points of
//! [`AbstractPcodeMachine`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachine) and
//! its components into a single trait. Its use is not required, but may make things easier. It
//! also encapsulates some "special knowledge," that might not otherwise be obvious to a developer,
//! e.g., it creates the concrete state pieces, so the developer need not guess (or keep up to
//! date) the concrete state piece types to instantiate.
//!
//! The factory itself should be a singleton. See the SymZ3 parts factory
//! ([`SymZ3PartsFactory`](crate::pcode::emu::symz3::sym_z3_parts_factory::SymZ3PartsFactory)) for
//! a complete example solution using this trait.
//!
//! `U` is Java's `AuxEmulatorPartsFactory<U>` type parameter: the type of auxiliary values. Java's
//! `Pair<byte[], U>` (the paired concrete/auxiliary value carried through most of these parts) is
//! rendered as the tuple `(Vec<u8>, U)`, matching the convention already used by
//! [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece)
//! and [`PairedPcodeArithmetic`](crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic).
//!
//! # Typed products
//!
//! Java's factory hands back `PcodeExecutorState<Pair<byte[], U>>` and `PcodeThread<...>` and lets
//! the thread downcast them where it needs more (e.g. `SymZ3PcodeThread.getState()`). A Rust thread
//! is generic over the concrete types of its state delegates (see
//! [`ThreadPcodeExecutorState`](crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState)),
//! so the factory names its products as associated types:
//! [`SharedState`](AuxEmulatorPartsFactory::SharedState),
//! [`LocalState`](AuxEmulatorPartsFactory::LocalState), and
//! [`Thread`](AuxEmulatorPartsFactory::Thread). The machine keeps its shared state behind a
//! [`SharedPcodeExecutorState`] handle, which is what each thread holds as its shared delegate, so
//! every thread sees the machine's one memory, as in Java.
//!
//! # State callbacks
//!
//! `CB` is the type of the [`PcodeStateCallbacks`] the emulator hands the state pieces. Java passes
//! one callbacks object (`cb.wrapFor(thread)`), whose type is the same for every state; here it is
//! a type parameter of the trait, defaulting to [`NoPcodeStateCallbacks`] -- which is what
//! [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator) passes, see its module
//! docs -- so the associated state types may depend on it (e.g. a paired state over a
//! `BytesPcodeExecutorStatePiece<CB>`).
//!
//! # Deviations from Java
//!
//! * **Construction-time libraries.** Java calls `createSharedUseropLibrary(this)` and
//!   `createLocalUseropStub(this)` from within the emulator's constructor, on a `this` of which
//!   only the language and arithmetic are assigned yet (and no in-tree implementor reads it). The
//!   Rust emulator does not exist until its base is built from these libraries, so the factory
//!   receives the emulator's language instead.
//! * **Thread-time parts.** Java's `createLocalUseropLibrary`/`createExecutor` take the emulator
//!   as the thread's `getMachine()`. A Rust thread holds only the part of its machine that the
//!   machine shares with its threads (see
//!   [`abstract_pcode_machine`](crate::pcode::emu::abstract_pcode_machine)'s module docs), so that
//!   [`PcodeMachineShared`] is what these receive.
//! * **`createLocalState`'s thread.** Java passes the half-constructed thread; a Rust thread is
//!   built from its local state, so the factory receives the name the thread will have.
//! * **`createThread` has no default body.** Java's default is `new AuxPcodeThread<>(name,
//!   emulator)`. The product type is an associated type, which a trait cannot default, so each
//!   factory writes it; for a plain auxiliary thread that is
//!   [`AuxPcodeThread::new_aux`](crate::pcode::emu::auxiliary::aux_pcode_thread::AuxPcodeThread)
//!   over the given [`AuxThreadParts`]. The factory receives itself as an `Arc`, since the thread's
//!   hooks keep the factory (Java recovers it from the machine with `getPartsFactory()`).

use std::sync::Arc;

use crate::pcode::emu::abstract_pcode_machine::PcodeMachineShared;
use crate::pcode::emu::auxiliary::aux_pcode_emulator::AuxPcodeEmulator;
use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxThreadParts;
use crate::pcode::emu::default_pcode_thread::{PcodeThreadExecutor, ThreadCore};
use crate::pcode::emu::pcode_thread::{ErasedPcodeThread, PcodeThread};
use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
use crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::{NoPcodeStateCallbacks, PcodeStateCallbacks};
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::Language;

/// An auxiliary emulator parts factory.
///
/// This can manufacture all the parts needed for an emulator with concrete and some
/// implementation-defined auxiliary state. See the module docs for the associated types and the
/// `CB` parameter.
pub trait AuxEmulatorPartsFactory<U: 'static, CB: PcodeStateCallbacks + 'static = NoPcodeStateCallbacks>:
    Sized + 'static
{
    /// The emulator's shared (memory) state, as [`create_shared_state`](Self::create_shared_state)
    /// composes it.
    type SharedState: PcodeExecutorState<(Vec<u8>, U)> + 'static;

    /// A thread's local (register) state, as [`create_local_state`](Self::create_local_state)
    /// composes it.
    type LocalState: PcodeExecutorState<(Vec<u8>, U)> + 'static;

    /// The emulator's threads, as [`create_thread`](Self::create_thread) builds them.
    type Thread: PcodeThread<(Vec<u8>, U)> + 'static;

    /// Get the arithmetic for the emulator given a target language.
    fn get_arithmetic(&self, language: &dyn Language) -> Arc<dyn PcodeArithmetic<U>>;

    /// Create the userop library for the emulator (used by all threads).
    ///
    /// Java passes the emulator under construction; see the module docs.
    fn create_shared_userop_library(
        &self,
        language: &SleighLanguage,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create a stub userop library for the emulator's threads.
    ///
    /// Java passes the emulator under construction; see the module docs.
    fn create_local_userop_stub(
        &self,
        language: &SleighLanguage,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create a userop library for a given thread.
    ///
    /// `emulator` is the part of the emulator the thread holds; see the module docs.
    fn create_local_userop_library(
        &self,
        emulator: &PcodeMachineShared<(Vec<u8>, U)>,
        thread: &dyn ErasedPcodeThread,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create an executor for the given thread.
    ///
    /// This allows the implementor to override or intercept the logic for individual p-code
    /// operations that would not otherwise be possible in the arithmetic, e.g., to print
    /// diagnostics on a conditional branch. An override typically returns
    /// `PcodeThreadExecutor::for_thread(thread).with_extension(...)`.
    ///
    /// Java's default body constructs `new PcodeThreadExecutor<>(thread)`, which is
    /// [`PcodeThreadExecutor::for_thread`]. Java's parameter is the `DefaultPcodeThread` under
    /// construction, of which an executor reads only the state its `protected` members expose, i.e.
    /// the thread's [`ThreadCore`], typed by this factory's own states.
    fn create_executor(
        &self,
        _emulator: &PcodeMachineShared<(Vec<u8>, U)>,
        thread: &ThreadCore<(Vec<u8>, U), SharedPcodeExecutorState<Self::SharedState>, Self::LocalState>,
    ) -> PcodeThreadExecutor<(Vec<u8>, U)> {
        PcodeThreadExecutor::for_thread(thread)
    }

    /// Create a thread with the given name.
    ///
    /// `parts` is what the thread's constructor reads off the emulator (see
    /// [`AuxThreadParts`]); Java's default body, `new AuxPcodeThread<>(name, emulator)`, is
    /// `AuxPcodeThread::new_aux(name, parts, None, self)`. See the module docs on why there is no
    /// default here, and why the factory arrives as an `Arc`.
    fn create_thread(
        self: Arc<Self>,
        emulator: &dyn AuxPcodeEmulator<U>,
        name: &str,
        parts: AuxThreadParts<U, Self::SharedState, Self::LocalState>,
    ) -> Self::Thread;

    /// Create the shared (memory) state of a new emulator.
    ///
    /// This is usually composed of pieces using `PairedPcodeExecutorStatePiece`, but it does not
    /// have to be. It must incorporate the concrete piece provided. It should be self contained
    /// and relatively fast.
    ///
    /// Java passes the same `PcodeStateCallbacks` object both inside `concrete` and as `cb`; here
    /// `concrete` is the real [`BytesPcodeExecutorStatePiece`] over the same callbacks type `CB`,
    /// and `cb` is the shared handle to those callbacks, so an implementor can build further
    /// pieces reporting to the very same callbacks.
    fn create_shared_state(
        &self,
        emulator: &dyn AuxPcodeEmulator<U>,
        concrete: BytesPcodeExecutorStatePiece<CB>,
        cb: Arc<CB>,
    ) -> Self::SharedState;

    /// Create the local (register) state of a new emulator.
    ///
    /// This is usually composed of pieces using `PairedPcodeExecutorStatePiece`, but it does not
    /// have to be. It must incorporate the concrete piece provided. It should be self contained
    /// and relatively fast. `thread_name` stands for Java's thread; see the module docs.
    fn create_local_state(
        &self,
        emulator: &dyn AuxPcodeEmulator<U>,
        thread_name: &str,
        concrete: BytesPcodeExecutorStatePiece<CB>,
        cb: Arc<CB>,
    ) -> Self::LocalState;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase;
    use crate::pcode::emu::auxiliary::aux_pcode_thread::AuxPcodeThread;
    use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor::PcodeExecutor;
    use crate::pcode::exec::pcode_userop_library::{nil, ErasedPcodeUseropLibrary, UseropMap};
    use crate::pcode::emu::pcode_emulation_callbacks::PcodeEmulationCallbacks;
    use crate::program::model::address::{AddressSpace, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::lang::{LanguageDescription, LanguageID, ParallelInstructionLanguageHelper, ParseError};
    use crate::program::model::pcode::{OpCode, PackedDecode};
    use std::collections::HashMap;

    /// A minimal, but real, arithmetic over `i64`, mirroring the `StubArithmetic` test double
    /// used by `pcode_userop_library_factory` -- just enough of `PcodeArithmetic` to be
    /// constructed and observed, not to compute anything meaningful.
    struct StubArithmetic;

    impl PcodeArithmetic<i64> for StubArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            *in1
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            *in1
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            let mut bytes = [0u8; 8];
            let n = value.len().min(8);
            bytes[..n].copy_from_slice(&value[..n]);
            i64::from_le_bytes(bytes)
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.to_le_bytes().to_vec())
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct MockLanguage;

    impl Language for MockLanguage {
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
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("test should not call this")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("test should not call this")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("test should not call this")
        }
        fn get_instruction_alignment(&self) -> i32 {
            unimplemented!("test should not call this")
        }
        fn supports_pcode(&self) -> bool {
            unimplemented!("test should not call this")
        }
        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
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
        fn get_registers_at(&self, _address: &crate::program::model::address::Address) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("test should not call this")
        }
        fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_at(&self, _addr: &crate::program::model::address::Address, _size: i32) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_context_base_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
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
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
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
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            unimplemented!("test should not call this")
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("test should not call this")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("test should not call this")
        }
    }

    /// A named userop that does nothing, just enough to populate a library and be found by name
    /// -- the same minimal double `pcode_userop_library`'s own tests use.
    struct NamedUserop {
        name: String,
    }

    impl crate::pcode::exec::pcode_userop_library::PcodeUseropDefinition<(Vec<u8>, i64)> for NamedUserop {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            _executor: &PcodeExecutor<(Vec<u8>, i64)>,
            _library: &dyn PcodeUseropLibrary<(Vec<u8>, i64)>,
            _op: &crate::program::model::pcode::PcodeOp,
            _out_var: Option<&crate::program::model::pcode::Varnode>,
            _in_vars: &[crate::program::model::pcode::Varnode],
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
        fn get_output_type(&self) -> Option<std::any::TypeId> {
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

    /// Arithmetic over `(Vec<u8>, i64)`, just enough to build a
    /// [`MockAuxPcodeEmulator`]'s embedded [`AbstractPcodeMachineBase`].
    struct MockEmulatorArithmetic;

    impl PcodeArithmetic<(Vec<u8>, i64)> for MockEmulatorArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &(Vec<u8>, i64),
            _sizein2: i32,
            _in2: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in1.clone()
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sizein_value: i32,
            in_value: &(Vec<u8>, i64),
        ) -> (Vec<u8>, i64) {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &(Vec<u8>, i64),
            _sizein_value: i32,
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

    /// Callbacks that do nothing, so [`MockAuxPcodeEmulator`]'s base has something to hold.
    struct NoCallbacks;

    impl PcodeEmulationCallbacks<(Vec<u8>, i64)> for NoCallbacks {}

    /// Builds a minimal but real `SleighLanguage`, mirroring the identical helper in
    /// `abstract_pcode_machine`'s and `pcode_userop_library_factory`'s own tests.
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

    struct MockPcodeThread;
    impl ErasedPcodeThread for MockPcodeThread {}

    /// A state that is never built by these tests: [`MockFactory`] only needs its type.
    struct NoState;

    impl crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece for NoState {}

    impl PcodeExecutorStatePiece<(Vec<u8>, i64), (Vec<u8>, i64)> for NoState {
        fn get_language(&self) -> Box<dyn Language> {
            unreachable!("never built")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            unreachable!("never built")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<(Vec<u8>, i64)>> {
            unreachable!("never built")
        }
        fn stream_pieces(&self) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece> {
            unreachable!("never built")
        }
        fn set_var_abstract(&mut self, _: &Arc<AddressSpace>, _: &(Vec<u8>, i64), _: i32, _: bool, _: &(Vec<u8>, i64)) {
            unreachable!("never built")
        }
        fn set_var_internal_abstract(&mut self, _: &Arc<AddressSpace>, _: &(Vec<u8>, i64), _: i32, _: &(Vec<u8>, i64)) {
            unreachable!("never built")
        }
        fn get_var_abstract(&self, _: &Arc<AddressSpace>, _: &(Vec<u8>, i64), _: i32, _: bool, _: Reason) -> (Vec<u8>, i64) {
            unreachable!("never built")
        }
        fn get_var_internal_abstract(&self, _: &Arc<AddressSpace>, _: &(Vec<u8>, i64), _: i32, _: Reason) -> (Vec<u8>, i64) {
            unreachable!("never built")
        }
        fn get_register_values(&self) -> Vec<(crate::program::model::lang::RegisterRef, (Vec<u8>, i64))> {
            unreachable!("never built")
        }
        fn get_concrete_buffer(&self, _: &crate::program::model::address::Address, _: Purpose) -> Box<dyn crate::program::model::mem::MemBuffer> {
            unreachable!("never built")
        }
        fn clear(&mut self) {
            unreachable!("never built")
        }
    }

    impl PcodeExecutorState<(Vec<u8>, i64)> for NoState {}

    /// A minimal implementor of `AuxEmulatorPartsFactory<i64>`, exercising the trait's shape --
    /// Java's `Pair<byte[], U>` values threaded through as `(Vec<u8>, i64)`, and its products
    /// named by associated types.
    struct MockFactory;

    impl AuxEmulatorPartsFactory<i64> for MockFactory {
        type SharedState = NoState;
        type LocalState = NoState;
        type Thread = AuxPcodeThread<i64, MockFactory>;

        fn get_arithmetic(&self, _language: &dyn Language) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }

        fn create_shared_userop_library(
            &self,
            _language: &SleighLanguage,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__shared")
        }

        fn create_local_userop_stub(
            &self,
            _language: &SleighLanguage,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__stub")
        }

        fn create_local_userop_library(
            &self,
            _emulator: &PcodeMachineShared<(Vec<u8>, i64)>,
            _thread: &dyn ErasedPcodeThread,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__local")
        }

        fn create_thread(
            self: Arc<Self>,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            name: &str,
            parts: AuxThreadParts<i64, NoState, NoState>,
        ) -> Self::Thread {
            AuxPcodeThread::new_aux(name, parts, None, self)
        }

        fn create_shared_state(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
            _cb: Arc<NoPcodeStateCallbacks>,
        ) -> NoState {
            unreachable!("not exercised by these tests")
        }

        fn create_local_state(
            &self,
            _emulator: &dyn AuxPcodeEmulator<i64>,
            _thread_name: &str,
            _concrete: BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>,
            _cb: Arc<NoPcodeStateCallbacks>,
        ) -> NoState {
            unreachable!("not exercised by these tests")
        }
    }

    #[test]
    fn get_arithmetic_returns_the_factorys_arithmetic() {
        let factory = MockFactory;
        let arithmetic = factory.get_arithmetic(&MockLanguage);
        assert_eq!(arithmetic.get_endian(), Some(Endian::Little));
        assert_eq!(arithmetic.size_of(&0), 8);
    }

    #[test]
    fn create_userop_library_methods_thread_the_pair_type_through() {
        // Each of the three userop-library methods returns a library over `(Vec<u8>, i64)`,
        // matching Java's `PcodeUseropLibrary<Pair<byte[], U>>`.
        let factory = MockFactory;
        let language = test_language();
        let shared = factory.create_shared_userop_library(&language);
        assert!(shared.get_userops().contains_key("__shared"));

        let stub = factory.create_local_userop_stub(&language);
        assert!(stub.get_userops().contains_key("__stub"));

        let machine = AbstractPcodeMachineBase::new(
            Arc::new(test_language()),
            Arc::new(NoCallbacks),
            Arc::new(MockEmulatorArithmetic),
            Box::new(nil()),
            Box::new(nil()),
            None,
        );
        let local = factory.create_local_userop_library(machine.shared(), &MockPcodeThread);
        assert!(local.get_userops().contains_key("__local"));
    }
}
