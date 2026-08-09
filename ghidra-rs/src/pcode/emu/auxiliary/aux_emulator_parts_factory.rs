//! A factory that manufactures all the parts needed for an emulator with concrete and some
//! implementation-defined auxiliary state.
//!
//! Corresponds to `ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory`.
//!
//! More capable emulators may also use many of these parts. Usually, the additional capabilities
//! deal with how state is loaded and stored or otherwise made available to the user.
//!
//! This "parts factory" pattern aims to flatten the extension points of `AbstractPcodeMachine`
//! (not yet ported) and its components into a single trait. Its use is not required, but may make
//! things easier. It also encapsulates some "special knowledge," that might not otherwise be
//! obvious to a developer, e.g., it creates the concrete state pieces, so the developer need not
//! guess (or keep up to date) the concrete state piece types to instantiate.
//!
//! The factory itself should be a singleton. See the Taint Analyzer (not yet ported) for a
//! complete example solution using this trait.
//!
//! `U` is Java's `AuxEmulatorPartsFactory<U>` type parameter: the type of auxiliary values. Java's
//! `Pair<byte[], U>` (the paired concrete/auxiliary value carried through most of these parts) is
//! rendered as the tuple `(Vec<u8>, U)`, matching the convention already used by
//! [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece)
//! and [`PairedPcodeArithmetic`](crate::pcode::exec::paired_pcode_arithmetic::PairedPcodeArithmetic).
//!
//! `AuxPcodeEmulator` and `PcodeThread` arrive type-erased (`&dyn`, without `U`), following the
//! convention already used for [`PcodeStateInitializer`](crate::pcode::emu::pcode_state_initializer::PcodeStateInitializer):
//! Java declares `AuxPcodeEmulator<U>`/`PcodeThread<Pair<byte[], U>>`, but this trait never
//! inspects either beyond passing it along, so no generic-preserving Rust shape is needed. See
//! [`crate::pcode::seam_stubs`] for their placeholder definitions.
//!
//! `PcodeStateCallbacks` has generic methods (see
//! [`PcodeStateCallbacks`](crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks)), so it
//! is not object-safe; `create_shared_state`/`create_local_state` take it as a generic `CB`
//! parameter instead of `&dyn PcodeStateCallbacks`, matching the convention already used by
//! [`AbstractLongOffsetPcodeExecutorStatePiece`](crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::AbstractLongOffsetPcodeExecutorStatePiece).

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::seam_stubs::{
    AuxPcodeEmulator, BytesPcodeExecutorStatePiece, DefaultPcodeThread, PcodeExecutor, PcodeThread,
};
use crate::program::model::lang::Language;

/// An auxiliary emulator parts factory.
///
/// This can manufacture all the parts needed for an emulator with concrete and some
/// implementation-defined auxiliary state.
pub trait AuxEmulatorPartsFactory<U: 'static> {
    /// Get the arithmetic for the emulator given a target language.
    fn get_arithmetic(&self, language: &dyn Language) -> Arc<dyn PcodeArithmetic<U>>;

    /// Create the userop library for the emulator (used by all threads).
    fn create_shared_userop_library(
        &self,
        emulator: &dyn AuxPcodeEmulator,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create a stub userop library for the emulator's threads.
    fn create_local_userop_stub(
        &self,
        emulator: &dyn AuxPcodeEmulator,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create a userop library for a given thread.
    fn create_local_userop_library(
        &self,
        emulator: &dyn AuxPcodeEmulator,
        thread: &dyn PcodeThread,
    ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, U)>>;

    /// Create an executor for the given thread.
    ///
    /// This allows the implementor to override or intercept the logic for individual p-code
    /// operations that would not otherwise be possible in the arithmetic, e.g., to print
    /// diagnostics on a conditional branch.
    ///
    /// Java's default body constructs `new PcodeThreadExecutor<>(thread)`. `PcodeThreadExecutor`
    /// (`DefaultPcodeThread`'s executor) is not yet ported, so this default panics; implementors
    /// that need a working default must override it until that port lands.
    fn create_executor(
        &self,
        _emulator: &dyn AuxPcodeEmulator,
        _thread: &dyn DefaultPcodeThread,
    ) -> Box<dyn PcodeExecutor<(Vec<u8>, U)>> {
        unimplemented!("DefaultPcodeThread.PcodeThreadExecutor not yet ported")
    }

    /// Create a thread with the given name.
    ///
    /// Java's default body constructs `new AuxPcodeThread<>(name, emulator)`. `AuxPcodeThread` is
    /// not yet ported, so this default panics; implementors that need a working default must
    /// override it until that port lands.
    fn create_thread(&self, _emulator: &dyn AuxPcodeEmulator, _name: &str) -> Arc<dyn PcodeThread> {
        unimplemented!("AuxPcodeThread not yet ported")
    }

    /// Create the shared (memory) state of a new emulator.
    ///
    /// This is usually composed of pieces using `PairedPcodeExecutorStatePiece`, but it does not
    /// have to be. It must incorporate the concrete piece provided. It should be self contained
    /// and relatively fast.
    fn create_shared_state<CB: PcodeStateCallbacks>(
        &self,
        emulator: &dyn AuxPcodeEmulator,
        concrete: Box<dyn BytesPcodeExecutorStatePiece>,
        cb: &CB,
    ) -> Box<dyn PcodeExecutorState<(Vec<u8>, U)>>;

    /// Create the local (register) state of a new emulator.
    ///
    /// This is usually composed of pieces using `PairedPcodeExecutorStatePiece`, but it does not
    /// have to be. It must incorporate the concrete piece provided. It should be self contained
    /// and relatively fast.
    fn create_local_state<CB: PcodeStateCallbacks>(
        &self,
        emulator: &dyn AuxPcodeEmulator,
        thread: &dyn PcodeThread,
        concrete: Box<dyn BytesPcodeExecutorStatePiece>,
        cb: &CB,
    ) -> Box<dyn PcodeExecutorState<(Vec<u8>, U)>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, UseropMap};
    use crate::pcode::seam_stubs::PcodeExecutor as StubPcodeExecutor;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::{LanguageDescription, LanguageID, ParallelInstructionLanguageHelper, ParseError};
    use crate::program::model::pcode::OpCode;
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
            _executor: &dyn StubPcodeExecutor<(Vec<u8>, i64)>,
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

    struct MockAuxPcodeEmulator;
    impl AuxPcodeEmulator for MockAuxPcodeEmulator {}

    struct MockPcodeThread;
    impl PcodeThread for MockPcodeThread {}

    /// A minimal implementor of `AuxEmulatorPartsFactory<i64>`, exercising the trait's shape --
    /// Java's `Pair<byte[], U>` values threaded through as `(Vec<u8>, i64)` -- without needing
    /// the not-yet-ported concrete state/thread machinery.
    struct MockFactory;

    impl AuxEmulatorPartsFactory<i64> for MockFactory {
        fn get_arithmetic(&self, _language: &dyn Language) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }

        fn create_shared_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__shared")
        }

        fn create_local_userop_stub(
            &self,
            _emulator: &dyn AuxPcodeEmulator,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__stub")
        }

        fn create_local_userop_library(
            &self,
            _emulator: &dyn AuxPcodeEmulator,
            _thread: &dyn PcodeThread,
        ) -> Box<dyn PcodeUseropLibrary<(Vec<u8>, i64)>> {
            named_userop_library("__local")
        }

        fn create_shared_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator,
            _concrete: Box<dyn BytesPcodeExecutorStatePiece>,
            _cb: &CB,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
        }

        fn create_local_state<CB: PcodeStateCallbacks>(
            &self,
            _emulator: &dyn AuxPcodeEmulator,
            _thread: &dyn PcodeThread,
            _concrete: Box<dyn BytesPcodeExecutorStatePiece>,
            _cb: &CB,
        ) -> Box<dyn PcodeExecutorState<(Vec<u8>, i64)>> {
            unimplemented!("not exercised by these tests")
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
        // Each of the three abstract userop-library methods returns a library over
        // `(Vec<u8>, i64)`, matching Java's `PcodeUseropLibrary<Pair<byte[], U>>`.
        let factory = MockFactory;
        let shared = factory.create_shared_userop_library(&MockAuxPcodeEmulator);
        assert!(shared.get_userops().contains_key("__shared"));

        let stub = factory.create_local_userop_stub(&MockAuxPcodeEmulator);
        assert!(stub.get_userops().contains_key("__stub"));

        let local =
            factory.create_local_userop_library(&MockAuxPcodeEmulator, &MockPcodeThread);
        assert!(local.get_userops().contains_key("__local"));
    }

    #[test]
    #[should_panic(expected = "AuxPcodeThread not yet ported")]
    fn create_thread_default_panics_until_aux_pcode_thread_is_ported() {
        // Java's default constructs `new AuxPcodeThread<>(name, emulator)`; until that class is
        // ported, the default cannot be implemented faithfully.
        let factory = MockFactory;
        let _ = factory.create_thread(&MockAuxPcodeEmulator, "thread0");
    }
}
