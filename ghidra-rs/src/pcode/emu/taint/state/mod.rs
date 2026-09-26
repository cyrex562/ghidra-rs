//! The taint emulator's state: per-address-space taint storage and the state piece that owns it.
//!
//! Port of the `ghidra.pcode.emu.taint.state` package.

pub mod taint_pcode_executor_state_piece;
pub mod taint_space;

pub use taint_pcode_executor_state_piece::TaintPcodeExecutorStatePiece;
pub use taint_space::TaintSpace;

/// Fixtures shared by this package's tests: a minimal language and recording callbacks.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::sync::Arc;

    use super::TaintPcodeExecutorStatePiece;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
        DefaultAddressFactory,
    };
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::mem::MemBuffer;

    pub fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    pub fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2)
    }

    pub fn unique_space() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 3)
    }

    /// Callbacks recording every `dataWritten` and `readUninitialized`, and otherwise behaving
    /// like `NONE` (reporting every requested range as still uninitialized).
    #[derive(Default)]
    pub struct RecordingCallbacks {
        /// `(space name, offset, length)` of each `data_written`.
        pub writes: RefCell<Vec<(String, i64, i32)>>,
        /// `(space name, offset, length)` of each `read_uninitialized`.
        pub reads: RefCell<Vec<(String, i64, u64)>>,
    }

    impl PcodeStateCallbacks for RecordingCallbacks {
        fn data_written<A, T>(
            &self,
            piece: &dyn PcodeExecutorStatePiece<A, T>,
            address: &Address,
            length: i32,
            _value: &T,
        ) {
            // The piece named to the callback is the taint piece itself.
            assert_eq!(piece.get_arithmetic().get_domain(), "TaintVec");
            self.writes.borrow_mut().push((
                address.space().name().to_string(),
                address.offset(),
                length,
            ));
        }

        fn read_uninitialized<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            set: &dyn AddressSetView,
            _reason: Reason,
        ) -> AddressSet {
            if let Some(range) = set.first_range() {
                self.reads.borrow_mut().push((
                    range.min_address().space().name().to_string(),
                    range.min_address().offset(),
                    range.length(),
                ));
            }
            AddressSet::from_set(set)
        }
    }

    /// Little-endian arithmetic over concrete byte vectors -- the `byte[]` address domain the
    /// taint piece is paired with (Java takes it from the concrete piece).
    pub struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _: OpCode, _: i32, _: i32, _: &Vec<u8>) -> Vec<u8> {
            unreachable!("the taint piece never does address arithmetic")
        }
        fn binary_op(&self, _: OpCode, _: i32, _: i32, _: &Vec<u8>, _: i32, _: &Vec<u8>) -> Vec<u8> {
            unreachable!("the taint piece never does address arithmetic")
        }
        fn mod_before_store(&self, _: i32, _: &AddressSpace, _: &Vec<u8>, _: i32, v: &Vec<u8>) -> Vec<u8> {
            v.clone()
        }
        fn mod_after_load(&self, _: i32, _: &AddressSpace, _: &Vec<u8>, _: i32, v: &Vec<u8>) -> Vec<u8> {
            v.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(&self, value: &Vec<u8>, _: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// A taint piece over [`MockLanguage`] and [`BytesArithmetic`], using the given callbacks.
    pub fn new_piece(cb: Arc<RecordingCallbacks>) -> TaintPcodeExecutorStatePiece<RecordingCallbacks> {
        TaintPcodeExecutorStatePiece::new(Arc::new(MockLanguage), Arc::new(BytesArithmetic), cb)
    }

    /// A little-endian language exposing an address factory (for the unique space) and two
    /// registers: `R0` (4 bytes at register:0) and `R1` (2 bytes at register:4).
    pub struct MockLanguage;

    fn registers() -> Vec<RegisterRef> {
        vec![
            Register::new("R0", "", register_space().address(0), 4, false, Register::TYPE_NONE),
            Register::new("R1", "", register_space().address(4), 2, false, Register::TYPE_NONE),
        ]
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            crate::program::model::lang::LanguageID::new("Mock:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            7
        }
        fn get_minor_version(&self) -> i32 {
            3
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![ram_space(), register_space(), unique_space()]))
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::InstructionPrototype>,
            crate::program::model::lang::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            registers()
        }
        fn get_register_names(&self) -> Vec<String> {
            vec!["R0".to_string(), "R1".to_string()]
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }
}
