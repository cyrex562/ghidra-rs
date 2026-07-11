use crate::program::model::lang::Language;
use crate::program::model::listing::CodeUnit;
use crate::util::classfinder::ExtensionPoint;
use std::error::Error;

/// Marker trait for external disassembler implementations.
///
/// External disassemblers provide disassembly capabilities for code units
/// using external tools or libraries. This trait is an extension point that allows
/// pluggable implementations of disassembly functionality.
///
/// Java equivalent: `ghidra.app.util.disassemble.ExternalDisassembler`
pub trait ExternalDisassembler: ExtensionPoint {
    /// Gets the disassembly string for the given code unit.
    ///
    /// # Arguments
    /// * `cu` - The code unit to disassemble
    ///
    /// # Returns
    /// The disassembly string for the code unit
    ///
    /// # Errors
    /// Returns an error if the disassembly cannot be performed
    fn get_disassembly(&self, cu: &dyn CodeUnit) -> Result<String, Box<dyn Error>>;

    /// Gets the disassembly display prefix for the given code unit.
    ///
    /// The prefix is typically used to display additional information about
    /// the disassembly, such as address or comments.
    ///
    /// # Arguments
    /// * `cu` - The code unit to get the prefix for
    ///
    /// # Returns
    /// The display prefix string for the code unit
    ///
    /// # Errors
    /// Returns an error if the prefix cannot be retrieved
    fn get_disassembly_display_prefix(&self, cu: &dyn CodeUnit) -> Result<String, Box<dyn Error>>;

    /// Gets the disassembly of a byte sequence for a specified language.
    ///
    /// This method allows disassembly of raw bytes without requiring an existing code unit.
    ///
    /// # Arguments
    /// * `language` - The language context for disassembly
    /// * `is_big_endian` - Whether bytes are in big-endian format
    /// * `address` - The address at which the bytes are located
    /// * `byte_string` - The bytes to disassemble
    ///
    /// # Returns
    /// The disassembly string for the byte sequence
    ///
    /// # Errors
    /// Returns an error if the disassembly cannot be performed
    fn get_disassembly_of_bytes(
        &self,
        language: &dyn Language,
        is_big_endian: bool,
        address: i64,
        byte_string: &[u8],
    ) -> Result<String, Box<dyn Error>>;

    /// Checks if this disassembler supports the given language.
    ///
    /// # Arguments
    /// * `language` - The language to check for support
    ///
    /// # Returns
    /// `true` if the language is supported, `false` otherwise
    fn is_supported_language(&self, language: &dyn Language) -> bool;

    /// Cleans up resources used by this disassembler.
    ///
    /// This method should be called when the disassembler is no longer needed
    /// to free any system resources that may have been allocated.
    fn destroy(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::lang::ParseError;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalLocation, ExternalReference, RefType, Reference, ReferenceIterator, SourceType,
        Symbol, SymbolType,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{
        AddressLabelInfo, CommentType, MemBuffer, MemoryBlockDefinition, Processor,
    };
    use crate::util::task::TaskMonitor;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        Register::new("r0", "General purpose register 0", Address::new(space, 0), 4, false, 0)
    }

    struct MockSymbol;
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            mock_address(0x100)
        }
        fn get_name(&self) -> &str {
            "LAB_00000100"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockReference;
    impl Reference for MockReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn from_address(&self) -> Address {
            mock_address(0x100)
        }
        fn to_address(&self) -> Address {
            mock_address(0x200)
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            RefType::Flow
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SourceType {
            SourceType::Analysis
        }
    }

    struct MockExternalReference;
    impl Reference for MockExternalReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn from_address(&self) -> Address {
            mock_address(0x100)
        }
        fn to_address(&self) -> Address {
            mock_address(0x300)
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            RefType::Data
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            true
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            false
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SourceType {
            SourceType::Analysis
        }
    }

    struct MockExternalLocation;
    impl ExternalLocation for MockExternalLocation {}

    impl ExternalReference for MockExternalReference {
        fn get_external_location(&self) -> Box<dyn ExternalLocation> {
            Box::new(MockExternalLocation)
        }
        fn get_library_name(&self) -> String {
            "mock_lib".to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockReferenceIterator;
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            None
        }
    }

    struct MockCodeUnit;

    impl MemBuffer for MockCodeUnit {
        fn get_address(&self) -> Address {
            mock_address(0x100)
        }
    }
    impl PropertySet for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000100".to_string()
        }
        fn get_label(&self) -> Option<String> {
            Some("LAB_00000100".to_string())
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            vec![Arc::new(MockSymbol)]
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            Some(Arc::new(MockSymbol))
        }
        fn get_min_address(&self) -> Address {
            mock_address(0x100)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0x103)
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            4
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }
        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            vec![Arc::new(MockReference)]
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            Some(Arc::new(MockReference))
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            vec![Arc::new(MockReference)]
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            Some(Arc::new(MockExternalReference))
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    struct MockProcessor;
    impl Processor for MockProcessor {}

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }
        fn get_compiler_spec_name(&self) -> String {
            "GCC".to_string()
        }
        fn get_source(&self) -> String {
            "gcc.cspec".to_string()
        }
    }

    struct MockLanguageDescription;
    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
        }
        fn get_instruction_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
        }
        fn get_size(&self) -> i32 {
            32
        }
        fn get_variant(&self) -> String {
            "default".to_string()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_description(&self) -> String {
            "Mock x86 32-bit little endian".to_string()
        }
        fn is_deprecated(&self) -> bool {
            false
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }
        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct MockAddressLabelInfo;
    impl AddressLabelInfo for MockAddressLabelInfo {}

    struct MockMemoryBlockDefinition;
    impl MemoryBlockDefinition for MockMemoryBlockDefinition {}

    struct MockAddressFactory;
    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_address_space_by_name(&self, _name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_space_by_id(&self, _id: i32) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_num_address_spaces(&self) -> usize {
            0
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            false
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            Box::new(MockLanguageDescription)
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(MockAddressFactory)
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            mock_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            mock_space()
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
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            vec![mock_register()]
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            Some(mock_register())
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![mock_register()]
        }
        fn get_register_names(&self) -> Vec<String> {
            vec!["r0".to_string()]
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            if name == "r0" {
                Some(mock_register())
            } else {
                None
            }
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            Some(mock_register())
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            vec![Box::new(MockMemoryBlockDefinition)]
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            vec![Box::new(MockAddressLabelInfo)]
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
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
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
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

    struct TestDisassembler {
        supported: bool,
    }

    impl ExtensionPoint for TestDisassembler {}

    impl ExternalDisassembler for TestDisassembler {
        fn get_disassembly(
            &self,
            _cu: &dyn CodeUnit,
        ) -> Result<String, Box<dyn Error>> {
            Ok("test disassembly".to_string())
        }

        fn get_disassembly_display_prefix(
            &self,
            _cu: &dyn CodeUnit,
        ) -> Result<String, Box<dyn Error>> {
            Ok("test prefix".to_string())
        }

        fn get_disassembly_of_bytes(
            &self,
            _language: &dyn Language,
            _is_big_endian: bool,
            _address: i64,
            _byte_string: &[u8],
        ) -> Result<String, Box<dyn Error>> {
            Ok("test bytes disassembly".to_string())
        }

        fn is_supported_language(&self, _language: &dyn Language) -> bool {
            self.supported
        }

        fn destroy(&self) {}
    }

    #[test]
    fn test_disassembler_trait_is_object_safe() {
        let disassembler: Box<dyn ExternalDisassembler> = Box::new(TestDisassembler {
            supported: true,
        });
        let language = MockLanguage;
        assert!(disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_get_disassembly_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let cu = MockCodeUnit;
        let result = disassembler.get_disassembly(&cu);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test disassembly");
    }

    #[test]
    fn test_get_disassembly_display_prefix_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let cu = MockCodeUnit;
        let result = disassembler.get_disassembly_display_prefix(&cu);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test prefix");
    }

    #[test]
    fn test_get_disassembly_of_bytes_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let language = MockLanguage;
        let bytes = [0x90u8, 0x00, 0x00, 0x00];
        let result = disassembler.get_disassembly_of_bytes(&language, true, 0x1000, &bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test bytes disassembly");
    }

    #[test]
    fn test_is_supported_language_true() {
        let disassembler = TestDisassembler { supported: true };
        let language = MockLanguage;
        assert!(disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_is_supported_language_false() {
        let disassembler = TestDisassembler { supported: false };
        let language = MockLanguage;
        assert!(!disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_destroy_does_not_panic() {
        let disassembler = TestDisassembler { supported: true };
        disassembler.destroy();
    }
}
