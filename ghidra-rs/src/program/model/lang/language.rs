use std::collections::HashSet;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::insufficient_bytes_exception::InsufficientBytesException;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::seam_stubs::{
    AddressLabelInfo, CompilerSpecID, LanguageDescription, MemBuffer, MemoryBlockDefinition,
    Processor,
};
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `Language.parse`.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error(transparent)]
    InsufficientBytes(#[from] InsufficientBytesException),
    #[error(transparent)]
    UnknownInstruction(#[from] UnknownInstructionException),
}

/// A machine language, providing everything needed to parse instructions and describe the
/// registers, address spaces, and compiler specifications associated with a processor.
///
/// Port of `ghidra.program.model.lang.Language`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared only
/// `get_language_id`; that method is retained here as part of the full trait.
pub trait Language {
    /// Returns the `LanguageID` of this language, which is used as a primary key to find the
    /// language when Ghidra loads it.
    fn get_language_id(&self) -> LanguageID;

    /// Returns the `LanguageDescription` of this language, which contains useful information
    /// about the characteristics of the language.
    fn get_language_description(&self) -> Box<dyn LanguageDescription>;

    /// Returns a parallel instruction helper for this language, or `None` if one has not been
    /// defined.
    fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>>;

    /// Returns the processor name on which this language is based (30386, Pentium, 68010, etc).
    fn get_processor(&self) -> Box<dyn Processor>;

    /// Returns the major version for this language. Languages which do not support this feature
    /// may always return a constant value of 1.
    fn get_version(&self) -> i32;

    /// Returns the minor version for this language. Languages which do not support this feature
    /// may always return a constant value of 0.
    fn get_minor_version(&self) -> i32;

    /// Get the `AddressFactory` for this language. The returned address factory allows addresses
    /// associated with physical, constant and unique spaces to be instantiated. NOTE: this
    /// factory does not know about compiler or program specified spaces; spaces such as stack
    /// and overlay spaces are not defined by the language.
    fn get_address_factory(&self) -> Box<dyn AddressFactory>;

    /// Get the default memory/code space.
    fn get_default_space(&self) -> Arc<AddressSpace>;

    /// Get the preferred data space used by loaders for data sections.
    fn get_default_data_space(&self) -> Arc<AddressSpace>;

    /// Get the endian type for this language. (If a language supports both, this returns an
    /// initial or default value.) Returns `true` for big-endian, `false` for little-endian.
    fn is_big_endian(&self) -> bool;

    /// Get instruction alignment in terms of bytes.
    fn get_instruction_alignment(&self) -> i32;

    /// Return `true` if the instructions in this language support p-code.
    fn supports_pcode(&self) -> bool;

    /// Returns `true` if the language has defined the specified location as volatile.
    fn is_volatile(&self, addr: &Address) -> bool;

    /// Get the `InstructionPrototype` that matches the bytes presented by the `MemBuffer`.
    ///
    /// # Errors
    /// Returns [`ParseError::InsufficientBytes`] if there are not enough bytes in memory to
    /// satisfy a legal instruction, or [`ParseError::UnknownInstruction`] if the byte pattern
    /// does not match any legal instruction.
    fn parse(
        &self,
        buf: &dyn MemBuffer,
        context: &mut dyn ProcessorContext,
        in_delay_slot: bool,
    ) -> Result<Box<dyn InstructionPrototype>, ParseError>;

    /// Get the total number of user defined pcode names. Only works for Pcode based languages.
    fn get_number_of_user_defined_op_names(&self) -> i32;

    /// Get the user defined name for a given index, or `None` if not defined. Only works for
    /// Pcode based languages.
    fn get_user_defined_op_name(&self, index: i32) -> Option<String>;

    /// Returns all the registers (each different size is a different register) for an address.
    fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef>;

    /// Get a register given the address space it is in, its offset in the space and its size.
    fn get_register_in_space(
        &self,
        addrspc: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
    ) -> Option<RegisterRef>;

    /// Get an unsorted unmodifiable list of registers that this language defines (including
    /// context registers).
    fn get_registers(&self) -> Vec<RegisterRef>;

    /// Get an alphabetically sorted list of original register names (including context
    /// registers). Names correspond to the original register name and not aliases which may be
    /// defined.
    fn get_register_names(&self) -> Vec<String>;

    /// Get a register given its name.
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef>;

    /// Get a register given its underlying address location and size. A size of 0 returns the
    /// largest register at the specified address.
    fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef>;

    /// Get the default program counter register for this language, if there is one.
    fn get_program_counter(&self) -> Option<RegisterRef>;

    /// Returns the processor context base register, or `None` if one has not been defined by the
    /// language. Stands in for the Java `Register.NO_CONTEXT` sentinel.
    fn get_context_base_register(&self) -> Option<RegisterRef>;

    /// Get an unsorted unmodifiable list of processor context registers that this language
    /// defines (includes the context base register and its context field registers).
    fn get_context_registers(&self) -> Vec<RegisterRef>;

    /// Returns the default memory blocks for this language.
    fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>>;

    /// Returns the default symbols for this language. This list does not contain registers.
    fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>>;

    /// Returns the name of the segmented space for this language, or the empty string if the
    /// memory model for this language is not segmented.
    fn get_segmented_space(&self) -> String;

    /// Returns the volatile addresses for this language.
    fn get_volatile_addresses(&self) -> Box<dyn AddressSetView>;

    /// Apply context settings to the `DefaultProgramContext` as specified by the configuration.
    fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext);

    /// Refreshes the definition of this language if possible. Use of this method is intended for
    /// development purposes only, since stale references to prior language resources (e.g.,
    /// registers) may persist.
    ///
    /// # Errors
    /// Returns an error if reloading the language spec file(s) fails.
    fn reload_language(&self, task_monitor: &dyn TaskMonitor) -> std::io::Result<()>;

    /// Returns a list of all compatible compiler spec descriptions. The first item in the list is
    /// the default.
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>>;

    /// Returns the compiler spec associated with a given `CompilerSpecID`.
    ///
    /// # Errors
    /// Returns [`CompilerSpecNotFoundException`] if no such compiler spec exists.
    fn get_compiler_spec_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException>;

    /// Returns the default compiler spec for this language, used when a loader cannot determine
    /// the compiler spec or for upgrades when a program had no compiler spec registered. NOTE:
    /// this has nothing to do with the compiler spec registered for a program.
    fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec>;

    /// Returns whether this language has a property defined.
    fn has_property(&self, key: &str) -> bool;

    /// Gets the value of a property as an int, returning `default_int` if undefined.
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32;

    /// Gets the value of a property as a boolean, returning `default_boolean` if undefined.
    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool;

    /// Gets the value of a property as a string, returning `default_string` if undefined. Stands
    /// in for the two-argument overload of `Language.getProperty`.
    fn get_property_or(&self, key: &str, default_string: &str) -> String;

    /// Gets a property defined for this language, or `None` if that property isn't defined.
    /// Stands in for the one-argument overload of `Language.getProperty`.
    fn get_property(&self, key: &str) -> Option<String>;

    /// Returns a read-only set view of the property keys defined on this language.
    fn get_property_keys(&self) -> HashSet<String>;

    /// Returns whether the language has a valid manual defined.
    fn has_manual(&self) -> bool;

    /// Get the `ManualEntry` for the given instruction mnemonic, or `None`. A default manual
    /// entry will be returned if an instruction can not be found within the index and a manual
    /// exists.
    fn get_manual_entry(&self, instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry>;

    /// Returns a read-only set view of the instruction mnemonic keys defined on this language.
    fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String>;

    /// Returns the error generated trying to load the manual, or `None` if it succeeded.
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Returns an unmodifiable list of vector registers, sorted first by size and then by name.
    fn get_sorted_vector_registers(&self) -> Vec<RegisterRef>;

    /// Returns the address set of all registers.
    fn get_register_addresses(&self) -> Box<dyn AddressSetView>;

    /// Returns the maximum instruction length that a language may produce, including any delay
    /// slots which may be present, if specified. This value is primarily intended when
    /// considering the maximum number of bytes beyond the current instruction and its delay
    /// slots which may be needed when determining an `inst_next2` location for a given
    /// instruction.
    fn get_maximum_instruction_length(&self) -> Option<i32>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSet;
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::seam_stubs::RegisterValue;
    use std::collections::HashSet;

    struct MockLanguageDescription;
    impl LanguageDescription for MockLanguageDescription {}

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

    struct MockAddressLabelInfo;
    impl AddressLabelInfo for MockAddressLabelInfo {}

    struct MockMemoryBlockDefinition;
    impl MemoryBlockDefinition for MockMemoryBlockDefinition {}

    struct MockMemBuffer {
        address: Address,
    }
    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

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

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            0,
        );
        Register::new("r0", "General purpose register 0", Address::new(space, 0), 4, false, 0)
    }

    struct MockRegisterValue {
        register: RegisterRef,
    }
    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }
        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
            })
        }
        fn has_any_value(&self) -> bool {
            false
        }
        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            0
        }
    }

    struct MockDefaultProgramContext;
    impl DefaultProgramContext for MockDefaultProgramContext {
        fn set_default_value(
            &mut self,
            _register_value: Box<dyn RegisterValue>,
            _start: &Address,
            _end: &Address,
        ) {
        }
        fn get_default_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
    }

    struct MockProcessorContext {
        base_register: RegisterRef,
    }
    impl ProcessorContextView for MockProcessorContext {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            Some(self.base_register.clone())
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![self.base_register.clone()]
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }
    impl ProcessorContext for MockProcessorContext {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(&mut self, _value: Box<dyn RegisterValue>) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
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

        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
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

    #[test]
    fn usable_as_trait_object() {
        let language: Box<dyn Language> = Box::new(MockLanguage);

        assert_eq!(language.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert!(!language.is_big_endian());
        assert!(language.supports_pcode());
        assert_eq!(language.get_register_by_name("r0").unwrap().borrow().name(), "r0");
        assert!(language.get_register_by_name("bogus").is_none());
        assert_eq!(language.get_maximum_instruction_length(), Some(16));
        assert!(language
            .get_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc")))
            .is_err());

        let mut ctx = MockProcessorContext {
            base_register: mock_register(),
        };
        let buf = MockMemBuffer {
            address: Address::new(mock_space(), 0),
        };
        assert!(language.parse(&buf, &mut ctx, false).is_err());
    }
}
