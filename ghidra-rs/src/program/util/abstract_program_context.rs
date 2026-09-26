//! Port of `ghidra.program.util.AbstractProgramContext`.
//!
//! Java's `AbstractProgramContext` is `abstract`: it implements only a subset of
//! `ProgramContext`/`DefaultProgramContext` (the register/language bookkeeping and
//! flowing/non-flowing context mask machinery) and leaves the rest -- everything about actually
//! storing and retrieving register *values* -- to its concrete subclasses. Since this port uses
//! composition rather than inheritance (this session's established convention for "extends X"),
//! this type does not itself `impl ProgramContext`; it exposes the same methods as inherent `pub
//! fn`s with matching signatures, so [`AbstractStoredProgramContext`](super::abstract_stored_program_context::AbstractStoredProgramContext)
//! (which composes this type and does implement the full trait) can delegate to them
//! mechanically, exactly mirroring the Java method-by-method.

use std::sync::Arc;

use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;

/// Shared, real logic for a processor register context over an address space.
///
/// Port of `ghidra.program.util.AbstractProgramContext`.
pub struct AbstractProgramContext {
    language: Arc<dyn Language>,
    base_context_register: RegisterRef,
    has_non_flowing_context: bool,
    non_flowing_context_register_mask: Vec<u8>,
    flowing_context_register_mask: Vec<u8>,
    default_disassembly_context: RegisterValue,
}

impl AbstractProgramContext {
    /// Constructs a new context for `language`.
    pub fn new(language: Arc<dyn Language>) -> Self {
        let base_context_register = language.get_context_base_register().unwrap_or_else(Register::no_context);
        let default_disassembly_context = RegisterValue::new(base_context_register.clone());
        let mask_len = base_context_register.base_mask().len();

        let mut ctx = Self {
            language,
            base_context_register,
            has_non_flowing_context: false,
            non_flowing_context_register_mask: vec![0u8; mask_len],
            flowing_context_register_mask: vec![0u8; mask_len],
            default_disassembly_context,
        };
        ctx.init_context_bit_masks(&ctx.base_context_register.clone());
        ctx
    }

    /// Get the underlying language associated with this context and its registers.
    pub fn language(&self) -> Arc<dyn Language> {
        self.language.clone()
    }

    /// Set those bits in `non_flowing_context_register_mask` which should not flow with
    /// context.
    fn init_context_bit_masks(&mut self, context_reg: &RegisterRef) {
        let sub_mask = context_reg.base_mask();
        if !context_reg.follows_flow() {
            self.has_non_flowing_context = true;
            for i in 0..self.non_flowing_context_register_mask.len() {
                self.non_flowing_context_register_mask[i] |= sub_mask[i];
                self.flowing_context_register_mask[i] &= !sub_mask[i];
            }
        } else {
            for i in 0..self.flowing_context_register_mask.len() {
                self.flowing_context_register_mask[i] |= sub_mask[i];
            }
            if context_reg.has_children() {
                for child_reg in context_reg.child_registers() {
                    self.init_context_bit_masks(&child_reg);
                }
            }
        }
    }

    /// Re-initializes this context for a new language (e.g. following a language upgrade).
    ///
    /// Port of `AbstractProgramContext.init(Language)`.
    pub fn init(&mut self, language: Arc<dyn Language>) {
        let base_context_register = language.get_context_base_register().unwrap_or_else(Register::no_context);
        let default_disassembly_context = RegisterValue::new(base_context_register.clone());
        let mask_len = base_context_register.base_mask().len();

        self.language = language;
        self.base_context_register = base_context_register;
        self.default_disassembly_context = default_disassembly_context;
        self.has_non_flowing_context = false;
        self.non_flowing_context_register_mask = vec![0u8; mask_len];
        self.flowing_context_register_mask = vec![0u8; mask_len];
        let base = self.base_context_register.clone();
        self.init_context_bit_masks(&base);
    }

    /// Returns true if one or more non-flowing context register fields have been defined within
    /// the base processor context register.
    pub fn has_non_flowing_context(&self) -> bool {
        self.has_non_flowing_context
    }

    /// Modify a register value to eliminate non-flowing bits, returning a value suitable for
    /// flowing.
    pub fn get_flow_value(&self, value: RegisterValue) -> RegisterValue {
        if !self.has_non_flowing_context || !value.register().is_processor_context() {
            return value;
        }
        let concrete = value;
        concrete.clear_bit_values(&self.non_flowing_context_register_mask)
    }

    /// Modify a register value to only include non-flowing bits, returning `None` if the value
    /// does not correspond to a context register or no non-flowing context fields have been
    /// defined.
    pub fn get_non_flow_value(&self, value: RegisterValue) -> Option<RegisterValue> {
        if !self.has_non_flowing_context || !value.register().is_processor_context() {
            return None;
        }
        let concrete = value;
        Some(concrete.clear_bit_values(&self.flowing_context_register_mask))
    }

    /// Gets the registers for this context that are used for processor context states.
    pub fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.language.get_context_registers()
    }

    /// Get a Register object given the name of a register, or `None` if no register has that
    /// name.
    pub fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    /// Get an alphabetically sorted list of original register names.
    pub fn get_register_names(&self) -> Vec<String> {
        self.language.get_register_names()
    }

    /// Get all the register descriptions defined for this program context.
    pub fn get_registers(&self) -> Vec<RegisterRef> {
        self.language.get_registers()
    }

    /// Returns the base context register.
    pub fn get_base_context_register(&self) -> RegisterRef {
        self.base_context_register.clone()
    }

    /// Get the current default disassembly context to be used when initiating disassembly.
    pub fn get_default_disassembly_context(&self) -> RegisterValue {
        self.default_disassembly_context.clone()
    }

    /// Set the initial disassembly context to be used when initiating disassembly.
    pub fn set_default_disassembly_context(&mut self, value: RegisterValue) {
        self.default_disassembly_context = value;
    }

    /// Non-boxed accessor for the current default disassembly context, for use by composing
    /// types that already work in terms of the concrete [`RegisterValue`].
    pub fn default_disassembly_context(&self) -> RegisterValue {
        self.default_disassembly_context.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::lang::language::ParseError;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use std::collections::HashSet;
    use std::sync::Arc;

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
            LanguageID::new("test:LE:32:default").unwrap()
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
            "Test language".to_string()
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

    struct MockMemBuffer {
        address: Address,
    }
    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
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

    fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    /// A configurable but real `Language`: caller-supplied registers and (optional) context base
    /// register.
    struct TestLanguage {
        context_base: Option<RegisterRef>,
        registers: Vec<RegisterRef>,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
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
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
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
        ) -> Result<Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
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
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.iter().map(|r| r.name().to_string()).collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.iter().find(|r| r.name() == name).cloned()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            self.context_base.clone()
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            match &self.context_base {
                Some(base) => base.child_registers(),
                None => Vec::new(),
            }
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
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

    /// Builds a `TestLanguage` with one base processor-context register with two children (one
    /// flowing, one non-flowing), plus a plain (non-context) register `r0`.
    fn language_with_non_flowing_context() -> TestLanguage {
        let space = reg_space();
        let context_base = Register::new("contextreg", "", Address::new(space.clone(), 0), 4, false, Register::TYPE_CONTEXT);

        let flowing_child = Register::new("flow_field", "", Address::new(space.clone(), 0), 1, false, Register::TYPE_CONTEXT);
        let non_flowing_child = Register::new(
            "nonflow_field",
            "",
            Address::new(space.clone(), 1),
            1,
            false,
            Register::TYPE_CONTEXT | Register::TYPE_DOES_NOT_FOLLOW_FLOW,
        );
        let [context_base, flowing_child, non_flowing_child]: [Register; 3] =
            crate::program::model::lang::register::test_support::linked(&[&context_base, &flowing_child, &non_flowing_child], &[(0, &[1, 2])])
                .try_into()
                .unwrap();

        let r0 = Register::new("r0", "", Address::new(space, 8), 4, false, 0);

        TestLanguage {
            context_base: Some(context_base.clone()),
            registers: vec![context_base, flowing_child, non_flowing_child, r0],
        }
    }

    fn language_without_context() -> TestLanguage {
        TestLanguage { context_base: None, registers: Vec::new() }
    }

    fn test_context() -> AbstractProgramContext {
        AbstractProgramContext::new(Arc::new(language_with_non_flowing_context()))
    }

    #[test]
    fn detects_non_flowing_context_from_language() {
        let ctx = test_context();
        assert!(ctx.has_non_flowing_context());
    }

    #[test]
    fn base_context_register_and_registers_delegate_to_language() {
        let ctx = test_context();
        assert_eq!(ctx.get_base_context_register().name(), "contextreg");
        assert_eq!(ctx.get_context_registers().len(), 2);
        assert!(ctx.get_register("r0").is_some());
        assert!(ctx.get_register("nonexistent").is_none());
        assert_eq!(ctx.get_registers().len(), 4);
        assert!(ctx.get_register_names().contains(&"r0".to_string()));
    }

    #[test]
    fn default_disassembly_context_round_trips() {
        let mut ctx = test_context();
        let base_reg = ctx.get_base_context_register();
        let value = RegisterValue::with_value(base_reg, 0xAB);
        ctx.set_default_disassembly_context(value);

        let got = ctx.get_default_disassembly_context();
        assert_eq!(got.unsigned_value_ignore_mask(), 0xAB);
    }

    #[test]
    fn get_flow_value_clears_non_flowing_bits_from_context_register() {
        let ctx = test_context();
        let base_reg = ctx.get_base_context_register();
        // Set every bit of the 4-byte context register. `nonflow_field` occupies bits 8-15
        // (byte offset 1, little-endian byte numbering -> bits [8,15]).
        let value = RegisterValue::with_value(base_reg, 0xFFFF_FFFF);

        let flow_value = ctx.get_flow_value(value);
        // Flowing value: the non-flowing field's bits (8-15) are cleared; everything else (which
        // this language treats as flowing, including bits with no explicit child) is preserved.
        assert_eq!(flow_value.unsigned_value_ignore_mask(), 0xFFFF_00FF);
    }

    #[test]
    fn get_non_flow_value_keeps_only_non_flowing_bits() {
        let ctx = test_context();
        let base_reg = ctx.get_base_context_register();
        let value = RegisterValue::with_value(base_reg, 0xFFFF_FFFF);

        let non_flow_value = ctx.get_non_flow_value(value).expect("non-flowing context is defined");
        // Non-flowing value: only the non-flowing field's bits (8-15) survive.
        assert_eq!(non_flow_value.unsigned_value_ignore_mask(), 0x0000_FF00);
    }

    #[test]
    fn get_flow_value_is_identity_for_non_context_register() {
        let ctx = test_context();
        let r0 = ctx.get_register("r0").unwrap();
        let value = RegisterValue::with_value(r0, 42);
        let flow_value = ctx.get_flow_value(value);
        assert_eq!(flow_value.unsigned_value_ignore_mask(), 42);
    }

    #[test]
    fn init_reinitializes_for_a_new_language() {
        let mut ctx = test_context();
        assert!(ctx.has_non_flowing_context());

        ctx.init(Arc::new(language_without_context()));
        assert!(!ctx.has_non_flowing_context());
        assert_eq!(ctx.get_base_context_register().name(), "NO_CONTEXT");
    }
}
