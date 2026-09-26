//! Port of `ghidra.program.model.pcode.VarnodeTranslator`.
//!
//! Helper class used to translate between pcode [`Varnode`]s and Registers/Constants/etc for a
//! given [`Language`]. A thin wrapper around a `Language` reference; every method just forwards to
//! the underlying language (or, for [`get_varnode`](VarnodeTranslator::get_varnode), builds a
//! `Varnode` directly from a `Register`'s address and size).
//!
//! Java declares two overloaded `getRegister` methods (`getRegister(Varnode)` and
//! `getRegister(String)`); Rust has no overloading, so the `String` overload is named
//! [`get_register_by_name`](VarnodeTranslator::get_register_by_name) here.

use std::sync::Arc;

use crate::program::model::lang::{Language, Register, RegisterRef};
use crate::program::model::listing::Program;
use crate::program::model::pcode::Varnode;

/// Translates between pcode Varnodes and Registers/Constants/etc for a given `Language`. Port of
/// `ghidra.program.model.pcode.VarnodeTranslator`.
pub struct VarnodeTranslator {
    language: Arc<dyn Language>,
}

impl VarnodeTranslator {
    /// Port of `VarnodeTranslator(Language)`.
    pub fn new(language: Arc<dyn Language>) -> Self {
        Self { language }
    }

    /// Port of `VarnodeTranslator(Program)`, which calls `program.getLanguage()` unconditionally
    /// and hands the result (always non-null for a real Java `Program`) to the `Language`
    /// constructor.
    ///
    /// This crate's [`Program::get_language`] returns `Option` (its default body returns `None`
    /// for implementors that don't override it), so this panics when the program reports no
    /// language -- matching the `NullPointerException` a real Java `Program` without a language
    /// would raise once the constructor tried to use it.
    ///
    /// # Panics
    /// Panics if `program.get_language()` returns `None`.
    pub fn from_program(program: &dyn Program) -> Self {
        let language = program
            .get_language()
            .expect("VarnodeTranslator::from_program: program reported no language");
        Self::new(language)
    }

    /// Returns `true` if this translator's language supports pcode.
    ///
    /// Port of `VarnodeTranslator.supportsPcode()`.
    pub fn supports_pcode(&self) -> bool {
        self.language.supports_pcode()
    }

    /// Translate the Varnode into a register if possible.
    ///
    /// Port of `VarnodeTranslator.getRegister(Varnode)`. Takes `Option<&Varnode>` (rather than
    /// `&Varnode`) to preserve Java's explicit `if (node == null) return null;` null-check, which
    /// this crate's non-nullable `Varnode` reference can't otherwise represent.
    pub fn get_register(&self, node: Option<&Varnode>) -> Option<RegisterRef> {
        let node = node?;
        self.language.get_register_at(node.get_address(), node.get_size())
    }

    /// Get a varnode that maps to the given register.
    ///
    /// Port of `VarnodeTranslator.getVarnode(Register)`.
    pub fn get_varnode(&self, register: &Register) -> Varnode {
        Varnode::new(register.address().clone(), register.minimum_byte_size())
    }

    /// Get register given a register name.
    ///
    /// Port of `VarnodeTranslator.getRegister(String)`.
    pub fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    /// Get all defined registers for the program this translator was created with.
    ///
    /// Port of `VarnodeTranslator.getRegisters()`.
    pub fn get_registers(&self) -> Vec<RegisterRef> {
        self.language.get_registers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::insufficient_bytes_exception::InsufficientBytesException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn eax() -> RegisterRef {
        Register::new("EAX", "accumulator", Address::new(reg_space(), 0), 4, false, 0)
    }

    /// A `Language` whose registers/pcode-support are configurable per test, everything else
    /// `unimplemented!` since these tests never touch it.
    struct MockLanguage {
        supports_pcode: bool,
        registers: Vec<RegisterRef>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!()
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            struct P;
            impl Processor for P {}
            Box::new(P)
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!()
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
            self.supports_pcode
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
            self.registers.clone()
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
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.iter().map(|r| r.name().to_string()).collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.iter().find(|r| r.name() == name).cloned()
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            self.registers
                .iter()
                .find(|r| r.address() == addr && (size == 0 || r.minimum_byte_size() == size))
                .cloned()
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
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
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!()
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
            None
        }
    }

    fn translator(supports_pcode: bool) -> VarnodeTranslator {
        VarnodeTranslator::new(Arc::new(MockLanguage { supports_pcode, registers: vec![eax()] }))
    }

    #[test]
    fn supports_pcode_forwards_to_language() {
        assert!(translator(true).supports_pcode());
        assert!(!translator(false).supports_pcode());
    }

    #[test]
    fn get_register_translates_matching_varnode() {
        let t = translator(true);
        let vn = Varnode::new(Address::new(reg_space(), 0), 4);

        let reg = t.get_register(Some(&vn)).expect("EAX-sized varnode should resolve");
        assert_eq!(reg.name(), "EAX");
    }

    /// Port of Java's explicit `if (node == null) return null;` early-out.
    #[test]
    fn get_register_of_none_is_none() {
        let t = translator(true);
        assert!(t.get_register(None).is_none());
    }

    #[test]
    fn get_register_of_unmatched_varnode_is_none() {
        let t = translator(true);
        let vn = Varnode::new(Address::new(ram_space(), 0x1234), 4);
        assert!(t.get_register(Some(&vn)).is_none());
    }

    #[test]
    fn get_varnode_from_register_uses_its_address_and_minimum_byte_size() {
        let t = translator(true);
        let reg = eax();

        let vn = t.get_varnode(&reg);

        assert_eq!(vn.get_address(), reg.address());
        assert_eq!(vn.get_size(), reg.minimum_byte_size());
        assert_eq!(vn.get_size(), 4);
    }

    #[test]
    fn get_register_by_name_finds_and_rejects() {
        let t = translator(true);
        assert!(t.get_register_by_name("EAX").is_some());
        assert!(t.get_register_by_name("nope").is_none());
    }

    #[test]
    fn get_registers_forwards_full_list() {
        let t = translator(true);
        let regs = t.get_registers();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].name(), "EAX");
    }
}
