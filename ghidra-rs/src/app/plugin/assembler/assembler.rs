//! Mirrors `ghidra.app.plugin.assembler.Assembler`.

use super::GenericAssembler;

/// The primary interface for performing assembly in Ghidra.
///
/// Mirrors `ghidra.app.plugin.assembler.Assembler`, which is a plain marker interface --
/// `Assembler extends GenericAssembler<AssemblyResolvedPatterns>` with no members of its own.
/// The Rust trait mirrors that exactly: a supertrait bound on
/// [`GenericAssembler`](crate::app::plugin::assembler::GenericAssembler) with no additional
/// methods.
///
/// Use the `Assemblers` class (not yet ported) to obtain a suitable implementation for a given
/// program or language.
pub trait Assembler: GenericAssembler {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;
    use crate::app::plugin::assembler::{AssembleError, AssembleLineError};
    use crate::app::seam_stubs::{
        AssemblyPatternBlock, AssemblyResolutionResults, AssemblyResolvedPatterns,
        AssemblySyntaxException,
    };
    use crate::program::model::address::Address;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::Language;
    use crate::program::model::listing::{Instruction, InstructionIterator};
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Arc;

    // --- Language mock ---
    //
    // No method here is exercised beyond `get_language_id`, so every other abstract method
    // panics if reached, following the convention used by `assembler_builder.rs`'s tests.

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this test")
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this test")
        }

        fn get_default_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this test")
        }

        fn get_default_data_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this test")
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
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this test")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(
            &self,
            _address: &Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<crate::program::model::address::AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_register_at(
            &self,
            _addr: &Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
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

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this test")
        }

        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by this test")
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

        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn has_manual(&self) -> bool {
            false
        }

        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    // --- Assembler mock ---
    //
    // Implements both `GenericAssembler` (the unnarrowed supertrait every assembler
    // implementation must satisfy) and the empty `Assembler` marker trait, matching Java's
    // `Assembler extends GenericAssembler<AssemblyResolvedPatterns>`.

    struct MockAssembler;

    impl GenericAssembler for MockAssembler {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_program(&self) -> Option<Arc<dyn crate::program::model::listing::Program>> {
            None
        }

        fn assemble(
            &self,
            _at: &Address,
            _listing: &[&str],
        ) -> Result<Box<dyn InstructionIterator>, AssembleError> {
            unimplemented!("not exercised by this test")
        }

        fn assemble_line(&self, _at: &Address, _line: &str) -> Result<Vec<u8>, AssembleLineError> {
            unimplemented!("not exercised by this test")
        }

        fn assemble_line_with_context(
            &self,
            _at: &Address,
            _line: &str,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Result<Vec<u8>, AssembleLineError> {
            unimplemented!("not exercised by this test")
        }

        fn parse_line(&self, _line: &str) -> Vec<Box<dyn AssemblyParseResult>> {
            unimplemented!("not exercised by this test")
        }

        fn resolve_tree(
            &self,
            _parse: &dyn AssemblyParseResult,
            _at: &Address,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by this test")
        }

        fn resolve_tree_at(
            &self,
            _parse: &dyn AssemblyParseResult,
            _at: &Address,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by this test")
        }

        fn resolve_line(
            &self,
            _at: &Address,
            _line: &str,
        ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>> {
            unimplemented!("not exercised by this test")
        }

        fn resolve_line_with_context(
            &self,
            _at: &Address,
            _line: &str,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>> {
            unimplemented!("not exercised by this test")
        }

        fn patch_program(
            &self,
            _res: &dyn AssemblyResolvedPatterns,
            _at: &Address,
        ) -> Result<Arc<dyn Instruction>, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }

        fn patch_program_bytes(
            &self,
            _insbytes: &[u8],
            _at: &Address,
        ) -> Result<Box<dyn InstructionIterator>, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }

        fn get_context_at(&self, _addr: &Address) -> Box<dyn AssemblyPatternBlock> {
            unimplemented!("not exercised by this test")
        }
    }

    impl Assembler for MockAssembler {}

    #[test]
    fn trait_is_object_safe_and_usable_through_supertrait() {
        let asm: Box<dyn Assembler> = Box::new(MockAssembler);
        // Confirm the trait object is usable through `GenericAssembler` too, matching Java's
        // `Assembler extends GenericAssembler<AssemblyResolvedPatterns>`.
        assert!((&*asm as &dyn GenericAssembler).get_program().is_none());
        assert_eq!(
            (&*asm as &dyn GenericAssembler).get_language().get_language_id().to_string(),
            "test:LE:32:default"
        );
    }
}
