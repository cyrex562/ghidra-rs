//! Mirrors `ghidra.app.plugin.assembler.GenericAssembler`.

use std::sync::Arc;

use thiserror::Error;

use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;
use crate::app::seam_stubs::{
    AssemblyPatternBlock, AssemblyResolutionResults, AssemblyResolvedPatterns,
    AssemblySyntaxException,
};
use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::lang::Language;
use crate::program::model::listing::{Instruction, InstructionIterator, Program};
use crate::program::model::mem::MemoryAccessException;

use super::AssemblySemanticException;

/// Combines the checked exceptions declared on `GenericAssembler.assemble`.
///
/// The `Syntax` variant deliberately omits `#[from]`: thiserror's `#[from]`/`#[source]` wiring
/// requires the field type to implement `std::error::Error` directly, but
/// `Box<dyn AssemblySyntaxException>` -- a trait object over a trait whose only supertrait is
/// `std::error::Error` -- does not itself implement that trait (no blanket impl covers custom
/// `Error` subtraits the way it does for `Box<dyn Error>` itself). A manual `From` impl below
/// provides the same ergonomic `?` conversion using just `Display`, which the trait bound does
/// give us.
#[derive(Error, Debug)]
pub enum AssembleError {
    #[error("{0}")]
    Syntax(Box<dyn AssemblySyntaxException>),
    #[error(transparent)]
    Semantic(#[from] AssemblySemanticException),
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
}

impl From<Box<dyn AssemblySyntaxException>> for AssembleError {
    fn from(e: Box<dyn AssemblySyntaxException>) -> Self {
        AssembleError::Syntax(e)
    }
}

impl From<AssembleLineError> for AssembleError {
    fn from(e: AssembleLineError) -> Self {
        match e {
            AssembleLineError::Syntax(e) => AssembleError::Syntax(e),
            AssembleLineError::Semantic(e) => AssembleError::Semantic(e),
        }
    }
}

/// Combines the checked exceptions declared on `GenericAssembler.assembleLine`. See
/// [`AssembleError`]'s docs for why `Syntax` omits `#[from]` in favor of a manual impl.
#[derive(Error, Debug)]
pub enum AssembleLineError {
    #[error("{0}")]
    Syntax(Box<dyn AssemblySyntaxException>),
    #[error(transparent)]
    Semantic(#[from] AssemblySemanticException),
}

impl From<Box<dyn AssemblySyntaxException>> for AssembleLineError {
    fn from(e: Box<dyn AssemblySyntaxException>) -> Self {
        AssembleLineError::Syntax(e)
    }
}

/// A high-level interface for assembling instructions, optionally bound to a program.
///
/// Mirrors `ghidra.app.plugin.assembler.GenericAssembler`, cut to a trait to break a dependency
/// cycle running through the assembler, parse-result, and resolution types (same cycle
/// [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) was cut for). Java
/// declares this as `GenericAssembler<RP extends AssemblyResolvedPatterns>`, but the type
/// parameter `RP` is never referenced by any method in the interface body (every method that
/// deals in resolved patterns uses the unparameterized `AssemblyResolvedPatterns` type directly),
/// so it carries no information and is dropped here.
///
/// [`AssemblyResolutionResults`], [`AssemblyPatternBlock`], and [`AssemblyResolvedPatterns`] are
/// not yet ported, so they're referenced through the same minimal placeholder traits
/// `AssemblySelector` uses, in [`crate::app::seam_stubs`]. `AssemblySyntaxException` is likewise
/// unported; its stand-in is the same [`AssemblySyntaxException`](crate::app::seam_stubs::AssemblySyntaxException)
/// stub. `Language`, `Program`, `Instruction`, and `InstructionIterator` are all already ported,
/// so they're referenced directly.
///
/// Every method here is abstract in Java (this is a plain interface with no default methods), so
/// none of the trait methods below have default bodies either.
pub trait GenericAssembler {
    /// Get the language of this assembler.
    ///
    /// Mirrors `GenericAssembler.getLanguage()`.
    fn get_language(&self) -> Box<dyn Language>;

    /// If the assembler is bound to a program, get that program.
    ///
    /// Mirrors `GenericAssembler.getProgram()`.
    fn get_program(&self) -> Option<Arc<dyn Program>>;

    /// Assemble a sequence of instructions and place them at the given address.
    ///
    /// This method is only valid if the assembler is bound to a program. An instance may
    /// optionally implement this method without a program binding. In that case, the returned
    /// iterator will refer to pseudo instructions.
    ///
    /// Mirrors `GenericAssembler.assemble(Address, String...)`.
    fn assemble(
        &self,
        at: &Address,
        listing: &[&str],
    ) -> Result<Box<dyn InstructionIterator>, AssembleError>;

    /// Assemble a line instruction at the given address.
    ///
    /// This method is valid with or without a bound program. Even if bound, the program is not
    /// modified; however, the appropriate context information is taken from the bound program.
    /// Without a program, the language's default context is taken at the given location.
    ///
    /// Mirrors `GenericAssembler.assembleLine(Address, String)`.
    fn assemble_line(&self, at: &Address, line: &str) -> Result<Vec<u8>, AssembleLineError>;

    /// Assemble a line instruction at the given address, assuming the given context.
    ///
    /// Mirrors `GenericAssembler.assembleLine(Address, String, AssemblyPatternBlock)`.
    fn assemble_line_with_context(
        &self,
        at: &Address,
        line: &str,
        ctx: &dyn AssemblyPatternBlock,
    ) -> Result<Vec<u8>, AssembleLineError>;

    /// Parse a line instruction.
    ///
    /// Mirrors `GenericAssembler.parseLine(String)`.
    fn parse_line(&self, line: &str) -> Vec<Box<dyn AssemblyParseResult>>;

    /// Resolve a given parse tree at the given address, assuming the given context.
    ///
    /// Mirrors `GenericAssembler.resolveTree(AssemblyParseResult, Address,
    /// AssemblyPatternBlock)`.
    fn resolve_tree(
        &self,
        parse: &dyn AssemblyParseResult,
        at: &Address,
        ctx: &dyn AssemblyPatternBlock,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Resolve a given parse tree at the given address.
    ///
    /// Mirrors `GenericAssembler.resolveTree(AssemblyParseResult, Address)`.
    fn resolve_tree_at(
        &self,
        parse: &dyn AssemblyParseResult,
        at: &Address,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Assemble a line instruction at the given address.
    ///
    /// Mirrors `GenericAssembler.resolveLine(Address, String)`.
    fn resolve_line(
        &self,
        at: &Address,
        line: &str,
    ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>>;

    /// Assemble a line instruction at the given address, assuming the given context.
    ///
    /// Mirrors `GenericAssembler.resolveLine(Address, String, AssemblyPatternBlock)`.
    fn resolve_line_with_context(
        &self,
        at: &Address,
        line: &str,
        ctx: &dyn AssemblyPatternBlock,
    ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>>;

    /// Place a resolved (and fully-masked) instruction into the bound program.
    ///
    /// This method is not valid without a program binding.
    ///
    /// Mirrors `GenericAssembler.patchProgram(AssemblyResolvedPatterns, Address)`.
    fn patch_program(
        &self,
        res: &dyn AssemblyResolvedPatterns,
        at: &Address,
    ) -> Result<Arc<dyn Instruction>, MemoryAccessException>;

    /// Place instruction bytes into the bound program.
    ///
    /// This method is not valid without a program binding.
    ///
    /// Mirrors `GenericAssembler.patchProgram(byte[], Address)`.
    fn patch_program_bytes(
        &self,
        insbytes: &[u8],
        at: &Address,
    ) -> Result<Box<dyn InstructionIterator>, MemoryAccessException>;

    /// Get the context at a given address.
    ///
    /// If there is a program binding, this will extract the actual context at the given address.
    /// Otherwise, it will obtain the default context at the given address for the language.
    ///
    /// Mirrors `GenericAssembler.getContextAt(Address)`.
    fn get_context_at(&self, addr: &Address) -> Box<dyn AssemblyPatternBlock>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{AssemblyResolutionEntry, AssemblySyntaxError};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use crate::program::model::listing::EmptyInstructionIterator;
    use crate::program::model::lang::language_id::LanguageID;

    fn mock_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    // --- Language mock ---
    //
    // `Language` has no default methods, so every abstract method needs a body; only
    // `get_language_id` and `is_big_endian` are actually exercised by this test, so the rest
    // just panic if reached, following the convention already used by other `MockLanguage`
    // impls in this crate (e.g. `register_translator.rs`).

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
            ParseError,
        > {
            unimplemented!("not exercised by this test")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(&self, _address: &Address) -> Vec<crate::program::model::lang::register::RegisterRef> {
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

        fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
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

        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
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

    // --- AssemblyPatternBlock mock ---

    #[derive(Clone)]
    struct MockBlock {
        vals: Vec<i8>,
    }

    impl AssemblyPatternBlock for MockBlock {
        fn get_vals(&self) -> Vec<i8> {
            self.vals.clone()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![-1; self.vals.len()] })
        }
    }

    // --- AssemblyParseResult mock ---

    struct MockParse {
        text: String,
        error: bool,
    }

    impl std::fmt::Display for MockParse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl AssemblyParseResult for MockParse {
        fn is_error(&self) -> bool {
            self.error
        }
    }

    // --- AssemblyResolutionResults mock ---

    struct MockResolutionResults;

    impl AssemblyResolutionResults for MockResolutionResults {
        fn resolutions(&self) -> Vec<AssemblyResolutionEntry> {
            Vec::new()
        }
    }

    // --- GenericAssembler mock ---
    //
    // Stands in for one of the abstract `AbstractAssembler` subclasses Ghidra ships (there is no
    // default implementation to instantiate directly, since `GenericAssembler` is a plain
    // interface).

    struct MockAssembler {
        bound: bool,
    }

    impl GenericAssembler for MockAssembler {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_program(&self) -> Option<Arc<dyn Program>> {
            if self.bound {
                unimplemented!("this test never constructs a bound Program")
            } else {
                None
            }
        }

        fn assemble(
            &self,
            at: &Address,
            listing: &[&str],
        ) -> Result<Box<dyn InstructionIterator>, AssembleError> {
            for line in listing {
                self.assemble_line(at, line)?;
            }
            Ok(Box::new(EmptyInstructionIterator))
        }

        fn assemble_line(&self, _at: &Address, line: &str) -> Result<Vec<u8>, AssembleLineError> {
            if line.is_empty() {
                return Err(AssembleLineError::Syntax(Box::new(AssemblySyntaxError::new(
                    "empty line",
                ))));
            }
            Ok(line.bytes().collect())
        }

        fn assemble_line_with_context(
            &self,
            at: &Address,
            line: &str,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Result<Vec<u8>, AssembleLineError> {
            self.assemble_line(at, line)
        }

        fn parse_line(&self, line: &str) -> Vec<Box<dyn AssemblyParseResult>> {
            vec![Box::new(MockParse { text: line.to_string(), error: line.is_empty() })]
        }

        fn resolve_tree(
            &self,
            _parse: &dyn AssemblyParseResult,
            _at: &Address,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Box<dyn AssemblyResolutionResults> {
            Box::new(MockResolutionResults)
        }

        fn resolve_tree_at(
            &self,
            parse: &dyn AssemblyParseResult,
            at: &Address,
        ) -> Box<dyn AssemblyResolutionResults> {
            let ctx = self.get_context_at(at);
            self.resolve_tree(parse, at, ctx.as_ref())
        }

        fn resolve_line(
            &self,
            _at: &Address,
            line: &str,
        ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>> {
            if line.is_empty() {
                return Err(Box::new(AssemblySyntaxError::new("empty line")));
            }
            Ok(Box::new(MockResolutionResults))
        }

        fn resolve_line_with_context(
            &self,
            at: &Address,
            line: &str,
            _ctx: &dyn AssemblyPatternBlock,
        ) -> Result<Box<dyn AssemblyResolutionResults>, Box<dyn AssemblySyntaxException>> {
            self.resolve_line(at, line)
        }

        fn patch_program(
            &self,
            _res: &dyn AssemblyResolvedPatterns,
            at: &Address,
        ) -> Result<Arc<dyn Instruction>, MemoryAccessException> {
            if !self.bound {
                return Err(MemoryAccessException::new("assembler is not bound to a program"));
            }
            Ok(mock_instruction(at.clone(), at.clone()))
        }

        fn patch_program_bytes(
            &self,
            _insbytes: &[u8],
            _at: &Address,
        ) -> Result<Box<dyn InstructionIterator>, MemoryAccessException> {
            if !self.bound {
                return Err(MemoryAccessException::new("assembler is not bound to a program"));
            }
            Ok(Box::new(EmptyInstructionIterator))
        }

        fn get_context_at(&self, _addr: &Address) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![0, 0] })
        }
    }

    #[test]
    fn get_language_and_program_reflect_binding_state() {
        let unbound = MockAssembler { bound: false };
        assert_eq!(
            unbound.get_language().get_language_id().to_string(),
            "test:LE:32:default"
        );
        assert!(unbound.get_program().is_none());
    }

    #[test]
    fn assemble_line_encodes_or_reports_syntax_error() {
        let asm = MockAssembler { bound: false };
        let at = mock_addr(0x1000);

        let bytes = asm.assemble_line(&at, "nop").expect("non-empty line assembles");
        assert_eq!(bytes, b"nop".to_vec());

        let err = asm.assemble_line(&at, "").expect_err("empty line is a syntax error");
        assert!(matches!(err, AssembleLineError::Syntax(_)));
        assert_eq!(err.to_string(), "empty line");
    }

    #[test]
    fn assemble_stops_at_the_first_bad_line() {
        let asm = MockAssembler { bound: false };
        let at = mock_addr(0x2000);

        let err = match asm.assemble(&at, &["nop", "", "nop"]) {
            Err(e) => e,
            Ok(_) => panic!("second line is empty, should fail"),
        };
        assert!(matches!(err, AssembleError::Syntax(_)));
    }

    #[test]
    fn parse_line_reports_error_state() {
        let asm = MockAssembler { bound: false };
        let good = asm.parse_line("mov r0, r1");
        assert_eq!(good.len(), 1);
        assert!(!good[0].is_error());

        let bad = asm.parse_line("");
        assert!(bad[0].is_error());
    }

    #[test]
    fn patch_program_requires_a_binding() {
        let at = mock_addr(0x3000);

        let unbound = MockAssembler { bound: false };
        assert!(unbound.get_context_at(&at).get_vals().iter().all(|&v| v == 0));
        let err = match unbound.patch_program_bytes(&[0x90], &at) {
            Err(e) => e,
            Ok(_) => panic!("no program bound, should fail"),
        };
        assert_eq!(err.to_string(), "assembler is not bound to a program");

        let bound = MockAssembler { bound: true };
        let instr = bound.patch_program_bytes(&[0x90], &at);
        assert!(instr.is_ok());
    }

    #[test]
    fn resolve_line_mirrors_syntax_errors_from_assemble_line() {
        let asm = MockAssembler { bound: false };
        let at = mock_addr(0x4000);

        assert!(asm.resolve_line(&at, "nop").is_ok());
        let err = match asm.resolve_line(&at, "") {
            Err(e) => e,
            Ok(_) => panic!("empty line is a syntax error, should fail"),
        };
        assert_eq!(err.to_string(), "empty line");
    }

    #[test]
    fn trait_is_object_safe() {
        let asm: Box<dyn GenericAssembler> = Box::new(MockAssembler { bound: true });
        let at = mock_addr(0x5000);
        let parse = MockParse { text: "nop".to_string(), error: false };
        let results = asm.resolve_tree_at(&parse, &at);
        assert!(results.resolutions().is_empty());

        let patched = asm.patch_program(
            &*{
                // A minimal `AssemblyResolvedPatterns` is not needed beyond object safety here;
                // `patch_program`'s mock implementation ignores its `res` parameter.
                #[derive(Debug)]
                struct Unused;
                impl std::fmt::Display for Unused {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(f, "Unused")
                    }
                }
                impl crate::app::plugin::assembler::sleigh::sem::AssemblyResolution for Unused {
                    fn get_description(&self) -> String {
                        String::new()
                    }
                    fn get_children(&self) -> Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>> {
                        vec![]
                    }
                    fn has_children(&self) -> bool {
                        false
                    }
                    fn get_right(&self) -> Option<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>> {
                        None
                    }
                    fn line_to_string(&self) -> String {
                        String::new()
                    }
                    fn is_backfill(&self) -> bool {
                        false
                    }
                    fn is_error(&self) -> bool {
                        false
                    }
                    fn shift(&self, _amt: i32) -> Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution> {
                        Box::new(Unused)
                    }
                    fn parent(
                        &self,
                        _description: &str,
                        _op_count: i32,
                    ) -> Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution> {
                        Box::new(Unused)
                    }
                    fn collect_all_right(
                        &self,
                        _into: &mut Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>>,
                    ) {
                    }
                    fn to_string_indented(&self, _indent: &str) -> String {
                        String::new()
                    }
                    fn compare_to(
                        &self,
                        _other: &dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution,
                    ) -> std::cmp::Ordering {
                        std::cmp::Ordering::Equal
                    }
                }
                impl AssemblyResolvedPatterns for Unused {
                    fn get_instruction_length(&self) -> i32 {
                        0
                    }
                    fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
                        Box::new(MockBlock { vals: vec![] })
                    }
                    fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
                        Box::new(MockBlock { vals: vec![] })
                    }
                }
                Box::new(Unused) as Box<dyn AssemblyResolvedPatterns>
            },
            &at,
        );
        assert!(patched.is_ok());
    }
}
