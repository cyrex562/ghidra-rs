//! Port of `ghidra.app.plugin.assembler.Assemblers`.
//!
//! The primary entry point for obtaining an [`Assembler`] for a Ghidra-supported language.
//!
//! The general flow is: first, obtain an assembler for a language or program via one of the
//! functions in this module. Second, call its `assemble`/`assemble_line`-family methods (see
//! [`GenericAssembler`](crate::app::plugin::assembler::GenericAssembler)) to perform assembly. More
//! advanced uses pass an [`AssemblySelector`] to control certain aspects of assembly instruction
//! selection, and to obtain advanced diagnostics, like detailed errors and code completion.
//!
//! Java's `Assemblers` is a `public final class` with only static members and no public
//! constructor -- a pure statics holder never instantiated, the same shape already ported as a
//! plain module of free functions for
//! [`markup_item_factory`](crate::feature::vt::api::implementation::markup_item_factory) and
//! [`vt_markup_type_factory`](crate::feature::vt::api::markuptype::vt_markup_type_factory); this
//! port follows the same convention rather than an artificial zero-field struct.
//!
//! # Deviation from Java: `getBuilderForLang`'s `instanceof SleighLanguage` branch
//!
//! Java's private `getBuilderForLang`:
//!
//! ```java
//! protected static AssemblerBuilder getBuilderForLang(Language lang) {
//!     AssemblerBuilder ab = builders.get(lang.getLanguageID());
//!     if (ab != null) {
//!         return ab;
//!     }
//!     if (lang instanceof SleighLanguage) {
//!         ab = new SleighAssemblerBuilder((SleighLanguage) lang);
//!         builders.put(lang.getLanguageID(), ab);
//!         return ab;
//!     }
//!     throw new UnsupportedOperationException("Unsupported language type: " + lang.getClass());
//! }
//! ```
//!
//! cannot construct a fresh builder on a cache miss in this port, for two independent reasons:
//!
//! * [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) does not implement
//!   [`Language`] in this crate, so there is nothing for a `&dyn Language` to be runtime-downcast
//!   to -- the same gap already documented on
//!   [`PcodeProgram`](crate::pcode::exec::pcode_program)'s and
//!   [`DebuggerPcodeUtils`](crate::pcode::exec::debugger_pcode_utils)'s own module docs for the
//!   identical `instanceof SleighLanguage` check.
//! * [`SleighAssemblerBuilder`](crate::app::plugin::assembler::sleigh::SleighAssemblerBuilder) is
//!   itself ported only as a trait (cut to break a dependency cycle -- see its own doc comment),
//!   with no concrete, constructible implementor to `new` up. That trait's own doc comment even
//!   names this class, `Assemblers`, as where a caller should go to obtain one -- circular until a
//!   concrete implementation exists.
//!
//! [`get_builder_for_lang`] therefore always takes Java's `else` branch -- the
//! `UnsupportedOperationException` -- once the cache misses, exactly as Java's own method would for
//! *any* non-`SleighLanguage` `Language` today. The cache itself (`builders`) is real, working, and
//! exercised by this module's tests via [`register_builder`], a Rust-only addition standing in for
//! the `builders.put(...)` side effect Java's `SleighLanguage` branch performs -- since that branch
//! can never run here, this is the only way to populate the cache (and the only way this module's
//! own functions can be meaningfully tested without a concrete `SleighAssemblerBuilder`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::app::plugin::assembler::assembly_selector::DefaultAssemblySelector;
use crate::app::plugin::assembler::{Assembler, AssemblerBuilder, AssemblySelector};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::listing::Program;

// `+ Send + Sync` is added explicitly at every use of `dyn AssemblerBuilder` in this module: the
// trait itself declares neither bound (mirroring Java, which has no such concept), but a `static`
// registry requires its contents to be `Sync`. This is the same pattern already used for other
// trait objects that need to cross that boundary in this crate (e.g.
// `Box<dyn VTAssociationTableDBAdapter + Send + Sync>` in
// `feature::vt::api::main::db::association_database_manager`).
type BuilderRegistry = Mutex<HashMap<LanguageID, Arc<dyn AssemblerBuilder + Send + Sync>>>;

static BUILDERS: OnceLock<BuilderRegistry> = OnceLock::new();

fn builders() -> &'static BuilderRegistry {
    BUILDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a builder for a language id, without going through [`get_builder_for_lang`]'s
/// unreachable `SleighLanguage` construction branch.
///
/// Has no Java counterpart: `Assemblers.builders` is populated only as a side effect of
/// `getBuilderForLang` successfully constructing a `SleighAssemblerBuilder`. Since that
/// construction can't happen in this port (see the module docs), this is the only way to populate
/// the cache -- e.g. once a concrete `AssemblerBuilder` implementation exists for a given language,
/// or from this module's own tests.
pub fn register_builder(language_id: LanguageID, builder: Arc<dyn AssemblerBuilder + Send + Sync>) {
    builders().lock().unwrap().insert(language_id, builder);
}

/// Get a builder for the given language, possibly using a cached one.
///
/// Mirrors the protected `Assemblers.getBuilderForLang(Language)`, exposed at `pub(crate)`
/// visibility to match Java's package-private access. See the module docs for why a cache miss
/// always panics here, mirroring Java's `UnsupportedOperationException` for any non-`SleighLanguage`
/// `Language` (every `Language` in this port, currently).
///
/// # Panics
///
/// Panics if no builder is registered for `lang`'s language id, mirroring Java's
/// `UnsupportedOperationException("Unsupported language type: " + lang.getClass())`.
pub(crate) fn get_builder_for_lang(lang: &dyn Language) -> Arc<dyn AssemblerBuilder + Send + Sync> {
    let language_id = lang.get_language_id();
    if let Some(ab) = builders().lock().unwrap().get(&language_id) {
        return Arc::clone(ab);
    }
    panic!("Unsupported language type: {language_id} (no AssemblerBuilder registered)");
}

/// Get an assembler for the given program.
///
/// Provides an assembler suitable for the program's language, and bound to the program. Calls to
/// its `assemble` methods will cause modifications to the bound program. If this is the first time
/// an assembler for the program's language has been requested, this function may take some time to
/// build the assembler.
///
/// Mirrors `Assemblers.getAssembler(Program, AssemblySelector)`.
///
/// # Panics
///
/// Panics if `program.get_language()` is `None` (Java's `Program.getLanguage()` never returns
/// `null`, but this crate's [`Program`] trait models it as optional for implementors that don't
/// track one), or per [`get_builder_for_lang`].
pub fn get_assembler_with_selector(
    program: Arc<dyn Program>,
    selector: Box<dyn AssemblySelector>,
) -> Box<dyn Assembler> {
    let language = program.get_language().expect("Program must have a language");
    let b = get_builder_for_lang(language.as_ref());
    // Fully qualified: `AssemblerBuilder::get_assembler_with_program` and
    // `GenericAssemblerBuilder::get_assembler_with_program` are both in scope and same-named
    // (the narrowing covariant override -- see `AssemblerBuilder`'s own doc comment), so plain
    // dot-call syntax is ambiguous.
    AssemblerBuilder::get_assembler_with_program(b.as_ref(), selector, program)
}

/// Get an assembler for the given language.
///
/// Provides a suitable assembler for the given language. Only calls to its `assemble_line` method
/// are valid. If this is the first time a language has been requested, this function may take some
/// time to build the assembler. Otherwise, it returns a cached assembler.
///
/// Mirrors `Assemblers.getAssembler(Language, AssemblySelector)`.
///
/// # Panics
///
/// Per [`get_builder_for_lang`].
pub fn get_assembler_for_language_with_selector(
    lang: &dyn Language,
    selector: Box<dyn AssemblySelector>,
) -> Box<dyn Assembler> {
    let b = get_builder_for_lang(lang);
    // Fully qualified for the same reason as `get_assembler_with_selector` above.
    AssemblerBuilder::get_assembler(b.as_ref(), selector)
}

/// Get an assembler for the given program, using the default [`AssemblySelector`].
///
/// Mirrors `Assemblers.getAssembler(Program)`, which delegates to
/// [`get_assembler_with_selector`] with `new AssemblySelector()`.
pub fn get_assembler(program: Arc<dyn Program>) -> Box<dyn Assembler> {
    get_assembler_with_selector(program, Box::new(DefaultAssemblySelector::new()))
}

/// Get an assembler for the given language, using the default [`AssemblySelector`].
///
/// Mirrors `Assemblers.getAssembler(Language)`, which delegates to
/// [`get_assembler_for_language_with_selector`] with `new AssemblySelector()`.
pub fn get_assembler_for_language(lang: &dyn Language) -> Box<dyn Assembler> {
    get_assembler_for_language_with_selector(lang, Box::new(DefaultAssemblySelector::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;
    use crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedPatterns;
    use crate::app::plugin::assembler::{AssembleError, AssembleLineError, GenericAssembler, GenericAssemblerBuilder};
    use crate::app::seam_stubs::{AssemblyPatternBlock, AssemblyResolutionResults, AssemblySyntaxException};
    use crate::program::model::address::Address;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::listing::{Instruction, InstructionIterator};
    use crate::program::model::mem::MemoryAccessException;

    // --- Language mock ---

    struct MockLanguage {
        id: &'static str,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new(self.id).unwrap()
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
            _buf: &dyn crate::program::model::mem::MemBuffer,
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
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
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
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

    // --- Assembler / AssemblerBuilder mocks ---

    struct MockAssembler {
        bound: bool,
        language_id: &'static str,
    }

    impl GenericAssembler for MockAssembler {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage { id: self.language_id })
        }
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            if self.bound {
                unimplemented!("this test never constructs a bound Program")
            } else {
                None
            }
        }
        fn assemble(&self, _at: &Address, _listing: &[&str]) -> Result<Box<dyn InstructionIterator>, AssembleError> {
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
        fn resolve_tree_at(&self, _parse: &dyn AssemblyParseResult, _at: &Address) -> Box<dyn AssemblyResolutionResults> {
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
        fn patch_program(&self, _res: &dyn AssemblyResolvedPatterns, _at: &Address) -> Result<Arc<dyn Instruction>, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn patch_program_bytes(&self, _insbytes: &[u8], _at: &Address) -> Result<Box<dyn InstructionIterator>, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn get_context_at(&self, _addr: &Address) -> Box<dyn AssemblyPatternBlock> {
            unimplemented!("not exercised by this test")
        }
    }

    impl Assembler for MockAssembler {}

    // `AtomicU32` (not `Cell<u32>`): this mock is stored behind `Arc<dyn AssemblerBuilder + Send +
    // Sync>` in the module's registry (see the module docs on why that bound is needed), so it
    // must itself be `Send + Sync` -- which `Cell` is not.
    struct MockBuilder {
        language_id: LanguageID,
        with_program_calls: std::sync::atomic::AtomicU32,
        without_program_calls: std::sync::atomic::AtomicU32,
    }

    impl MockBuilder {
        fn new(id: &str) -> Self {
            Self {
                language_id: LanguageID::new(id).unwrap(),
                with_program_calls: std::sync::atomic::AtomicU32::new(0),
                without_program_calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn with_program_calls(&self) -> u32 {
            self.with_program_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn without_program_calls(&self) -> u32 {
            self.without_program_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl GenericAssemblerBuilder for MockBuilder {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage { id: "test:LE:32:default" })
        }
        fn get_assembler(&self, selector: Box<dyn AssemblySelector>) -> Box<dyn GenericAssembler> {
            drop(selector);
            self.without_program_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::new(MockAssembler { bound: false, language_id: "test:LE:32:default" })
        }
        fn get_assembler_with_program(
            &self,
            selector: Box<dyn AssemblySelector>,
            _program: Arc<dyn Program>,
        ) -> Box<dyn GenericAssembler> {
            drop(selector);
            self.with_program_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::new(MockAssembler { bound: true, language_id: "test:LE:32:default" })
        }
    }

    impl AssemblerBuilder for MockBuilder {
        fn get_assembler(&self, selector: Box<dyn AssemblySelector>) -> Box<dyn Assembler> {
            drop(selector);
            self.without_program_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::new(MockAssembler { bound: false, language_id: "test:LE:32:default" })
        }
        fn get_assembler_with_program(
            &self,
            selector: Box<dyn AssemblySelector>,
            _program: Arc<dyn Program>,
        ) -> Box<dyn Assembler> {
            drop(selector);
            self.with_program_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::new(MockAssembler { bound: true, language_id: "test:LE:32:default" })
        }
    }

    // --- Program mock ---

    struct MockProgram {
        language_id: &'static str,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            self.language_id.to_string()
        }
        fn get_language(&self) -> Option<Arc<dyn Language>> {
            Some(Arc::new(MockLanguage { id: self.language_id }))
        }
    }

    fn unique_id(tag: &str) -> String {
        // Each test registers under its own language id so tests running in parallel (they share
        // the module-level `BUILDERS` static) never interfere with each other.
        format!("assemblers-test-{tag}:LE:32:default")
    }

    #[test]
    fn get_builder_for_lang_returns_a_registered_builder() {
        let id = unique_id("cache-hit");
        let builder: Arc<dyn AssemblerBuilder + Send + Sync> = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder);

        let lang = MockLanguage { id: Box::leak(id.into_boxed_str()) };
        let found = get_builder_for_lang(&lang);
        assert_eq!(found.get_language_id().to_string(), lang.get_language_id().to_string());
    }

    #[test]
    #[should_panic(expected = "Unsupported language type")]
    fn get_builder_for_lang_panics_on_a_cache_miss() {
        // Mirrors Java's `UnsupportedOperationException` for a `Language` that both (a) isn't
        // already cached and (b) isn't a `SleighLanguage` -- which, per the module docs, is every
        // `Language` in this port right now, since the `SleighLanguage` construction branch can't
        // be expressed.
        let id = unique_id("cache-miss");
        let lang = MockLanguage { id: Box::leak(id.into_boxed_str()) };
        get_builder_for_lang(&lang);
    }

    #[test]
    fn get_assembler_with_selector_binds_to_the_program() {
        let id = unique_id("with-selector");
        let builder = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder.clone());

        let program: Arc<dyn Program> = Arc::new(MockProgram { language_id: Box::leak(id.into_boxed_str()) });
        let _asm = get_assembler_with_selector(program, Box::new(DefaultAssemblySelector::new()));
        assert_eq!(builder.with_program_calls(), 1);
        assert_eq!(builder.without_program_calls(), 0);
    }

    #[test]
    fn get_assembler_uses_the_default_selector() {
        let id = unique_id("default-selector-program");
        let builder = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder.clone());

        let program: Arc<dyn Program> = Arc::new(MockProgram { language_id: Box::leak(id.into_boxed_str()) });
        let _asm = get_assembler(program);
        assert_eq!(builder.with_program_calls(), 1);
    }

    #[test]
    fn get_assembler_for_language_with_selector_does_not_bind_a_program() {
        let id = unique_id("language-with-selector");
        let builder = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder.clone());

        let lang = MockLanguage { id: Box::leak(id.into_boxed_str()) };
        let _asm = get_assembler_for_language_with_selector(&lang, Box::new(DefaultAssemblySelector::new()));
        assert_eq!(builder.without_program_calls(), 1);
        assert_eq!(builder.with_program_calls(), 0);
    }

    #[test]
    fn get_assembler_for_language_uses_the_default_selector() {
        let id = unique_id("default-selector-language");
        let builder = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder.clone());

        let lang = MockLanguage { id: Box::leak(id.into_boxed_str()) };
        let _asm = get_assembler_for_language(&lang);
        assert_eq!(builder.without_program_calls(), 1);
    }

    #[test]
    #[should_panic(expected = "Program must have a language")]
    fn get_assembler_panics_when_program_has_no_language() {
        struct NoLanguageProgram;
        impl crate::framework::model::DomainObject for NoLanguageProgram {}
        impl Program for NoLanguageProgram {
            fn get_name(&self) -> String {
                "no-language".to_string()
            }
            fn get_language_id(&self) -> String {
                String::new()
            }
        }
        let program: Arc<dyn Program> = Arc::new(NoLanguageProgram);
        get_assembler(program);
    }

    #[test]
    fn builder_is_cached_across_repeated_lookups() {
        let id = unique_id("cached-across-lookups");
        let builder: Arc<dyn AssemblerBuilder + Send + Sync> = Arc::new(MockBuilder::new(&id));
        register_builder(LanguageID::new(&id).unwrap(), builder);

        let lang = MockLanguage { id: Box::leak(id.into_boxed_str()) };
        let first = get_builder_for_lang(&lang);
        let second = get_builder_for_lang(&lang);
        assert!(Arc::ptr_eq(&first, &second));
    }
}
