//! Port of `ghidra.program.model.lang.LanguageCompilerSpecPair`.
//!
//! Represents an opinion's processor language and compiler: an immutable pair of a
//! [`LanguageID`] and a [`CompilerSpecID`].
//!
//! A lightweight placeholder of the same name already exists at
//! [`crate::program::seam_stubs::LanguageCompilerSpecPair`], threaded through
//! [`LanguageService`]'s and [`ProgramArchitecture`](crate::program::model::lang::program_architecture::ProgramArchitecture)'s
//! trait signatures (~18 call sites) before this real class was ported. Its two fields already
//! hold the real, fully-ported [`LanguageID`]/[`CompilerSpecID`] value types (this crate never
//! stubbed those), so the only things the placeholder is genuinely missing are the
//! `getLanguage`/`getCompilerSpec`/`getLanguageDescription`/`getCompilerSpecDescription` lookup
//! methods, `compareTo`, and the two-`String` constructor -- all ported here on this
//! independent, full-fidelity type. Rewiring the placeholder's ~18 existing call sites to this
//! type is out of scope for this port (a much larger refactor spanning many unrelated files).
//!
//! ## Dropped: the four zero-argument lookup overloads
//!
//! Java's `getLanguage()`, `getCompilerSpec()`, `getLanguageDescription()`, and
//! `getCompilerSpecDescription()` (no arguments) all reach for the process-wide
//! `DefaultLanguageService.getLanguageService()` singleton. That accessor was deliberately
//! dropped when [`DefaultLanguageService`](crate::program::util::default_language_service::DefaultLanguageService)
//! was ported -- see its module docs -- because "singleton lifecycle is not part of the instance
//! contract" the trait exists to describe. This crate has no replacement global instance to
//! reach for, so those four overloads have no port; only the `LanguageService`-parameterized
//! overloads below are implemented, exactly mirroring the precedent already set by
//! `compiler_spec_for` in
//! [`debugger_platform_offer.rs`](crate::app::plugin::core::debug::mapping::debugger_platform_offer).

use std::cmp::Ordering;
use std::fmt;

use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_not_found_exception::LanguageNotFoundException;
use crate::program::model::lang::language_service::LanguageService;

/// Error produced by [`LanguageCompilerSpecPair::get_compiler_spec`] /
/// [`LanguageCompilerSpecPair::get_compiler_spec_description`], which can fail either while
/// resolving the language or, having resolved it, while resolving the compiler spec.
///
/// Java declares `throws CompilerSpecNotFoundException, LanguageNotFoundException` on both
/// methods; this crate models both as ordinary `Result` errors, so a function that can hit
/// either needs a type that can represent both (mirroring the precedent set by
/// `PcodeInjectLibraryError` in `pcode_inject_library.rs`).
#[derive(Debug)]
pub enum LanguageCompilerSpecLookupError {
    /// The language itself could not be found.
    Language(LanguageNotFoundException),
    /// The language was found, but it has no compiler spec matching this pair's `CompilerSpecID`.
    CompilerSpec(CompilerSpecNotFoundException),
}

impl fmt::Display for LanguageCompilerSpecLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Language(e) => write!(f, "{e}"),
            Self::CompilerSpec(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LanguageCompilerSpecLookupError {}

impl From<LanguageNotFoundException> for LanguageCompilerSpecLookupError {
    fn from(e: LanguageNotFoundException) -> Self {
        Self::Language(e)
    }
}

impl From<CompilerSpecNotFoundException> for LanguageCompilerSpecLookupError {
    fn from(e: CompilerSpecNotFoundException) -> Self {
        Self::CompilerSpec(e)
    }
}

/// Represents an opinion's processor language and compiler.
///
/// Port of `ghidra.program.model.lang.LanguageCompilerSpecPair`. See the module docs for the
/// relationship to the pre-existing `program::seam_stubs::LanguageCompilerSpecPair` placeholder
/// and for what was intentionally left unported.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanguageCompilerSpecPair {
    pub language_id: LanguageID,
    pub compiler_spec_id: CompilerSpecID,
}

impl LanguageCompilerSpecPair {
    /// Creates a new language and compiler pair from ID strings.
    ///
    /// Port of `LanguageCompilerSpecPair(String, String)`.
    ///
    /// # Panics
    /// Panics if either ID string is empty, mirroring Java's `IllegalArgumentException`. Java
    /// also null-checks both arguments, which has no port: `&str` cannot be null.
    pub fn new(language_id: &str, compiler_spec_id: &str) -> Self {
        assert!(!language_id.is_empty(), "empty languageID not allowed");
        assert!(!compiler_spec_id.is_empty(), "empty compilerSpecID not allowed");
        Self {
            language_id: LanguageID::new(language_id)
                .expect("checked non-empty above, LanguageID::new only rejects empty ids"),
            compiler_spec_id: CompilerSpecID::new(Some(compiler_spec_id)),
        }
    }

    /// Creates a new language and compiler pair from already-constructed IDs.
    ///
    /// Port of `LanguageCompilerSpecPair(LanguageID, CompilerSpecID)`. Java null-checks both
    /// arguments; that has no port since neither ID type is nullable in Rust.
    pub fn from_ids(language_id: LanguageID, compiler_spec_id: CompilerSpecID) -> Self {
        Self { language_id, compiler_spec_id }
    }

    /// Get the language ID.
    pub fn get_language_id(&self) -> &LanguageID {
        &self.language_id
    }

    /// Get the compiler spec ID.
    pub fn get_compiler_spec_id(&self) -> &CompilerSpecID {
        &self.compiler_spec_id
    }

    /// Gets the [`Language`] for this pair's [`LanguageID`], using the given language service to
    /// do the lookup.
    ///
    /// Port of `LanguageCompilerSpecPair.getLanguage(LanguageService)`.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if no `Language` could be found.
    pub fn get_language(
        &self,
        language_service: &dyn LanguageService,
    ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
        language_service.get_language(&self.language_id).map_err(Into::into)
    }

    /// Gets the [`CompilerSpec`] for this pair's [`CompilerSpecID`], using the given language
    /// service to do the lookup.
    ///
    /// Port of `LanguageCompilerSpecPair.getCompilerSpec(LanguageService)`.
    ///
    /// # Errors
    /// Returns [`LanguageCompilerSpecLookupError`] if no `Language` could be found, or no
    /// `CompilerSpec` matching this pair's `CompilerSpecID` could be found.
    pub fn get_compiler_spec(
        &self,
        language_service: &dyn LanguageService,
    ) -> Result<Box<dyn CompilerSpec>, LanguageCompilerSpecLookupError> {
        let language = self.get_language(language_service)?;
        Ok(language.get_compiler_spec_by_id(&self.compiler_spec_id)?)
    }

    /// Gets the [`LanguageDescription`] for this pair's [`LanguageID`], using the given language
    /// service to do the lookup.
    ///
    /// Port of `LanguageCompilerSpecPair.getLanguageDescription(LanguageService)`.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if no `LanguageDescription` could be found.
    pub fn get_language_description(
        &self,
        language_service: &dyn LanguageService,
    ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
        language_service.get_language_description(&self.language_id).map_err(Into::into)
    }

    /// Gets the [`CompilerSpecDescription`] for this pair's [`CompilerSpecID`], using the given
    /// language service to do the lookup.
    ///
    /// Port of `LanguageCompilerSpecPair.getCompilerSpecDescription(LanguageService)`.
    ///
    /// # Errors
    /// Returns [`LanguageCompilerSpecLookupError`] if no `LanguageDescription` could be found, or
    /// no `CompilerSpecDescription` matching this pair's `CompilerSpecID` could be found.
    pub fn get_compiler_spec_description(
        &self,
        language_service: &dyn LanguageService,
    ) -> Result<Box<dyn CompilerSpecDescription>, LanguageCompilerSpecLookupError> {
        let description = self.get_language_description(language_service)?;
        Ok(description.get_compiler_spec_description_by_id(&self.compiler_spec_id)?)
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    /// Port of `LanguageCompilerSpecPair.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.language_id, self.compiler_spec_id)
    }
}

impl PartialOrd for LanguageCompilerSpecPair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageCompilerSpecPair {
    /// Port of `LanguageCompilerSpecPair.compareTo`: compares by language ID first, falling back
    /// to compiler spec ID only when the language IDs are equal.
    fn cmp(&self, other: &Self) -> Ordering {
        self.language_id.cmp(&other.language_id).then_with(|| self.compiler_spec_id.cmp(&other.compiler_spec_id))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::{PcodeInjectLibrary, Processor};
    use std::collections::HashSet;

    #[test]
    fn new_from_strings_builds_pair() {
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        assert_eq!(pair.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(pair.get_compiler_spec_id().get_id_as_string(), "gcc");
    }

    #[test]
    #[should_panic(expected = "empty languageID not allowed")]
    fn new_rejects_empty_language_id() {
        LanguageCompilerSpecPair::new("", "gcc");
    }

    #[test]
    #[should_panic(expected = "empty compilerSpecID not allowed")]
    fn new_rejects_empty_compiler_spec_id() {
        LanguageCompilerSpecPair::new("x86:LE:32:default", "");
    }

    #[test]
    fn from_ids_builds_pair() {
        let pair = LanguageCompilerSpecPair::from_ids(
            LanguageID::new("arm:LE:32:v8").unwrap(),
            CompilerSpecID::new(Some("default")),
        );
        assert_eq!(pair.language_id.get_id_as_string(), "arm:LE:32:v8");
    }

    #[test]
    fn to_string_joins_ids_with_colon() {
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        assert_eq!(pair.to_string(), "x86:LE:32:default:gcc");
    }

    #[test]
    fn equality_and_hash_match_field_by_field() {
        let a = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let b = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let c = LanguageCompilerSpecPair::new("x86:LE:32:default", "windows");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn compare_to_orders_by_language_then_compiler_spec() {
        let a = LanguageCompilerSpecPair::new("arm:LE:32:v8", "default");
        let b = LanguageCompilerSpecPair::new("x86:LE:32:default", "default");
        assert!(a < b, "language ID takes priority");

        let c = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let d = LanguageCompilerSpecPair::new("x86:LE:32:default", "windows");
        assert!(c < d, "same language ID falls back to compiler spec ID");
    }

    #[test]
    fn compare_to_equal_pairs_is_equal_ordering() {
        let a = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let b = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    // --- LanguageService-based lookup methods ---
    //
    // Full `Language`/`CompilerSpec` mocks, closely modeled on the established pattern in
    // `address_xml.rs`'s test module (`MockLanguage`/`MockCompilerSpec`): every trait method
    // must be implemented (Rust has no partial `impl`), so methods not exercised by these tests
    // return a trivial default or `unimplemented!()`.

    struct MockProcessor;
    impl Processor for MockProcessor {}


    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockCompilerSpecDescription(CompilerSpecID);
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.0.clone()
        }
        fn get_compiler_spec_name(&self) -> String {
            "mock".to_string()
        }
        fn get_source(&self) -> String {
            "mock.cspec".to_string()
        }
    }

    struct MockLanguageDescription {
        id: LanguageID,
        known_compiler_spec: CompilerSpecID,
    }
    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.id.clone()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_endian(&self) -> Endian {
            Endian::Little
        }
        fn get_instruction_endian(&self) -> Endian {
            Endian::Little
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
            String::new()
        }
        fn is_deprecated(&self) -> bool {
            false
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription(self.known_compiler_spec.clone()))]
        }
        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            if *compiler_spec_id == self.known_compiler_spec {
                Ok(Box::new(MockCompilerSpecDescription(compiler_spec_id.clone())))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.id, compiler_spec_id))
            }
        }
        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct MockLanguage {
        language_id: LanguageID,
        compiler_spec_id: CompilerSpecID,
    }
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
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
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> std::sync::Arc<AddressSpace> {
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
        }
        fn get_default_data_space(&self) -> std::sync::Arc<AddressSpace> {
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
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
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
            _addrspc: &std::sync::Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
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
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            if *compiler_spec_id == self.compiler_spec_id {
                Ok(Box::new(MockCompilerSpec {
                    language_id: self.language_id.clone(),
                    compiler_spec_id: compiler_spec_id.clone(),
                }))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.language_id, compiler_spec_id))
            }
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
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockCompilerSpec {
        language_id: LanguageID,
        compiler_spec_id: CompilerSpecID,
    }
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage {
                language_id: self.language_id.clone(),
                compiler_spec_id: self.compiler_spec_id.clone(),
            })
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription(self.compiler_spec_id.clone()))
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.compiler_spec_id.clone()
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<std::sync::Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> std::sync::Arc<AddressSpace> {
            AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
        }
        fn get_stack_base_space(&self) -> std::sync::Arc<AddressSpace> {
            self.get_stack_space()
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Arc<PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Arc<PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Arc<PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
            Some(Arc::new(PrototypeModel::new()))
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            DecompilerLanguage::CLanguage
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
        ) -> Arc<PrototypeModel> {
            Arc::new(PrototypeModel::new())
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            Box::new(MockPcodeInjectLibrary)
        }
        fn match_convention(&self, _convention_name: &str) -> Arc<PrototypeModel> {
            Arc::new(PrototypeModel::new())
        }
        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Arc<PrototypeModel> {
            Arc::new(PrototypeModel::new())
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
            true
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
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
        }
    }

    struct MockLanguageService {
        known_language_id: LanguageID,
        known_compiler_spec_id: CompilerSpecID,
    }

    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, crate::program::seam_stubs::LanguageNotFoundException> {
            if *language_id == self.known_language_id {
                Ok(Box::new(MockLanguage {
                    language_id: self.known_language_id.clone(),
                    compiler_spec_id: self.known_compiler_spec_id.clone(),
                }))
            } else {
                Err(crate::program::seam_stubs::LanguageNotFoundException(format!(
                    "not found: {language_id}"
                )))
            }
        }
        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn Language>, crate::program::seam_stubs::LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, crate::program::seam_stubs::LanguageNotFoundException> {
            if *language_id == self.known_language_id {
                Ok(Box::new(MockLanguageDescription {
                    id: self.known_language_id.clone(),
                    known_compiler_spec: self.known_compiler_spec_id.clone(),
                }))
            } else {
                Err(crate::program::seam_stubs::LanguageNotFoundException(format!(
                    "not found: {language_id}"
                )))
            }
        }
        fn get_language_descriptions(&self, _include_deprecated_languages: bool) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        #[allow(deprecated)]
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs(
            &self,
            _query: &crate::program::seam_stubs::LanguageCompilerSpecQuery,
        ) -> Vec<crate::program::seam_stubs::LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &crate::program::seam_stubs::ExternalLanguageCompilerSpecQuery,
        ) -> Vec<crate::program::seam_stubs::LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_descriptions_for_processor(&self, _processor: &dyn Processor) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    fn mock_service() -> MockLanguageService {
        MockLanguageService {
            known_language_id: LanguageID::new("x86:LE:32:default").unwrap(),
            known_compiler_spec_id: CompilerSpecID::new(Some("gcc")),
        }
    }

    #[test]
    fn get_language_resolves_via_service() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let language = pair.get_language(&service).expect("language should resolve");
        assert_eq!(language.get_language_id(), pair.language_id);
    }

    #[test]
    fn get_language_reports_not_found() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("arm:LE:32:v8", "default");
        let err = pair.get_language(&service).err().unwrap();
        assert!(err.message().contains("not found"));
    }

    #[test]
    fn get_compiler_spec_resolves_via_service() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let cspec = pair.get_compiler_spec(&service).expect("compiler spec should resolve");
        assert_eq!(cspec.get_compiler_spec_id(), pair.compiler_spec_id);
    }

    #[test]
    fn get_compiler_spec_reports_compiler_spec_not_found() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "windows");
        let err = pair.get_compiler_spec(&service).err().unwrap();
        assert!(matches!(err, LanguageCompilerSpecLookupError::CompilerSpec(_)));
    }

    #[test]
    fn get_compiler_spec_reports_language_not_found() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("arm:LE:32:v8", "default");
        let err = pair.get_compiler_spec(&service).err().unwrap();
        assert!(matches!(err, LanguageCompilerSpecLookupError::Language(_)));
    }

    #[test]
    fn get_language_description_resolves_via_service() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let description = pair.get_language_description(&service).expect("description should resolve");
        assert_eq!(description.get_language_id(), pair.language_id);
    }

    #[test]
    fn get_compiler_spec_description_resolves_via_service() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let description =
            pair.get_compiler_spec_description(&service).expect("compiler spec description should resolve");
        assert_eq!(description.get_compiler_spec_id(), pair.compiler_spec_id);
    }

    #[test]
    fn get_compiler_spec_description_reports_compiler_spec_not_found() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "windows");
        let err = pair.get_compiler_spec_description(&service).err().unwrap();
        assert!(matches!(err, LanguageCompilerSpecLookupError::CompilerSpec(_)));
    }
}
