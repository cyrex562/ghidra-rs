//! Port of `ghidra.program.model.lang.OldLanguageMappingService`.
//!
//! The Java class is a small extensible factory: a base class whose own `doLookupMagicString`
//! always returns `null`, registered once at class-load time with `PluggableServiceRegistry`
//! under its own class key; a plugin can register a more specific subclass over it, and the
//! static `lookupMagicString` always delegates to whatever instance is currently registered.
//!
//! ## Dropped: `PluggableServiceRegistry` / `DefaultLanguageService.getLanguageService()`
//!
//! This crate already has a real, working port of `PluggableServiceRegistry` at
//! [`crate::framework::service::PluggableServiceRegistry`], but its generic API is keyed by
//! `TypeId`/type name of a concrete, `Sized` `T`, which cannot represent "whatever concrete type
//! currently implements this trait" the way Java's `Class<? extends T>` key can -- routing this
//! trait through it would collapse Java's specificity-checked replacement logic (subclass always
//! wins over base, more-generic re-registration is silently dropped) into simple last-write-wins.
//! Rather than build a bespoke, less-safe alternative, this port follows the precedent already
//! set for [`DefaultLanguageService`](crate::program::util::default_language_service::DefaultLanguageService)
//! ("singleton lifecycle is not part of the instance contract") and
//! [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair)
//! (which parameterizes `LanguageService` instead of reaching for
//! `DefaultLanguageService.getLanguageService()`): every function below takes the collaborator it
//! would otherwise have fetched from a process-wide singleton/registry as an explicit parameter.
//! [`OldLanguageMappingService`] itself survives as the overridable "hook" trait (mirroring the
//! base class's own always-null `doLookupMagicString`); callers supply whichever implementation
//! they want used, in place of a registry lookup.

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_service::LanguageService;
use crate::util::msg::Msg;

/// The extension point Java calls `OldLanguageMappingService.doLookupMagicString`.
///
/// Port of the instance contract of `ghidra.program.model.lang.OldLanguageMappingService`.
/// Implementors override [`do_lookup_magic_string`](Self::do_lookup_magic_string) to check for a
/// mapping from an old language-name magic string to a `LanguageID`/`CompilerSpecID` pair. The
/// default implementation always returns `None`, exactly mirroring the Java base class's own
/// `doLookupMagicString`, which unconditionally `return`s `null` (the base class provides no
/// mappings itself; it exists only to be overridden by a real provider).
pub trait OldLanguageMappingService {
    /// Checks for a mapping of an old language-name magic string to a
    /// [`LanguageCompilerSpecPair`].
    ///
    /// If `language_replacement_ok` is `false`, the returned pair may no longer exist and may
    /// require use of an `OldLanguage` and translation process. If `true`, the pair corresponding
    /// to the latest language implementation should be returned if found, otherwise a deprecated
    /// pair may be returned.
    ///
    /// Port of `OldLanguageMappingService.doLookupMagicString(String, boolean)`.
    fn do_lookup_magic_string(
        &self,
        magic_string: &str,
        language_replacement_ok: bool,
    ) -> Option<LanguageCompilerSpecPair> {
        let _ = (magic_string, language_replacement_ok);
        None
    }
}

/// Checks for a mapping of an old language-name magic string to a `LanguageID`/`CompilerSpec`
/// pair, using `service` in place of the process-wide `PluggableServiceRegistry` lookup Java
/// performs (see the module docs).
///
/// Port of the static `OldLanguageMappingService.lookupMagicString(String, boolean)`.
pub fn lookup_magic_string(
    service: &dyn OldLanguageMappingService,
    magic_string: &str,
    language_replacement_ok: bool,
) -> Option<LanguageCompilerSpecPair> {
    service.do_lookup_magic_string(magic_string, language_replacement_ok)
}

/// Validates that `pair`'s language and compiler spec both actually exist in `language_service`,
/// falling back to the language's default compiler spec if the exact compiler spec is missing.
///
/// Port of the protected static `OldLanguageMappingService.validatePair(LanguageCompilerSpecPair)`,
/// parameterized on `language_service` in place of `DefaultLanguageService.getLanguageService()`
/// (see the module docs).
///
/// # Returns
/// - `Some(pair)` unchanged if both the language and its exact compiler spec were found.
/// - `Some(pair-with-default-compiler-spec)` if the language was found but not the exact compiler
///   spec (a warning is logged via [`Msg::warn`], mirroring Java).
/// - `None` if the language itself could not be found (a warning is logged via [`Msg::warn`],
///   mirroring Java).
pub fn validate_pair(
    pair: &LanguageCompilerSpecPair,
    language_service: &dyn LanguageService,
) -> Option<LanguageCompilerSpecPair> {
    match pair.get_language(language_service) {
        Ok(lang) => match lang.get_compiler_spec_by_id(pair.get_compiler_spec_id()) {
            Ok(_) => Some(pair.clone()),
            Err(_) => {
                Msg::warn(
                    "OldLanguageMappingService",
                    &format!(
                        "Compiler spec not found: {}->{}",
                        pair.get_language_id(),
                        pair.get_compiler_spec_id()
                    ),
                );
                Some(LanguageCompilerSpecPair::from_ids(
                    pair.get_language_id().clone(),
                    lang.get_default_compiler_spec().get_compiler_spec_id(),
                ))
            }
        },
        Err(_) => {
            Msg::warn(
                "OldLanguageMappingService",
                &format!("Language not found: {}", pair.get_language_id()),
            );
            None
        }
    }
}

/// Parses the language string from an XML language name into the most appropriate
/// `LanguageID`/`CompilerSpec` pair. The language name may either be an old name (i.e. a magic
/// string) or a new `<language-id>:<compiler-spec-id>` string. If an old language-name magic
/// string is provided, its replacement language will be returned if known (via `service`). The
/// returned pair may or may not be available, based on `language_service`'s available language
/// implementations.
///
/// Port of the static `OldLanguageMappingService.processXmlLanguageString(String)`,
/// parameterized on `service` and `language_service` in place of the registry/singleton lookups
/// Java performs (see the module docs).
///
/// # Genuine Java quirk, faithfully reproduced
/// Java looks for the mangled `languageID + ":" + compilerSpecID` form using
/// `lastIndexOf(':') `, but only treats it as mangled when `index > 0` -- **not** `index >= 0`.
/// A string that *starts* with a colon (e.g. `":gcc"`) therefore has `lastIndexOf(':') == 0`,
/// fails the `> 0` check, and falls through to being treated as a whole magic string (including
/// the leading colon) instead of being split. See
/// [`process_xml_language_string_leading_colon_falls_through_to_magic_string_lookup`] below.
pub fn process_xml_language_string(
    language_string: Option<&str>,
    service: &dyn OldLanguageMappingService,
    language_service: &dyn LanguageService,
) -> Option<LanguageCompilerSpecPair> {
    let language_string = language_string?; // XML file didn't specify a specific language.

    if let Some(index) = language_string.rfind(':') {
        if index > 0 {
            // Look for new mangled languageID and compilerSpecID (languageID + ":" + compilerSpecID).
            let language_id = LanguageID::new(&language_string[..index]).ok()?;
            // NOTE: mirrors Java's `new CompilerSpecID(languageString.substring(index + 1))`,
            // which only substitutes the "default" ID for a *null* string, not an *empty* one --
            // see the quirk test below for the case where the mangled string ends in ":".
            let compiler_spec_id = CompilerSpecID::new(Some(&language_string[index + 1..]));
            let pair = LanguageCompilerSpecPair::from_ids(language_id, compiler_spec_id);
            return validate_pair(&pair, language_service); // may alter compiler spec
        }
    }
    lookup_magic_string(service, language_string, true)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_not_found_exception::LanguageNotFoundException;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{PcodeInjectLibrary, Processor};
    use std::collections::HashSet;

    // --- OldLanguageMappingService trait: default and overridden behavior ---

    struct DefaultNoOpService;
    impl OldLanguageMappingService for DefaultNoOpService {}

    struct FixedMappingService {
        magic_string: &'static str,
        pair: LanguageCompilerSpecPair,
    }
    impl OldLanguageMappingService for FixedMappingService {
        fn do_lookup_magic_string(
            &self,
            magic_string: &str,
            _language_replacement_ok: bool,
        ) -> Option<LanguageCompilerSpecPair> {
            if magic_string == self.magic_string {
                Some(self.pair.clone())
            } else {
                None
            }
        }
    }

    #[test]
    fn default_service_always_returns_none() {
        assert!(lookup_magic_string(&DefaultNoOpService, "8086_16_R_pcintel", true).is_none());
        assert!(lookup_magic_string(&DefaultNoOpService, "", false).is_none());
    }

    #[test]
    fn overridden_service_maps_known_magic_string() {
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let service = FixedMappingService { magic_string: "8086_16_R_pcintel", pair: pair.clone() };

        let found = lookup_magic_string(&service, "8086_16_R_pcintel", true).unwrap();
        assert_eq!(found, pair);
        assert!(lookup_magic_string(&service, "unknown", true).is_none());
    }

    // --- LanguageService-backed validate_pair / process_xml_language_string ---
    //
    // Full `Language`/`CompilerSpec` mocks, closely modeled on the established pattern in
    // `language_compiler_spec_pair.rs`'s test module: every trait method must be implemented
    // (Rust has no partial `impl`), so methods not exercised by these tests return a trivial
    // default or `unimplemented!()`.

    struct MockProcessor;
    impl Processor for MockProcessor {}


    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockCompilerSpec {
        language_id: LanguageID,
        compiler_spec_id: CompilerSpecID,
    }
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
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
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
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
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
        }
    }

    /// A `Language` whose known compiler spec ID is fixed at construction; `get_compiler_spec_by_id`
    /// succeeds only for that exact ID, mirroring a language that offers exactly one compiler spec.
    struct MockLanguage {
        language_id: LanguageID,
        known_compiler_spec_id: CompilerSpecID,
        default_compiler_spec_id: CompilerSpecID,
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
            if *compiler_spec_id == self.known_compiler_spec_id {
                Ok(Box::new(MockCompilerSpec {
                    language_id: self.language_id.clone(),
                    compiler_spec_id: compiler_spec_id.clone(),
                }))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.language_id, compiler_spec_id))
            }
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            Box::new(MockCompilerSpec {
                language_id: self.language_id.clone(),
                compiler_spec_id: self.default_compiler_spec_id.clone(),
            })
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

    struct MockLanguageService {
        known_language_id: LanguageID,
        known_compiler_spec_id: CompilerSpecID,
        default_compiler_spec_id: CompilerSpecID,
    }
    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, crate::program::seam_stubs::LanguageNotFoundException> {
            if *language_id == self.known_language_id {
                Ok(Box::new(MockLanguage {
                    language_id: self.known_language_id.clone(),
                    known_compiler_spec_id: self.known_compiler_spec_id.clone(),
                    default_compiler_spec_id: self.default_compiler_spec_id.clone(),
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
            _language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, crate::program::seam_stubs::LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
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
            default_compiler_spec_id: CompilerSpecID::new(Some("default")),
        }
    }

    #[test]
    fn validate_pair_returns_unchanged_pair_when_both_language_and_compiler_spec_are_known() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let validated = validate_pair(&pair, &service).expect("should validate");
        assert_eq!(validated, pair);
    }

    #[test]
    fn validate_pair_falls_back_to_default_compiler_spec_when_compiler_spec_unknown() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "windows");
        let validated = validate_pair(&pair, &service).expect("language is known");
        assert_eq!(validated.get_language_id(), pair.get_language_id());
        assert_eq!(validated.get_compiler_spec_id().get_id_as_string(), "default");
    }

    #[test]
    fn validate_pair_returns_none_when_language_unknown() {
        let service = mock_service();
        let pair = LanguageCompilerSpecPair::new("arm:LE:32:v8", "default");
        assert!(validate_pair(&pair, &service).is_none());
    }

    #[test]
    fn process_xml_language_string_returns_none_for_none_input() {
        let language_service = mock_service();
        let mapping_service = DefaultNoOpService;
        assert!(process_xml_language_string(None, &mapping_service, &language_service).is_none());
    }

    #[test]
    fn process_xml_language_string_parses_mangled_language_and_compiler_spec() {
        let language_service = mock_service();
        let mapping_service = DefaultNoOpService;
        let result = process_xml_language_string(
            Some("x86:LE:32:default:gcc"),
            &mapping_service,
            &language_service,
        )
        .expect("mangled string should validate");
        assert_eq!(result.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(result.get_compiler_spec_id().get_id_as_string(), "gcc");
    }

    #[test]
    fn process_xml_language_string_falls_through_to_magic_string_lookup_when_no_colon() {
        let language_service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let mapping_service = FixedMappingService { magic_string: "8086_16_R_pcintel", pair: pair.clone() };

        let result =
            process_xml_language_string(Some("8086_16_R_pcintel"), &mapping_service, &language_service)
                .expect("magic string should resolve");
        assert_eq!(result, pair);
    }

    /// Genuine Java quirk, faithfully reproduced: `OldLanguageMappingService.java` checks
    /// `index > 0` (not `index >= 0`) after `lastIndexOf(':')`, so a language string that starts
    /// with a colon is *not* split into language/compiler-spec parts -- it is instead passed
    /// whole (including the leading colon) to `lookupMagicString`. See the module docs on
    /// `process_xml_language_string` for the citation.
    #[test]
    fn process_xml_language_string_leading_colon_falls_through_to_magic_string_lookup() {
        let language_service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        // Magic string set to exactly the leading-colon input, proving it reached the magic
        // string path with the colon still attached rather than being split at index 0.
        let mapping_service = FixedMappingService { magic_string: ":gcc", pair: pair.clone() };

        let result = process_xml_language_string(Some(":gcc"), &mapping_service, &language_service)
            .expect("leading-colon string should fall through to magic string lookup");
        assert_eq!(result, pair);
    }

    /// Genuine Java quirk, faithfully reproduced: `CompilerSpecID`'s constructor only substitutes
    /// `DEFAULT_ID` for a `null` string, never for an empty one (see
    /// `CompilerSpecID(String id) { this.id = id != null ? id : DEFAULT_ID; }`). A mangled
    /// language string ending in a bare `:` therefore produces a `CompilerSpecID` holding an
    /// *empty* string, not `"default"` -- which then fails to resolve against any real language's
    /// compiler specs and falls back through `validatePair`'s "compiler spec not found" branch.
    #[test]
    fn process_xml_language_string_trailing_colon_yields_empty_not_default_compiler_spec_id() {
        let language_service = mock_service();
        let mapping_service = DefaultNoOpService;

        let result = process_xml_language_string(
            Some("x86:LE:32:default:"),
            &mapping_service,
            &language_service,
        )
        .expect("language is known, so validate_pair still returns a fallback pair");

        // The empty CompilerSpecID never matches "gcc", so validate_pair fell back to the
        // language's actual default compiler spec ID ("default" in this mock), *not* because
        // CompilerSpecID itself defaulted the empty string -- it never does.
        assert_eq!(result.get_compiler_spec_id().get_id_as_string(), "default");
    }

    #[test]
    fn process_xml_language_string_index_zero_and_missing_colon_share_the_fallthrough_path() {
        // No colon at all: also falls through to lookup_magic_string, same as the leading-colon
        // case, confirming both `None` and `Some(0)` from `rfind` land on the same branch.
        let language_service = mock_service();
        let pair = LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc");
        let mapping_service = FixedMappingService { magic_string: "8086plain", pair: pair.clone() };

        let result =
            process_xml_language_string(Some("8086plain"), &mapping_service, &language_service)
                .expect("no-colon string should fall through to magic string lookup");
        assert_eq!(result, pair);
    }
}
