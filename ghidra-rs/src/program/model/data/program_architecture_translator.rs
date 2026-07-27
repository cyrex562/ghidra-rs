//! Port of `ghidra.program.model.data.ProgramArchitectureTranslator`, promoted to a trait because
//! it was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends LanguageTranslatorAdapter`. `LanguageTranslatorAdapter` itself is not
//! yet ported, so this trait extends [`LanguageTranslator`] directly -- the already-ported
//! interface `LanguageTranslatorAdapter implements`, and the interface
//! `ProgramArchitectureTranslator` inherits every non-overridden method from.
//!
//! The two field getters `getOldCompilerSpec()`/`getNewCompilerSpec()` are ported as
//! [`old_compiler_spec`]/[`new_compiler_spec`](ProgramArchitectureTranslator::old_compiler_spec)
//! -- dropping the Java `get` prefix -- because `LanguageTranslator` already declares a
//! *different*, arg-taking `get_old_compiler_spec(&CompilerSpecID)` (port of
//! `LanguageTranslator.getOldCompilerSpec(CompilerSpecID)`, an upgrade-time lookup that is
//! unrelated to this class's fixed old/new fields despite the shared Java name via overloading).
//! Rust has no method overloading, so keeping the Java name here would collide with the
//! supertrait method and force callers through disambiguating UFCS syntax; the field getters are
//! given distinct names instead, mirroring the `complex_*`-renaming precedent in
//! [`AbstractComplexDataType`](crate::program::model::data::abstract_complex_data_type::AbstractComplexDataType).
//!
//! The two Java constructors validate/resolve state (an [`IncompatibleLanguageException`] check,
//! two `Language::get_compiler_spec_by_id` lookups, a language-ID/version lookup, and finally the
//! inherited `LanguageTranslatorAdapter.validateDefaultSpaceMap()`) rather than simply assigning
//! fields, so they cannot become trait associated functions (an object-safe trait cannot declare
//! an associated function returning `Self`) or a struct constructor (there is no concrete struct
//! to define -- the whole point of this port is the trait seam). `validateDefaultSpaceMap()` in
//! particular is inherited, protected construction-time behavior that belongs to
//! `LanguageTranslatorAdapter`, not to this class's own declared surface, so it is left out
//! entirely (port it alongside `LanguageTranslatorAdapter` instead). The two constructors'
//! remaining logic that *is* this class's own -- the processor-compatibility check and the
//! `LanguageID`/version resolution helper -- is ported as the free functions
//! [`validate_processor_compatibility`] and [`resolve_language_by_id`], which a concrete
//! implementation's constructor can call once `LanguageTranslatorAdapter` exists to build on.

use std::sync::Arc;

use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::incompatible_language_exception::IncompatibleLanguageException;
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::program::util::language_translator::LanguageTranslator;

/// Port of `ghidra.program.model.data.ProgramArchitectureTranslator`.
///
/// A [`LanguageTranslator`] specialized for translating a program between two compiler
/// specifications of the *same* processor -- e.g. when a program's architecture (compiler spec)
/// is being changed without also changing its instruction set / `Language`.
pub trait ProgramArchitectureTranslator: LanguageTranslator {
    /// Returns the compiler specification for the old (source) architecture. Port of
    /// `getOldCompilerSpec()`.
    fn old_compiler_spec(&self) -> Arc<dyn CompilerSpec>;

    /// Returns the compiler specification for the new (destination) architecture. Port of
    /// `getNewCompilerSpec()`.
    fn new_compiler_spec(&self) -> Arc<dyn CompilerSpec>;
}

/// Port of the processor-compatibility check performed by the body of
/// `ProgramArchitectureTranslator(Language, CompilerSpecID, Language, CompilerSpecID)`, prior to
/// resolving either compiler spec: `oldLanguage.getProcessor().equals(newLanguage.getProcessor())`.
///
/// # Errors
/// Returns [`IncompatibleLanguageException`] if `old_language` and `new_language` are for
/// different processors.
pub fn validate_processor_compatibility(
    old_language: &dyn Language,
    new_language: &dyn Language,
) -> Result<(), IncompatibleLanguageException> {
    let old_processor_name = old_language.get_processor().name();
    let new_processor_name = new_language.get_processor().name();
    if old_processor_name != new_processor_name {
        return Err(IncompatibleLanguageException::new(format!(
            "Architecture processors differ: {} vs {}",
            old_processor_name, new_processor_name
        )));
    }
    Ok(())
}

/// Port of the private static `getLanguage(LanguageID, int)` helper used by
/// `ProgramArchitectureTranslator(LanguageID, int, CompilerSpecID, Language, CompilerSpecID)` to
/// resolve its old language before delegating to the other constructor. In Java this looked the
/// language up via the `DefaultLanguageService` singleton; here the equivalent
/// [`LanguageService`] is supplied explicitly by the caller.
///
/// # Errors
/// Returns [`LanguageNotFoundException`] if no language is registered for `language_id`, or if
/// `language_version` is positive and does not match the resolved language's version.
pub fn resolve_language_by_id(
    language_service: &dyn LanguageService,
    language_id: &LanguageID,
    language_version: i32,
) -> Result<Box<dyn Language>, LanguageNotFoundException> {
    let language = language_service.get_language(language_id)?;
    if language_version > 0 && language.get_version() != language_version {
        return Err(LanguageNotFoundException(format!(
            "Language not found for '{}' version {}.x",
            language_id, language_version
        )));
    }
    Ok(language)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::lang::compiler_spec::EvaluationModelType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::listing::Program;
    use crate::program::model::pcode::Encoder;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{
        ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
        MemBuffer, AddressLabelInfo, PcodeInjectLibrary, Processor,
        RegisterValue,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::language::ParseError;
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    struct MockProcessor(&'static str);

    impl Processor for MockProcessor {
        fn name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockLanguage {
        id: &'static str,
        version: i32,
        processor_name: &'static str,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new(self.id).unwrap()
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
            Box::new(MockProcessor(self.processor_name))
        }

        fn get_version(&self) -> i32 {
            self.version
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
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
        ) -> Result<Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>, ParseError>
        {
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
            _addrspc: &Arc<AddressSpace>,
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

        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockCompilerSpec {
        id: &'static str,
    }

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some(self.id))
        }

        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }

        fn is_stack_right_justified(&self) -> bool {
            false
        }

        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }

        fn get_stack_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn stack_grows_negative(&self) -> bool {
            true
        }

        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }

        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_prototype_evaluation_model(&self, _model_type: EvaluationModelType) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_global(&self, _addr: &Address) -> bool {
            false
        }

        fn get_data_organization(&self) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!("not exercised by this smoke test")
        }

        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
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

    struct MockTranslator {
        old_spec: Arc<dyn CompilerSpec>,
        new_spec: Arc<dyn CompilerSpec>,
    }

    impl LanguageTranslator for MockTranslator {
        fn is_valid(&self) -> bool {
            true
        }

        fn get_old_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_old_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_old_version(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_version(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_address_space(&self, _old_space_name: &str) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_old_register(&self, _old_addr: &Address, _size: i32) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_old_register_containing(&self, _old_addr: &Address) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_old_context_register(&self) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_register(&self, _old_reg: &RegisterRef) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_context_register(&self) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_register_value(&self, _old_value: &dyn RegisterValue) -> Option<Box<dyn RegisterValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_value_translation_required(&self, _old_reg: &RegisterRef) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_new_compiler_spec_id(&self, old_compiler_spec_id: &CompilerSpecID) -> CompilerSpecID {
            old_compiler_spec_id.clone()
        }

        fn get_old_compiler_spec(
            &self,
            old_compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(
                &self.get_old_language_id(),
                old_compiler_spec_id,
            ))
        }

        fn fixup_instructions(
            &self,
            _program: &mut dyn Program,
            _old_language: &dyn Language,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    impl ProgramArchitectureTranslator for MockTranslator {
        fn old_compiler_spec(&self) -> Arc<dyn CompilerSpec> {
            self.old_spec.clone()
        }

        fn new_compiler_spec(&self) -> Arc<dyn CompilerSpec> {
            self.new_spec.clone()
        }
    }

    struct MockLanguageService {
        known: MockLanguage,
    }

    impl LanguageService for MockLanguageService {
        fn get_language(&self, language_id: &LanguageID) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            if language_id.get_id_as_string() == self.known.id {
                Ok(Box::new(MockLanguage {
                    id: self.known.id,
                    version: self.known.version,
                    processor_name: self.known.processor_name,
                }))
            } else {
                Err(LanguageNotFoundException(format!("Language not found for '{}'", language_id)))
            }
        }

        fn get_default_language(&self, _processor: &dyn Processor) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_description(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_descriptions(&self, _include_deprecated_languages: bool) -> Vec<Box<dyn LanguageDescription>> {
            unimplemented!("not exercised by this smoke test")
        }

        #[allow(deprecated)]
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_compiler_spec_pairs(&self, _query: &LanguageCompilerSpecQuery) -> Vec<LanguageCompilerSpecPair> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_descriptions_for_processor(&self, _processor: &dyn Processor) -> Vec<Box<dyn LanguageDescription>> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn trait_object_exposes_old_and_new_compiler_specs() {
        let translator: Box<dyn ProgramArchitectureTranslator> = Box::new(MockTranslator {
            old_spec: Arc::new(MockCompilerSpec { id: "gcc" }),
            new_spec: Arc::new(MockCompilerSpec { id: "visualstudio" }),
        });

        assert_eq!(translator.old_compiler_spec().get_compiler_spec_id().to_string(), "gcc");
        assert_eq!(translator.new_compiler_spec().get_compiler_spec_id().to_string(), "visualstudio");
        // Reachable through the LanguageTranslator supertrait too, proving the trait hierarchy
        // composes as a single trait object.
        assert!(translator.is_valid());
    }

    #[test]
    fn validate_processor_compatibility_accepts_matching_processors() {
        let old_language = MockLanguage { id: "x86:LE:32:default", version: 1, processor_name: "x86" };
        let new_language = MockLanguage { id: "x86:LE:64:default", version: 1, processor_name: "x86" };

        assert!(validate_processor_compatibility(&old_language, &new_language).is_ok());
    }

    #[test]
    fn validate_processor_compatibility_rejects_differing_processors() {
        let old_language = MockLanguage { id: "x86:LE:32:default", version: 1, processor_name: "x86" };
        let new_language = MockLanguage { id: "ARM:LE:32:v8", version: 1, processor_name: "ARM" };

        let err = validate_processor_compatibility(&old_language, &new_language).unwrap_err();
        assert!(err.message().contains("x86"));
        assert!(err.message().contains("ARM"));
    }

    #[test]
    fn resolve_language_by_id_matches_version() {
        let service = MockLanguageService {
            known: MockLanguage { id: "x86:LE:32:default", version: 5, processor_name: "x86" },
        };
        let id = LanguageID::new("x86:LE:32:default").unwrap();

        assert!(resolve_language_by_id(&service, &id, 5).is_ok());
        // A non-positive version means "don't care".
        assert!(resolve_language_by_id(&service, &id, 0).is_ok());
    }

    #[test]
    fn resolve_language_by_id_rejects_version_mismatch() {
        let service = MockLanguageService {
            known: MockLanguage { id: "x86:LE:32:default", version: 5, processor_name: "x86" },
        };
        let id = LanguageID::new("x86:LE:32:default").unwrap();

        let err = resolve_language_by_id(&service, &id, 3).err().unwrap();
        assert!(err.to_string().contains("version 3.x"));
    }

    #[test]
    fn resolve_language_by_id_rejects_unknown_id() {
        let service = MockLanguageService {
            known: MockLanguage { id: "x86:LE:32:default", version: 5, processor_name: "x86" },
        };
        let id = LanguageID::new("bogus:LE:32:default").unwrap();

        assert!(resolve_language_by_id(&service, &id, 0).is_err());
    }
}
