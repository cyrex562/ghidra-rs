//! An offer to map from a trace to a Ghidra language / compiler.
//!
//! Port of `ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer`.

use crate::app::seam_stubs::PluginTool;
use crate::debug::api::platform::DebuggerPlatformMapper;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_service::LanguageService;
use crate::trace::model::trace::Trace;

/// An offer to map from a trace to a Ghidra language / compiler.
///
/// Port of `ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer`.
pub trait DebuggerPlatformOffer {
    /// Get a human-readable description of the offer.
    ///
    /// Generally, more detailed descriptions imply a higher confidence.
    fn get_description(&self) -> String;

    /// Get the confidence of this offer.
    ///
    /// Offers with numerically higher confidence are preferred. Negative confidence values are
    /// considered "manual overrides," and so are never selected automatically and are hidden
    /// from prompts by default.
    ///
    /// TODO: Spec out some standard numbers. Maybe an enum?
    fn get_confidence(&self) -> i32;

    /// Check if the confidence indicates this offer is a manual override.
    fn is_override(&self) -> bool {
        self.get_confidence() < 0
    }

    /// Get the language to which this offer can map.
    fn get_language(&self) -> Option<Box<dyn Language>> {
        self.get_compiler_spec().map(|c_spec| c_spec.get_language())
    }

    /// Get the language ID to which this offer can map.
    fn get_language_id(&self) -> Option<LanguageID> {
        self.get_language().map(|language| language.get_language_id())
    }

    /// Get the compiler to which this offer can map.
    fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>>;

    /// Get the compiler spec ID to which this offer can map.
    fn get_compiler_spec_id(&self) -> Option<CompilerSpecID> {
        self.get_compiler_spec()
            .map(|c_spec| c_spec.get_compiler_spec_id())
    }

    /// Get the mapper, which implements this offer.
    fn take(&self, tool: &dyn PluginTool, trace: &dyn Trace) -> Box<dyn DebuggerPlatformMapper>;

    /// Check if this or an equivalent offer was the creator of the given mapper.
    fn is_creator_of(&self, mapper: &dyn DebuggerPlatformMapper) -> bool;
}

/// Load a compiler spec from a language service given the language and cspec IDs.
///
/// Port of the Java default method `DebuggerPlatformOffer.getCompilerSpec(LanguageID,
/// CompilerSpecID)`. That method reaches for the process-wide
/// `DefaultLanguageService.getLanguageService()` singleton; the singleton accessor was dropped
/// when [`DefaultLanguageService`](crate::program::util::default_language_service::DefaultLanguageService)
/// was ported (see its module docs for why), so implementors of [`DebuggerPlatformOffer`] that
/// need this behavior call this free function with a language service in hand instead.
///
/// # Panics
///
/// Mirrors Java's `catch (LanguageNotFoundException | CompilerSpecNotFoundException e) { throw
/// new AssertionError(e); }`: panics if either the language or the compiler spec is not found.
pub fn compiler_spec_for(
    lang_service: &dyn LanguageService,
    lang_id: &LanguageID,
    c_spec_id: Option<&CompilerSpecID>,
) -> Box<dyn CompilerSpec> {
    let language = lang_service
        .get_language(lang_id)
        .unwrap_or_else(|e| panic!("AssertionError: {e}"));
    match c_spec_id {
        None => language.get_default_compiler_spec(),
        Some(id) => language
            .get_compiler_spec_by_id(id)
            .unwrap_or_else(|e| panic!("AssertionError: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::{
        AddressLabelInfo, ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair,
        LanguageCompilerSpecQuery, LanguageNotFoundException, PcodeInjectLibrary, Processor,
    };

    struct MockPrototypeModel;
    impl PrototypeModel for MockPrototypeModel {}

    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockCompilerSpecDescription {
        id: CompilerSpecID,
    }
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
        }
        fn get_compiler_spec_name(&self) -> String {
            "GCC".to_string()
        }
        fn get_source(&self) -> String {
            "gcc.cspec".to_string()
        }
    }

    struct MockCompilerSpec {
        id: CompilerSpecID,
    }
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription { id: self.id.clone() })
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            self.id.clone()
        }
        fn get_stack_pointer(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(
            &self,
            _space_name: &str,
        ) -> Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            crate::program::model::address::AddressSpace::new(
                "stack",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Stack,
                0,
            )
        }
        fn get_stack_base_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            self.get_stack_space()
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            Some(Box::new(MockPrototypeModel))
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            DecompilerLanguage::CLanguage
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }
        fn is_global(&self, _addr: &crate::program::model::address::Address) -> bool {
            true
        }
        fn get_data_organization(
            &self,
        ) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            Box::new(MockPcodeInjectLibrary)
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }
        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
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
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
        }
    }

    struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<
            Box<
                dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper,
            >,
        > {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(
            &self,
        ) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
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
        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
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
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &std::sync::Arc<crate::program::model::address::AddressSpace>,
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
            _addr: &crate::program::model::address::Address,
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
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<
            Box<dyn CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            Ok(Box::new(MockCompilerSpec {
                id: compiler_spec_id.clone(),
            }))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            Box::new(MockCompilerSpec {
                id: CompilerSpecID::new(Some("default")),
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
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
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
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockOffer {
        confidence: i32,
        c_spec_id: Option<CompilerSpecID>,
    }
    impl DebuggerPlatformOffer for MockOffer {
        fn get_description(&self) -> String {
            "mock offer".to_string()
        }
        fn get_confidence(&self) -> i32 {
            self.confidence
        }
        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            self.c_spec_id
                .clone()
                .map(|id| Box::new(MockCompilerSpec { id }) as Box<dyn CompilerSpec>)
        }
        fn take(&self, _tool: &dyn PluginTool, _trace: &dyn Trace) -> Box<dyn DebuggerPlatformMapper> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_creator_of(&self, _mapper: &dyn DebuggerPlatformMapper) -> bool {
            false
        }
    }

    #[test]
    fn confidence_sign_determines_override() {
        let manual = MockOffer { confidence: -1, c_spec_id: None };
        let automatic = MockOffer { confidence: 50, c_spec_id: None };
        assert!(manual.is_override());
        assert!(!automatic.is_override());
    }

    #[test]
    fn language_and_compiler_spec_id_default_to_none_without_compiler_spec() {
        let offer = MockOffer { confidence: 0, c_spec_id: None };
        assert!(offer.get_compiler_spec().is_none());
        assert!(offer.get_language().is_none());
        assert!(offer.get_language_id().is_none());
        assert!(offer.get_compiler_spec_id().is_none());
    }

    #[test]
    fn language_and_compiler_spec_id_derive_from_compiler_spec() {
        let offer = MockOffer {
            confidence: 50,
            c_spec_id: Some(CompilerSpecID::new(Some("gcc"))),
        };
        assert_eq!(offer.get_compiler_spec_id(), Some(CompilerSpecID::new(Some("gcc"))));
        assert_eq!(
            offer.get_language_id(),
            Some(LanguageID::new("x86:LE:32:default").unwrap())
        );
    }

    struct MockLanguageService;
    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            if language_id.get_id_as_string() == "x86:LE:32:default" {
                Ok(Box::new(MockLanguage))
            } else {
                Err(LanguageNotFoundException(format!(
                    "No language '{}'",
                    language_id
                )))
            }
        }
        fn get_default_language(
            &self,
            _processor: &dyn Processor,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            Ok(Box::new(MockLanguage))
        }
        fn get_language_description(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        #[allow(deprecated)]
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<crate::program::model::lang::endian::Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    #[test]
    fn compiler_spec_for_uses_default_when_cspec_id_is_none() {
        let service = MockLanguageService;
        let lang_id = LanguageID::new("x86:LE:32:default").unwrap();
        let c_spec = compiler_spec_for(&service, &lang_id, None);
        assert_eq!(c_spec.get_compiler_spec_id(), CompilerSpecID::new(Some("default")));
    }

    #[test]
    fn compiler_spec_for_uses_given_id_when_present() {
        let service = MockLanguageService;
        let lang_id = LanguageID::new("x86:LE:32:default").unwrap();
        let gcc = CompilerSpecID::new(Some("gcc"));
        let c_spec = compiler_spec_for(&service, &lang_id, Some(&gcc));
        assert_eq!(c_spec.get_compiler_spec_id(), gcc);
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn compiler_spec_for_panics_when_language_not_found() {
        let service = MockLanguageService;
        let lang_id = LanguageID::new("bogus:LE:32:default").unwrap();
        compiler_spec_for(&service, &lang_id, None);
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let offer: Box<dyn DebuggerPlatformOffer> = Box::new(MockOffer { confidence: 0, c_spec_id: None });
        let _ = offer;
    }
}
