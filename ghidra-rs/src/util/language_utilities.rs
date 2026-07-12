use std::collections::HashSet;

use crate::program::model::lang::{LanguageID, LanguageService};
use crate::program::seam_stubs::{LanguageCompilerSpecPair, LanguageNotFoundException};

/// Port of `ghidra.util.LanguageUtilities`.
///
/// The Java interface's `static` methods obtained a `LanguageService` from the
/// `DefaultLanguageService` singleton before doing their work. Here the service is supplied
/// directly via `&self`, so this trait is implemented for every [`LanguageService`] and its
/// helpers are called the same way any other `LanguageService` method would be.
pub trait LanguageUtilities: LanguageService {
    /// Returns all language/compiler-spec pairs compatible with any of the given language IDs.
    ///
    /// Duplicate pairs are removed while preserving first-seen insertion order, matching Java's
    /// `LinkedHashSet` semantics.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if any of the given language IDs cannot be resolved.
    fn get_all_pairs_for_languages(
        &self,
        language_ids: &HashSet<LanguageID>,
    ) -> Result<Vec<LanguageCompilerSpecPair>, LanguageNotFoundException> {
        let mut result: Vec<LanguageCompilerSpecPair> = Vec::new();
        for language_id in language_ids {
            let language = self.get_language(language_id)?;
            for csd in language.get_compatible_compiler_spec_descriptions() {
                let pair =
                    LanguageCompilerSpecPair::new(language_id.clone(), csd.get_compiler_spec_id());
                if !result.contains(&pair) {
                    result.push(pair);
                }
            }
        }
        Ok(result)
    }

    /// Returns all language/compiler-spec pairs compatible with the given language ID.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if the given language ID cannot be resolved.
    fn get_all_pairs_for_language(
        &self,
        language: &LanguageID,
    ) -> Result<Vec<LanguageCompilerSpecPair>, LanguageNotFoundException> {
        let mut singleton = HashSet::new();
        singleton.insert(language.clone());
        self.get_all_pairs_for_languages(&singleton)
    }
}

impl<T: LanguageService + ?Sized> LanguageUtilities for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::{
        CompilerSpecDescription, CompilerSpecID, Language, LanguageDescription,
    };
    use crate::program::seam_stubs::{
        ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecQuery, Processor,
    };

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

    struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }

        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>>
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

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_default_data_space(
            &self,
        ) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for this smoke test")
        }

        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_instruction_alignment(&self) -> i32 {
            1
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }

        fn supports_pcode(&self) -> bool {
            true
        }

        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
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
            Err(crate::program::model::lang::language::ParseError::UnknownInstruction(
                crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException::new(),
            ))
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
        ) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            Err(
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ),
            )
        }

        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not needed for this smoke test")
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

        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn get_manual_exception(
            &self,
        ) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(
            &self,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
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
            Err(LanguageNotFoundException(
                "No default language for processor".to_string(),
            ))
        }

        fn get_language_description(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            unimplemented!("not needed for this smoke test")
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
            _endianness: Option<Endian>,
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
    fn get_all_pairs_for_language_known_id() {
        let service = MockLanguageService;
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let pairs = service.get_all_pairs_for_language(&id).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].get_compiler_spec_id().to_string(), "gcc");
    }

    #[test]
    fn get_all_pairs_for_languages_unknown_id_errs() {
        let service = MockLanguageService;
        let mut ids = HashSet::new();
        ids.insert(LanguageID::new("bogus:LE:32:default").unwrap());
        assert!(service.get_all_pairs_for_languages(&ids).is_err());
    }

    #[test]
    fn usable_as_trait_object() {
        let service: Box<dyn LanguageUtilities> = Box::new(MockLanguageService);
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert_eq!(service.get_all_pairs_for_language(&id).unwrap().len(), 1);
    }
}
