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
