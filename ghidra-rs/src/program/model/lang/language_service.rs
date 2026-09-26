use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::{
    ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
    LanguageNotFoundException, Processor,
};

/// Service that provides a `Language` given a name, and information about the language.
///
/// Port of `ghidra.program.model.lang.LanguageService`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// members;
/// [`VersionedLanguageService`](crate::program::model::lang::versioned_language_service::VersionedLanguageService)
/// used it only as an empty supertrait, so the empty surface is retained here as part of the
/// full trait.
pub trait LanguageService {
    /// Returns the language with the given language ID.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if no language can be found for the given ID.
    fn get_language(
        &self,
        language_id: &LanguageID,
    ) -> Result<Box<dyn Language>, LanguageNotFoundException>;

    /// Returns the default Language to use for the given processor.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if there are no languages at all for the given
    /// processor.
    fn get_default_language(
        &self,
        processor: &dyn Processor,
    ) -> Result<Box<dyn Language>, LanguageNotFoundException>;

    /// Get language information for the given language ID.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if there is no language for the given ID.
    fn get_language_description(
        &self,
        language_id: &LanguageID,
    ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException>;

    /// Returns all known language descriptions.
    fn get_language_descriptions(
        &self,
        include_deprecated_languages: bool,
    ) -> Vec<Box<dyn LanguageDescription>>;

    /// Returns all known language descriptions which satisfy the criteria identified by the
    /// non-`None` parameters. A `None` value implies a don't-care wildcard value.
    ///
    /// # Deprecated
    /// Use [`LanguageService::get_language_descriptions_for_processor`] instead.
    #[deprecated(note = "use get_language_descriptions_for_processor instead")]
    fn get_language_descriptions_matching(
        &self,
        processor: &dyn Processor,
        endianness: Option<Endian>,
        size: Option<i32>,
        variant: Option<&str>,
    ) -> Vec<Box<dyn LanguageDescription>>;

    /// Returns all known language/compiler spec pairs which satisfy the criteria identified by
    /// the non-`None` fields of `query`. OMITS DEPRECATED LANGUAGES.
    fn get_language_compiler_spec_pairs(
        &self,
        query: &LanguageCompilerSpecQuery,
    ) -> Vec<LanguageCompilerSpecPair>;

    /// Returns all known language/compiler spec pairs which satisfy the criteria identified by
    /// the non-`None` fields of `query`. OMITS DEPRECATED LANGUAGES. This uses an
    /// `ExternalLanguageCompilerSpecQuery` rather than a `LanguageCompilerSpecQuery`.
    fn get_language_compiler_spec_pairs_external(
        &self,
        query: &ExternalLanguageCompilerSpecQuery,
    ) -> Vec<LanguageCompilerSpecPair>;

    /// Returns all language descriptions associated with the given processor.
    fn get_language_descriptions_for_processor(
        &self,
        processor: &dyn Processor,
    ) -> Vec<Box<dyn LanguageDescription>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;

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

    struct MockLanguageDescription;
    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
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
            "Mock x86 32-bit little endian".to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct MockLanguageService;

    impl LanguageService for MockLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            Err(LanguageNotFoundException(format!(
                "No language '{}'",
                language_id
            )))
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
            language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            if language_id.get_id_as_string() == "x86:LE:32:default" {
                Ok(Box::new(MockLanguageDescription))
            } else {
                Err(LanguageNotFoundException(format!(
                    "No description for '{}'",
                    language_id
                )))
            }
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(MockLanguageDescription)]
        }

        #[allow(deprecated)]
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(MockLanguageDescription)]
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            vec![LanguageCompilerSpecPair::new(
                LanguageID::new("x86:LE:32:default").unwrap(),
                CompilerSpecID::new(Some("gcc")),
            )]
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
            vec![Box::new(MockLanguageDescription)]
        }
    }

    #[test]
    fn get_language_description_known_id() {
        let service = MockLanguageService;
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(service.get_language_description(&id).is_ok());
    }

    #[test]
    fn get_language_unknown_id_errs() {
        let service = MockLanguageService;
        let id = LanguageID::new("bogus:LE:32:default").unwrap();
        let err = service.get_language(&id).err().unwrap();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    #[allow(deprecated)]
    fn usable_as_trait_object() {
        let service: Box<dyn LanguageService> = Box::new(MockLanguageService);
        let id = LanguageID::new("x86:LE:32:default").unwrap();

        assert_eq!(service.get_language_descriptions(false).len(), 1);
        assert!(service.get_language_description(&id).is_ok());
        assert_eq!(
            service
                .get_language_compiler_spec_pairs(&LanguageCompilerSpecQuery::new(
                    None, None, None, None, None
                ))
                .len(),
            1
        );
        assert!(service
            .get_language_compiler_spec_pairs_external(&ExternalLanguageCompilerSpecQuery::new(
                None, None, None, None, None
            ))
            .is_empty());
        assert_eq!(
            service
                .get_language_descriptions_matching(&MockProcessor, None, None, None)
                .len(),
            1
        );
        assert_eq!(
            service.get_language_descriptions_for_processor(&MockProcessor).len(),
            1
        );
        assert!(service.get_default_language(&MockProcessor).is_err());
    }
}
