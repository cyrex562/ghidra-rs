use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::seam_stubs::LanguageNotFoundException;

/// Service that provides a `Language` given a name, and information about the language.
///
/// Port of `ghidra.program.model.lang.VersionedLanguageService`. The Java interface extends
/// `LanguageService`.
pub trait VersionedLanguageService: LanguageService {
    /// Returns a specific language version with the given language ID.
    /// This form should only be used when handling language upgrade concerns.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if the specified language version can not be found
    /// for the given ID.
    fn get_language(
        &self,
        language_id: &LanguageID,
        version: i32,
    ) -> Result<Box<dyn Language>, LanguageNotFoundException>;

    /// Get language information for a specific version of the given language ID.
    /// This form should only be used when handling language upgrade concerns.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if there is no language for the given ID.
    fn get_language_description(
        &self,
        language_id: &LanguageID,
        version: i32,
    ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProcessor;
    impl crate::program::seam_stubs::Processor for MockProcessor {}

    struct MockCompilerSpecDescription;
    impl crate::program::model::lang::compiler_spec_description::CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
            crate::program::model::lang::compiler_spec_id::CompilerSpecID::new(Some("gcc"))
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

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            Box::new(MockProcessor)
        }

        fn get_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
        }

        fn get_instruction_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
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

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            Err(
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ),
            )
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct MockVersionedLanguageService {
        known_version: i32,
    }

    impl LanguageService for MockVersionedLanguageService {
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
            _processor: &dyn crate::program::seam_stubs::Processor,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            Err(LanguageNotFoundException(
                "No default language for processor".to_string(),
            ))
        }

        fn get_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            Err(LanguageNotFoundException(format!(
                "No description for '{}'",
                language_id
            )))
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
            _processor: &dyn crate::program::seam_stubs::Processor,
            _endianness: Option<crate::program::model::lang::endian::Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(MockLanguageDescription)]
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

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn crate::program::seam_stubs::Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(MockLanguageDescription)]
        }
    }

    impl VersionedLanguageService for MockVersionedLanguageService {
        fn get_language(
            &self,
            language_id: &LanguageID,
            version: i32,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            Err(LanguageNotFoundException(format!(
                "No language '{}' version {} (known version {})",
                language_id, version, self.known_version
            )))
        }

        fn get_language_description(
            &self,
            language_id: &LanguageID,
            version: i32,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            if version == self.known_version {
                Ok(Box::new(MockLanguageDescription))
            } else {
                Err(LanguageNotFoundException(format!(
                    "No description for '{}' version {}",
                    language_id, version
                )))
            }
        }
    }

    #[test]
    fn get_language_description_known_version() {
        let service = MockVersionedLanguageService { known_version: 2 };
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(
            <MockVersionedLanguageService as VersionedLanguageService>::get_language_description(
                &service, &id, 2
            )
            .is_ok()
        );
    }

    #[test]
    fn get_language_unknown_version_errs() {
        let service = MockVersionedLanguageService { known_version: 2 };
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let err = <MockVersionedLanguageService as VersionedLanguageService>::get_language(
            &service, &id, 1,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("version 1"));
    }

    #[test]
    fn usable_as_trait_object() {
        let service: Box<dyn VersionedLanguageService> =
            Box::new(MockVersionedLanguageService { known_version: 1 });
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(VersionedLanguageService::get_language_description(&*service, &id, 1).is_ok());
    }
}
