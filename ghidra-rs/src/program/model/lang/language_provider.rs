use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// NOTE: ALL LanguageProvider CLASSES MUST END IN "LanguageProvider". If not,
/// the (Java) `ClassSearcher` will not find them; this naming convention is not enforced by
/// the Rust trait.
///
/// Service for providing languages.
///
/// Port of `ghidra.program.model.lang.LanguageProvider`. The Java `ExtensionPoint` marker
/// interface (used for classpath discovery) has no Rust equivalent and is dropped.
pub trait LanguageProvider {
    /// Returns the language with the given name or `None` if no language has that name.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if a language instantiation error occurred.
    fn get_language(
        &self,
        language_id: &LanguageID,
    ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
        self.get_language_with_monitor(language_id, &DummyMonitor)
    }

    /// Returns the language with the given name or `None` if no language has that name.
    ///
    /// # Errors
    /// Returns [`LanguageNotFoundException`] if a language instantiation error occurred.
    fn get_language_with_monitor(
        &self,
        language_id: &LanguageID,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException>;

    /// Returns a list of language descriptions provided by this provider.
    fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>>;

    /// Returns `true` if one or more languages or language descriptions failed to load
    /// properly.
    fn had_load_failure(&self) -> bool;

    /// Returns `true` if the given language has been successfully loaded.
    fn is_language_loaded(&self, language_id: &LanguageID) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProcessor;
    impl crate::program::seam_stubs::Processor for MockProcessor {}

    struct MockCompilerSpecDescription;
    impl crate::program::model::lang::compiler_spec_description::CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> crate::program::seam_stubs::CompilerSpecID {
            crate::program::seam_stubs::CompilerSpecID::new(Some("gcc"))
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
            compiler_spec_id: &crate::program::seam_stubs::CompilerSpecID,
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

    struct MockLanguageProvider {
        loaded: bool,
        had_failure: bool,
    }

    impl LanguageProvider for MockLanguageProvider {
        fn get_language_with_monitor(
            &self,
            language_id: &LanguageID,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
            if !self.loaded {
                return Err(LanguageNotFoundException(format!(
                    "Language not found for '{}'",
                    language_id
                )));
            }
            Ok(None)
        }

        fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>> {
            vec![Box::new(MockLanguageDescription)]
        }

        fn had_load_failure(&self) -> bool {
            self.had_failure
        }

        fn is_language_loaded(&self, _language_id: &LanguageID) -> bool {
            self.loaded
        }
    }

    #[test]
    fn default_get_language_delegates_to_monitor_variant() {
        let provider = MockLanguageProvider {
            loaded: true,
            had_failure: false,
        };
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let result = provider.get_language(&id);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn get_language_propagates_not_found_error() {
        let provider = MockLanguageProvider {
            loaded: false,
            had_failure: true,
        };
        let id = LanguageID::new("bogus:LE:32:default").unwrap();
        let err = provider.get_language(&id).unwrap_err();
        assert_eq!(err.to_string(), "Language not found for 'bogus:LE:32:default'");
    }

    #[test]
    fn usable_as_trait_object() {
        let provider: Box<dyn LanguageProvider> = Box::new(MockLanguageProvider {
            loaded: true,
            had_failure: false,
        });
        assert!(!provider.had_load_failure());
        assert_eq!(provider.get_language_descriptions().len(), 1);
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(provider.is_language_loaded(&id));
    }
}
