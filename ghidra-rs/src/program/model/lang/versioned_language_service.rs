use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::{LanguageDescription, LanguageNotFoundException, LanguageService};

/// Service that provides a `Language` given a name, and information about the language.
///
/// Port of `ghidra.program.model.lang.VersionedLanguageService`. The Java interface extends
/// `LanguageService`, which is ported here only as a minimal placeholder supertrait (see
/// `seam_stubs.rs`) until it is fully ported.
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

    struct MockLanguageDescription;
    impl LanguageDescription for MockLanguageDescription {}

    struct MockVersionedLanguageService {
        known_version: i32,
    }

    impl LanguageService for MockVersionedLanguageService {}

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
        assert!(service.get_language_description(&id, 2).is_ok());
    }

    #[test]
    fn get_language_unknown_version_errs() {
        let service = MockVersionedLanguageService { known_version: 2 };
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let err = service.get_language(&id, 1).unwrap_err();
        assert!(err.to_string().contains("version 1"));
    }

    #[test]
    fn usable_as_trait_object() {
        let service: Box<dyn VersionedLanguageService> =
            Box::new(MockVersionedLanguageService { known_version: 1 });
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        assert!(service.get_language_description(&id, 1).is_ok());
    }
}
