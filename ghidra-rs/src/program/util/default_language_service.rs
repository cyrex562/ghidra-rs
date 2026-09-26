//! Port of `ghidra.program.util.DefaultLanguageService`.
//!
//! In Java this is a concrete class implementing `LanguageService`, backed by a process-wide
//! singleton (`getLanguageService()`) that is seeded from `SleighLanguageProvider` on first
//! access. It was selected as a dependency-cycle cut-point, so its instance surface is promoted
//! to the [`DefaultLanguageService`] trait here, with
//! [`LanguageService`](crate::program::model::lang::language_service::LanguageService) as a
//! supertrait (the overridden `getLanguage`/`getDefaultLanguage`/`getLanguageDescription*`/
//! `getLanguageCompilerSpecPairs*` members already live there).
//!
//! Dropped entirely:
//! - The static singleton accessor `getLanguageService()` and the private constructors that seed
//!   it from `SleighLanguageProvider.getSleighLanguageProvider()`. Singleton lifecycle is not
//!   part of the instance contract this trait exists to describe, mirroring the scope decision
//!   already made for
//!   [`SleighLanguageProvider`](crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider).
//! - The private nested `LanguageInfo` bookkeeping class and the private `addLanguages` helper
//!   that populates it from a `LanguageProvider`: these are implementation details of the
//!   concrete Java class, not part of the abstract contract.
//!
//! Kept as trait methods (genuine additions over the `LanguageService` supertrait):
//! - [`get_external_language_descriptions`](DefaultLanguageService::get_external_language_descriptions),
//!   with a default implementation replicating the Java method's filtering logic (including the
//!   private `languageMatchesExternalProcessor` helper, inlined as the free function
//!   [`language_matches_external_processor`]).
//! - [`get_defined_external_tool_names`](DefaultLanguageService::get_defined_external_tool_names),
//!   ported from the `public static` Java method of the same name. Since the singleton is
//!   dropped, this becomes an instance method (called through `LanguageService`, which any
//!   `DefaultLanguageService` implementor already provides) rather than reaching for a global.

use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_service::LanguageService;

/// Default `LanguageService` used to gather up all the languages that were found during the
/// class search (search was for language providers).
///
/// Port of the instance contract of `ghidra.program.util.DefaultLanguageService` (see the module
/// docs for what is out of scope).
pub trait DefaultLanguageService: LanguageService {
    /// Returns external names for languages associated with other tools that match the given
    /// criteria. For example, x86 languages are usually referred to as "metapc" by IDA-PRO.
    ///
    /// A `None` criterion is a don't-care wildcard, except `external_processor_name`: when it is
    /// `None` every language matches on that criterion, but when it is `Some` a match also
    /// requires `external_tool` to be `Some` and to have a registered external name for that
    /// tool equal (case-insensitively) to `external_processor_name`.
    fn get_external_language_descriptions(
        &self,
        external_processor_name: Option<&str>,
        external_tool: Option<&str>,
        endianness: Option<Endian>,
        size: Option<i32>,
    ) -> Vec<Box<dyn LanguageDescription>> {
        self.get_language_descriptions(true)
            .into_iter()
            .filter(|description| {
                language_matches_external_processor(
                    description.as_ref(),
                    external_processor_name,
                    external_tool,
                )
            })
            .filter(|description| {
                endianness.map_or(true, |endian| endian == description.get_endian())
            })
            .filter(|description| size.map_or(true, |size| size == description.get_size()))
            .collect()
    }

    /// Returns external names for the specified language associated with other tools, or `None`
    /// if `language_id`/`tool` is empty or no matching, non-empty external-name list is found.
    fn get_defined_external_tool_names(
        &self,
        language_id: &str,
        tool: &str,
        include_deprecated: bool,
    ) -> Option<Vec<String>> {
        if language_id.is_empty() || tool.is_empty() {
            return None;
        }
        for description in self.get_language_descriptions(include_deprecated) {
            if language_id == description.get_language_id().get_id_as_string() {
                if let Some(external_names) = description.get_external_names(tool) {
                    return Some(external_names);
                }
            }
        }
        None
    }
}

/// Port of the private static helper `DefaultLanguageService.languageMatchesExternalProcessor`.
fn language_matches_external_processor(
    description: &dyn LanguageDescription,
    external_processor_name: Option<&str>,
    external_tool: Option<&str>,
) -> bool {
    let Some(external_processor_name) = external_processor_name else {
        return true;
    };
    let Some(external_tool) = external_tool else {
        return false;
    };
    let Some(ext_names) = description.get_external_names(external_tool) else {
        return false;
    };
    ext_names
        .iter()
        .any(|ext_name| external_processor_name.eq_ignore_ascii_case(ext_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::{
        ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
        LanguageNotFoundException, Processor,
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

    struct MockLanguageDescription {
        language_id: &'static str,
        endian: Endian,
        size: i32,
        external_names: Option<Vec<&'static str>>,
    }

    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new(self.language_id).unwrap()
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }

        fn get_endian(&self) -> Endian {
            self.endian
        }

        fn get_instruction_endian(&self) -> Endian {
            self.endian
        }

        fn get_size(&self) -> i32 {
            self.size
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
            format!("Mock {}", self.language_id)
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

        fn get_external_names(&self, external_tool: &str) -> Option<Vec<String>> {
            if external_tool == "IDA-PRO" {
                self.external_names
                    .as_ref()
                    .map(|names| names.iter().map(|n| n.to_string()).collect())
            } else {
                None
            }
        }
    }

    struct MockDefaultLanguageService {
        descriptions: Vec<MockLanguageDescription>,
    }

    impl LanguageService for MockDefaultLanguageService {
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
            Err(LanguageNotFoundException(format!(
                "No description for '{}'",
                language_id
            )))
        }

        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            self.descriptions
                .iter()
                .map(|d| {
                    Box::new(MockLanguageDescription {
                        language_id: d.language_id,
                        endian: d.endian,
                        size: d.size,
                        external_names: d.external_names.clone(),
                    }) as Box<dyn LanguageDescription>
                })
                .collect()
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

    impl DefaultLanguageService for MockDefaultLanguageService {}

    fn service() -> MockDefaultLanguageService {
        MockDefaultLanguageService {
            descriptions: vec![
                MockLanguageDescription {
                    language_id: "x86:LE:32:default",
                    endian: Endian::Little,
                    size: 32,
                    external_names: Some(vec!["metapc"]),
                },
                MockLanguageDescription {
                    language_id: "8051:BE:16:default",
                    endian: Endian::Big,
                    size: 16,
                    external_names: None,
                },
            ],
        }
    }

    #[test]
    fn get_external_language_descriptions_matches_case_insensitively() {
        let service = service();
        let matches = service.get_external_language_descriptions(
            Some("METAPC"),
            Some("IDA-PRO"),
            None,
            None,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].get_language_id(),
            LanguageID::new("x86:LE:32:default").unwrap()
        );
    }

    #[test]
    fn get_external_language_descriptions_requires_tool_when_name_given() {
        let service = service();
        let matches =
            service.get_external_language_descriptions(Some("metapc"), None, None, None);
        assert!(matches.is_empty());
    }

    #[test]
    fn get_external_language_descriptions_filters_by_endian_and_size() {
        let service = service();
        let matches = service.get_external_language_descriptions(
            None,
            None,
            Some(Endian::Big),
            Some(16),
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].get_language_id(),
            LanguageID::new("8051:BE:16:default").unwrap()
        );
    }

    #[test]
    fn get_defined_external_tool_names_known_language() {
        let service = service();
        let names =
            service.get_defined_external_tool_names("x86:LE:32:default", "IDA-PRO", true);
        assert_eq!(names, Some(vec!["metapc".to_string()]));
    }

    #[test]
    fn get_defined_external_tool_names_missing_returns_none() {
        let service = service();
        assert!(service
            .get_defined_external_tool_names("8051:BE:16:default", "IDA-PRO", true)
            .is_none());
        assert!(service
            .get_defined_external_tool_names("", "IDA-PRO", true)
            .is_none());
        assert!(service
            .get_defined_external_tool_names("x86:LE:32:default", "", true)
            .is_none());
    }

    #[test]
    fn usable_as_trait_object() {
        let boxed: Box<dyn DefaultLanguageService> = Box::new(service());
        assert_eq!(
            boxed
                .get_external_language_descriptions(None, None, None, None)
                .len(),
            2
        );
    }
}
