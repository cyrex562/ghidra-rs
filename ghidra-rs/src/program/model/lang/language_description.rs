use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::Processor;

/// Describes the basic characteristics of a
/// [`Language`](crate::program::model::lang::language::Language) -- its ID, processor,
/// endianness, size, version, and compatible compiler specs -- without requiring the full
/// language to be loaded.
///
/// Port of `ghidra.program.model.lang.LanguageDescription`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods; the placeholder's (empty) surface is retained here as part of the full trait, so
/// existing mock implementations continue to compile.
pub trait LanguageDescription {
    /// Returns the `LanguageID` for this language.
    fn get_language_id(&self) -> LanguageID;

    /// Returns the processor name on which this language is based.
    fn get_processor(&self) -> Box<dyn Processor>;

    /// Returns the endianness of data for this language.
    fn get_endian(&self) -> Endian;

    /// Returns the endianness with which instructions are encoded for this language. This may
    /// differ from [`LanguageDescription::get_endian`] for languages with bi-endian processors.
    fn get_instruction_endian(&self) -> Endian;

    /// Returns the size, in bits, of pointers/addresses for this language.
    fn get_size(&self) -> i32;

    /// Returns the variant name for this language.
    fn get_variant(&self) -> String;

    /// Returns the major version of this language.
    fn get_version(&self) -> i32;

    /// Returns the minor version of this language.
    fn get_minor_version(&self) -> i32;

    /// Returns a human readable description of this language.
    fn get_description(&self) -> String;

    /// Returns `true` if this language has been marked deprecated.
    fn is_deprecated(&self) -> bool;

    /// Returns all compiler spec descriptions compatible with this language.
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>>;

    /// Returns the compiler spec description matching `compiler_spec_id`.
    ///
    /// # Errors
    /// Returns [`CompilerSpecNotFoundException`] if no such compiler spec is compatible with
    /// this language.
    fn get_compiler_spec_description_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException>;

    /// Returns external names for this language associated with other tools. For example, x86
    /// languages are usually referred to as "metapc" by IDA-PRO, so
    /// `get_external_names("IDA-PRO")` returns "metapc" for most x86 languages. Returns `None`
    /// if there are no results.
    fn get_external_names(&self, external_tool: &str) -> Option<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
            if compiler_spec_id == &CompilerSpecID::new(Some("gcc")) {
                Ok(Box::new(MockCompilerSpecDescription))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
            }
        }

        fn get_external_names(&self, external_tool: &str) -> Option<Vec<String>> {
            if external_tool == "IDA-PRO" {
                Some(vec!["metapc".to_string()])
            } else {
                None
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let description: Box<dyn LanguageDescription> = Box::new(MockLanguageDescription);

        assert_eq!(description.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(description.get_endian(), Endian::Little);
        assert_eq!(description.get_size(), 32);
        assert!(!description.is_deprecated());
        assert_eq!(description.get_compatible_compiler_spec_descriptions().len(), 1);
        assert!(description
            .get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("gcc")))
            .is_ok());
        assert!(description
            .get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("visualstudio")))
            .is_err());
        assert_eq!(
            description.get_external_names("IDA-PRO"),
            Some(vec!["metapc".to_string()])
        );
        assert_eq!(description.get_external_names("other"), None);
    }
}
