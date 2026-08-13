//! An extension point to dynamically support source language-specific spec extensions.
//!
//! Port of `ghidra.app.util.sourcelanguage.SourceLanguageSpecExtension`. The Java interface also
//! extends `ExtensionPoint`, a marker interface with no methods that exists solely to aid Ghidra's
//! classpath scanner; it has no Rust equivalent and is omitted.

use crate::app::seam_stubs::MessageLog;
use crate::app::util::sourcelanguage::source_language_id::SourceLanguageId;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// Processor-related attributes that form conditions for applying spec extension contents to a program.
///
/// Port of `SourceLanguageSpecExtension.SpecExtensionRule`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecExtensionRule {
    /// The name of the processor (required).
    pub processor: String,
    /// The processor endianness ("little" or "big"), or empty/None for wildcard.
    pub endian: Option<String>,
    /// The processor size (e.g., "32", "64"), or empty/None for wildcard.
    pub size: Option<String>,
    /// The processor variant, or empty/None for wildcard.
    pub variant: Option<String>,
    /// The names of the supported binary file formats, or empty/None for wildcard.
    pub formats: Option<Vec<String>>,
    /// The contents of the spec extension, which is currently always XML.
    pub contents: String,
}

impl SpecExtensionRule {
    /// Creates a new `SpecExtensionRule` with all required and optional attributes.
    pub fn new(
        processor: impl Into<String>,
        endian: Option<String>,
        size: Option<String>,
        variant: Option<String>,
        formats: Option<Vec<String>>,
        contents: impl Into<String>,
    ) -> Self {
        Self {
            processor: processor.into(),
            endian,
            size,
            variant,
            formats,
            contents: contents.into(),
        }
    }
}

/// An extension point to dynamically support source language-specific spec extensions.
///
/// Implementers provide a collection of [`SpecExtensionRule`]s that match processor attributes
/// and provide XML spec extension contents for a source language.
///
/// Port of `ghidra.app.util.sourcelanguage.SourceLanguageSpecExtension`.
pub trait SourceLanguageSpecExtension {
    /// Returns the [`SourceLanguageId`] of the source language this extension is compatible with.
    fn get_compatible_source_language(&self) -> Box<dyn SourceLanguageId>;

    /// Returns the source language's [`SpecExtensionRule`]s.
    ///
    /// # Arguments
    /// * `program` - The program being analyzed
    /// * `log` - Error log for recording issues during rule retrieval
    /// * `monitor` - Task monitor for cancellation and progress tracking
    ///
    /// # Returns
    /// A collection of spec extension rules applicable to the source language
    fn get_spec_extension_rules(
        &self,
        program: &dyn Program,
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Vec<SpecExtensionRule>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal mock implementation of SourceLanguageSpecExtension for testing.
    struct MockSourceLanguageSpecExtension {
        language_id: String,
        rules: Vec<SpecExtensionRule>,
    }

    impl SourceLanguageSpecExtension for MockSourceLanguageSpecExtension {
        fn get_compatible_source_language(&self) -> Box<dyn SourceLanguageId> {
            struct MockLanguageId(String);
            impl SourceLanguageId for MockLanguageId {
                fn get_id_as_string(&self) -> &str {
                    &self.0
                }
            }
            Box::new(MockLanguageId(self.language_id.clone()))
        }

        fn get_spec_extension_rules(
            &self,
            _program: &dyn Program,
            _log: &dyn MessageLog,
            _monitor: &dyn TaskMonitor,
        ) -> Vec<SpecExtensionRule> {
            self.rules.clone()
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    struct MockMessageLog;

    impl MessageLog for MockMessageLog {}

    #[test]
    fn spec_extension_rule_creation() {
        let rule = SpecExtensionRule::new(
            "x86",
            Some("little".to_string()),
            Some("64".to_string()),
            None,
            Some(vec!["ELF".to_string(), "PE".to_string()]),
            "<spec></spec>",
        );

        assert_eq!(rule.processor, "x86");
        assert_eq!(rule.endian, Some("little".to_string()));
        assert_eq!(rule.size, Some("64".to_string()));
        assert_eq!(rule.variant, None);
        assert_eq!(rule.formats, Some(vec!["ELF".to_string(), "PE".to_string()]));
        assert_eq!(rule.contents, "<spec></spec>");
    }

    #[test]
    fn spec_extension_rule_with_wildcards() {
        let rule = SpecExtensionRule::new("arm", None, None, None, None, "<spec></spec>");

        assert_eq!(rule.processor, "arm");
        assert!(rule.endian.is_none());
        assert!(rule.size.is_none());
        assert!(rule.variant.is_none());
        assert!(rule.formats.is_none());
    }

    #[test]
    fn source_language_spec_extension_is_object_safe() {
        let program = MockProgram;
        let log = MockMessageLog;
        let monitor = crate::util::task::DummyMonitor;

        let rule = SpecExtensionRule::new(
            "mips",
            Some("big".to_string()),
            Some("32".to_string()),
            None,
            None,
            "<cspec></cspec>",
        );

        let extension: Box<dyn SourceLanguageSpecExtension> =
            Box::new(MockSourceLanguageSpecExtension {
                language_id: "dwarf".to_string(),
                rules: vec![rule.clone()],
            });

        let lang_id = extension.get_compatible_source_language();
        assert_eq!(lang_id.get_id_as_string(), "dwarf");

        let retrieved_rules = extension.get_spec_extension_rules(&program, &log, &monitor);
        assert_eq!(retrieved_rules.len(), 1);
        assert_eq!(retrieved_rules[0], rule);
    }

    #[test]
    fn spec_extension_rule_equality() {
        let rule1 = SpecExtensionRule::new(
            "x86",
            Some("little".to_string()),
            Some("64".to_string()),
            None,
            None,
            "<spec></spec>",
        );

        let rule2 = SpecExtensionRule::new(
            "x86",
            Some("little".to_string()),
            Some("64".to_string()),
            None,
            None,
            "<spec></spec>",
        );

        assert_eq!(rule1, rule2);
    }
}
