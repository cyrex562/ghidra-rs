//! Port of `ghidra.program.model.lang.LanguageNotFoundException`.
//!
//! In Java this `extends IOException` and offers seven constructor overloads, each producing a
//! differently formatted message. Rust has no constructor overloading, so each Java constructor
//! becomes a distinctly named associated function below.
//!
//! A lightweight placeholder of the same name already exists at
//! [`crate::program::seam_stubs::LanguageNotFoundException`] (a bare `pub struct(pub String)`),
//! used across ~20 not-yet-fully-ported call sites (`LanguageService`, `LanguageProvider`,
//! `VersionedLanguageService`, various loaders, etc.) as the error type threaded through trait
//! signatures. Rewiring all of those call sites to this real type is out of scope for this port
//! (a much larger refactor spanning many unrelated files); this type stands alongside it as the
//! faithful, full-fidelity port, with a [`From`] impl below to bridge a seam-stub error into this
//! type where a caller already has one in hand (see
//! [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair),
//! which needs exactly this to report this real exception type from methods that call through
//! [`LanguageService`](crate::program::model::lang::language_service::LanguageService)).

use std::fmt;

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::Processor;

/// Exception thrown when the named language cannot be found.
///
/// Port of `ghidra.program.model.lang.LanguageNotFoundException`.
#[derive(Debug)]
pub struct LanguageNotFoundException {
    message: String,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LanguageNotFoundException {
    /// A newer version of the language is required.
    ///
    /// Port of `LanguageNotFoundException(LanguageID, int, int)`.
    pub fn for_version(language_id: &LanguageID, major_version: i32, minor_version: i32) -> Self {
        Self {
            message: format!(
                "Language version (V{}.{} or later) required for '{}'",
                major_version, minor_version, language_id
            ),
            cause: None,
        }
    }

    /// The language was not found.
    ///
    /// Port of `LanguageNotFoundException(LanguageID)`, which Java implements by delegating to
    /// the `(LanguageID, Throwable)` constructor with a `null` cause.
    pub fn for_language(language_id: &LanguageID) -> Self {
        Self { message: format!("Language not found for '{}'", language_id), cause: None }
    }

    /// The language was not found because of an underlying exception.
    ///
    /// Port of `LanguageNotFoundException(LanguageID, Throwable)`.
    pub fn for_language_with_cause(
        language_id: &LanguageID,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: format!("Language not found for '{}'", language_id),
            cause: Some(Box::new(cause)),
        }
    }

    /// A raw, caller-supplied message.
    ///
    /// Port of `LanguageNotFoundException(String)`.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: None }
    }

    /// Neither the language nor the compiler spec was found.
    ///
    /// Port of `LanguageNotFoundException(LanguageID, CompilerSpecID)`.
    pub fn for_language_and_compiler_spec(
        language_id: &LanguageID,
        compiler_spec_id: &CompilerSpecID,
    ) -> Self {
        Self {
            message: format!(
                "Language/Compiler Spec not found for '{}/{}'",
                language_id, compiler_spec_id
            ),
            cause: None,
        }
    }

    /// The language was not found, with an extra caller-supplied detail message appended.
    ///
    /// Port of `LanguageNotFoundException(LanguageID, String)`.
    pub fn for_language_with_detail(language_id: &LanguageID, msg: &str) -> Self {
        Self { message: format!("Language not found for '{}' {}", language_id, msg), cause: None }
    }

    /// No language was found for the given processor.
    ///
    /// Port of `LanguageNotFoundException(Processor)`.
    pub fn for_processor(processor: &dyn Processor) -> Self {
        Self { message: format!("Language not found for processor: {}", processor.name()), cause: None }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LanguageNotFoundException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LanguageNotFoundException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Bridges the pre-existing seam-stub placeholder (see the module docs) into this real type,
/// preserving its message and dropping the (never-populated) cause chain.
impl From<crate::program::seam_stubs::LanguageNotFoundException> for LanguageNotFoundException {
    fn from(e: crate::program::seam_stubs::LanguageNotFoundException) -> Self {
        Self::with_message(e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lang_id(s: &str) -> LanguageID {
        LanguageID::new(s).unwrap()
    }

    #[test]
    fn for_version_formats_message() {
        let e = LanguageNotFoundException::for_version(&lang_id("x86:LE:32:default"), 3, 1);
        assert_eq!(
            e.message(),
            "Language version (V3.1 or later) required for 'x86:LE:32:default'"
        );
    }

    #[test]
    fn for_language_formats_message() {
        let e = LanguageNotFoundException::for_language(&lang_id("x86:LE:32:default"));
        assert_eq!(e.message(), "Language not found for 'x86:LE:32:default'");
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn for_language_with_cause_formats_message_and_keeps_source() {
        let cause = LanguageNotFoundException::with_message("inner failure");
        let e = LanguageNotFoundException::for_language_with_cause(&lang_id("8051:BE:16:default"), cause);
        assert_eq!(e.message(), "Language not found for '8051:BE:16:default'");
        let source = std::error::Error::source(&e).expect("cause should be recorded");
        assert_eq!(source.to_string(), "inner failure");
    }

    #[test]
    fn with_message_uses_raw_message() {
        let e = LanguageNotFoundException::with_message("custom message");
        assert_eq!(e.message(), "custom message");
    }

    #[test]
    fn for_language_and_compiler_spec_formats_message() {
        let e = LanguageNotFoundException::for_language_and_compiler_spec(
            &lang_id("x86:LE:32:default"),
            &CompilerSpecID::new(Some("gcc")),
        );
        assert_eq!(e.message(), "Language/Compiler Spec not found for 'x86:LE:32:default/gcc'");
    }

    #[test]
    fn for_language_with_detail_formats_message() {
        let e = LanguageNotFoundException::for_language_with_detail(
            &lang_id("x86:LE:32:default"),
            "(deprecated)",
        );
        assert_eq!(e.message(), "Language not found for 'x86:LE:32:default' (deprecated)");
    }

    #[test]
    fn for_processor_formats_message() {
        struct MockProcessor;
        impl Processor for MockProcessor {
            fn name(&self) -> String {
                "x86".to_string()
            }
        }
        let e = LanguageNotFoundException::for_processor(&MockProcessor);
        assert_eq!(e.message(), "Language not found for processor: x86");
    }

    #[test]
    fn display_matches_message() {
        let e = LanguageNotFoundException::with_message("boom");
        assert_eq!(e.to_string(), "boom");
    }

    #[test]
    fn from_seam_stub_preserves_message() {
        let stub = crate::program::seam_stubs::LanguageNotFoundException("stub message".to_string());
        let real: LanguageNotFoundException = stub.into();
        assert_eq!(real.message(), "stub message");
    }
}
