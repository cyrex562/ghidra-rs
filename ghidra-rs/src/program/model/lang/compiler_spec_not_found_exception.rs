use std::fmt;

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;

/// Error thrown when the named compiler spec cannot be found.
///
/// Port of `ghidra.program.model.lang.CompilerSpecNotFoundException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerSpecNotFoundException {
    message: String,
}

impl CompilerSpecNotFoundException {
    /// Constructs an exception for the given language/compiler spec pair.
    pub fn new(language_id: &LanguageID, compiler_spec_id: &CompilerSpecID) -> Self {
        Self {
            message: format!("Compiler Spec not found for '{}/{}'", language_id, compiler_spec_id),
        }
    }

    /// Constructs an exception recording a failure while reading the compiler spec's resource
    /// file.
    pub fn with_resource_read_error(
        language_id: &LanguageID,
        compiler_spec_id: &CompilerSpecID,
        resource_file_name: &str,
        cause: &dyn std::error::Error,
    ) -> Self {
        Self {
            message: format!(
                "Exception reading {}/{}({}): {}",
                language_id, compiler_spec_id, resource_file_name, cause
            ),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CompilerSpecNotFoundException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CompilerSpecNotFoundException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_message_with_language_and_compiler_spec() {
        let err = CompilerSpecNotFoundException::new(
            &LanguageID::new("x86:LE:32:default").unwrap(),
            &CompilerSpecID::new(Some("gcc")),
        );
        assert_eq!(
            err.message(),
            "Compiler Spec not found for 'x86:LE:32:default/gcc'"
        );
    }

    #[test]
    fn formats_message_with_resource_read_error() {
        let cause = CompilerSpecNotFoundException::new(
            &LanguageID::new("x86:LE:32:default").unwrap(),
            &CompilerSpecID::new(Some("gcc")),
        );
        let err = CompilerSpecNotFoundException::with_resource_read_error(
            &LanguageID::new("x86:LE:32:default").unwrap(),
            &CompilerSpecID::new(Some("visualstudio")),
            "x86.cspec",
            &cause,
        );
        assert_eq!(
            err.message(),
            "Exception reading x86:LE:32:default/visualstudio(x86.cspec): Compiler Spec not found for 'x86:LE:32:default/gcc'"
        );
    }
}
