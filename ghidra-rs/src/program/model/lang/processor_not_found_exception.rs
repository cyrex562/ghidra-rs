use crate::util::exception::UsrException;
use std::fmt;

/// Error thrown when a processor cannot be found by name.
///
/// This mirrors Ghidra's `ProcessorNotFoundException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorNotFoundException {
    message: String,
}

impl ProcessorNotFoundException {
    /// Constructs a `ProcessorNotFoundException` for the named processor.
    ///
    /// The message format matches the Java source exactly.
    pub fn new(processor_name: impl AsRef<str>) -> Self {
        Self {
            message: format!(
                "Could not find processor {} (which was expected to already exist)",
                processor_name.as_ref()
            ),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProcessorNotFoundException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProcessorNotFoundException {}

impl From<ProcessorNotFoundException> for UsrException {
    fn from(value: ProcessorNotFoundException) -> Self {
        Self(value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_message_with_processor_name() {
        let err = ProcessorNotFoundException::new("x86");
        assert_eq!(
            err.message(),
            "Could not find processor x86 (which was expected to already exist)"
        );
    }

    #[test]
    fn display_matches_message() {
        let err = ProcessorNotFoundException::new("ARM");
        assert_eq!(
            err.to_string(),
            "Could not find processor ARM (which was expected to already exist)"
        );
    }

    #[test]
    fn different_processor_names_produce_different_messages() {
        let a = ProcessorNotFoundException::new("x86");
        let b = ProcessorNotFoundException::new("MIPS");
        assert_ne!(a, b);
    }

    #[test]
    fn converts_to_user_exception() {
        let err = ProcessorNotFoundException::new("SPARC");
        let usr: UsrException = err.into();
        assert_eq!(
            usr,
            UsrException(
                "Could not find processor SPARC (which was expected to already exist)".to_string()
            )
        );
    }
}
