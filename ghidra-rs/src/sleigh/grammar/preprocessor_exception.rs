use thiserror::Error as ThisError;

/// Exception thrown when the Sleigh preprocessor encounters an error.
///
/// Mirrors `ghidra.sleigh.grammar.PreprocessorException`.
#[derive(Debug, ThisError)]
#[error("{message}")]
pub struct PreprocessorException {
    message: String,
}

impl PreprocessorException {
    /// Constructs a preprocessor exception with location and context information.
    ///
    /// Formats the message as: `{message} at {filename}:{lineno}({overall}): {line}`
    pub fn new(
        message: impl Into<String>,
        filename: impl Into<String>,
        lineno: i32,
        overall: i32,
        line: impl Into<String>,
    ) -> Self {
        let msg = message.into();
        let file = filename.into();
        let l = line.into();
        let formatted = format!(
            "{} at {}:{}({}): {}",
            msg, file, lineno, overall, l
        );
        Self {
            message: formatted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_message_with_location_info() {
        let exc = PreprocessorException::new(
            "undefined macro",
            "test.sleigh",
            42,
            100,
            "let x = UNDEFINED_MACRO",
        );
        assert_eq!(
            exc.to_string(),
            "undefined macro at test.sleigh:42(100): let x = UNDEFINED_MACRO"
        );
    }

    #[test]
    fn empty_strings_handled() {
        let exc = PreprocessorException::new("error", "", 1, 0, "");
        assert_eq!(exc.to_string(), "error at :1(0): ");
    }

    #[test]
    fn large_line_numbers() {
        let exc = PreprocessorException::new("problem", "file.sl", 999999, 1000000, "code");
        assert_eq!(
            exc.to_string(),
            "problem at file.sl:999999(1000000): code"
        );
    }

    #[test]
    fn debug_format() {
        let exc = PreprocessorException::new("test", "f.sl", 1, 2, "line");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("test at f.sl:1(2): line"));
    }
}
