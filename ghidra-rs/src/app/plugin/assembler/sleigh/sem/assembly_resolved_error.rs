/// Marker trait for error-typed assembly resolution records.
///
/// An implementing record represents a resolution step that encountered an error.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError`.
pub trait AssemblyResolvedError: super::AssemblyResolution {
    /// Human-readable error message for this record.
    fn get_error(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    struct TestError {
        error: String,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Error: {}", self.error)
        }
    }

    impl std::fmt::Debug for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestError({})", self.error)
        }
    }

    impl super::super::AssemblyResolution for TestError {
        fn get_description(&self) -> String {
            format!("Error: {}", self.error)
        }

        fn get_children(&self) -> Vec<Box<dyn super::super::AssemblyResolution>> {
            vec![]
        }

        fn has_children(&self) -> bool {
            false
        }

        fn get_right(&self) -> Option<Box<dyn super::super::AssemblyResolution>> {
            None
        }

        fn line_to_string(&self) -> String {
            self.get_description()
        }

        fn is_backfill(&self) -> bool {
            false
        }

        fn is_error(&self) -> bool {
            true
        }

        fn shift(&self, _amt: i32) -> Box<dyn super::super::AssemblyResolution> {
            Box::new(TestError { error: self.error.clone() })
        }

        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn super::super::AssemblyResolution> {
            Box::new(TestError { error: description.to_string() })
        }

        fn collect_all_right(&self, _into: &mut Vec<Box<dyn super::super::AssemblyResolution>>) {}

        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.get_description())
        }

        fn compare_to(&self, other: &dyn super::super::AssemblyResolution) -> Ordering {
            self.get_description().cmp(other.get_description().as_str())
        }
    }

    impl AssemblyResolvedError for TestError {
        fn get_error(&self) -> String {
            self.error.clone()
        }
    }

    #[test]
    fn get_error_returns_error_message() {
        let err = TestError { error: "bad opcode".to_string() };
        assert_eq!(err.get_error(), "bad opcode");
    }

    #[test]
    fn error_implements_assembly_resolution() {
        let err = TestError { error: "test error".to_string() };
        assert!(err.is_error());
        assert!(!err.is_backfill());
    }

    #[test]
    fn error_has_correct_description() {
        let err = TestError { error: "invalid register".to_string() };
        assert_eq!(err.get_description(), "Error: invalid register");
    }

    #[test]
    fn get_error_with_empty_string() {
        let err = TestError { error: String::new() };
        assert_eq!(err.get_error(), "");
    }

    #[test]
    fn get_error_with_multiword_message() {
        let err = TestError { error: "unknown instruction format".to_string() };
        assert_eq!(err.get_error(), "unknown instruction format");
    }

    #[test]
    fn error_trait_is_object_safe() {
        let err = TestError { error: "test".to_string() };
        let _: &dyn AssemblyResolvedError = &err;
    }
}
