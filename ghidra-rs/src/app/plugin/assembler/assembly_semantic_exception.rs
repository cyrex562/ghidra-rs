/// Exception thrown when all resolutions of an assembly instruction result in semantic errors.
///
/// For SLEIGH, semantic errors amount to incompatible contexts.
///
/// Mirrors `ghidra.app.plugin.assembler.AssemblySemanticException`.
#[derive(Debug)]
pub struct AssemblySemanticException {
    message: String,
    errors: Vec<Box<dyn super::sleigh::sem::AssemblyResolvedError>>,
}

impl AssemblySemanticException {
    /// Construct a semantic exception with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            errors: Vec::new(),
        }
    }

    /// Construct a semantic exception with the associated semantic errors.
    pub fn with_errors(
        errors: Vec<Box<dyn super::sleigh::sem::AssemblyResolvedError>>,
    ) -> Self {
        let message = errors
            .iter()
            .map(|e| e.get_error())
            .collect::<Vec<_>>()
            .join("\n");
        Self { message, errors }
    }

    /// Get the collection of associated semantic errors.
    pub fn get_errors(&self) -> &[Box<dyn super::sleigh::sem::AssemblyResolvedError>] {
        &self.errors
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for AssemblySemanticException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblySemanticException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::error::Error;

    struct MockResolvedError {
        error_msg: String,
    }

    impl std::fmt::Display for MockResolvedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.error_msg)
        }
    }

    impl std::fmt::Debug for MockResolvedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockResolvedError({})", self.error_msg)
        }
    }

    impl super::super::sleigh::sem::AssemblyResolution for MockResolvedError {
        fn get_description(&self) -> String {
            self.error_msg.clone()
        }

        fn get_children(&self) -> Vec<Box<dyn super::super::sleigh::sem::AssemblyResolution>> {
            vec![]
        }

        fn has_children(&self) -> bool {
            false
        }

        fn get_right(&self) -> Option<Box<dyn super::super::sleigh::sem::AssemblyResolution>> {
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

        fn shift(&self, _amt: i32) -> Box<dyn super::super::sleigh::sem::AssemblyResolution> {
            Box::new(MockResolvedError {
                error_msg: self.error_msg.clone(),
            })
        }

        fn parent(
            &self,
            description: &str,
            _op_count: i32,
        ) -> Box<dyn super::super::sleigh::sem::AssemblyResolution> {
            Box::new(MockResolvedError {
                error_msg: description.to_string(),
            })
        }

        fn collect_all_right(
            &self,
            _into: &mut Vec<Box<dyn super::super::sleigh::sem::AssemblyResolution>>,
        ) {
        }

        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.get_description())
        }

        fn compare_to(&self, other: &dyn super::super::sleigh::sem::AssemblyResolution) -> Ordering {
            self.get_description()
                .cmp(&other.get_description())
        }
    }

    impl super::super::sleigh::sem::AssemblyResolvedError for MockResolvedError {
        fn get_error(&self) -> String {
            self.error_msg.clone()
        }
    }

    #[test]
    fn new_stores_message() {
        let exc = AssemblySemanticException::new("test error");
        assert_eq!(exc.message(), "test error");
        assert!(exc.get_errors().is_empty());
    }

    #[test]
    fn new_accepts_owned_string() {
        let msg = String::from("owned message");
        let exc = AssemblySemanticException::new(msg);
        assert_eq!(exc.message(), "owned message");
    }

    #[test]
    fn display_matches_message() {
        let exc = AssemblySemanticException::new("display test");
        assert_eq!(exc.to_string(), "display test");
    }

    #[test]
    fn debug_contains_message() {
        let exc = AssemblySemanticException::new("debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn implements_error_trait() {
        let exc = AssemblySemanticException::new("error");
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn with_errors_joins_errors_with_newline() {
        let errors: Vec<Box<dyn super::super::sleigh::sem::AssemblyResolvedError>> = vec![
            Box::new(MockResolvedError {
                error_msg: "error 1".to_string(),
            }),
            Box::new(MockResolvedError {
                error_msg: "error 2".to_string(),
            }),
            Box::new(MockResolvedError {
                error_msg: "error 3".to_string(),
            }),
        ];
        let exc = AssemblySemanticException::with_errors(errors);
        assert_eq!(exc.message(), "error 1\nerror 2\nerror 3");
    }

    #[test]
    fn with_errors_stores_errors() {
        let errors: Vec<Box<dyn super::super::sleigh::sem::AssemblyResolvedError>> =
            vec![Box::new(MockResolvedError {
                error_msg: "test error".to_string(),
            })];
        let exc = AssemblySemanticException::with_errors(errors);
        assert_eq!(exc.get_errors().len(), 1);
        assert_eq!(exc.get_errors()[0].get_error(), "test error");
    }

    #[test]
    fn with_errors_empty_list() {
        let errors: Vec<Box<dyn super::super::sleigh::sem::AssemblyResolvedError>> = vec![];
        let exc = AssemblySemanticException::with_errors(errors);
        assert_eq!(exc.message(), "");
        assert!(exc.get_errors().is_empty());
    }

    #[test]
    fn with_errors_single_error() {
        let errors: Vec<Box<dyn super::super::sleigh::sem::AssemblyResolvedError>> =
            vec![Box::new(MockResolvedError {
                error_msg: "single error".to_string(),
            })];
        let exc = AssemblySemanticException::with_errors(errors);
        assert_eq!(exc.message(), "single error");
        assert_eq!(exc.get_errors().len(), 1);
    }

    #[test]
    fn source_is_none() {
        let exc = AssemblySemanticException::new("no cause");
        assert!(exc.source().is_none());
    }

    #[test]
    fn empty_message_is_valid() {
        let exc = AssemblySemanticException::new("");
        assert_eq!(exc.message(), "");
        assert_eq!(exc.to_string(), "");
    }
}
