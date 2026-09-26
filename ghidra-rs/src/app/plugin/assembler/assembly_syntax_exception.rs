use super::sleigh::parse::AssemblyParseResult;

/// Thrown when all parses of an assembly instruction result in syntax errors.
///
/// Port of `ghidra.app.plugin.assembler.AssemblySyntaxException`, which extends
/// `AssemblyException`. Follows the composition-over-inheritance convention already used by
/// [`AssemblySelectionError`](super::assembly_selection_error::AssemblySelectionError) (a
/// standalone struct plus a `From` conversion to the base exception) and the errors-payload
/// pattern used by
/// [`AssemblySemanticException`](super::assembly_semantic_exception::AssemblySemanticException)
/// (a `Vec` in place of Java's `Set`, since `AssemblyParseResult` trait objects have no `Hash`).
pub struct AssemblySyntaxException {
    message: String,
    /// Mirrors the `Set<AssemblyParseResult> errors` field, which the Java class only assigns
    /// in the errors-taking constructor — the message-only constructor leaves it `null`. This
    /// port mirrors that with `None`; see [`AssemblySyntaxException::get_errors`] for the
    /// consequence.
    errors: Option<Vec<Box<dyn AssemblyParseResult>>>,
}

impl std::fmt::Debug for AssemblySyntaxException {
    /// `AssemblyParseResult` (unlike its sibling `AssemblyResolvedError`, used by
    /// [`AssemblySemanticException`](super::assembly_semantic_exception::AssemblySemanticException))
    /// requires only `Display`, not `Debug`, so this is written by hand instead of derived.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssemblySyntaxException")
            .field("message", &self.message)
            .field("errors_len", &self.errors.as_ref().map(|e| e.len()))
            .finish()
    }
}

impl AssemblySyntaxException {
    /// Construct a syntax exception with just a message.
    ///
    /// Mirrors `AssemblySyntaxException(String)`. Note: the real Java constructor leaves the
    /// `errors` field `null` in this case; see [`AssemblySyntaxException::get_errors`].
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            errors: None,
        }
    }

    /// Construct a syntax exception with the associated syntax errors.
    ///
    /// Mirrors `AssemblySyntaxException(Set<AssemblyParseResult>)`, which builds the message via
    /// `StringUtils.join(errors, "\n")` (each element's `toString()`, joined by newline).
    pub fn with_errors(errors: Vec<Box<dyn AssemblyParseResult>>) -> Self {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        Self {
            message,
            errors: Some(errors),
        }
    }

    /// Mirrors the message inherited from `AssemblyException`/`Exception`.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the collection of associated syntax errors.
    ///
    /// Mirrors `getErrors()`, which returns `Collections.unmodifiableCollection(errors)`.
    ///
    /// # Panics
    ///
    /// Faithful reproduction of a genuine Java bug: `errors` is only assigned by
    /// [`AssemblySyntaxException::with_errors`] — an instance built via
    /// [`AssemblySyntaxException::new`] (the message-only constructor) leaves the real Java
    /// `errors` field `null`, so calling the real `getErrors()` on it throws a
    /// `NullPointerException` from `Collections.unmodifiableCollection(null)`. This port
    /// reproduces that by panicking in the same situation, rather than silently returning an
    /// empty collection.
    pub fn get_errors(&self) -> &[Box<dyn AssemblyParseResult>] {
        self.errors.as_deref().expect(
            "AssemblySyntaxException.getErrors(): errors is null — mirrors the real Java \
             NullPointerException thrown by Collections.unmodifiableCollection(null) when this \
             instance was built via the message-only constructor",
        )
    }
}

impl std::fmt::Display for AssemblySyntaxException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblySyntaxException {}

impl From<AssemblySyntaxException> for super::AssemblyException {
    fn from(err: AssemblySyntaxException) -> Self {
        super::AssemblyException::new(err.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    struct MockParseResult {
        text: String,
    }

    impl std::fmt::Display for MockParseResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl AssemblyParseResult for MockParseResult {
        fn is_error(&self) -> bool {
            true
        }
    }

    fn err(text: &str) -> Box<dyn AssemblyParseResult> {
        Box::new(MockParseResult {
            text: text.to_string(),
        })
    }

    #[test]
    fn new_stores_message() {
        let e = AssemblySyntaxException::new("bad syntax");
        assert_eq!(e.message(), "bad syntax");
    }

    #[test]
    fn display_matches_message() {
        let e = AssemblySyntaxException::new("invalid token");
        assert_eq!(e.to_string(), "invalid token");
    }

    #[test]
    fn implements_error_trait() {
        let e = AssemblySyntaxException::new("err");
        let _: &dyn Error = &e;
        assert!(e.source().is_none());
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = AssemblySyntaxException::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn with_errors_joins_via_display_with_newline() {
        let errors: Vec<Box<dyn AssemblyParseResult>> =
            vec![err("expected mnemonic"), err("unexpected operand")];
        let e = AssemblySyntaxException::with_errors(errors);
        assert_eq!(e.message(), "expected mnemonic\nunexpected operand");
        assert_eq!(e.to_string(), "expected mnemonic\nunexpected operand");
    }

    #[test]
    fn with_errors_stores_errors_for_get_errors() {
        let errors: Vec<Box<dyn AssemblyParseResult>> = vec![err("bad token")];
        let e = AssemblySyntaxException::with_errors(errors);
        assert_eq!(e.get_errors().len(), 1);
        assert_eq!(e.get_errors()[0].to_string(), "bad token");
    }

    #[test]
    fn with_errors_empty_set_produces_empty_message() {
        let e = AssemblySyntaxException::with_errors(Vec::new());
        assert_eq!(e.message(), "");
        assert!(e.get_errors().is_empty());
    }

    #[test]
    fn converts_to_assembly_exception() {
        let e = AssemblySyntaxException::new("wrapped message");
        let base: super::super::AssemblyException = e.into();
        assert_eq!(base.message(), "wrapped message");
    }

    /// Faithful reproduction of the Java bug documented on
    /// [`AssemblySyntaxException::get_errors`]: calling it on an instance built via the
    /// message-only constructor panics, exactly like the real `getErrors()` throwing a
    /// `NullPointerException` from `Collections.unmodifiableCollection(null)`. Uses
    /// `catch_unwind` scoped tightly around just the `get_errors()` call, per this repo's
    /// testing convention, rather than a loose `#[should_panic]` on a multi-step test.
    #[test]
    fn get_errors_panics_when_built_via_message_only_constructor() {
        let e = AssemblySyntaxException::new("no errors set");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.get_errors()));
        assert!(
            result.is_err(),
            "get_errors() should panic (mirroring Java's NullPointerException) when errors is null"
        );
    }

    #[test]
    fn get_errors_does_not_panic_when_built_via_with_errors() {
        let e = AssemblySyntaxException::with_errors(vec![err("fine")]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.get_errors()));
        assert!(result.is_ok());
    }
}
