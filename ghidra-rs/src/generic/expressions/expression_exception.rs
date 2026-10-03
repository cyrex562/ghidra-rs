use thiserror::Error;

/// Exception thrown when using an [`ExpressionEvaluator`](super::expression_evaluator::ExpressionEvaluator).
///
/// Port of `generic.expressions.ExpressionException`, a trivial single-field checked exception
/// (`extends Exception`, carrying only a message). Ported as a tuple struct, matching this
/// crate's established convention for such simple message-only exception types (e.g.
/// [`crate::util::exception::UsrException`]).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct ExpressionException(pub String);

impl ExpressionException {
    /// Constructs a new `ExpressionException` with the given message.
    ///
    /// Corresponds to `new ExpressionException(String message)` in Java.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = ExpressionException::new("bad expression");
        assert_eq!(e.to_string(), "bad expression");
        assert_eq!(e.0, "bad expression");
    }

    #[test]
    fn accepts_owned_or_borrowed_message() {
        let owned = ExpressionException::new(String::from("owned"));
        let borrowed = ExpressionException::new("owned");
        assert_eq!(owned, borrowed);
    }

    #[test]
    fn implements_std_error() {
        let e: &dyn std::error::Error = &ExpressionException::new("boom");
        assert_eq!(e.to_string(), "boom");
        assert!(e.source().is_none());
    }

    #[test]
    fn equality_and_clone() {
        let a = ExpressionException::new("x");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, ExpressionException::new("y"));
    }
}
