//! An exception thrown when a p-code userop turns up missing.
//!
//! Corresponds to `ghidra.pcode.exec.SleighLinkException`.
//!
//! Java's class extends `RuntimeException` directly (not `PcodeExecutionException`): it is thrown
//! by [`PcodeExecutor::execute_callother`](crate::pcode::exec::pcode_executor::PcodeExecutor::execute_callother)
//! when a `CALLOTHER` op names a userop the library does not define, and it carries no cause or
//! frame -- just a message.
//!
//! # Divergence from Java
//!
//! [`PcodeExecutor::execute_callother`](crate::pcode::exec::pcode_executor::PcodeExecutor::execute_callother)
//! does not (yet) construct this type on a missing userop -- it reports the same message text
//! through a `LowlevelError` instead, per that method's own doc comment. This type exists as a
//! faithful, standalone port so callers that want the real exception shape can use it; wiring it
//! into the executor's error path is left for whoever unifies the executor's error types.

/// An exception thrown when a p-code userop turns up missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleighLinkException {
    message: String,
}

impl SleighLinkException {
    /// Construct the exception with the given message.
    ///
    /// Port of `SleighLinkException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SleighLinkException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SleighLinkException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_returns_the_message() {
        let e = SleighLinkException::new("Sleigh userop '__foo' is not in the library Bar");
        assert_eq!(e.message(), "Sleigh userop '__foo' is not in the library Bar");
    }

    #[test]
    fn display_matches_message() {
        let e = SleighLinkException::new("missing userop");
        assert_eq!(e.to_string(), "missing userop");
    }

    #[test]
    fn implements_error_trait_with_no_source() {
        let e = SleighLinkException::new("oops");
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned");
        let e = SleighLinkException::new(msg);
        assert_eq!(e.message(), "owned");
    }

    #[test]
    fn equality_compares_message() {
        assert_eq!(SleighLinkException::new("a"), SleighLinkException::new("a"));
        assert_ne!(SleighLinkException::new("a"), SleighLinkException::new("b"));
    }
}
