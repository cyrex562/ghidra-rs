use std::fmt;

/// Error raised when a required prelink section is absent from a Mach-O binary.
///
/// Mirrors `NoPreLinkSectionException` from the Java source: a checked exception
/// carrying a human-readable message that is propagated up to callers that parse
/// the prelink segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoPreLinkSectionException {
    message: String,
}

impl NoPreLinkSectionException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NoPreLinkSectionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NoPreLinkSectionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message() {
        let e = NoPreLinkSectionException::new("no prelink section found");
        assert_eq!(e.message(), "no prelink section found");
    }

    #[test]
    fn display_returns_message() {
        let e = NoPreLinkSectionException::new("missing __PRELINK_INFO");
        assert_eq!(e.to_string(), "missing __PRELINK_INFO");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = NoPreLinkSectionException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn implements_error_trait() {
        let e = NoPreLinkSectionException::new("err");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn equality() {
        let a = NoPreLinkSectionException::new("x");
        let b = NoPreLinkSectionException::new("x");
        let c = NoPreLinkSectionException::new("y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clone_is_independent() {
        let a = NoPreLinkSectionException::new("original");
        let b = a.clone();
        assert_eq!(a.message(), b.message());
    }

    #[test]
    fn usable_as_result_error() {
        fn may_fail(fail: bool) -> Result<(), NoPreLinkSectionException> {
            if fail {
                Err(NoPreLinkSectionException::new("section missing"))
            } else {
                Ok(())
            }
        }
        assert!(may_fail(false).is_ok());
        let err = may_fail(true).unwrap_err();
        assert_eq!(err.message(), "section missing");
    }
}
