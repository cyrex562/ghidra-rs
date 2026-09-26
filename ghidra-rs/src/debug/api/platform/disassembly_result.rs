/// Result of a disassembly operation.
///
/// Mirrors `ghidra.debug.api.platform.DisassemblyResult`.
///
/// `is_success` returns `true` whenever no error occurred (including when zero
/// instructions were disassembled — the "cancelled" case). Use `is_at_least_one`
/// to distinguish a fully-successful run from a zero-instruction run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblyResult {
    at_least_one: bool,
    error_message: Option<String>,
}

impl DisassemblyResult {
    /// Successful result: at least one instruction was disassembled.
    ///
    /// Mirrors the Java `SUCCESS` static constant.
    pub fn success_result() -> Self {
        Self { at_least_one: true, error_message: None }
    }

    /// Cancelled result: no instructions were disassembled, but no error occurred.
    ///
    /// Mirrors the Java `CANCELLED` static constant.
    pub fn cancelled_result() -> Self {
        Self { at_least_one: false, error_message: None }
    }

    /// Creates a failed result carrying the given error message.
    ///
    /// Mirrors `DisassemblyResult.failed(String errorMessage)`.
    pub fn failed(error_message: String) -> Self {
        Self { at_least_one: false, error_message: Some(error_message) }
    }

    /// Returns [`Self::success_result`] when `at_least_one` is `true`, otherwise
    /// [`Self::cancelled_result`].
    ///
    /// Mirrors `DisassemblyResult.success(boolean atLeastOne)`.
    pub fn success(at_least_one: bool) -> Self {
        if at_least_one { Self::success_result() } else { Self::cancelled_result() }
    }

    /// Returns `true` if at least one instruction was disassembled.
    pub fn is_at_least_one(&self) -> bool {
        self.at_least_one
    }

    /// Returns `true` when no error occurred (both success and cancelled qualify).
    pub fn is_success(&self) -> bool {
        self.error_message.is_none()
    }

    /// Returns the error message, or `None` if the result was not a failure.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_result_at_least_one_and_no_error() {
        let r = DisassemblyResult::success_result();
        assert!(r.is_at_least_one());
        assert!(r.is_success());
        assert_eq!(r.error_message(), None);
    }

    #[test]
    fn cancelled_result_not_at_least_one_but_is_success() {
        let r = DisassemblyResult::cancelled_result();
        assert!(!r.is_at_least_one());
        assert!(r.is_success());
        assert_eq!(r.error_message(), None);
    }

    #[test]
    fn failed_not_at_least_one_not_success_has_message() {
        let r = DisassemblyResult::failed("oops".to_owned());
        assert!(!r.is_at_least_one());
        assert!(!r.is_success());
        assert_eq!(r.error_message(), Some("oops"));
    }

    #[test]
    fn success_true_equals_success_result() {
        assert_eq!(DisassemblyResult::success(true), DisassemblyResult::success_result());
    }

    #[test]
    fn success_false_equals_cancelled_result() {
        assert_eq!(DisassemblyResult::success(false), DisassemblyResult::cancelled_result());
    }

    #[test]
    fn clone_preserves_fields() {
        let r = DisassemblyResult::failed("err".to_owned());
        let c = r.clone();
        assert_eq!(r, c);
    }

    #[test]
    fn debug_format_includes_struct_name() {
        let r = DisassemblyResult::success_result();
        let s = format!("{r:?}");
        assert!(s.contains("DisassemblyResult"));
    }
}
