use crate::pcode::exec::pcode_arithmetic::Purpose;

/// Exception thrown when the emulator attempts to concretize an abstract value.
///
/// Port of `ghidra.pcode.exec.ConcretionError`.
///
/// The emulator or a client attempted to concretize an abstract value, but was unable to do so.
/// This error carries the reason why the concrete value was needed, which can help diagnose
/// issues in symbolic execution or other abstract value handling.
pub struct ConcretionError {
    message: String,
    purpose: Purpose,
}

impl ConcretionError {
    /// Create the exception with a message and the reason a concrete value was needed.
    ///
    /// Port of `ConcretionError(String, Purpose)`.
    pub fn new(message: impl Into<String>, purpose: Purpose) -> Self {
        Self {
            message: message.into(),
            purpose,
        }
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the reason why the emulator needed a concrete value.
    ///
    /// Port of `getPurpose()`.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl std::fmt::Debug for ConcretionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcretionError")
            .field("message", &self.message)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl std::fmt::Display for ConcretionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ConcretionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_message_and_purpose() {
        let err = ConcretionError::new("abstract value cannot be concretized", Purpose::Load);
        assert_eq!(err.message(), "abstract value cannot be concretized");
        assert_eq!(err.purpose(), Purpose::Load);
    }

    #[test]
    fn message_returns_the_message() {
        let err = ConcretionError::new("test error", Purpose::Branch);
        assert_eq!(err.message(), "test error");
    }

    #[test]
    fn purpose_returns_the_purpose() {
        let err = ConcretionError::new("msg", Purpose::Condition);
        assert_eq!(err.purpose(), Purpose::Condition);
    }

    #[test]
    fn display_matches_message() {
        let err = ConcretionError::new("concretion failed", Purpose::Store);
        assert_eq!(err.to_string(), "concretion failed");
    }

    #[test]
    fn debug_includes_message_and_purpose() {
        let err = ConcretionError::new("debug test", Purpose::Decode);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("debug test"));
        assert!(debug_str.contains("Decode"));
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let err = ConcretionError::new(msg, Purpose::Other);
        assert_eq!(err.message(), "owned message");
    }

    #[test]
    fn different_purposes_are_distinguishable() {
        let err1 = ConcretionError::new("msg", Purpose::Load);
        let err2 = ConcretionError::new("msg", Purpose::Store);
        assert_eq!(err1.purpose(), Purpose::Load);
        assert_eq!(err2.purpose(), Purpose::Store);
        assert_ne!(err1.purpose(), err2.purpose());
    }
}
