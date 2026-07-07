use std::fmt;

/// Thrown when a method fails due to a locked domain object.
pub struct DomainObjectLockedException {
    message: String,
}

impl DomainObjectLockedException {
    /// Creates a new exception indicating the domain object is locked by `reason`.
    pub fn new(reason: &str) -> Self {
        DomainObjectLockedException {
            message: format!("Domain object is locked by {}", reason),
        }
    }
}

impl fmt::Display for DomainObjectLockedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Debug for DomainObjectLockedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainObjectLockedException")
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for DomainObjectLockedException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_format() {
        let ex = DomainObjectLockedException::new("user A");
        assert_eq!(ex.to_string(), "Domain object is locked by user A");
    }

    #[test]
    fn test_empty_reason() {
        let ex = DomainObjectLockedException::new("");
        assert_eq!(ex.to_string(), "Domain object is locked by ");
    }

    #[test]
    fn test_debug_format() {
        let ex = DomainObjectLockedException::new("some process");
        let s = format!("{:?}", ex);
        assert!(s.contains("DomainObjectLockedException"));
        assert!(s.contains("some process"));
    }

    #[test]
    fn test_is_error() {
        let ex = DomainObjectLockedException::new("X");
        let _: &dyn std::error::Error = &ex;
    }
}
