/// Exception thrown when a SLEIGH file cannot be accessed due to being locked.
///
/// Mirrors `ghidra.app.plugin.processors.sleigh.SleighFileLockException`.
#[derive(Debug)]
pub struct SleighFileLockException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SleighFileLockException {
    /// Constructs a `SleighFileLockException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `SleighFileLockException` with the given detail message and a cause.
    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(cause)),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SleighFileLockException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SleighFileLockException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = SleighFileLockException::new("file is locked");
        assert_eq!(e.message(), "file is locked");
    }

    #[test]
    fn new_source_is_none() {
        let e = SleighFileLockException::new("lock error");
        assert!(e.source().is_none());
    }

    #[test]
    fn display_matches_message() {
        let e = SleighFileLockException::new("sleigh file locked");
        assert_eq!(e.to_string(), "sleigh file locked");
    }

    #[test]
    fn debug_is_implemented() {
        let e = SleighFileLockException::new("locked");
        assert!(format!("{:?}", e).contains("locked"));
    }

    #[test]
    fn implements_error_trait() {
        let e = SleighFileLockException::new("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let e = SleighFileLockException::with_cause("file locked", cause);
        assert_eq!(e.message(), "file locked");
    }

    #[test]
    fn with_cause_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "locked by process");
        let e = SleighFileLockException::with_cause("cannot acquire lock", cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "locked by process");
    }

    #[test]
    fn with_cause_display_matches_message_not_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "file locked");
        let e = SleighFileLockException::with_cause("sleigh file lock error", cause);
        assert_eq!(e.to_string(), "sleigh file lock error");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned lock message");
        let e = SleighFileLockException::new(msg);
        assert_eq!(e.message(), "owned lock message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = SleighFileLockException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}
