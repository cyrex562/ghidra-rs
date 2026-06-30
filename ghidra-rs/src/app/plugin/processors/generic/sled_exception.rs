/// Exception generated from parsing SLED/SSL configuration files at load time.
///
/// Mirrors `ghidra.app.plugin.processors.generic.SledException`.
#[derive(Debug)]
pub struct SledException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SledException {
    /// Constructs a `SledException` with no detail message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            source: None,
        }
    }

    /// Constructs a `SledException` with the given detail message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a `SledException` wrapping another error, using its message.
    pub fn from_error(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            message: cause.to_string(),
            source: Some(Box::new(cause)),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for SledException {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SledException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SledException {
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
    fn new_has_empty_message() {
        let e = SledException::new();
        assert_eq!(e.message(), "");
    }

    #[test]
    fn default_equals_new() {
        let e = SledException::default();
        assert_eq!(e.message(), "");
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_stores_message() {
        let e = SledException::with_message("bad sled config");
        assert_eq!(e.message(), "bad sled config");
    }

    #[test]
    fn display_matches_message() {
        let e = SledException::with_message("parse error");
        assert_eq!(e.to_string(), "parse error");
    }

    #[test]
    fn debug_is_implemented() {
        let e = SledException::with_message("oops");
        assert!(format!("{:?}", e).contains("oops"));
    }

    #[test]
    fn implements_error_trait() {
        let e = SledException::with_message("err");
        let _: &dyn Error = &e;
    }

    #[test]
    fn new_source_is_none() {
        let e = SledException::new();
        assert!(e.source().is_none());
    }

    #[test]
    fn with_message_source_is_none() {
        let e = SledException::with_message("no cause");
        assert!(e.source().is_none());
    }

    #[test]
    fn from_error_uses_cause_message() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "sled parse failed");
        let e = SledException::from_error(cause);
        assert_eq!(e.message(), "sled parse failed");
    }

    #[test]
    fn from_error_exposes_source() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root");
        let e = SledException::from_error(cause);
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "root");
    }

    #[test]
    fn from_error_display_matches_cause() {
        let cause = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        let e = SledException::from_error(cause);
        assert_eq!(e.to_string(), "root cause");
    }

    #[test]
    fn accepts_owned_string() {
        let msg = String::from("owned message");
        let e = SledException::with_message(msg);
        assert_eq!(e.message(), "owned message");
    }

    #[test]
    fn empty_message_is_valid() {
        let e = SledException::with_message("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }
}
