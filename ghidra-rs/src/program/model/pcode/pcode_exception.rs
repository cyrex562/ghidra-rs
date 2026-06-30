use std::error::Error;
use std::fmt;

/// Exception generated from problems with Pcode.
#[derive(Debug)]
pub struct PcodeException {
    message: String,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl PcodeException {
    pub fn new(msg: &str) -> Self {
        Self {
            message: format!("Pcode: {}", msg),
            source: None,
        }
    }

    pub fn with_cause<E: Error + Send + Sync + 'static>(msg: &str, cause: E) -> Self {
        Self {
            message: format!("Pcode: {}", msg),
            source: Some(Box::new(cause)),
        }
    }
}

impl fmt::Display for PcodeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for PcodeException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "test error")
        }
    }

    impl Error for TestError {}

    #[test]
    fn test_message_prefix() {
        let e = PcodeException::new("bad opcode");
        assert_eq!(e.to_string(), "Pcode: bad opcode");
    }

    #[test]
    fn test_no_source_by_default() {
        let e = PcodeException::new("oops");
        assert!(Error::source(&e).is_none());
    }

    #[test]
    fn test_with_cause_message() {
        let e = PcodeException::with_cause("decode failed", TestError);
        assert_eq!(e.to_string(), "Pcode: decode failed");
    }

    #[test]
    fn test_with_cause_source_present() {
        let e = PcodeException::with_cause("decode failed", TestError);
        let src = Error::source(&e).expect("should have a source");
        assert_eq!(src.to_string(), "test error");
    }

    #[test]
    fn test_empty_message() {
        let e = PcodeException::new("");
        assert_eq!(e.to_string(), "Pcode: ");
    }
}
