use std::error::Error;
use std::fmt;

/// Exception thrown for errors decoding decompiler objects from stream
#[derive(Debug)]
pub struct DecoderException {
    message: String,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl DecoderException {
    pub fn new(msg: &str) -> Self {
        Self {
            message: format!("Decoding error: {}", msg),
            source: None,
        }
    }

    pub fn with_cause<E: Error + Send + Sync + 'static>(msg: &str, cause: E) -> Self {
        Self {
            message: format!("Decoding error: {}", msg),
            source: Some(Box::new(cause)),
        }
    }
}

impl fmt::Display for DecoderException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for DecoderException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestCause;

    impl fmt::Display for TestCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "underlying cause")
        }
    }

    impl Error for TestCause {}

    #[test]
    fn test_decoder_exception_new() {
        let e = DecoderException::new("invalid format");
        assert_eq!(e.to_string(), "Decoding error: invalid format");
    }

    #[test]
    fn test_decoder_exception_with_cause() {
        let e = DecoderException::with_cause("parse failed", TestCause);
        assert_eq!(e.to_string(), "Decoding error: parse failed");
    }

    #[test]
    fn test_decoder_exception_with_cause_source() {
        let e = DecoderException::with_cause("parse failed", TestCause);
        let src = Error::source(&e).expect("should have a source");
        assert_eq!(src.to_string(), "underlying cause");
    }

    #[test]
    fn test_decoder_exception_no_source() {
        let e = DecoderException::new("no cause");
        assert!(Error::source(&e).is_none());
    }

    #[test]
    fn test_decoder_exception_empty_message() {
        let e = DecoderException::new("");
        assert_eq!(e.to_string(), "Decoding error: ");
    }
}
