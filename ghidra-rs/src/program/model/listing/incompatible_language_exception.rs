use std::fmt;

/// Exception thrown when attempting to replace one language in a program with another that
/// is not "address space" compatible.
#[derive(Debug, Clone)]
pub struct IncompatibleLanguageException {
    message: String,
}

impl IncompatibleLanguageException {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IncompatibleLanguageException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IncompatibleLanguageException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_stores_message() {
        let e = IncompatibleLanguageException::new("languages differ");
        assert_eq!(e.message(), "languages differ");
    }

    #[test]
    fn display_shows_message() {
        let e = IncompatibleLanguageException::new("bad lang");
        assert_eq!(e.to_string(), "bad lang");
    }

    #[test]
    fn implements_error_trait() {
        let e = IncompatibleLanguageException::new("x");
        let _: &dyn Error = &e;
    }

    #[test]
    fn empty_message() {
        let e = IncompatibleLanguageException::new("");
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn clone_is_independent() {
        let e = IncompatibleLanguageException::new("orig");
        let c = e.clone();
        assert_eq!(c.message(), "orig");
    }
}
