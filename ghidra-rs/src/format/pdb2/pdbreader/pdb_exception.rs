/// Error used when there is an error processing components of the PDB file.
///
/// This could mean that a data buffer is not long enough, an invalid or unrecognizable value
/// is seen, or values parsed do not correspond with other values.
#[derive(Debug)]
pub struct PdbException {
    message: String,
}

impl PdbException {
    /// Creates a new [`PdbException`] with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        PdbException { message: message.into() }
    }
}

impl std::fmt::Display for PdbException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PdbException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_preserved() {
        let e = PdbException::new("buffer too short");
        assert_eq!(e.to_string(), "buffer too short");
    }

    #[test]
    fn debug_contains_message() {
        let e = PdbException::new("bad value");
        assert!(format!("{e:?}").contains("bad value"));
    }

    #[test]
    fn implements_error_trait() {
        let e = PdbException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn empty_message() {
        let e = PdbException::new("");
        assert_eq!(e.to_string(), "");
    }
}
