use std::fmt;

/// Thrown when a connection attempt targets a repository that does not exist on the server.
///
/// A valid server connection is required before this determination can be made.
#[derive(Debug)]
pub struct RepositoryNotFoundException {
    message: String,
}

impl RepositoryNotFoundException {
    /// Construct with an error message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl fmt::Display for RepositoryNotFoundException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RepositoryNotFoundException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_new_message() {
        let e = RepositoryNotFoundException::new("repo not found");
        assert_eq!(e.to_string(), "repo not found");
    }

    #[test]
    fn test_debug() {
        let e = RepositoryNotFoundException::new("test");
        assert!(format!("{:?}", e).contains("RepositoryNotFoundException"));
    }

    #[test]
    fn test_implements_error() {
        let e = RepositoryNotFoundException::new("test");
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_source_is_none() {
        let e = RepositoryNotFoundException::new("test");
        assert!(e.source().is_none());
    }
}
