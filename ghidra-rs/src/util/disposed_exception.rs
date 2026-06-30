use std::fmt;
use std::sync::Arc;

use super::ArcError;

/// Error signaling that a resource has been disposed and can no longer be used.
///
/// Wraps the underlying reason for disposal as a chained error source so callers
/// can inspect the original cause via [`std::error::Error::source`].
///
/// Port of `ghidra.async.DisposedException`.
#[derive(Debug, Clone)]
pub struct DisposedException {
    reason: ArcError,
}

impl DisposedException {
    /// Creates a new `DisposedException` wrapping `reason` as the cause.
    pub fn new(reason: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            reason: Arc::new(reason),
        }
    }

    /// Creates a new `DisposedException` from a shared error reference.
    pub fn from_arc(reason: ArcError) -> Self {
        Self { reason }
    }

    /// Returns the underlying reason for disposal.
    pub fn reason(&self) -> &ArcError {
        &self.reason
    }
}

impl fmt::Display for DisposedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for DisposedException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.reason.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    fn io_err(msg: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::Other, msg)
    }

    #[test]
    fn display_shows_reason_message() {
        let e = DisposedException::new(io_err("object was closed"));
        assert_eq!(e.to_string(), "object was closed");
    }

    #[test]
    fn source_returns_wrapped_error() {
        let e = DisposedException::new(io_err("gone"));
        assert!(e.source().is_some());
        assert_eq!(e.source().unwrap().to_string(), "gone");
    }

    #[test]
    fn from_arc_wraps_shared_error() {
        let arc: ArcError = Arc::new(io_err("arc reason"));
        let e = DisposedException::from_arc(Arc::clone(&arc));
        assert_eq!(e.reason().to_string(), "arc reason");
        assert_eq!(e.to_string(), "arc reason");
    }

    #[test]
    fn clone_shares_reason() {
        let e = DisposedException::new(io_err("shared"));
        let e2 = e.clone();
        assert_eq!(e.to_string(), e2.to_string());
        assert!(e2.source().is_some());
    }

    #[test]
    fn reason_accessor_matches_display() {
        let e = DisposedException::new(io_err("test reason"));
        assert_eq!(e.reason().to_string(), e.to_string());
    }
}
