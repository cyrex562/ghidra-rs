use std::fmt;

/// General runtime error indicating a catastrophic failure that may affect the integrity
/// of a domain object (e.g. an I/O error during a transaction).
pub struct DomainObjectException {
    cause: Box<dyn std::error::Error + Send + Sync>,
}

impl DomainObjectException {
    /// Creates a new exception wrapping `cause`, which provides failure detail.
    pub fn new<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        DomainObjectException {
            cause: Box::new(cause),
        }
    }
}

impl fmt::Display for DomainObjectException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainObjectException caused by: {}", self.cause)
    }
}

impl fmt::Debug for DomainObjectException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainObjectException")
            .field("cause", &self.cause)
            .finish()
    }
}

impl std::error::Error for DomainObjectException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_display_includes_cause() {
        let cause = io::Error::new(io::ErrorKind::Other, "disk full");
        let ex = DomainObjectException::new(cause);
        assert!(ex.to_string().starts_with("DomainObjectException caused by: "));
        assert!(ex.to_string().contains("disk full"));
    }

    #[test]
    fn test_source_returns_inner_error() {
        let cause = io::Error::new(io::ErrorKind::Other, "bad read");
        let ex = DomainObjectException::new(cause);
        let src = std::error::Error::source(&ex).expect("source should be present");
        assert!(src.to_string().contains("bad read"));
    }

    #[test]
    fn test_error_chain_traversal() {
        let cause = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let ex = DomainObjectException::new(cause);
        let mut chain = std::iter::successors(
            Some(&ex as &dyn std::error::Error),
            |e| e.source(),
        );
        chain.next(); // DomainObjectException itself
        let inner = chain.next().expect("inner error should be reachable");
        assert!(inner.to_string().contains("access denied"));
    }

    #[test]
    fn test_debug_format() {
        let cause = io::Error::new(io::ErrorKind::Other, "oops");
        let ex = DomainObjectException::new(cause);
        let s = format!("{:?}", ex);
        assert!(s.contains("DomainObjectException"));
    }
}
