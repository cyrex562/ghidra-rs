use std::fmt;

/// Error indicating that a trace has been closed and can no longer be accessed.
///
/// This is a specialized subtype of [`crate::framework::model::DomainObjectException`]
/// that signals the specific failure mode of attempting to access a closed trace.
///
/// Port of `ghidra.trace.model.TraceClosedException`.
pub struct TraceClosedException {
    cause: Box<dyn std::error::Error + Send + Sync>,
}

impl TraceClosedException {
    /// Creates a new exception wrapping `cause`.
    pub fn new<E: std::error::Error + Send + Sync + 'static>(cause: E) -> Self {
        TraceClosedException {
            cause: Box::new(cause),
        }
    }
}

impl fmt::Display for TraceClosedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceClosedException caused by: {}", self.cause)
    }
}

impl fmt::Debug for TraceClosedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceClosedException")
            .field("cause", &self.cause)
            .finish()
    }
}

impl std::error::Error for TraceClosedException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
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
    fn test_new_wraps_error() {
        let err = io_err("trace was closed");
        let exc = TraceClosedException::new(err);
        assert_eq!(exc.to_string(), "TraceClosedException caused by: trace was closed");
    }

    #[test]
    fn test_source_returns_inner_error() {
        let err = io_err("closed");
        let exc = TraceClosedException::new(err);
        let src = std::error::Error::source(&exc).expect("source should be present");
        assert!(src.to_string().contains("closed"));
    }

    #[test]
    fn test_debug_format() {
        let err = io_err("access denied");
        let exc = TraceClosedException::new(err);
        let s = format!("{:?}", exc);
        assert!(s.contains("TraceClosedException"));
    }

    #[test]
    fn test_error_chain_traversal() {
        let err = io_err("trace closed");
        let exc = TraceClosedException::new(err);
        let mut chain = std::iter::successors(
            Some(&exc as &dyn std::error::Error),
            |e| e.source(),
        );
        chain.next();
        let inner = chain.next().expect("inner error should be reachable");
        assert!(inner.to_string().contains("trace closed"));
    }
}
