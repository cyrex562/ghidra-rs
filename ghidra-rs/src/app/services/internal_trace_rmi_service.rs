//! The same as [`TraceRmiService`], but grants access to the internal types (without casting)
//! to implementors of `ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion`.
//!
//! Port of `ghidra.app.services.InternalTraceRmiService`.

use std::io;
use std::net::SocketAddr;

use crate::app::seam_stubs::{DefaultTraceRmiAcceptor, TraceRmiHandler, TraceRmiService};

/// The same as [`TraceRmiService`], but grants access to the internal types (without casting)
/// to implementors of `TraceRmiLaunchOpinion`.
pub trait InternalTraceRmiService: TraceRmiService {
    /// Prepare to accept a single connection by listening on the given address.
    fn accept_one(&self, address: Option<SocketAddr>) -> io::Result<Box<dyn DefaultTraceRmiAcceptor>>;

    /// Assuming a back-end debugger is listening, connect to it.
    fn connect(&self, address: SocketAddr) -> io::Result<Box<dyn TraceRmiHandler>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAcceptor;
    impl DefaultTraceRmiAcceptor for MockAcceptor {}

    struct MockHandler;
    impl TraceRmiHandler for MockHandler {}

    struct MockInternalTraceRmiService;

    impl TraceRmiService for MockInternalTraceRmiService {}

    impl InternalTraceRmiService for MockInternalTraceRmiService {
        fn accept_one(
            &self,
            _address: Option<SocketAddr>,
        ) -> io::Result<Box<dyn DefaultTraceRmiAcceptor>> {
            Ok(Box::new(MockAcceptor))
        }

        fn connect(&self, _address: SocketAddr) -> io::Result<Box<dyn TraceRmiHandler>> {
            Ok(Box::new(MockHandler))
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn InternalTraceRmiService> = Box::new(MockInternalTraceRmiService);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(service.accept_one(Some(addr)).is_ok());
        assert!(service.accept_one(None).is_ok());
        assert!(service.connect(addr).is_ok());
    }
}
