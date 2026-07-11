//! The same as [`TraceRmiService`], but grants access to the internal types (without casting)
//! to implementors of `ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion`.
//!
//! Port of `ghidra.app.services.InternalTraceRmiService`.

use std::io;
use std::net::SocketAddr;

use crate::app::seam_stubs::{DefaultTraceRmiAcceptor, TraceRmiHandler};
use crate::app::services::trace_rmi_service::TraceRmiService;

/// The same as [`TraceRmiService`], but grants access to the internal types (without casting)
/// to implementors of `TraceRmiLaunchOpinion`.
///
/// `accept_one_internal`/`connect_internal` mirror the covariant-return overrides of
/// [`TraceRmiService::accept_one`]/[`TraceRmiService::connect`] in the Java interface (which both
/// name the method the same as the overridden one); they are renamed here since Rust does not
/// support covariant trait-method overrides, which would otherwise collide with the supertrait
/// methods of the same name.
pub trait InternalTraceRmiService: TraceRmiService {
    /// Prepare to accept a single connection by listening on the given address.
    fn accept_one_internal(
        &self,
        address: Option<SocketAddr>,
    ) -> io::Result<Box<dyn DefaultTraceRmiAcceptor>>;

    /// Assuming a back-end debugger is listening, connect to it.
    fn connect_internal(&self, address: SocketAddr) -> io::Result<Box<dyn TraceRmiHandler>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAcceptor;
    impl DefaultTraceRmiAcceptor for MockAcceptor {}

    struct MockHandler;
    impl TraceRmiHandler for MockHandler {}

    struct MockConnection;
    impl crate::app::seam_stubs::TraceRmiConnection for MockConnection {}

    struct MockAcceptorOpaque;
    impl crate::app::seam_stubs::TraceRmiAcceptor for MockAcceptorOpaque {}

    struct MockInternalTraceRmiService {
        address: Option<SocketAddr>,
        started: bool,
    }

    impl TraceRmiService for MockInternalTraceRmiService {
        fn get_server_address(&self) -> Option<SocketAddr> {
            self.address
        }

        fn set_server_address(&mut self, server_address: Option<SocketAddr>) {
            self.address = server_address;
        }

        fn start_server(&mut self) -> io::Result<()> {
            self.started = true;
            Ok(())
        }

        fn stop_server(&mut self) {
            self.started = false;
        }

        fn is_server_started(&self) -> bool {
            self.started
        }

        fn connect(
            &self,
            _address: SocketAddr,
        ) -> io::Result<Box<dyn crate::app::seam_stubs::TraceRmiConnection>> {
            Ok(Box::new(MockConnection))
        }

        fn accept_one(
            &self,
            _address: Option<SocketAddr>,
        ) -> io::Result<Box<dyn crate::app::seam_stubs::TraceRmiAcceptor>> {
            Ok(Box::new(MockAcceptorOpaque))
        }

        fn get_all_connections(&self) -> Vec<Box<dyn crate::app::seam_stubs::TraceRmiConnection>> {
            Vec::new()
        }

        fn get_all_acceptors(&self) -> Vec<Box<dyn crate::app::seam_stubs::TraceRmiAcceptor>> {
            Vec::new()
        }

        fn add_trace_service_listener(
            &mut self,
            _listener: Box<dyn crate::app::seam_stubs::TraceRmiServiceListener>,
        ) {
        }

        fn remove_trace_service_listener(
            &mut self,
            _listener: &dyn crate::app::seam_stubs::TraceRmiServiceListener,
        ) {
        }
    }

    impl InternalTraceRmiService for MockInternalTraceRmiService {
        fn accept_one_internal(
            &self,
            _address: Option<SocketAddr>,
        ) -> io::Result<Box<dyn DefaultTraceRmiAcceptor>> {
            Ok(Box::new(MockAcceptor))
        }

        fn connect_internal(&self, _address: SocketAddr) -> io::Result<Box<dyn TraceRmiHandler>> {
            Ok(Box::new(MockHandler))
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn InternalTraceRmiService> =
            Box::new(MockInternalTraceRmiService { address: None, started: false });

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(service.accept_one_internal(Some(addr)).is_ok());
        assert!(service.accept_one_internal(None).is_ok());
        assert!(service.connect_internal(addr).is_ok());
    }
}
