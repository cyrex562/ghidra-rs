//! A service (both in the Ghidra framework sense, and in the network sense) for connecting
//! Trace RMI-based back-end debuggers.
//!
//! Port of `ghidra.app.services.TraceRmiService`. The Java `@ServiceInfo` annotation (default
//! provider `TraceRmiPlugin`) has no Rust equivalent and is omitted.
//!
//! This service connects to back-end debuggers, and/or allows back-end debuggers to connect to
//! it. Either way, Ghidra becomes the front-end, acting as the Trace RMI server, and the back-end
//! debugger acts as the Trace RMI client. The Ghidra front-end may also send control commands to
//! the back-end, e.g., to step, resume, or suspend the target.

use std::io;
use std::net::SocketAddr;

use crate::app::seam_stubs::{TraceRmiAcceptor, TraceRmiConnection, TraceRmiServiceListener};

/// A service (both in the Ghidra framework sense, and in the network sense) for connecting Trace
/// RMI-based back-end debuggers.
///
/// Port of `ghidra.app.services.TraceRmiService`.
pub trait TraceRmiService {
    /// Get the address (and port) of the Trace RMI TCP server.
    fn get_server_address(&self) -> Option<SocketAddr>;

    /// Set the address (and port) of the Trace RMI TCP server.
    ///
    /// `server_address` may be `None` to bind to an ephemeral port.
    fn set_server_address(&mut self, server_address: Option<SocketAddr>);

    /// Start the Trace RMI TCP server.
    fn start_server(&mut self) -> io::Result<()>;

    /// Stop the Trace RMI TCP server.
    fn stop_server(&mut self);

    /// Check if the service is listening for inbound connections (other than those expected by
    /// [`accept_one`](Self::accept_one)).
    fn is_server_started(&self) -> bool;

    /// Assuming a back-end debugger is listening, connect to it.
    fn connect(&self, address: SocketAddr) -> io::Result<Box<dyn TraceRmiConnection>>;

    /// Prepare to accept a single connection by listening on the given address.
    ///
    /// `address` may be `None` for an ephemeral port.
    fn accept_one(&self, address: Option<SocketAddr>) -> io::Result<Box<dyn TraceRmiAcceptor>>;

    /// Get all of the active connections.
    fn get_all_connections(&self) -> Vec<Box<dyn TraceRmiConnection>>;

    /// Get all of the acceptors currently listening for a connection.
    fn get_all_acceptors(&self) -> Vec<Box<dyn TraceRmiAcceptor>>;

    /// Add a listener for events on the Trace RMI service.
    fn add_trace_service_listener(&mut self, listener: Box<dyn TraceRmiServiceListener>);

    /// Remove a listener for events on the Trace RMI service.
    fn remove_trace_service_listener(&mut self, listener: &dyn TraceRmiServiceListener);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockConnection;
    impl TraceRmiConnection for MockConnection {}

    struct MockAcceptor;
    impl TraceRmiAcceptor for MockAcceptor {}

    struct MockListener;
    impl TraceRmiServiceListener for MockListener {}

    struct MockTraceRmiService {
        address: Option<SocketAddr>,
        started: bool,
    }

    impl TraceRmiService for MockTraceRmiService {
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

        fn connect(&self, _address: SocketAddr) -> io::Result<Box<dyn TraceRmiConnection>> {
            Ok(Box::new(MockConnection))
        }

        fn accept_one(
            &self,
            _address: Option<SocketAddr>,
        ) -> io::Result<Box<dyn TraceRmiAcceptor>> {
            Ok(Box::new(MockAcceptor))
        }

        fn get_all_connections(&self) -> Vec<Box<dyn TraceRmiConnection>> {
            Vec::new()
        }

        fn get_all_acceptors(&self) -> Vec<Box<dyn TraceRmiAcceptor>> {
            Vec::new()
        }

        fn add_trace_service_listener(&mut self, _listener: Box<dyn TraceRmiServiceListener>) {}

        fn remove_trace_service_listener(&mut self, _listener: &dyn TraceRmiServiceListener) {}
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn TraceRmiService> =
            Box::new(MockTraceRmiService { address: None, started: false });

        assert!(service.get_server_address().is_none());
        service.start_server().unwrap();
        assert!(service.is_server_started());

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        service.set_server_address(Some(addr));
        assert_eq!(service.get_server_address(), Some(addr));

        assert!(service.connect(addr).is_ok());
        assert!(service.accept_one(Some(addr)).is_ok());
        assert!(service.get_all_connections().is_empty());
        assert!(service.get_all_acceptors().is_empty());

        service.add_trace_service_listener(Box::new(MockListener));
        service.remove_trace_service_listener(&MockListener);

        service.stop_server();
        assert!(!service.is_server_started());
    }
}
