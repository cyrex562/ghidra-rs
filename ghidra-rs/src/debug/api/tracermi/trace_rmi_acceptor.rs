//! An acceptor for accepting a single Trace RMI connection.
//!
//! Corresponds to `ghidra.debug.api.tracermi.TraceRmiAcceptor`.

use std::io;
use std::net::SocketAddr;

use crate::debug::api::tracermi::TraceRmiConnection;

/// An acceptor to receive a single Trace RMI connection from a back-end.
///
/// Corresponds to `ghidra.debug.api.tracermi.TraceRmiAcceptor`.
pub trait TraceRmiAcceptor {
    /// Accept a single connection.
    ///
    /// This acceptor is no longer valid after the connection is accepted. If accepting the
    /// connection fails, e.g., because of a timeout, this acceptor is no longer valid.
    ///
    /// Returns the connection, if successful. Errors may represent I/O errors or cancellation
    /// (when [`cancel`](Self::cancel) is called, usually from the user canceling).
    fn accept(&self) -> Result<Box<dyn TraceRmiConnection>, io::Error>;

    /// Check if the acceptor is actually still accepting.
    ///
    /// Returns `true` if not accepting anymore.
    fn is_closed(&self) -> bool;

    /// Get the address (and port) where the acceptor is listening.
    fn address(&self) -> SocketAddr;

    /// Set the timeout.
    ///
    /// `millis` is the number of milliseconds after which an [`accept`](Self::accept) will time
    /// out.
    fn set_timeout(&self, millis: i32) -> io::Result<()>;

    /// Cancel the connection.
    ///
    /// If a different thread has called [`accept`](Self::accept), it will fail with a
    /// cancellation error.
    fn cancel(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::RemoteMethodRegistry;
    use crate::trace::model::trace::Trace;
    use crate::util::exception::TimeoutException;
    use std::sync::Mutex;

    struct FakeConnection;

    impl TraceRmiConnection for FakeConnection {
        fn description(&self) -> String {
            "test connection".to_string()
        }

        fn remote_address(&self) -> SocketAddr {
            "127.0.0.1:12345".parse().unwrap()
        }

        fn methods(&self) -> &dyn RemoteMethodRegistry {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn wait_for_trace(
            &self,
            _timeout_millis: u64,
        ) -> Result<Box<dyn Trace>, TimeoutException> {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn last_snapshot(&self, _trace: &dyn Trace) -> Option<i64> {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn force_close_trace(&mut self, _trace: &dyn Trace) {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn close(&mut self) -> io::Result<()> {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn is_closed(&self) -> bool {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn wait_closed(&self) {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn is_target(&self, _trace: &dyn Trace) -> bool {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn targets(&self) -> Vec<Box<dyn crate::debug::seam_stubs::Target>> {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn is_busy(&self) -> bool {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn is_target_busy(&self, _target: &dyn crate::debug::seam_stubs::Target) -> bool {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }

        fn forcibly_close_transactions(&mut self, _target: &dyn crate::debug::seam_stubs::Target) {
            unimplemented!("not exercised by TraceRmiAcceptor smoke test")
        }
    }

    struct TestAcceptor {
        closed: Mutex<bool>,
        address: SocketAddr,
    }

    impl TestAcceptor {
        fn new() -> Self {
            Self {
                closed: Mutex::new(false),
                address: "127.0.0.1:54321".parse().unwrap(),
            }
        }
    }

    impl TraceRmiAcceptor for TestAcceptor {
        fn accept(&self) -> Result<Box<dyn TraceRmiConnection>, io::Error> {
            let mut closed = self.closed.lock().unwrap();
            if *closed {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "acceptor is closed",
                ));
            }
            *closed = true;
            Ok(Box::new(FakeConnection))
        }

        fn is_closed(&self) -> bool {
            *self.closed.lock().unwrap()
        }

        fn address(&self) -> SocketAddr {
            self.address
        }

        fn set_timeout(&self, _millis: i32) -> io::Result<()> {
            Ok(())
        }

        fn cancel(&self) {
            *self.closed.lock().unwrap() = true;
        }
    }

    #[test]
    fn acceptor_accepts_single_connection() {
        let acceptor = TestAcceptor::new();
        assert!(!acceptor.is_closed());

        let conn = acceptor.accept();
        assert!(conn.is_ok());
        assert!(acceptor.is_closed());

        // Second accept should fail
        let conn2 = acceptor.accept();
        assert!(conn2.is_err());
    }

    #[test]
    fn acceptor_address_matches_configured() {
        let acceptor = TestAcceptor::new();
        let addr = acceptor.address();
        assert_eq!(addr.port(), 54321);
    }

    #[test]
    fn acceptor_cancel_closes() {
        let acceptor = TestAcceptor::new();
        assert!(!acceptor.is_closed());

        acceptor.cancel();
        assert!(acceptor.is_closed());

        let conn = acceptor.accept();
        assert!(conn.is_err());
    }

    #[test]
    fn acceptor_set_timeout_succeeds() {
        let acceptor = TestAcceptor::new();
        let result = acceptor.set_timeout(5000);
        assert!(result.is_ok());
    }

    #[test]
    fn acceptor_implements_trait_object() {
        let acceptor: Box<dyn TraceRmiAcceptor> = Box::new(TestAcceptor::new());
        assert!(!acceptor.is_closed());
        acceptor.cancel();
        assert!(acceptor.is_closed());
    }
}
