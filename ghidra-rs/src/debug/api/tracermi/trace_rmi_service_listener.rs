//! A listener for Trace RMI Service events.
//!
//! Corresponds to `ghidra.debug.api.tracermi.TraceRmiServiceListener`.

use std::net::SocketAddr;

use crate::debug::api::tracermi::{TraceRmiAcceptor, TraceRmiConnection};
use crate::debug::seam_stubs::Target;

/// The mechanism for creating a connection.
///
/// Mirrors `TraceRmiServiceListener.ConnectMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectMode {
    /// The connection was established via `TraceRmiService::connect`.
    Connect,
    /// The connection was established via `TraceRmiService::accept_one`.
    AcceptOne,
    /// The connection was established by the server. See `TraceRmiService::start_server`.
    Server,
}

/// A listener for Trace RMI Service events.
///
/// Corresponds to `ghidra.debug.api.tracermi.TraceRmiServiceListener`. Every method carries a
/// no-op default, mirroring the Java interface's default methods: implementors override only the
/// events they care about.
pub trait TraceRmiServiceListener {
    /// The server has been started on the given address.
    fn server_started(&self, _address: SocketAddr) {}

    /// The server has been stopped.
    fn server_stopped(&self) {}

    /// A new connection has been established.
    ///
    /// `acceptor` is the acceptor that created this connection, if established via
    /// `TraceRmiService::accept_one`.
    fn connected(
        &self,
        _connection: &dyn TraceRmiConnection,
        _mode: ConnectMode,
        _acceptor: &dyn TraceRmiAcceptor,
    ) {
    }

    /// A connection was lost or closed.
    fn disconnected(&self, _connection: &dyn TraceRmiConnection) {}

    /// The service is waiting for an inbound connection.
    ///
    /// The acceptor remains valid until one of three events occurs:
    /// [`connected`](Self::connected), [`accept_cancelled`](Self::accept_cancelled), or
    /// [`accept_failed`](Self::accept_failed).
    fn waiting_accept(&self, _acceptor: &dyn TraceRmiAcceptor) {}

    /// The client cancelled an inbound acceptor.
    fn accept_cancelled(&self, _acceptor: &dyn TraceRmiAcceptor) {}

    /// The service failed to complete an inbound connection.
    fn accept_failed(&self, _acceptor: &dyn TraceRmiAcceptor, _e: &dyn std::error::Error) {}

    /// A new target was created by a Trace RMI connection.
    ///
    /// The added benefit of this method compared to
    /// [`TargetPublicationListener`](crate::debug::api::target::TargetPublicationListener) is
    /// that it identifies *which connection*.
    fn target_published(&self, _connection: &dyn TraceRmiConnection, _target: &dyn Target) {}

    /// A transaction was opened for the given target.
    ///
    /// Note, this is different than listening for transactions on the `Trace` domain object,
    /// because this only includes those initiated *by the connection*.
    fn transaction_opened(&self, _connection: &dyn TraceRmiConnection, _target: &dyn Target) {}

    /// A transaction was closed for the given target.
    ///
    /// `aborted` should only be `true` in catastrophic cases.
    fn transaction_closed(
        &self,
        _connection: &dyn TraceRmiConnection,
        _target: &dyn Target,
        _aborted: bool,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::RemoteMethodRegistry;
    use crate::trace::model::trace::Trace;
    use crate::util::exception::TimeoutException;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// A `TraceRmiConnection` whose only exercised member is `description`: mirrors the
    /// `UnusedTrace` pattern used elsewhere in the crate.
    struct FakeConnection(&'static str);

    impl TraceRmiConnection for FakeConnection {
        fn description(&self) -> String {
            self.0.to_string()
        }
        fn remote_address(&self) -> SocketAddr {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn methods(&self) -> &dyn RemoteMethodRegistry {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn wait_for_trace(
            &self,
            _timeout_millis: u64,
        ) -> Result<Box<dyn Trace>, TimeoutException> {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn last_snapshot(&self, _trace: &dyn Trace) -> Option<i64> {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn force_close_trace(&mut self, _trace: &dyn Trace) {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn close(&mut self) -> io::Result<()> {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn is_closed(&self) -> bool {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn wait_closed(&self) {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn is_target(&self, _trace: &dyn Trace) -> bool {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn targets(&self) -> Vec<Box<dyn Target>> {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn is_busy(&self) -> bool {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn is_target_busy(&self, _target: &dyn Target) -> bool {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
        fn forcibly_close_transactions(&mut self, _target: &dyn Target) {
            unreachable!("not exercised by TraceRmiServiceListener smoke test")
        }
    }

    struct FakeAcceptor;
    impl TraceRmiAcceptor for FakeAcceptor {
        fn accept(&self) -> Result<Box<dyn TraceRmiConnection>, std::io::Error> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "not exercised"))
        }
        fn is_closed(&self) -> bool {
            false
        }
        fn address(&self) -> std::net::SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
        fn set_timeout(&self, _millis: i32) -> std::io::Result<()> {
            Ok(())
        }
        fn cancel(&self) {}
    }

    struct FakeTarget;
    impl Target for FakeTarget {}

    struct RecordingListener {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl TraceRmiServiceListener for RecordingListener {
        fn server_started(&self, address: SocketAddr) {
            self.events.lock().unwrap().push(format!("server_started({address})"));
        }
        fn server_stopped(&self) {
            self.events.lock().unwrap().push("server_stopped".to_string());
        }
        fn connected(
            &self,
            connection: &dyn TraceRmiConnection,
            mode: ConnectMode,
            _acceptor: &dyn TraceRmiAcceptor,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("connected({}, {:?})", connection.description(), mode));
        }
        fn disconnected(&self, connection: &dyn TraceRmiConnection) {
            self.events.lock().unwrap().push(format!("disconnected({})", connection.description()));
        }
        fn waiting_accept(&self, _acceptor: &dyn TraceRmiAcceptor) {
            self.events.lock().unwrap().push("waiting_accept".to_string());
        }
        fn accept_cancelled(&self, _acceptor: &dyn TraceRmiAcceptor) {
            self.events.lock().unwrap().push("accept_cancelled".to_string());
        }
        fn accept_failed(&self, _acceptor: &dyn TraceRmiAcceptor, e: &dyn std::error::Error) {
            self.events.lock().unwrap().push(format!("accept_failed({e})"));
        }
        fn target_published(&self, connection: &dyn TraceRmiConnection, _target: &dyn Target) {
            self.events
                .lock()
                .unwrap()
                .push(format!("target_published({})", connection.description()));
        }
        fn transaction_opened(&self, connection: &dyn TraceRmiConnection, _target: &dyn Target) {
            self.events
                .lock()
                .unwrap()
                .push(format!("transaction_opened({})", connection.description()));
        }
        fn transaction_closed(
            &self,
            connection: &dyn TraceRmiConnection,
            _target: &dyn Target,
            aborted: bool,
        ) {
            self.events.lock().unwrap().push(format!(
                "transaction_closed({}, aborted={})",
                connection.description(),
                aborted
            ));
        }
    }

    #[test]
    fn recording_listener_receives_dispatched_events_in_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = RecordingListener { events: events.clone() };
        let connection = FakeConnection("gdb @ localhost:12345");
        let acceptor = FakeAcceptor;
        let target = FakeTarget;
        let err = io::Error::new(io::ErrorKind::Other, "boom");

        listener.server_started("127.0.0.1:12345".parse().unwrap());
        listener.waiting_accept(&acceptor);
        listener.connected(&connection, ConnectMode::AcceptOne, &acceptor);
        listener.target_published(&connection, &target);
        listener.transaction_opened(&connection, &target);
        listener.transaction_closed(&connection, &target, true);
        listener.disconnected(&connection);
        listener.accept_cancelled(&acceptor);
        listener.accept_failed(&acceptor, &err);
        listener.server_stopped();

        let log = events.lock().unwrap();
        assert_eq!(
            *log,
            vec![
                "server_started(127.0.0.1:12345)".to_string(),
                "waiting_accept".to_string(),
                "connected(gdb @ localhost:12345, AcceptOne)".to_string(),
                "target_published(gdb @ localhost:12345)".to_string(),
                "transaction_opened(gdb @ localhost:12345)".to_string(),
                "transaction_closed(gdb @ localhost:12345, aborted=true)".to_string(),
                "disconnected(gdb @ localhost:12345)".to_string(),
                "accept_cancelled".to_string(),
                "accept_failed(boom)".to_string(),
                "server_stopped".to_string(),
            ]
        );
    }

    #[test]
    fn default_methods_are_no_ops() {
        struct NoOpListener;
        impl TraceRmiServiceListener for NoOpListener {}

        let listener = NoOpListener;
        let connection = FakeConnection("noop");
        let acceptor = FakeAcceptor;
        let target = FakeTarget;
        let err = io::Error::new(io::ErrorKind::Other, "boom");

        // Mirrors the empty bodies of the Java interface's default methods -- none of these
        // should panic.
        listener.server_started("127.0.0.1:0".parse().unwrap());
        listener.server_stopped();
        listener.connected(&connection, ConnectMode::Server, &acceptor);
        listener.disconnected(&connection);
        listener.waiting_accept(&acceptor);
        listener.accept_cancelled(&acceptor);
        listener.accept_failed(&acceptor, &err);
        listener.target_published(&connection, &target);
        listener.transaction_opened(&connection, &target);
        listener.transaction_closed(&connection, &target, false);
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        struct NoOpListener;
        impl TraceRmiServiceListener for NoOpListener {}

        let listener: Box<dyn TraceRmiServiceListener> = Box::new(NoOpListener);
        listener.server_stopped();
    }
}
