//! Port of `ghidra.server.remote.ServerPortFactory`.

use std::sync::{Mutex, OnceLock};

use crate::framework::remote::{RmiServerPortFactory, DEFAULT_PORT};

/// Holds the process-wide [`RmiServerPortFactory`] this module hands ports out from.
///
/// Java models this as a mutable `static RMIServerPortFactory portFactory` field, reassigned
/// wholesale by [`ServerPortFactory::set_base_port`]. Per this crate's established convention for
/// singleton/global mutable Java state (see e.g.
/// [`ShutdownHookRegistry`](crate::framework::shutdown_hook_registry::ShutdownHookRegistry)), that
/// lives behind a `static` `OnceLock<Mutex<_>>` here rather than requiring `unsafe` mutable
/// statics.
static PORT_FACTORY: OnceLock<Mutex<RmiServerPortFactory>> = OnceLock::new();

fn port_factory() -> &'static Mutex<RmiServerPortFactory> {
    PORT_FACTORY.get_or_init(|| Mutex::new(RmiServerPortFactory::new(DEFAULT_PORT)))
}

/// Provides the base RMI-related ports used by the Ghidra Server.
///
/// Port of `ghidra.server.remote.ServerPortFactory`. Java gives this class a private constructor
/// (construction not permitted) and only `static` members; mirrored here as a unit struct whose
/// methods forward to the shared [`PORT_FACTORY`].
pub struct ServerPortFactory;

impl ServerPortFactory {
    /// Set the base port to be used by server.
    ///
    /// Port of the package-private `static void setBasePort(int)`. Java restricts this to the
    /// `ghidra.server.remote` package; this crate has no exact equivalent narrower than
    /// `pub(crate)`, which is used here to preserve "not part of the public API" intent.
    pub(crate) fn set_base_port(port: u16) {
        *port_factory().lock().unwrap() = RmiServerPortFactory::new(port);
    }

    /// Returns RMI Registry port.
    ///
    /// Port of `static int getRMIRegistryPort()`.
    pub fn get_rmi_registry_port() -> u16 {
        port_factory().lock().unwrap().rmi_registry_port()
    }

    /// Returns the SSL-protected RMI port.
    ///
    /// Port of `static int getRMISSLPort()`.
    pub fn get_rmi_ssl_port() -> u16 {
        port_factory().lock().unwrap().rmi_ssl_port()
    }

    /// Returns the SSL Stream port.
    ///
    /// Port of `static int getStreamPort()`.
    pub fn get_stream_port() -> u16 {
        port_factory().lock().unwrap().stream_port()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ServerPortFactory's backing state is process-global, so serialize the tests that touch it
    // to avoid interference between them.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn default_ports_are_derived_from_the_default_base_port() {
        let _guard = TEST_GUARD.lock().unwrap();
        ServerPortFactory::set_base_port(DEFAULT_PORT);

        assert_eq!(ServerPortFactory::get_rmi_registry_port(), DEFAULT_PORT);
        assert_eq!(ServerPortFactory::get_rmi_ssl_port(), DEFAULT_PORT + 1);
        assert_eq!(ServerPortFactory::get_stream_port(), DEFAULT_PORT + 2);
    }

    #[test]
    fn set_base_port_changes_all_three_derived_ports() {
        let _guard = TEST_GUARD.lock().unwrap();
        ServerPortFactory::set_base_port(20000);

        assert_eq!(ServerPortFactory::get_rmi_registry_port(), 20000);
        assert_eq!(ServerPortFactory::get_rmi_ssl_port(), 20001);
        assert_eq!(ServerPortFactory::get_stream_port(), 20002);

        // Restore the default so other tests in this process observe the documented default.
        ServerPortFactory::set_base_port(DEFAULT_PORT);
    }

    #[test]
    fn ports_are_distinct() {
        let _guard = TEST_GUARD.lock().unwrap();
        ServerPortFactory::set_base_port(9000);

        let ports = [
            ServerPortFactory::get_rmi_registry_port(),
            ServerPortFactory::get_rmi_ssl_port(),
            ServerPortFactory::get_stream_port(),
        ];
        let unique: std::collections::HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 3);

        ServerPortFactory::set_base_port(DEFAULT_PORT);
    }
}
