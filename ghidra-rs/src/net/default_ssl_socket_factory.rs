//! Port of `ghidra.net.DefaultSSLSocketFactory`.
//!
//! Provides a replacement for the default `SSLSocketFactory` which utilizes the default
//! `SSLContext` established by [`DefaultSslContextInitializer`].
//!
//! # Deviation: no real TLS
//!
//! Java's class extends the JDK's abstract `javax.net.ssl.SSLSocketFactory` (itself extending
//! `javax.net.SocketFactory`), whose `createSocket` overloads produce genuine TLS-wrapped
//! sockets. This crate does not perform real TLS handshakes anywhere yet -- matching the
//! precedent already set by
//! [`GhidraSSLServerSocket`](crate::server::remote::ghidra_ssl_server_socket::GhidraSSLServerSocket)/
//! `SslSocket` on the server side and by
//! [`RemoteBlockStreamHandleBase::connect`](crate::server::stream::RemoteBlockStreamHandleBase::connect)
//! on the client side, both of which model "SSL sockets" as plain [`TcpStream`]s a caller may
//! layer real TLS onto later. [`SslSocketFactory`] below is this port's stand-in for the abstract
//! `SSLSocketFactory`/`SocketFactory` base (neither of which is ported elsewhere in this crate),
//! and [`PlainTcpSocketFactory`] is this port's stand-in for the JDK platform default
//! (`SSLSocketFactory.getDefault()`).

use std::io;
use std::net::{IpAddr, TcpStream};

/// A socket-creation abstraction mirroring the subset of `javax.net.ssl.SSLSocketFactory`'s
/// (itself extending `javax.net.SocketFactory`) surface that [`DefaultSSLSocketFactory`]
/// delegates to. See the module docs for why no real TLS handshake happens here.
pub trait SslSocketFactory: Send + Sync {
    /// Layers this factory's socket handling on top of an already-connected socket.
    ///
    /// Mirrors `createSocket(Socket s, String host, int port, boolean autoClose)`. `auto_close`
    /// mirrors the flag controlling whether the original socket should be closed once the
    /// returned one is; since no real TLS layer is added here (see the trait's own docs), this
    /// port has no need to actually branch on it, but it is still accepted for signature fidelity.
    fn create_socket_layered(
        &self,
        s: TcpStream,
        host: &str,
        port: u16,
        auto_close: bool,
    ) -> io::Result<TcpStream>;

    /// Mirrors `createSocket(String host, int port)`.
    fn create_socket(&self, host: &str, port: u16) -> io::Result<TcpStream>;

    /// Mirrors `createSocket(InetAddress host, int port)`.
    fn create_socket_addr(&self, host: IpAddr, port: u16) -> io::Result<TcpStream>;

    /// Mirrors `createSocket(String host, int port, InetAddress localHost, int localPort)`.
    ///
    /// `local_host`/`local_port` are accepted for signature fidelity but not honored: the Rust
    /// standard library has no safe API for binding a specific local endpoint before connecting
    /// (that would require the `socket2` crate or platform-specific raw socket options, neither
    /// of which this port introduces just for this parameter).
    fn create_socket_with_local(
        &self,
        host: &str,
        port: u16,
        local_host: IpAddr,
        local_port: u16,
    ) -> io::Result<TcpStream>;

    /// Mirrors `createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)`.
    ///
    /// See [`create_socket_with_local`](Self::create_socket_with_local)'s own docs on why
    /// `local_address`/`local_port` are accepted but not honored.
    fn create_socket_addr_with_local(
        &self,
        address: IpAddr,
        port: u16,
        local_address: IpAddr,
        local_port: u16,
    ) -> io::Result<TcpStream>;

    /// Mirrors `getDefaultCipherSuites()`.
    fn default_cipher_suites(&self) -> Vec<String>;

    /// Mirrors `getSupportedCipherSuites()`.
    fn supported_cipher_suites(&self) -> Vec<String>;
}

/// A plain-TCP [`SslSocketFactory`], standing in for the JDK platform default
/// (`SSLSocketFactory.getDefault()`). See the module docs for why no real TLS handshake happens.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlainTcpSocketFactory;

impl SslSocketFactory for PlainTcpSocketFactory {
    fn create_socket_layered(
        &self,
        s: TcpStream,
        _host: &str,
        _port: u16,
        _auto_close: bool,
    ) -> io::Result<TcpStream> {
        Ok(s)
    }

    fn create_socket(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect((host, port))
    }

    fn create_socket_addr(&self, host: IpAddr, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect((host, port))
    }

    fn create_socket_with_local(
        &self,
        host: &str,
        port: u16,
        _local_host: IpAddr,
        _local_port: u16,
    ) -> io::Result<TcpStream> {
        TcpStream::connect((host, port))
    }

    fn create_socket_addr_with_local(
        &self,
        address: IpAddr,
        port: u16,
        _local_address: IpAddr,
        _local_port: u16,
    ) -> io::Result<TcpStream> {
        TcpStream::connect((address, port))
    }

    fn default_cipher_suites(&self) -> Vec<String> {
        Vec::new()
    }

    fn supported_cipher_suites(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Provides a replacement for the default `SSLSocketFactory` which utilizes the default
/// `SSLContext` established by [`DefaultSslContextInitializer`].
///
/// Port of `ghidra.net.DefaultSSLSocketFactory`.
pub struct DefaultSSLSocketFactory {
    socket_factory: Box<dyn SslSocketFactory>,
}

impl std::fmt::Debug for DefaultSSLSocketFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultSSLSocketFactory").finish_non_exhaustive()
    }
}

impl DefaultSSLSocketFactory {
    /// `DefaultSSLSocketFactory` constructor. SSLContext initialization is performed using
    /// [`DefaultSslContextInitializer`].
    ///
    /// Port of `DefaultSSLSocketFactory()`:
    /// ```java
    /// SSLSocketFactory factory = null;
    /// try {
    ///     if (DefaultSSLContextInitializer.initialize()) {
    ///         factory = SSLContext.getDefault().getSocketFactory();
    ///     }
    /// }
    /// catch (NoSuchAlgorithmException e) {
    ///     Msg.error(this, "Failed to employ default SSLContext: " + e.toString(), e);
    /// }
    /// this.socketFactory = factory != null ? factory : (SSLSocketFactory) SSLSocketFactory.getDefault();
    /// ```
    ///
    /// Neither a process-global `SSLContext` singleton nor a way to derive a socket factory from
    /// one exists in this crate (see [`SslSocketFactory`]'s own docs on why this port performs no
    /// real TLS), so the two Java collaborators are supplied by the caller instead:
    /// * `initializer` stands in for the static `DefaultSSLContextInitializer.initialize()` call.
    /// * `context_socket_factory` stands in for `SSLContext.getDefault().getSocketFactory()`,
    ///   only invoked when `initializer.initialize()` succeeds, and itself allowed to fail
    ///   (returning `None`) the way Java's own `NoSuchAlgorithmException` catch could leave
    ///   `factory` as `null` even after a successful `initialize()`.
    /// * `fallback` stands in for the platform-default `(SSLSocketFactory)
    ///   SSLSocketFactory.getDefault()`, used whenever either of the above doesn't produce a
    ///   factory.
    pub fn new(
        initializer: &dyn crate::net::default_ssl_context_initializer::DefaultSslContextInitializer,
        context_socket_factory: impl FnOnce() -> Option<Box<dyn SslSocketFactory>>,
        fallback: Box<dyn SslSocketFactory>,
    ) -> Self {
        let factory = if initializer.initialize() { context_socket_factory() } else { None };
        Self { socket_factory: factory.unwrap_or(fallback) }
    }
}

impl SslSocketFactory for DefaultSSLSocketFactory {
    fn create_socket_layered(
        &self,
        s: TcpStream,
        host: &str,
        port: u16,
        auto_close: bool,
    ) -> io::Result<TcpStream> {
        self.socket_factory.create_socket_layered(s, host, port, auto_close)
    }

    fn create_socket(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        self.socket_factory.create_socket(host, port)
    }

    fn create_socket_addr(&self, host: IpAddr, port: u16) -> io::Result<TcpStream> {
        self.socket_factory.create_socket_addr(host, port)
    }

    fn create_socket_with_local(
        &self,
        host: &str,
        port: u16,
        local_host: IpAddr,
        local_port: u16,
    ) -> io::Result<TcpStream> {
        self.socket_factory.create_socket_with_local(host, port, local_host, local_port)
    }

    fn create_socket_addr_with_local(
        &self,
        address: IpAddr,
        port: u16,
        local_address: IpAddr,
        local_port: u16,
    ) -> io::Result<TcpStream> {
        self.socket_factory.create_socket_addr_with_local(address, port, local_address, local_port)
    }

    fn default_cipher_suites(&self) -> Vec<String> {
        self.socket_factory.default_cipher_suites()
    }

    fn supported_cipher_suites(&self) -> Vec<String> {
        self.socket_factory.supported_cipher_suites()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::default_ssl_context_initializer::DefaultSslContextInitializer;
    use crate::net::seam_stubs::{HttpClientsLike, KeyManagerFactoryLike, TrustManagerFactoryLike};
    use std::cell::Cell;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct MockKeyManagerFactory;
    impl KeyManagerFactoryLike for MockKeyManagerFactory {
        fn get_key_manager(&self) -> bool {
            true
        }
        fn invalidate_key_manager(&self) {}
    }

    #[derive(Default)]
    struct MockTrustManagerFactory;
    impl TrustManagerFactoryLike for MockTrustManagerFactory {
        fn get_trust_managers(&self) -> bool {
            true
        }
        fn invalidate_trust_managers(&self) {}
    }

    #[derive(Default)]
    struct MockHttpClients;
    impl HttpClientsLike for MockHttpClients {
        fn clear_http_client(&self) {}
    }

    /// A [`DefaultSslContextInitializer`] whose `initialize()` outcome is controlled directly by
    /// the test, standing in for the real Java bootstrap succeeding or failing.
    struct TestInitializer {
        key_manager_factory: MockKeyManagerFactory,
        trust_manager_factory: MockTrustManagerFactory,
        http_clients: MockHttpClients,
        should_initialize: Cell<bool>,
    }

    impl DefaultSslContextInitializer for TestInitializer {
        fn key_manager_factory(&self) -> &dyn KeyManagerFactoryLike {
            &self.key_manager_factory
        }
        fn trust_manager_factory(&self) -> &dyn TrustManagerFactoryLike {
            &self.trust_manager_factory
        }
        fn http_clients(&self) -> &dyn HttpClientsLike {
            &self.http_clients
        }
        fn has_cached_context(&self) -> bool {
            false
        }
        fn install_cached_context(&self) {}
        fn clear_cached_context(&self) {}
        fn build_and_install_context(&self) -> bool {
            self.should_initialize.get()
        }
    }

    fn initializer(succeeds: bool) -> TestInitializer {
        TestInitializer {
            key_manager_factory: MockKeyManagerFactory,
            trust_manager_factory: MockTrustManagerFactory,
            http_clients: MockHttpClients,
            should_initialize: Cell::new(succeeds),
        }
    }

    /// A no-op [`SslSocketFactory`] that just records which method was called, standing in for
    /// either the "context" factory or the "fallback" factory in tests.
    struct TaggedFactory {
        tag: &'static str,
        calls: std::sync::Arc<AtomicUsize>,
    }

    impl SslSocketFactory for TaggedFactory {
        fn create_socket_layered(
            &self,
            s: TcpStream,
            _host: &str,
            _port: u16,
            _auto_close: bool,
        ) -> io::Result<TcpStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(s)
        }
        fn create_socket(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TcpStream::connect((host, port))
        }
        fn create_socket_addr(&self, host: IpAddr, port: u16) -> io::Result<TcpStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TcpStream::connect((host, port))
        }
        fn create_socket_with_local(
            &self,
            host: &str,
            port: u16,
            _local_host: IpAddr,
            _local_port: u16,
        ) -> io::Result<TcpStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TcpStream::connect((host, port))
        }
        fn create_socket_addr_with_local(
            &self,
            address: IpAddr,
            port: u16,
            _local_address: IpAddr,
            _local_port: u16,
        ) -> io::Result<TcpStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TcpStream::connect((address, port))
        }
        fn default_cipher_suites(&self) -> Vec<String> {
            vec![self.tag.to_string()]
        }
        fn supported_cipher_suites(&self) -> Vec<String> {
            vec![self.tag.to_string()]
        }
    }

    #[test]
    fn uses_context_factory_when_initializer_succeeds_and_produces_one() {
        let init = initializer(true);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let context_calls = calls.clone();
        let factory = DefaultSSLSocketFactory::new(
            &init,
            move || Some(Box::new(TaggedFactory { tag: "context", calls: context_calls })),
            Box::new(TaggedFactory { tag: "fallback", calls: calls.clone() }),
        );
        assert_eq!(factory.default_cipher_suites(), vec!["context".to_string()]);
    }

    #[test]
    fn falls_back_when_initializer_fails() {
        let init = initializer(false);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let factory = DefaultSSLSocketFactory::new(
            &init,
            || panic!("context_socket_factory should not be invoked when initialize() fails"),
            Box::new(TaggedFactory { tag: "fallback", calls }),
        );
        assert_eq!(factory.default_cipher_suites(), vec!["fallback".to_string()]);
    }

    #[test]
    fn falls_back_when_initializer_succeeds_but_context_factory_still_unavailable() {
        // Mirrors Java's `NoSuchAlgorithmException` catch: `initialize()` can succeed while
        // obtaining the actual socket factory still fails, leaving `factory == null`.
        let init = initializer(true);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let factory = DefaultSSLSocketFactory::new(
            &init,
            || None,
            Box::new(TaggedFactory { tag: "fallback", calls }),
        );
        assert_eq!(factory.default_cipher_suites(), vec!["fallback".to_string()]);
    }

    #[test]
    fn create_socket_delegates_to_the_selected_factory_and_actually_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("get addr");
        let accept_thread = std::thread::spawn(move || listener.accept().expect("accept"));

        let init = initializer(false);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let factory = DefaultSSLSocketFactory::new(
            &init,
            || None,
            Box::new(TaggedFactory { tag: "fallback", calls: calls.clone() }),
        );

        let socket = factory.create_socket(&addr.ip().to_string(), addr.port()).expect("connect");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(socket.peer_addr().is_ok());

        accept_thread.join().expect("join accept thread");
    }

    #[test]
    fn create_socket_layered_returns_the_same_socket_since_no_real_tls_is_applied() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("get addr");
        let accept_thread = std::thread::spawn(move || listener.accept().expect("accept"));
        let raw = TcpStream::connect(addr).expect("connect");
        let raw_local_port = raw.local_addr().unwrap().port();

        let plain = PlainTcpSocketFactory;
        let layered = plain.create_socket_layered(raw, "127.0.0.1", addr.port(), false).unwrap();
        assert_eq!(layered.local_addr().unwrap().port(), raw_local_port);

        accept_thread.join().expect("join accept thread");
    }

    #[test]
    fn plain_tcp_socket_factory_reports_no_cipher_suites() {
        let plain = PlainTcpSocketFactory;
        assert!(plain.default_cipher_suites().is_empty());
        assert!(plain.supported_cipher_suites().is_empty());
    }

    #[test]
    fn usable_as_a_trait_object() {
        let init = initializer(false);
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let factory: Box<dyn SslSocketFactory> = Box::new(DefaultSSLSocketFactory::new(
            &init,
            || None,
            Box::new(TaggedFactory { tag: "fallback", calls }),
        ));
        assert_eq!(factory.supported_cipher_suites(), vec!["fallback".to_string()]);
    }
}
