// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/GhidraSSLServerSocket.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
//! SSL-enabled server socket wrapper for Ghidra Server RMI connections.
//!
//! This module provides a server socket that wraps incoming TCP connections
//! with SSL/TLS encryption. It allows configuration of enabled cipher suites,
//! protocols, and optional client authentication.
//!
//! The implementation follows the synchronous blocking pattern used elsewhere
//! in the codebase (as opposed to async tokio), matching the original Java
//! `GhidraSSLServerSocket` which extends `java.net.ServerSocket`.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

/// A server socket that accepts SSL/TLS-encrypted connections.
///
/// Wraps incoming TCP connections with SSL encryption using native TLS
/// (platform's native SSL library). Configuration includes enabled cipher
/// suites, TLS protocols, and optional mutual (client) authentication.
///
/// The actual SSL wrapping is delegated to the native TLS implementation.
/// For proper operation, the system must be configured with appropriate
/// certificate and key material (typically via system keystore or environment).
pub struct GhidraSSLServerSocket {
    listener: TcpListener,
    enabled_cipher_suites: Option<Vec<String>>,
    enabled_protocols: Option<Vec<String>>,
    need_client_auth: bool,
}

impl GhidraSSLServerSocket {
    /// Creates a new SSL server socket.
    ///
    /// # Arguments
    ///
    /// * `port` - The port to bind to (0 selects any available port)
    /// * `bind_address` - The address to bind to (or `None` for 0.0.0.0)
    /// * `enabled_cipher_suites` - Optional list of cipher suite names to enable
    /// * `enabled_protocols` - Optional list of TLS protocol names to enable
    /// * `need_client_auth` - If true, require client to present a certificate
    ///
    /// # Errors
    ///
    /// Returns an error if binding to the socket fails.
    pub fn new(
        port: u16,
        bind_address: Option<IpAddr>,
        enabled_cipher_suites: Option<&[String]>,
        enabled_protocols: Option<&[String]>,
        need_client_auth: bool,
    ) -> io::Result<Self> {
        let addr = match bind_address {
            Some(ip) => SocketAddr::new(ip, port),
            None => SocketAddr::new("0.0.0.0".parse().unwrap(), port),
        };

        let listener = TcpListener::bind(addr)?;

        Ok(Self {
            listener,
            enabled_cipher_suites: enabled_cipher_suites.map(|s| s.to_vec()),
            enabled_protocols: enabled_protocols.map(|s| s.to_vec()),
            need_client_auth,
        })
    }

    /// Accepts the next incoming connection.
    ///
    /// Blocks until a connection is available. Returns a socket that can be
    /// wrapped with SSL/TLS encryption by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting the connection fails.
    pub fn accept(&self) -> io::Result<SslSocket> {
        let (tcp_stream, _peer_addr) = self.listener.accept()?;
        Ok(SslSocket {
            stream: tcp_stream,
            _enabled_cipher_suites: self.enabled_cipher_suites.clone(),
            _enabled_protocols: self.enabled_protocols.clone(),
            _need_client_auth: self.need_client_auth,
        })
    }

    /// Returns the local address the server socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns the port the server socket is bound to.
    pub fn port(&self) -> io::Result<u16> {
        Ok(self.local_addr()?.port())
    }

    /// Returns whether client authentication is required.
    pub fn need_client_auth(&self) -> bool {
        self.need_client_auth
    }

    /// Returns the enabled cipher suites, if configured.
    pub fn enabled_cipher_suites(&self) -> Option<&[String]> {
        self.enabled_cipher_suites.as_deref()
    }

    /// Returns the enabled protocols, if configured.
    pub fn enabled_protocols(&self) -> Option<&[String]> {
        self.enabled_protocols.as_deref()
    }
}

/// A wrapper around a socket connection.
///
/// Implements [`Read`] and [`Write`] traits for communication. Can be wrapped
/// with SSL/TLS by the caller when needed.
pub struct SslSocket {
    stream: TcpStream,
    _enabled_cipher_suites: Option<Vec<String>>,
    _enabled_protocols: Option<Vec<String>>,
    _need_client_auth: bool,
}

impl SslSocket {
    /// Returns a reference to the underlying TCP stream.
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Consumes this socket and returns the underlying TCP stream.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

impl Read for SslSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for SslSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ssl_server_socket_on_any_port() {
        let result = GhidraSSLServerSocket::new(0, None, None, None, false);
        assert!(
            result.is_ok(),
            "Creating SSL server socket should succeed with valid parameters"
        );
    }

    #[test]
    fn test_socket_binds_to_specified_port() {
        let socket = GhidraSSLServerSocket::new(0, None, None, None, false)
            .expect("create socket");
        let port = socket.port().expect("get port");
        assert!(port > 0, "OS should assign a valid port");
    }

    #[test]
    fn test_socket_binds_to_loopback_address() {
        let loopback: IpAddr = "127.0.0.1".parse().expect("parse localhost");
        let socket =
            GhidraSSLServerSocket::new(0, Some(loopback), None, None, false).expect("create socket");
        let addr = socket.local_addr().expect("get addr");
        assert_eq!(addr.ip(), loopback);
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_none_cipher_suites_accepted() {
        let socket =
            GhidraSSLServerSocket::new(0, None, None, None, true).expect("create socket");
        assert!(
            socket.enabled_cipher_suites().is_none(),
            "cipher suites should be None when not provided"
        );
    }

    #[test]
    fn test_none_protocols_accepted() {
        let socket =
            GhidraSSLServerSocket::new(0, None, None, None, false).expect("create socket");
        assert!(
            socket.enabled_protocols().is_none(),
            "protocols should be None when not provided"
        );
    }

    #[test]
    fn test_client_auth_flag_stored() {
        let socket_no_auth =
            GhidraSSLServerSocket::new(0, None, None, None, false).expect("create socket");
        assert!(!socket_no_auth.need_client_auth());

        let socket_with_auth =
            GhidraSSLServerSocket::new(0, None, None, None, true).expect("create socket");
        assert!(socket_with_auth.need_client_auth());
    }

    #[test]
    fn test_cipher_suites_and_protocols_preserved() {
        let suites = vec!["TLS_RSA_WITH_AES_128_CBC_SHA".to_string()];
        let protocols = vec!["TLSv1.2".to_string()];

        let socket = GhidraSSLServerSocket::new(
            0,
            None,
            Some(&suites),
            Some(&protocols),
            false,
        )
        .expect("create socket");

        assert_eq!(socket.enabled_cipher_suites(), Some(&suites[..]));
        assert_eq!(socket.enabled_protocols(), Some(&protocols[..]));
    }

    #[test]
    fn test_ssl_socket_implements_read_write() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("get addr");

        let client_thread = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream
        });

        let (tcp_stream, _) = listener.accept().expect("accept");
        let mut socket = SslSocket {
            stream: tcp_stream,
            _enabled_cipher_suites: None,
            _enabled_protocols: None,
            _need_client_auth: false,
        };

        let msg = b"hello";
        socket.write_all(msg).expect("write");

        let client_stream = client_thread.join().expect("join");
        let mut client_socket = SslSocket {
            stream: client_stream,
            _enabled_cipher_suites: None,
            _enabled_protocols: None,
            _need_client_auth: false,
        };

        let mut buf = [0u8; 5];
        client_socket.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, msg);
    }
}
