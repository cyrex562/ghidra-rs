// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/stream/RemoteBlockStreamHandle.java
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
//! Provides a serializable handle to a remote block stream. The handle is always instantiated by
//! the server side and passed to the client via remote serialization.
//!
//! A single instance is used to serve both client and server roles at both ends of the
//! connection. The client side invokes [`RemoteBlockStreamHandleBase::connect`], which establishes
//! a connection to the remote server identified by the stream-server information. The stream ID
//! and authentication token are passed to the server to facilitate proper association with the
//! correct block stream.
//!
//! On the server side, when this handle is instantiated it should be registered with the
//! [`BlockStreamServer`] together with the associated block stream (see
//! [`BlockStreamServer::register_block_stream`]). It is the job of this handle and the server to
//! associate an accepted connection with the appropriate block stream.
//!
//! # Shape
//!
//! Java's `RemoteBlockStreamHandle<T extends BlockStream>` is an abstract, generic,
//! `Serializable` class with a single abstract method, `serveBlockStream(Socket, BlockStream)`.
//! Per this crate's composition-over-inheritance convention, [`RemoteBlockStreamHandleBase`] holds
//! every field the Java class declares and every method with a concrete body; the
//! [`RemoteBlockStreamHandle`] trait requires an implementer to expose that base (via
//! [`base`](RemoteBlockStreamHandle::base)) and to supply
//! [`serve_block_stream`](RemoteBlockStreamHandle::serve_block_stream), providing the base's
//! concrete methods as defaults built on top. Java's `T extends BlockStream` type parameter is
//! dropped: nothing in the class besides `serveBlockStream`'s parameter type depends on it, so
//! [`serve_block_stream`] is typed directly over `Box<dyn BlockStream>`.
//!
//! # Deviation: no real TLS
//!
//! Java's [`connect`](RemoteBlockStreamHandleBase::connect) uses
//! `javax.net.ssl.SSLSocketFactory.getDefault()` to establish an encrypted connection to the
//! stream server. This crate does not perform real TLS handshakes anywhere yet -- matching the
//! precedent already set by
//! [`GhidraSSLServerSocket`](crate::server::remote::ghidra_ssl_server_socket::GhidraSSLServerSocket)/
//! `SslSocket` on the server side, which likewise model "SSL sockets" as plain `TcpStream`s a
//! caller may layer real TLS onto later -- so this port uses [`std::net::TcpStream`] directly for
//! every socket it creates or accepts. The wire protocol itself (the fixed-width header/terminator
//! framing) is reproduced exactly.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use crate::framework::db::buffers::BlockStream;
use crate::generic::random::secure_random_factory::SecureRandomFactory;
use crate::server::seam_stubs::RemoteBlockStreamHandleLike;
use crate::server::stream::block_stream_server::BlockStreamServer;
use crate::util::string_utilities::StringUtilities;

/// System property controlling whether serialized `DataBuffer`s use compressed output.
///
/// Mirrors `db.buffers.DataBuffer.COMPRESSED_SERIAL_OUTPUT_PROPERTY`.
const COMPRESSED_SERIAL_OUTPUT_PROPERTY: &str = "db.buffers.DataBuffer.compressedOutput";

/// Mirrors `RemoteBlockStreamHandle.enableCompressedSerializationOutput`'s static initializer:
/// `Boolean.parseBoolean(System.getProperty(DataBuffer.COMPRESSED_SERIAL_OUTPUT_PROPERTY,
/// "false"))`.
///
/// Note the default here (`"false"`) differs from `DataBuffer`'s own static initializer for the
/// *same* property (which defaults to `"true"`) -- a real quirk of the two classes reading the
/// same property with different fallbacks, preserved as-is rather than unified.
///
/// `Boolean.parseBoolean` never throws: any value other than a case-insensitive `"true"` is
/// treated as `false`, mirrored here via [`str::eq_ignore_ascii_case`] rather than [`str::parse`]
/// (which would error on anything but exactly `"true"`/`"false"`).
pub fn enable_compressed_serialization_output() -> bool {
    std::env::var(COMPRESSED_SERIAL_OUTPUT_PROPERTY)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub const HEADER_PREFIX: &str = "@stream:";
pub const HEADER_SUFFIX: &str = "@";
pub const HEADER_LENGTH: usize = HEADER_PREFIX.len() + 16 + 16 + HEADER_SUFFIX.len();

pub const TERM_PREFIX: &str = "@end:";
pub const TERM_SUFFIX: &str = "@";
pub const TERM_LENGTH: usize = TERM_PREFIX.len() + 16 + TERM_SUFFIX.len();

/// Wraps the stream-request registration data parsed from a connection header.
///
/// Port of the nested `RemoteBlockStreamHandle.StreamRequest`. Java's class (and the static method
/// that produces it) are package-private; kept `pub` here since Rust has no package-private
/// visibility tier narrower than the crate, matching this project's established convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRequest {
    /// Assigned stream ID.
    pub stream_id: u64,
    /// Token to be used during client connection authentication.
    pub authentication_token: i64,
}

/// Parse a block stream connection header to obtain the stream ID and authentication token.
///
/// Port of the package-private static `parseStreamRequestHeader(byte[] headerBytes)`.
///
/// # Errors
/// Returns an error if `header_bytes` is not exactly [`HEADER_LENGTH`] bytes, does not carry the
/// expected [`HEADER_PREFIX`]/[`HEADER_SUFFIX`], or the embedded stream ID/authentication token
/// are not valid 16-digit hexadecimal values.
pub fn parse_stream_request_header(header_bytes: &[u8]) -> io::Result<StreamRequest> {
    if header_bytes.len() != HEADER_LENGTH {
        // Java throws the unchecked `IllegalArgumentException` here (distinct from the checked
        // `IOException` this method otherwise declares); folded into the same `io::Result` here
        // for a single uniform error channel, using `InvalidInput` to keep the two failure kinds
        // distinguishable by `ErrorKind`.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid headerBytes length"));
    }
    let head = String::from_utf8_lossy(header_bytes);
    if !head.starts_with(HEADER_PREFIX) || !head.ends_with(HEADER_SUFFIX) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid block stream header"));
    }
    let stream_id_str = &head[HEADER_PREFIX.len()..HEADER_PREFIX.len() + 16];
    let auth_token_str = &head[HEADER_PREFIX.len() + 16..HEADER_PREFIX.len() + 32];
    match (u64::from_str_radix(stream_id_str, 16), u64::from_str_radix(auth_token_str, 16)) {
        (Ok(stream_id), Ok(auth_token)) => {
            Ok(StreamRequest { stream_id, authentication_token: auth_token as i64 })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid request header stream ID: {stream_id_str}"),
        )),
    }
}

/// Generate a random number for use as a block stream authentication token.
///
/// Port of the private static synchronized `getRandom()`.
fn get_random() -> i64 {
    SecureRandomFactory::get_secure_random().gen_u64() as i64
}

/// Shared state and concrete-method bodies for a [`RemoteBlockStreamHandle`] implementation. See
/// the module docs for the composition-over-inheritance split.
pub struct RemoteBlockStreamHandleBase {
    stream_server_ip_address: String,
    stream_server_port: u16,
    stream_id: u64,
    authentication_token: i64,
    block_count: i32,
    block_size: i32,
    /// Port of the `protected final boolean compressed` field.
    pub compressed: bool,
    connection_pending: Mutex<bool>,
}

impl RemoteBlockStreamHandleBase {
    /// Abstract `RemoteBlockStreamHandle` constructor.
    ///
    /// Port of `RemoteBlockStreamHandle(BlockStreamServer server, int blockCount, int blockSize)`.
    ///
    /// # Errors
    /// Returns an error if the block stream server is not running or has no server hostname.
    pub fn new(
        server: &dyn BlockStreamServer,
        block_count: i32,
        block_size: i32,
    ) -> io::Result<Self> {
        let stream_server_ip_address = server.server_hostname();
        if !server.is_running() || stream_server_ip_address.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "block stream server is not running"));
        }
        let stream_server_port = server
            .server_port()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "block stream server is not running"))?;
        let stream_id = server.next_stream_id();
        let authentication_token = get_random();
        Ok(Self {
            stream_server_ip_address: stream_server_ip_address.unwrap(),
            stream_server_port,
            stream_id,
            authentication_token,
            block_count,
            block_size,
            compressed: enable_compressed_serialization_output(),
            connection_pending: Mutex::new(true),
        })
    }

    /// Determine if a connection has not yet been requested for this handle.
    ///
    /// Port of the `synchronized boolean isPending()`.
    pub fn is_pending(&self) -> bool {
        *self.connection_pending.lock().unwrap()
    }

    /// Get the unique ID for this stream.
    ///
    /// Port of the package-private `long getStreamID()`.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Get the authentication token value.
    ///
    /// Port of the package-private `long getAuthenticationToken()`.
    pub fn authentication_token(&self) -> i64 {
        self.authentication_token
    }

    /// Get the number of blocks to be transferred.
    ///
    /// Port of `int getBlockCount()`.
    pub fn block_count(&self) -> i32 {
        self.block_count
    }

    /// Get the raw block size.
    ///
    /// Port of the package-private `int getBlockSize()`.
    pub fn block_size(&self) -> i32 {
        self.block_size
    }

    /// Get the preferred socket send/receive buffer size to be used.
    ///
    /// Port of the protected `int getPreferredBufferSize()`.
    pub fn preferred_buffer_size(&self) -> i32 {
        (self.block_size() + 4) * 12
    }

    /// Get the stream request header to be sent when establishing the server connection.
    ///
    /// Format: `"{HEADER_PREFIX}xxxxxxxxxxxxxxxxXXXXXXXXXXXXXXXX{HEADER_SUFFIX}"` where `x`'s
    /// provide the stream ID as a hex value, and `X`'s provide the stream authentication token.
    ///
    /// Port of the private `String getStreamRequestHeader()`.
    fn stream_request_header(&self) -> String {
        let stream_id_hex = format!("{:x}", self.stream_id).pad('0', 16);
        let auth_token_hex = format!("{:x}", self.authentication_token as u64).pad('0', 16);
        format!("{HEADER_PREFIX}{stream_id_hex}{auth_token_hex}{HEADER_SUFFIX}")
    }

    /// Get the stream termination footer to be sent when ending the server connection.
    ///
    /// Format: `"{TERM_PREFIX}xxxxxxxxxxxxxxxx{TERM_SUFFIX}"` where `x`'s provide the stream ID
    /// as a hex value.
    ///
    /// Port of the private `String getStreamTerminator()`.
    fn stream_terminator(&self) -> String {
        let stream_id_hex = format!("{:x}", self.stream_id).pad('0', 16);
        format!("{TERM_PREFIX}{stream_id_hex}{TERM_SUFFIX}")
    }

    /// Perform verification of termination footer bytes.
    ///
    /// Port of the package-private `void checkTerminator(byte[] terminatorBytes)`.
    ///
    /// # Errors
    /// Returns an error if `terminator_bytes` is not exactly [`TERM_LENGTH`] bytes, does not
    /// carry the expected [`TERM_PREFIX`]/[`TERM_SUFFIX`], or does not encode this handle's
    /// stream ID.
    pub fn check_terminator(&self, terminator_bytes: &[u8]) -> io::Result<()> {
        if terminator_bytes.len() != TERM_LENGTH {
            // See `parse_stream_request_header`'s own docs for why Java's unchecked
            // `IllegalArgumentException` is folded into this same `io::Result` channel.
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid terminatorBytes length"));
        }
        let term = String::from_utf8_lossy(terminator_bytes);
        if !term.starts_with(TERM_PREFIX) || !term.ends_with(TERM_SUFFIX) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid block stream terminator"));
        }
        let stream_id_str = &term[TERM_PREFIX.len()..TERM_PREFIX.len() + 16];
        match u64::from_str_radix(stream_id_str, 16) {
            Ok(parsed) if parsed == self.stream_id => Ok(()),
            Ok(_) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, "invalid block stream terminator stream ID"))
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid block stream terminator stream ID: {stream_id_str}"),
            )),
        }
    }

    /// Invoked by the client during the open-block-stream operation; completes the connection
    /// into the server.
    ///
    /// Port of the protected `Socket connect()`. See the module docs for why this returns a plain
    /// [`TcpStream`] rather than layering real TLS on top.
    ///
    /// # Errors
    /// Returns an error if this handle has already been connected, or if the connection attempt
    /// itself fails.
    pub fn connect(&self) -> io::Result<TcpStream> {
        {
            let mut pending = self.connection_pending.lock().unwrap();
            if !*pending {
                return Err(io::Error::new(io::ErrorKind::Other, "already connected"));
            }
            *pending = false;
        }

        let mut socket =
            TcpStream::connect((self.stream_server_ip_address.as_str(), self.stream_server_port))?;

        // TODO: set socket options?

        // Write stream connection request info.
        socket.write_all(self.stream_request_header().as_bytes())?;
        socket.flush()?;

        Ok(socket)
    }

    /// Send the stream termination footer bytes over the socket.
    ///
    /// Port of the protected `void writeStreamEnd(Socket socket)`.
    pub fn write_stream_end(&self, socket: &mut TcpStream) -> io::Result<()> {
        socket.write_all(self.stream_terminator().as_bytes())?;
        socket.flush()
    }

    /// Read the stream terminator from the socket. Timeout should be disabled for the side which
    /// has written the stream to the socket output.
    ///
    /// Port of the protected `void readStreamEnd(Socket socket, boolean enableTimeout)`.
    /// `enable_timeout` is accepted for signature fidelity but unused, matching Java's own `TODO:
    /// no timeouts currently used (relies on BufferFile handle)` comment and commented-out body.
    ///
    /// # Errors
    /// Returns an error (mirroring Java's `EOFException`) if the stream terminates before
    /// [`TERM_LENGTH`] bytes are read, or if the read terminator fails
    /// [`check_terminator`](Self::check_terminator).
    pub fn read_stream_end(&self, socket: &mut TcpStream, _enable_timeout: bool) -> io::Result<()> {
        let mut term = vec![0u8; TERM_LENGTH];
        let mut total = 0;
        while total < term.len() {
            let readlen = socket.read(&mut term[total..])?;
            if readlen == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected end of stream"));
            }
            total += readlen;
        }
        self.check_terminator(&term)
    }
}

/// Provides a serializable handle to a remote block stream. See the module docs.
///
/// Port of the abstract `ghidra.server.stream.RemoteBlockStreamHandle<T extends BlockStream>`.
pub trait RemoteBlockStreamHandle: Send + Sync {
    /// The shared state (server address, stream ID, authentication token, block sizing, pending
    /// flag) every handle carries.
    fn base(&self) -> &RemoteBlockStreamHandleBase;

    /// Port of `isPending()`.
    fn is_pending(&self) -> bool {
        self.base().is_pending()
    }

    /// Port of `getStreamID()`.
    fn get_stream_id(&self) -> u64 {
        self.base().stream_id()
    }

    /// Port of `getAuthenticationToken()`.
    fn get_authentication_token(&self) -> i64 {
        self.base().authentication_token()
    }

    /// Port of `getBlockCount()`.
    fn get_block_count(&self) -> i32 {
        self.base().block_count()
    }

    /// Port of `getBlockSize()`.
    fn get_block_size(&self) -> i32 {
        self.base().block_size()
    }

    /// Port of `getPreferredBufferSize()`.
    fn get_preferred_buffer_size(&self) -> i32 {
        self.base().preferred_buffer_size()
    }

    /// Port of `checkTerminator(byte[])`.
    fn check_terminator(&self, terminator_bytes: &[u8]) -> io::Result<()> {
        self.base().check_terminator(terminator_bytes)
    }

    /// Port of `connect()`.
    fn connect(&self) -> io::Result<TcpStream> {
        self.base().connect()
    }

    /// Port of `writeStreamEnd(Socket)`.
    fn write_stream_end(&self, socket: &mut TcpStream) -> io::Result<()> {
        self.base().write_stream_end(socket)
    }

    /// Port of `readStreamEnd(Socket, boolean)`.
    fn read_stream_end(&self, socket: &mut TcpStream, enable_timeout: bool) -> io::Result<()> {
        self.base().read_stream_end(socket, enable_timeout)
    }

    /// Invoked by [`BlockStreamServer`] to complete the socket-to-block-stream connection. This
    /// method should be called from its own thread and will block until the block stream is
    /// closed.
    ///
    /// Port of the abstract, package-private `void serveBlockStream(Socket, BlockStream)`.
    fn serve_block_stream(&self, socket: TcpStream, block_stream: Box<dyn BlockStream>) -> io::Result<()>;
}

/// Any [`RemoteBlockStreamHandle`] satisfies the lighter
/// [`RemoteBlockStreamHandleLike`](crate::server::seam_stubs::RemoteBlockStreamHandleLike)
/// placeholder [`BlockStreamServer::register_block_stream`] was cut down to (see that seam's own
/// docs), so a real handle can be registered with a [`BlockStreamServer`] without any adapter.
impl<H: RemoteBlockStreamHandle> RemoteBlockStreamHandleLike for H {
    fn stream_id(&self) -> u64 {
        self.get_stream_id()
    }

    fn is_pending(&self) -> bool {
        self.is_pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Mutex as StdMutex;

    struct MockBlockStreamServer {
        running: bool,
        hostname: Option<String>,
        port: Option<u16>,
        next_id: AtomicU64,
    }

    impl BlockStreamServer for MockBlockStreamServer {
        fn is_running(&self) -> bool {
            self.running
        }
        fn server_port(&self) -> Option<u16> {
            self.port
        }
        fn server_hostname(&self) -> Option<String> {
            self.hostname.clone()
        }
        fn next_stream_id(&self) -> u64 {
            self.next_id.fetch_add(1, AtomicOrdering::SeqCst)
        }
        fn register_block_stream(
            &self,
            _stream_handle: Box<dyn RemoteBlockStreamHandleLike>,
            _block_stream: Box<dyn BlockStream>,
        ) -> Result<bool, crate::server::stream::block_stream_server::BlockStreamRegistrationError> {
            Ok(true)
        }
        fn start_server(&self, _socket: std::net::TcpListener, _host: &str) -> io::Result<()> {
            Ok(())
        }
        fn stop_server(&self) {}
    }

    fn running_server(port: u16) -> MockBlockStreamServer {
        MockBlockStreamServer {
            running: true,
            hostname: Some("127.0.0.1".to_string()),
            port: Some(port),
            next_id: AtomicU64::new(1),
        }
    }

    struct MockBlockStream;

    impl BlockStream for MockBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }
        fn get_block_count(&self) -> usize {
            1
        }
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A minimal concrete handle recording whatever `serveBlockStream` was invoked with.
    struct TestHandle {
        base: RemoteBlockStreamHandleBase,
        served: StdMutex<Vec<u64>>,
    }

    impl RemoteBlockStreamHandle for TestHandle {
        fn base(&self) -> &RemoteBlockStreamHandleBase {
            &self.base
        }

        fn serve_block_stream(
            &self,
            _socket: TcpStream,
            _block_stream: Box<dyn BlockStream>,
        ) -> io::Result<()> {
            self.served.lock().unwrap().push(self.get_stream_id());
            Ok(())
        }
    }

    fn test_handle(server: &dyn BlockStreamServer) -> TestHandle {
        TestHandle {
            base: RemoteBlockStreamHandleBase::new(server, 10, 4096).expect("construct handle"),
            served: StdMutex::new(Vec::new()),
        }
    }

    #[test]
    fn constructor_captures_server_fields() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        assert_eq!(handle.get_block_count(), 10);
        assert_eq!(handle.get_block_size(), 4096);
        assert_eq!(handle.get_stream_id(), 1);
        assert!(RemoteBlockStreamHandle::is_pending(&handle));
    }

    #[test]
    fn constructor_fails_when_server_not_running() {
        let server = MockBlockStreamServer {
            running: false,
            hostname: Some("127.0.0.1".to_string()),
            port: Some(1),
            next_id: AtomicU64::new(1),
        };
        assert!(RemoteBlockStreamHandleBase::new(&server, 1, 1).is_err());
    }

    #[test]
    fn constructor_fails_when_no_hostname() {
        let server = MockBlockStreamServer {
            running: true,
            hostname: None,
            port: Some(1),
            next_id: AtomicU64::new(1),
        };
        assert!(RemoteBlockStreamHandleBase::new(&server, 1, 1).is_err());
    }

    #[test]
    fn preferred_buffer_size_matches_java_formula() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        // (blockSize + 4) * 12 = (4096 + 4) * 12
        assert_eq!(handle.get_preferred_buffer_size(), (4096 + 4) * 12);
    }

    #[test]
    fn each_construction_advances_the_stream_id() {
        let server = running_server(4444);
        let h1 = test_handle(&server);
        let h2 = test_handle(&server);
        assert_ne!(h1.get_stream_id(), h2.get_stream_id());
    }

    #[test]
    fn stream_terminator_round_trips_through_check_terminator() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let terminator = handle.base().stream_terminator();
        assert_eq!(terminator.len(), TERM_LENGTH);
        assert!(handle.check_terminator(terminator.as_bytes()).is_ok());
    }

    #[test]
    fn check_terminator_rejects_wrong_length() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        assert!(handle.check_terminator(b"too short").is_err());
    }

    #[test]
    fn check_terminator_rejects_wrong_prefix_suffix() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let mut bad = "X".repeat(TERM_LENGTH).into_bytes();
        bad[0] = b'@';
        assert!(handle.check_terminator(&bad).is_err());
    }

    #[test]
    fn check_terminator_rejects_mismatched_stream_id() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let wrong_id_term = format!("{TERM_PREFIX}{}{TERM_SUFFIX}", "f".repeat(16));
        assert!(handle.check_terminator(wrong_id_term.as_bytes()).is_err());
    }

    #[test]
    fn check_terminator_rejects_non_hex_stream_id() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let non_hex_term = format!("{TERM_PREFIX}{}{TERM_SUFFIX}", "z".repeat(16));
        assert!(handle.check_terminator(non_hex_term.as_bytes()).is_err());
    }

    #[test]
    fn stream_request_header_parses_back_to_the_same_ids() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let header = handle.base().stream_request_header();
        assert_eq!(header.len(), HEADER_LENGTH);

        let parsed = parse_stream_request_header(header.as_bytes()).unwrap();
        assert_eq!(parsed.stream_id, handle.get_stream_id());
        assert_eq!(parsed.authentication_token, handle.get_authentication_token());
    }

    #[test]
    fn parse_stream_request_header_rejects_wrong_length() {
        assert!(parse_stream_request_header(b"short").is_err());
    }

    #[test]
    fn parse_stream_request_header_rejects_bad_prefix() {
        let bad = format!("XXXXXXXX{}{}{HEADER_SUFFIX}", "1".repeat(16), "2".repeat(16));
        assert!(parse_stream_request_header(bad.as_bytes()).is_err());
    }

    #[test]
    fn connect_writes_the_expected_header_and_toggles_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        let server = running_server(port);
        let handle = test_handle(&server);
        assert!(RemoteBlockStreamHandle::is_pending(&handle));

        let expected_header = handle.base().stream_request_header();
        let accept_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = vec![0u8; HEADER_LENGTH];
            stream.read_exact(&mut buf).expect("read header");
            String::from_utf8(buf).expect("utf8 header")
        });

        let _socket = handle.connect().expect("connect");
        assert!(!RemoteBlockStreamHandle::is_pending(&handle));

        let received_header = accept_thread.join().expect("join accept thread");
        assert_eq!(received_header, expected_header);
    }

    #[test]
    fn connect_twice_fails_with_already_connected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        let server = running_server(port);
        let handle = test_handle(&server);

        let accept_thread = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept");
            // Keep the connection open long enough for both connect() attempts below.
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        let _socket = handle.connect().expect("first connect succeeds");
        let second = handle.connect();
        assert!(second.is_err());

        accept_thread.join().expect("join accept thread");
    }

    #[test]
    fn write_stream_end_then_read_stream_end_round_trips_over_a_loopback_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("get addr");
        let server = running_server(addr.port());
        let handle = test_handle(&server);

        let client_thread = std::thread::spawn(move || TcpStream::connect(addr).expect("connect"));
        let (mut server_side, _) = listener.accept().expect("accept");
        let mut client_side = client_thread.join().expect("join client thread");

        // Same handle on both ends, so the terminator's stream ID matches what the reader side
        // expects.
        handle.write_stream_end(&mut client_side).expect("write stream end");
        handle.read_stream_end(&mut server_side, false).expect("read stream end");
    }

    #[test]
    fn read_stream_end_reports_eof_on_short_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("get addr");
        let server = running_server(addr.port());
        let handle = test_handle(&server);

        let writer_thread = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect");
            client.write_all(b"short").expect("write short data");
            drop(client);
        });

        let (mut server_side, _) = listener.accept().expect("accept");
        writer_thread.join().expect("join writer thread");

        let result = handle.read_stream_end(&mut server_side, false);
        assert!(result.is_err());
    }

    #[test]
    fn compressed_field_reflects_system_property_default() {
        // No override is set in this test process, so the (deliberately non-unified, see the
        // module docs) default of "false" for this class specifically applies.
        let server = running_server(4444);
        let handle = test_handle(&server);
        if std::env::var(COMPRESSED_SERIAL_OUTPUT_PROPERTY).is_err() {
            assert!(!handle.base().compressed);
        }
    }

    #[test]
    fn serve_block_stream_is_invoked_with_this_handles_stream_id() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().unwrap();
        let client_thread = std::thread::spawn(move || TcpStream::connect(addr).expect("connect"));
        let (server_side, _) = listener.accept().expect("accept");
        let _client = client_thread.join().unwrap();

        handle.serve_block_stream(server_side, Box::new(MockBlockStream)).unwrap();
        assert_eq!(*handle.served.lock().unwrap(), vec![handle.get_stream_id()]);
    }

    #[test]
    fn usable_as_remote_block_stream_handle_like() {
        let server = running_server(4444);
        let handle = test_handle(&server);
        let as_like: &dyn RemoteBlockStreamHandleLike = &handle;
        assert_eq!(as_like.stream_id(), handle.get_stream_id());
        assert!(as_like.is_pending());
    }
}
