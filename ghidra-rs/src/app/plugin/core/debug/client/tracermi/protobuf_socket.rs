use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

/// A framed socket for sending and receiving length-prefixed protobuf messages.
///
/// Each message is preceded by a 4-byte big-endian length field. The type
/// parameter `T` represents the message type; callers supply encoder and decoder
/// functions to keep framing logic independent of any particular protobuf library.
///
/// Ported from `ghidra.app.plugin.core.debug.client.tracermi.ProtobufSocket`.
/// In the Java version, this uses `SocketChannel` and works with protobuf's
/// `AbstractMessage`. The Rust equivalent uses `TcpStream` with generic
/// encoder/decoder functions.
///
/// Like Java's separate `synchronized (lenSend)` / `synchronized (lenRecv)` blocks, sending and
/// receiving are serialized by two *independent* locks, so one thread may block in
/// [`recv`](Self::recv) (as `RmiReplyHandlerThread` does) while another [`send`](Self::send)s.
/// Both go through `&TcpStream`, which implements `Read` and `Write`.
pub struct ProtobufSocket<T: Send> {
    stream: TcpStream,
    send_lock: Mutex<()>,
    recv_lock: Mutex<()>,
    encoder: Box<dyn Fn(&T) -> Vec<u8> + Send + Sync>,
    decoder: Box<dyn Fn(&[u8]) -> io::Result<T> + Send + Sync>,
}

impl<T: Send + 'static> ProtobufSocket<T> {
    /// Creates a new [`ProtobufSocket`] wrapping a `TcpStream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - The underlying TCP connection.
    /// * `encoder` - Function that serializes a message `T` to bytes.
    /// * `decoder` - Function that deserializes bytes back to a message `T`.
    pub fn new(
        stream: TcpStream,
        encoder: impl Fn(&T) -> Vec<u8> + Send + Sync + 'static,
        decoder: impl Fn(&[u8]) -> io::Result<T> + Send + Sync + 'static,
    ) -> Self {
        Self {
            stream,
            send_lock: Mutex::new(()),
            recv_lock: Mutex::new(()),
            encoder: Box::new(encoder),
            decoder: Box::new(decoder),
        }
    }

    /// Sends a message as a length-prefixed frame.
    ///
    /// The frame format is:
    /// - 4 bytes: big-endian length of the payload
    /// - N bytes: the encoded message payload
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if writing to the socket fails.
    pub fn send(&self, msg: &T) -> io::Result<()> {
        let bytes = (self.encoder)(msg);
        let len = (bytes.len() as u32).to_be_bytes();
        let _guard = self.send_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut stream = &self.stream;
        stream.write_all(&len)?;
        stream.write_all(&bytes)
    }

    /// Receives and decodes a length-prefixed message.
    ///
    /// Reads a 4-byte big-endian length, allocates an exact-size buffer,
    /// reads the payload, then calls the decoder.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if reading from the socket fails or if decoding fails.
    pub fn recv(&self) -> io::Result<T> {
        let _guard = self.recv_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut stream = &self.stream;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        (self.decoder)(&buf)
    }

    /// Closes the socket connection.
    ///
    /// Catches any errors during closure and logs them; does not propagate
    /// the error, matching the Java behavior. Shutting down both directions also wakes a thread
    /// blocked in [`recv`](Self::recv), which then fails with an I/O error.
    pub fn close(&self) {
        if self.stream.shutdown(std::net::Shutdown::Both).is_err() {
            crate::util::msg::Msg::error("ProtobufSocket", &"Unable to close ProtobufSocket");
        }
    }

    /// Returns the remote address of the connected peer, or `None` on error.
    ///
    /// This mirrors the Java `getRemoteAddress()` behavior, returning `None`
    /// instead of null when the address cannot be retrieved.
    pub fn get_remote_address(&self) -> Option<String> {
        self.stream.peer_addr().ok().map(|addr| addr.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn identity_encoder(msg: &Vec<u8>) -> Vec<u8> {
        msg.clone()
    }

    fn identity_decoder(buf: &[u8]) -> io::Result<Vec<u8>> {
        Ok(buf.to_vec())
    }

    #[test]
    fn send_recv_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            ProtobufSocket::new(conn, identity_encoder, identity_decoder)
                .recv()
                .unwrap()
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client = ProtobufSocket::new(stream, identity_encoder, identity_decoder);
        let message = b"hello protobuf".to_vec();
        client.send(&message).unwrap();

        let received = server.join().unwrap();
        assert_eq!(received, message);
    }

    #[test]
    fn framing_uses_four_byte_big_endian_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut header = [0u8; 4];
            conn.read_exact(&mut header).unwrap();
            u32::from_be_bytes(header)
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client: ProtobufSocket<Vec<u8>> =
            ProtobufSocket::new(stream, identity_encoder, identity_decoder);
        let message = b"test".to_vec();
        client.send(&message).unwrap();

        let length_header = server.join().unwrap();
        assert_eq!(length_header, 4u32);
    }

    #[test]
    fn empty_message_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            ProtobufSocket::new(conn, identity_encoder, identity_decoder)
                .recv()
                .unwrap()
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client = ProtobufSocket::new(stream, identity_encoder, identity_decoder);
        client.send(&vec![]).unwrap();

        let received = server.join().unwrap();
        assert!(received.is_empty());
    }

    #[test]
    fn get_remote_address_returns_peer_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            ProtobufSocket::new(conn, identity_encoder, identity_decoder)
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client = ProtobufSocket::new(stream, identity_encoder, identity_decoder);

        let server_sock = server.join().unwrap();
        let addr_opt = server_sock.get_remote_address();

        assert!(addr_opt.is_some());
        let addr_str = addr_opt.unwrap();
        assert!(addr_str.contains("127.0.0.1"));
    }

    #[test]
    fn close_does_not_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            ProtobufSocket::new(conn, identity_encoder, identity_decoder)
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client = ProtobufSocket::new(stream, identity_encoder, identity_decoder);

        client.close();

        let _server_sock = server.join().unwrap();
    }

    #[test]
    fn multiple_messages_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let sock = ProtobufSocket::new(conn, identity_encoder, identity_decoder);
            let a = sock.recv().unwrap();
            let b = sock.recv().unwrap();
            (a, b)
        });

        let stream = TcpStream::connect(addr).unwrap();
        let client = ProtobufSocket::new(stream, identity_encoder, identity_decoder);
        client.send(&b"first".to_vec()).unwrap();
        client.send(&b"second".to_vec()).unwrap();

        let (a, b) = server.join().unwrap();
        assert_eq!(a, b"first".to_vec());
        assert_eq!(b, b"second".to_vec());
    }

    /// A thread blocked in `recv` must not stop another thread from sending (Java guards the
    /// two directions with separate locks).
    #[test]
    fn send_proceeds_while_another_thread_is_blocked_in_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let (peer, _) = listener.accept().unwrap();

        let sock = std::sync::Arc::new(ProtobufSocket::new(
            stream,
            identity_encoder,
            identity_decoder,
        ));
        let receiver = {
            let sock = sock.clone();
            thread::spawn(move || sock.recv().unwrap())
        };
        // Give the receiver time to block inside recv.
        thread::sleep(std::time::Duration::from_millis(50));
        sock.send(&b"ping".to_vec()).unwrap();

        let peer = ProtobufSocket::new(peer, identity_encoder, identity_decoder);
        assert_eq!(peer.recv().unwrap(), b"ping".to_vec());
        peer.send(&b"pong".to_vec()).unwrap();
        assert_eq!(receiver.join().unwrap(), b"pong".to_vec());
    }
}
