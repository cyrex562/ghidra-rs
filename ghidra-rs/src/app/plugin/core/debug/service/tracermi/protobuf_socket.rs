use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

/// A framed socket that sends and receives length-prefixed protobuf messages.
///
/// Each message is preceded by a 4-byte big-endian length field. The type
/// parameter `T` is the decoded message type; callers supply encoder and decoder
/// functions, keeping framing logic independent of any particular protobuf library.
///
/// Ported from `ghidra.app.plugin.core.debug.service.tracermi.ProtobufSocket`.
pub struct ProtobufSocket<T> {
    stream: Mutex<TcpStream>,
    encoder: Box<dyn Fn(&T) -> Vec<u8> + Send + Sync>,
    decoder: Box<dyn Fn(&[u8]) -> io::Result<T> + Send + Sync>,
}

impl<T: Send + 'static> ProtobufSocket<T> {
    /// Creates a new [`ProtobufSocket`] wrapping `stream`.
    ///
    /// - `encoder` converts a message to its on-wire byte representation.
    /// - `decoder` parses the raw bytes back into a message, returning an error on failure.
    pub fn new(
        stream: TcpStream,
        encoder: impl Fn(&T) -> Vec<u8> + Send + Sync + 'static,
        decoder: impl Fn(&[u8]) -> io::Result<T> + Send + Sync + 'static,
    ) -> Self {
        Self {
            stream: Mutex::new(stream),
            encoder: Box::new(encoder),
            decoder: Box::new(decoder),
        }
    }

    /// Sends `msg` as a length-prefixed frame: 4-byte big-endian length followed by payload.
    pub fn send(&self, msg: &T) -> io::Result<()> {
        let bytes = (self.encoder)(msg);
        let len = (bytes.len() as u32).to_be_bytes();
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&len)?;
        stream.write_all(&bytes)
    }

    /// Receives a length-prefixed frame and decodes it.
    ///
    /// Reads a 4-byte big-endian length, allocates an exact-size buffer, reads
    /// the payload, then calls the decoder.
    pub fn recv(&self) -> io::Result<T> {
        let mut stream = self.stream.lock().unwrap();
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        (self.decoder)(&buf)
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
}
