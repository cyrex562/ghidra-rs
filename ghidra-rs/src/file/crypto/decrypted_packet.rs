use std::io::Read;
use std::path::PathBuf;

/// The result of a decryption operation: either a file written to disk or an in-memory stream.
///
/// Mirrors `ghidra.file.crypto.DecryptedPacket`. The two Java constructors map to
/// [`DecryptedPacket::from_file`] and [`DecryptedPacket::from_stream`].
pub enum DecryptedPacket {
    /// The decrypted content was written to a temporary file on disk.
    File(PathBuf),
    /// The decrypted content is held in an in-memory stream with a declared byte length.
    Stream {
        stream: Box<dyn Read>,
        length: i32,
    },
}

impl DecryptedPacket {
    /// Creates a packet backed by a file on disk, mirroring `DecryptedPacket(File)`.
    pub fn from_file(path: PathBuf) -> Self {
        DecryptedPacket::File(path)
    }

    /// Creates a packet backed by an in-memory stream, mirroring
    /// `DecryptedPacket(InputStream, int)`.
    pub fn from_stream(stream: Box<dyn Read>, length: i32) -> Self {
        DecryptedPacket::Stream { stream, length }
    }

    /// Releases resources held by this packet.
    ///
    /// Mirrors Java's `dispose()`: closes the underlying stream when present. In Rust, dropping
    /// the value has the same effect; this method offers an explicit call site for callers that
    /// follow the Java pattern.
    pub fn dispose(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn from_file_produces_file_variant() {
        let path = PathBuf::from("/tmp/test.bin");
        let packet = DecryptedPacket::from_file(path.clone());
        match packet {
            DecryptedPacket::File(p) => assert_eq!(p, path),
            DecryptedPacket::Stream { .. } => panic!("expected File variant"),
        }
    }

    #[test]
    fn from_stream_produces_stream_variant() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let length = data.len() as i32;
        let stream: Box<dyn Read> = Box::new(Cursor::new(data));
        let packet = DecryptedPacket::from_stream(stream, length);
        match packet {
            DecryptedPacket::Stream { length: l, .. } => assert_eq!(l, 4),
            DecryptedPacket::File(_) => panic!("expected Stream variant"),
        }
    }

    #[test]
    fn stream_length_preserved() {
        let stream: Box<dyn Read> = Box::new(Cursor::new(vec![0u8; 256]));
        let packet = DecryptedPacket::from_stream(stream, 256);
        match packet {
            DecryptedPacket::Stream { length, .. } => assert_eq!(length, 256),
            _ => panic!("expected Stream variant"),
        }
    }

    #[test]
    fn negative_length_sentinel_preserved() {
        // Java uses -1 as a sentinel when constructed from a File.
        // from_stream should faithfully store whatever length is passed.
        let stream: Box<dyn Read> = Box::new(Cursor::new(vec![]));
        let packet = DecryptedPacket::from_stream(stream, -1);
        match packet {
            DecryptedPacket::Stream { length, .. } => assert_eq!(length, -1),
            _ => panic!("expected Stream variant"),
        }
    }

    #[test]
    fn dispose_file_packet_does_not_panic() {
        let packet = DecryptedPacket::from_file(PathBuf::from("/tmp/dummy"));
        packet.dispose();
    }

    #[test]
    fn dispose_stream_packet_closes_stream() {
        let stream: Box<dyn Read> = Box::new(Cursor::new(vec![1u8, 2, 3]));
        let packet = DecryptedPacket::from_stream(stream, 3);
        packet.dispose();
    }

    #[test]
    fn stream_is_readable() {
        let data = vec![0x01u8, 0x02, 0x03];
        let stream: Box<dyn Read> = Box::new(Cursor::new(data.clone()));
        let mut packet_stream = match DecryptedPacket::from_stream(stream, 3) {
            DecryptedPacket::Stream { stream, .. } => stream,
            _ => panic!("expected Stream variant"),
        };
        let mut buf = vec![0u8; 3];
        packet_stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, data);
    }
}
