use std::io::{self, Read};

use super::ByteIngest;

/// A [`ByteIngest`] that accumulates ingested bytes into an in-memory buffer.
#[derive(Debug, Default)]
pub struct StringIngest {
    out_stream: Option<Vec<u8>>,
    description: Option<String>,
    max_bytes: usize,
}

impl StringIngest {
    /// Create a new, unopened `StringIngest`.
    pub fn new() -> Self {
        Self {
            out_stream: None,
            description: None,
            max_bytes: 0,
        }
    }
}

impl ByteIngest for StringIngest {
    fn clear(&mut self) {
        self.out_stream = None;
        self.description = None;
    }

    fn open(&mut self, max: usize, desc: &str) {
        self.max_bytes = max;
        self.description = Some(desc.to_string());
        self.out_stream = Some(Vec::new());
    }

    fn ingest_stream_to_next_terminator(&mut self, in_stream: &mut dyn Read) -> io::Result<()> {
        let buf = self.out_stream.as_mut().expect("StringIngest not opened");
        let mut byte = [0u8; 1];
        loop {
            if in_stream.read(&mut byte)? == 0 {
                break;
            }
            if byte[0] == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.len() >= self.max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Buffer size exceeded: {}",
                        self.description.as_deref().unwrap_or("")
                    ),
                ));
            }
        }
        Ok(())
    }

    fn ingest_stream(&mut self, _in_stream: &mut dyn Read) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Not supported"))
    }

    fn ingest_bytes(&mut self, byte_array: &[u8], off: usize, sz: usize) -> io::Result<()> {
        let buf = self.out_stream.as_mut().expect("StringIngest not opened");
        for &byte in &byte_array[off..off + sz] {
            buf.push(byte);
            if buf.len() >= self.max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Buffer size exceeded: {}",
                        self.description.as_deref().unwrap_or("")
                    ),
                ));
            }
        }
        Ok(())
    }

    fn end_ingest(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> bool {
        match &self.out_stream {
            None => true,
            Some(buf) => buf.is_empty(),
        }
    }
}

impl std::fmt::Display for StringIngest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.out_stream {
            None => write!(f, "<empty>"),
            Some(buf) => write!(f, "{}", String::from_utf8_lossy(buf)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_new_is_empty_and_displays_empty() {
        let ing = StringIngest::new();
        assert!(ing.is_empty());
        assert_eq!(ing.to_string(), "<empty>");
    }

    #[test]
    fn test_open_resets_state() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        assert!(ing.is_empty());
        assert_eq!(ing.to_string(), "");
    }

    #[test]
    fn test_ingest_bytes_basic() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(b"hello", 0, 5).unwrap();
        assert!(!ing.is_empty());
        assert_eq!(ing.to_string(), "hello");
    }

    #[test]
    fn test_ingest_bytes_offset_and_size() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(b"xxhelloxx", 2, 5).unwrap();
        assert_eq!(ing.to_string(), "hello");
    }

    #[test]
    fn test_ingest_bytes_exceeds_max() {
        let mut ing = StringIngest::new();
        ing.open(2, "test-source");
        let err = ing.ingest_bytes(b"abc", 0, 3).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("test-source"));
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_stops_at_zero() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        let data = vec![b'A', b'B', 0x00, b'C', b'D'];
        let mut cursor = Cursor::new(data);
        ing.ingest_stream_to_next_terminator(&mut cursor).unwrap();
        assert_eq!(ing.to_string(), "AB");
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_no_terminator() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        let data = vec![b'A', b'B', b'C'];
        let mut cursor = Cursor::new(data);
        ing.ingest_stream_to_next_terminator(&mut cursor).unwrap();
        assert_eq!(ing.to_string(), "ABC");
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_exceeds_max() {
        let mut ing = StringIngest::new();
        ing.open(2, "test");
        let data = vec![b'A', b'B', b'C'];
        let mut cursor = Cursor::new(data);
        let err = ing
            .ingest_stream_to_next_terminator(&mut cursor)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_ingest_stream_not_supported() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data);
        let err = ing.ingest_stream(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_clear_resets_to_empty() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(b"abc", 0, 3).unwrap();
        assert!(!ing.is_empty());
        ing.clear();
        assert!(ing.is_empty());
        assert_eq!(ing.to_string(), "<empty>");
    }

    #[test]
    fn test_end_ingest_is_noop() {
        let mut ing = StringIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(b"abc", 0, 3).unwrap();
        ing.end_ingest().unwrap();
        assert_eq!(ing.to_string(), "abc");
    }
}
