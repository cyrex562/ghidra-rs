use std::io::{self, Read};

/// An object that can ingest bytes from a stream in preparation for decoding.
pub trait ByteIngest {
    /// Clear any previous cached bytes.
    fn clear(&mut self);

    /// Open the ingester for receiving bytes.
    ///
    /// Establishes the description of the source of the bytes and the maximum
    /// number of bytes that can be read.
    ///
    /// # Parameters
    /// - `max`: maximum number of bytes that can be read
    /// - `desc`: description of the byte source
    fn open(&mut self, max: usize, desc: &str);

    /// Ingest bytes from the stream up to and including the first 0 byte.
    ///
    /// Can be called multiple times to read bytes in different chunks. An absolute
    /// limit set by a prior call to [`open`][Self::open] is enforced; exceeding it
    /// returns an error.
    fn ingest_stream_to_next_terminator(&mut self, in_stream: &mut dyn Read) -> io::Result<()>;

    /// Ingest bytes from the stream until end of stream.
    ///
    /// An absolute limit set by a prior call to [`open`][Self::open] is enforced;
    /// exceeding it returns an error.
    fn ingest_stream(&mut self, in_stream: &mut dyn Read) -> io::Result<()>;

    /// Ingest `sz` bytes from `byte_array` starting at offset `off`.
    ///
    /// If these bytes would cause the total number of bytes ingested to exceed the
    /// maximum set by [`open`][Self::open], an error is returned. Can be called
    /// multiple times to read in different chunks.
    fn ingest_bytes(&mut self, byte_array: &[u8], off: usize, sz: usize) -> io::Result<()>;

    /// Formal indicator that ingesting of bytes is complete and processing can begin.
    fn end_ingest(&mut self) -> io::Result<()>;

    /// Returns `true` if no bytes have yet been ingested.
    fn is_empty(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct VecByteIngest {
        buf: Vec<u8>,
        max: usize,
        ended: bool,
    }

    impl VecByteIngest {
        fn new() -> Self {
            Self { buf: Vec::new(), max: 0, ended: false }
        }
    }

    impl ByteIngest for VecByteIngest {
        fn clear(&mut self) {
            self.buf.clear();
            self.ended = false;
        }

        fn open(&mut self, max: usize, _desc: &str) {
            self.buf.clear();
            self.max = max;
            self.ended = false;
        }

        fn ingest_stream_to_next_terminator(
            &mut self,
            in_stream: &mut dyn Read,
        ) -> io::Result<()> {
            let mut byte = [0u8; 1];
            loop {
                if in_stream.read(&mut byte)? == 0 {
                    break;
                }
                if self.buf.len() >= self.max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "max bytes exceeded",
                    ));
                }
                self.buf.push(byte[0]);
                if byte[0] == 0 {
                    break;
                }
            }
            Ok(())
        }

        fn ingest_stream(&mut self, in_stream: &mut dyn Read) -> io::Result<()> {
            let mut byte = [0u8; 1];
            loop {
                if in_stream.read(&mut byte)? == 0 {
                    break;
                }
                if self.buf.len() >= self.max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "max bytes exceeded",
                    ));
                }
                self.buf.push(byte[0]);
            }
            Ok(())
        }

        fn ingest_bytes(&mut self, byte_array: &[u8], off: usize, sz: usize) -> io::Result<()> {
            if self.buf.len() + sz > self.max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "max bytes exceeded",
                ));
            }
            self.buf.extend_from_slice(&byte_array[off..off + sz]);
            Ok(())
        }

        fn end_ingest(&mut self) -> io::Result<()> {
            self.ended = true;
            Ok(())
        }

        fn is_empty(&self) -> bool {
            self.buf.is_empty()
        }
    }

    #[test]
    fn test_is_empty_initially() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        assert!(ing.is_empty());
    }

    #[test]
    fn test_ingest_bytes_basic() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(&[1, 2, 3, 4], 0, 4).unwrap();
        assert!(!ing.is_empty());
        assert_eq!(ing.buf, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ingest_bytes_offset_and_size() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(&[10, 20, 30, 40, 50], 1, 3).unwrap();
        assert_eq!(ing.buf, vec![20, 30, 40]);
    }

    #[test]
    fn test_ingest_bytes_exceeds_max() {
        let mut ing = VecByteIngest::new();
        ing.open(2, "test");
        let err = ing.ingest_bytes(&[1, 2, 3], 0, 3).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_ingest_bytes_multiple_chunks() {
        let mut ing = VecByteIngest::new();
        ing.open(10, "test");
        ing.ingest_bytes(&[1, 2], 0, 2).unwrap();
        ing.ingest_bytes(&[3, 4], 0, 2).unwrap();
        assert_eq!(ing.buf, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_stops_at_zero() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        let data = vec![0x41, 0x42, 0x00, 0x43, 0x44];
        let mut cursor = Cursor::new(data);
        ing.ingest_stream_to_next_terminator(&mut cursor).unwrap();
        assert_eq!(ing.buf, vec![0x41, 0x42, 0x00]);
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_no_terminator() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        let data = vec![0x41, 0x42, 0x43];
        let mut cursor = Cursor::new(data);
        ing.ingest_stream_to_next_terminator(&mut cursor).unwrap();
        assert_eq!(ing.buf, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_ingest_stream_reads_until_eof() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        let data = vec![0x01, 0x00, 0x02];
        let mut cursor = Cursor::new(data);
        ing.ingest_stream(&mut cursor).unwrap();
        assert_eq!(ing.buf, vec![0x01, 0x00, 0x02]);
    }

    #[test]
    fn test_ingest_stream_exceeds_max() {
        let mut ing = VecByteIngest::new();
        ing.open(2, "test");
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data);
        let err = ing.ingest_stream(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_clear_resets_buffer() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(&[1, 2, 3], 0, 3).unwrap();
        assert!(!ing.is_empty());
        ing.clear();
        assert!(ing.is_empty());
    }

    #[test]
    fn test_end_ingest() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "test");
        ing.ingest_bytes(&[1, 2, 3], 0, 3).unwrap();
        ing.end_ingest().unwrap();
        assert!(ing.ended);
    }

    #[test]
    fn test_open_clears_previous_data() {
        let mut ing = VecByteIngest::new();
        ing.open(64, "first");
        ing.ingest_bytes(&[9, 8, 7], 0, 3).unwrap();
        ing.open(64, "second");
        assert!(ing.is_empty());
    }
}
