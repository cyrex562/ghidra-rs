use std::io;

/// Provides a random-access handle to a file with read/write operations.
pub trait DataFileHandle {
    /// Returns `true` if this data file handle is open read-only.
    fn is_read_only(&mut self) -> io::Result<bool>;

    /// Reads exactly `b.len()` bytes from this file into the byte array,
    /// starting at the current file pointer. This method reads repeatedly
    /// until the requested number of bytes are read.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` with kind `UnexpectedEof` if the file reaches
    /// the end before reading all the bytes, or if another I/O error occurs.
    fn read(&mut self, b: &mut [u8]) -> io::Result<()>;

    /// Reads exactly `len` bytes from this file into the byte array,
    /// starting at offset `off` in the buffer. This method reads repeatedly
    /// until the requested number of bytes are read.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` with kind `UnexpectedEof` if the file reaches
    /// the end before reading all the bytes, or if another I/O error occurs.
    fn read_at(&mut self, b: &mut [u8], off: usize, len: usize) -> io::Result<()>;

    /// Skips over `n` bytes of input, discarding the skipped bytes.
    ///
    /// This method may skip over some smaller number of bytes, possibly zero.
    /// Reaching end-of-file before `n` bytes have been skipped is possible.
    /// This method never throws an `UnexpectedEof` error. The actual number
    /// of bytes skipped is returned. If `n` is negative, no bytes are skipped.
    ///
    /// # Returns
    ///
    /// The actual number of bytes skipped (always non-negative).
    fn skip_bytes(&mut self, n: i32) -> io::Result<i32>;

    /// Writes the specified byte to this file. The write starts at
    /// the current file pointer.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn write(&mut self, b: i32) -> io::Result<()>;

    /// Writes all bytes from the specified byte array to this file,
    /// starting at the current file pointer.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn write_bytes(&mut self, b: &[u8]) -> io::Result<()>;

    /// Writes `len` bytes from the specified byte array starting at
    /// offset `off` to this file.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn write_at(&mut self, b: &[u8], off: usize, len: usize) -> io::Result<()>;

    /// Sets the file-pointer offset, measured from the beginning of this file,
    /// at which the next read or write occurs. The offset may be set beyond
    /// the end of the file. Setting the offset beyond the end of the file
    /// does not change the file length. The file length will change only by
    /// writing after the offset has been set beyond the end of the file.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if `pos` is less than 0 or if an I/O error occurs.
    fn seek(&mut self, pos: i64) -> io::Result<()>;

    /// Returns the length of this file, measured in bytes.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn length(&mut self) -> io::Result<i64>;

    /// Sets the length of this file.
    ///
    /// If the present length of the file is greater than `new_length`,
    /// the file will be truncated. In this case, if the file offset is greater
    /// than `new_length`, the offset will be set to `new_length`.
    ///
    /// If the present length of the file is smaller than `new_length`,
    /// the file will be extended. The contents of the extended portion are
    /// undefined.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn set_length(&mut self, new_length: i64) -> io::Result<()>;

    /// Closes this file handle and releases any system resources associated
    /// with it. A closed handle cannot perform input or output operations
    /// and cannot be reopened.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if an I/O error occurs.
    fn close(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MockFileHandle {
        is_read_only: bool,
        position: i64,
        data: Vec<u8>,
        closed: bool,
    }

    impl MockFileHandle {
        fn new() -> Self {
            Self {
                is_read_only: false,
                position: 0,
                data: vec![],
                closed: false,
            }
        }
    }

    impl DataFileHandle for MockFileHandle {
        fn is_read_only(&mut self) -> io::Result<bool> {
            Ok(self.is_read_only)
        }

        fn read(&mut self, b: &mut [u8]) -> io::Result<()> {
            self.read_at(b, 0, b.len())
        }

        fn read_at(&mut self, b: &mut [u8], off: usize, len: usize) -> io::Result<()> {
            let end_pos = self.position as usize + len;
            if end_pos > self.data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "end of file reached",
                ));
            }
            let slice = &self.data[self.position as usize..end_pos];
            b[off..off + len].copy_from_slice(slice);
            self.position += len as i64;
            Ok(())
        }

        fn skip_bytes(&mut self, n: i32) -> io::Result<i32> {
            if n <= 0 {
                return Ok(0);
            }
            let skip_amount = std::cmp::min(n as usize, self.data.len() - self.position as usize);
            self.position += skip_amount as i64;
            Ok(skip_amount as i32)
        }

        fn write(&mut self, b: i32) -> io::Result<()> {
            let byte = (b & 0xFF) as u8;
            self.write_bytes(&[byte])
        }

        fn write_bytes(&mut self, b: &[u8]) -> io::Result<()> {
            self.write_at(b, 0, b.len())
        }

        fn write_at(&mut self, b: &[u8], off: usize, len: usize) -> io::Result<()> {
            let pos = self.position as usize;
            let end_pos = pos + len;

            if end_pos > self.data.len() {
                self.data.resize(end_pos, 0);
            }
            self.data[pos..end_pos].copy_from_slice(&b[off..off + len]);
            self.position += len as i64;
            Ok(())
        }

        fn seek(&mut self, pos: i64) -> io::Result<()> {
            if pos < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "position cannot be negative",
                ));
            }
            self.position = pos;
            Ok(())
        }

        fn length(&mut self) -> io::Result<i64> {
            Ok(self.data.len() as i64)
        }

        fn set_length(&mut self, new_length: i64) -> io::Result<()> {
            if new_length < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "length cannot be negative",
                ));
            }
            let new_len = new_length as usize;
            if new_len < self.data.len() {
                self.data.truncate(new_len);
                if self.position > new_length {
                    self.position = new_length;
                }
            } else {
                self.data.resize(new_len, 0);
            }
            Ok(())
        }

        fn close(&mut self) -> io::Result<()> {
            self.closed = true;
            Ok(())
        }
    }

    #[test]
    fn test_is_read_only_writable() {
        let mut handle = MockFileHandle::new();
        assert_eq!(handle.is_read_only().unwrap(), false);
    }

    #[test]
    fn test_write_and_length() {
        let mut handle = MockFileHandle::new();
        let data = b"hello";
        handle.write_bytes(data).unwrap();
        assert_eq!(handle.length().unwrap(), 5);
    }

    #[test]
    fn test_write_read_roundtrip() {
        let mut handle = MockFileHandle::new();
        let original = b"test data";
        handle.write_bytes(original).unwrap();

        handle.seek(0).unwrap();
        let mut buffer = vec![0u8; 9];
        handle.read(&mut buffer).unwrap();
        assert_eq!(&buffer, original);
    }

    #[test]
    fn test_seek_beyond_eof() {
        let mut handle = MockFileHandle::new();
        handle.seek(100).unwrap();
        assert_eq!(handle.seek(100).unwrap(), ());
    }

    #[test]
    fn test_seek_negative_fails() {
        let mut handle = MockFileHandle::new();
        assert!(handle.seek(-1).is_err());
    }

    #[test]
    fn test_skip_bytes_zero() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"abc").unwrap();
        handle.seek(0).unwrap();
        assert_eq!(handle.skip_bytes(0).unwrap(), 0);
        assert_eq!(handle.seek(0).unwrap(), ());
    }

    #[test]
    fn test_skip_bytes_negative() {
        let mut handle = MockFileHandle::new();
        assert_eq!(handle.skip_bytes(-5).unwrap(), 0);
    }

    #[test]
    fn test_skip_bytes_partial() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"abcdef").unwrap();
        handle.seek(0).unwrap();
        let skipped = handle.skip_bytes(4).unwrap();
        assert_eq!(skipped, 4);
    }

    #[test]
    fn test_skip_bytes_past_eof() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"abc").unwrap();
        handle.seek(0).unwrap();
        let skipped = handle.skip_bytes(100).unwrap();
        assert_eq!(skipped, 3);
    }

    #[test]
    fn test_set_length_truncate() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"hello world").unwrap();
        assert_eq!(handle.length().unwrap(), 11);

        handle.set_length(5).unwrap();
        assert_eq!(handle.length().unwrap(), 5);
    }

    #[test]
    fn test_set_length_extend() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"hi").unwrap();
        handle.set_length(5).unwrap();
        assert_eq!(handle.length().unwrap(), 5);
    }

    #[test]
    fn test_set_length_adjusts_position() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"hello world").unwrap();
        handle.seek(10).unwrap();
        handle.set_length(5).unwrap();
        assert_eq!(handle.seek(5).unwrap(), ());
    }

    #[test]
    fn test_write_single_byte() {
        let mut handle = MockFileHandle::new();
        handle.write(65).unwrap();
        assert_eq!(handle.length().unwrap(), 1);
    }

    #[test]
    fn test_write_with_offset() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"hello").unwrap();
        handle.seek(5).unwrap();
        handle.write_at(b" world", 0, 6).unwrap();
        assert_eq!(handle.length().unwrap(), 11);
    }

    #[test]
    fn test_read_exact_failure() {
        let mut handle = MockFileHandle::new();
        handle.write_bytes(b"abc").unwrap();
        handle.seek(0).unwrap();

        let mut buffer = vec![0u8; 10];
        let result = handle.read(&mut buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_close() {
        let mut handle = MockFileHandle::new();
        handle.close().unwrap();
        assert!(handle.closed);
    }
}
