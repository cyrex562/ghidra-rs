//! Port of `ghidra.util.database.DBBufferInputStream`: an input stream backed by a database
//! chained buffer -- the read-side counterpart of
//! [`DBBufferOutputStream`](crate::util::database::DBBufferOutputStream).
//!
//! The Java class `extends InputStream`, overriding `available`, `mark`, `markSupported`,
//! `read(byte[])`, `read(byte[], int, int)`, `read()`, `readAllBytes`, `readNBytes(byte[], int,
//! int)`, `readNBytes(int)`, and `reset`. Per this crate's convention of preferring native Rust
//! traits where the semantics allow it (see `DBBufferOutputStream`'s module docs for the same
//! reasoning on the write side), the two `read(byte[]...)` overloads plus the no-arg `read()`
//! collapse into a single [`std::io::Read`] impl over a composed
//! [`Box<dyn DBBuffer>`](crate::framework::db::DBBuffer): `read(byte[])` is just `read(byte[], 0,
//! byte[].length)`, and Rust callers get the `off`/`len` that overload takes by slicing the
//! buffer themselves (`stream.read(&mut buf[off..off + len])`) rather than needing a distinct
//! method. `readNBytes(byte[], int, int)` is a pure delegation straight through to
//! `read(byte[], int, int)` with no behavior of its own, so it's likewise folded away rather than
//! kept as a redundant wrapper.
//!
//! `available`, `mark`, `markSupported`, `reset`, `readAllBytes`, and `readNBytes(int)` have no
//! `Read`-trait equivalent and are kept as explicit inherent methods, mirroring
//! [`DBBufferOutputStream::close`](crate::util::database::DBBufferOutputStream::close)'s "no
//! `Write`-trait analogue" precedent. `skip(long)` is likewise kept as an inherent method, since
//! `std::io::Read` has no `skip` of its own (that lives on `Seek`, which a chained-buffer-backed
//! stream doesn't otherwise need).
//!
//! # A Java quirk that does *not* survive translation
//!
//! `read(byte[])`/`read(byte[], int, int)` (lines 53-61 and 63-72 of the original) check
//! end-of-stream *before* checking whether zero bytes were even requested:
//! ```java
//! if (offset == buffer.length()) {
//!     return -1;
//! }
//! int len = Math.min(available(), b.length);
//! ```
//! Per the documented `InputStream.read(byte[])`/`read(byte[], int, int)` contract, a zero-length
//! request must return `0` unconditionally, even at end-of-stream -- so calling `read(new
//! byte[0])` while already at EOF is a genuine, if minor, contract violation in the original
//! Java: it returns `-1` where the contract requires `0`. This doesn't have an observable
//! translation here, though: [`std::io::Read::read`] represents *both* "at EOF" and "zero bytes
//! requested" with the identical `Ok(0)` -- there is no `-1`-shaped sentinel to get wrong. So
//! both the buggy Java check ordering and the contract-correct ordering produce the same `Ok(0)`
//! once ported. The EOF-first check is kept anyway in [`read`](DBBufferInputStream::read) purely
//! to mirror the original's structure, not because it changes anything observable.

use std::io;

use crate::framework::db::DBBuffer;

/// An input stream backed by a database chained buffer. Mirrors
/// `ghidra.util.database.DBBufferInputStream`.
pub struct DBBufferInputStream {
    buffer: Box<dyn DBBuffer>,
    offset: usize,
    mark: Option<usize>,
}

impl DBBufferInputStream {
    /// Mirrors `DBBufferInputStream(DBBuffer)`.
    pub fn new(buffer: Box<dyn DBBuffer>) -> Self {
        Self { buffer, offset: 0, mark: None }
    }

    /// Mirrors `available()`.
    pub fn available(&self) -> usize {
        self.buffer.length() - self.offset
    }

    /// Mirrors `mark(int)`. Java accepts a `readlimit` parameter but never actually uses it to
    /// invalidate the mark; this stream is backed by a fully random-access database buffer, so
    /// there is no notion of a mark becoming stale after reading too far past it. Kept here (as
    /// `_readlimit`) purely for API parity with the original signature.
    pub fn mark(&mut self, _readlimit: i32) {
        self.mark = Some(self.offset);
    }

    /// Mirrors `markSupported()`, which unconditionally returns `true`.
    pub fn mark_supported(&self) -> bool {
        true
    }

    /// Mirrors `reset()`: rewinds to the position last saved by [`mark`](Self::mark), or errors
    /// if no mark has been set (matching Java's `throw new IOException("No mark")`).
    pub fn reset(&mut self) -> io::Result<()> {
        match self.mark {
            Some(mark) => {
                self.offset = mark;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "No mark")),
        }
    }

    /// Mirrors `skip(long)`: advances past up to `n` bytes (never past end-of-stream), returning
    /// the number of bytes actually skipped. A negative `n` skips nothing, matching Java.
    pub fn skip(&mut self, n: i64) -> io::Result<i64> {
        if n < 0 {
            return Ok(0);
        }
        let n = (self.available() as i64).min(n);
        self.offset += n as usize;
        Ok(n)
    }

    /// Mirrors `readAllBytes()`: reads every remaining byte and advances to end-of-stream.
    pub fn read_all_bytes(&mut self) -> io::Result<Vec<u8>> {
        let mut result = vec![0u8; self.available()];
        self.buffer.get_all(self.offset, &mut result)?;
        self.offset += result.len();
        Ok(result)
    }

    /// Mirrors `readNBytes(int)`: reads up to `len` bytes (capped by what remains), returning
    /// exactly that many.
    pub fn read_n_bytes(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let len = self.available().min(len);
        let mut result = vec![0u8; len];
        self.buffer.get_all(self.offset, &mut result)?;
        self.offset += len;
        Ok(result)
    }
}

impl io::Read for DBBufferInputStream {
    /// Mirrors `read(byte[], int, int)` -- the general case Rust's `Read::read` corresponds to,
    /// with an implicit `off` of 0 since the caller already sliced `buf` down to the desired
    /// window. `read(byte[])` and the no-arg `read()` are both special cases of this same logic
    /// (a full-length slice, and a one-byte slice, respectively).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.buffer.length() {
            return Ok(0);
        }
        let len = self.available().min(buf.len());
        self.buffer.get_all(self.offset, &mut buf[..len])?;
        self.offset += len;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// Minimal in-memory `DBBuffer` mock, same shape as the one in `db_buffer_output_stream.rs`'s
    /// own tests.
    struct MockDBBuffer {
        data: Vec<u8>,
    }

    fn bounds_err() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "index out of bounds")
    }

    impl DBBuffer for MockDBBuffer {
        fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
            let tail = self.data.split_off(offset);
            Ok(Box::new(MockDBBuffer { data: tail }))
        }

        fn set_size(&mut self, size: usize, _preserve_data: bool) -> io::Result<()> {
            self.data.resize(size, 0);
            Ok(())
        }

        fn length(&self) -> usize {
            self.data.len()
        }

        fn get_id(&self) -> i32 {
            0
        }

        fn fill(&mut self, start_offset: usize, end_offset: usize, fill_byte: u8) -> io::Result<()> {
            for b in &mut self.data[start_offset..end_offset] {
                *b = fill_byte;
            }
            Ok(())
        }

        fn append(&mut self, mut buffer: Box<dyn DBBuffer>) -> io::Result<()> {
            let len = buffer.length();
            let mut tail = vec![0u8; len];
            buffer.get_all(0, &mut tail)?;
            self.data.extend_from_slice(&tail);
            buffer.delete()
        }

        fn get_byte(&self, offset: usize) -> io::Result<u8> {
            self.data.get(offset).copied().ok_or_else(bounds_err)
        }

        fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()> {
            if offset + length > self.data.len() || data_offset + length > data.len() {
                return Err(bounds_err());
            }
            data[data_offset..data_offset + length].copy_from_slice(&self.data[offset..offset + length]);
            Ok(())
        }

        fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
            let mut buf = vec![0u8; self.data.len()];
            reader.read_exact(&mut buf).ok();
            self.data.copy_from_slice(&buf);
            Ok(())
        }

        fn put(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> io::Result<()> {
            if offset + length > self.data.len() || data_offset + length > bytes.len() {
                return Err(bounds_err());
            }
            self.data[offset..offset + length].copy_from_slice(&bytes[data_offset..data_offset + length]);
            Ok(())
        }

        fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()> {
            if offset >= self.data.len() {
                return Err(bounds_err());
            }
            self.data[offset] = b;
            Ok(())
        }

        fn delete(&mut self) -> io::Result<()> {
            self.data.clear();
            Ok(())
        }
    }

    fn buffer_with(data: &[u8]) -> Box<dyn DBBuffer> {
        Box::new(MockDBBuffer { data: data.to_vec() })
    }

    #[test]
    fn read_returns_bytes_in_order_across_multiple_calls() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3, 4, 5, 6]));
        let mut first = [0u8; 4];
        assert_eq!(input.read(&mut first).unwrap(), 4);
        assert_eq!(first, [1, 2, 3, 4]);
        let mut second = [0u8; 4];
        assert_eq!(input.read(&mut second).unwrap(), 2);
        assert_eq!(&second[..2], &[5, 6]);
    }

    #[test]
    fn read_returns_zero_at_eof() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2]));
        let mut buf = [0u8; 2];
        assert_eq!(input.read(&mut buf).unwrap(), 2);
        // At EOF, Rust's Read::read reports Ok(0) (the idiomatic analogue of Java's -1).
        assert_eq!(input.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn read_single_byte_matches_java_no_arg_read() {
        // Java's read() masks with 0xff and returns the byte as an int; a one-byte Read::read
        // slice is the direct Rust analogue.
        let mut input = DBBufferInputStream::new(buffer_with(&[0xFF, 0x01]));
        let mut byte = [0u8; 1];
        assert_eq!(input.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 0xFF);
    }

    #[test]
    fn available_reflects_remaining_bytes_and_shrinks_as_read_advances() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3, 4]));
        assert_eq!(input.available(), 4);
        let mut buf = [0u8; 2];
        input.read(&mut buf).unwrap();
        assert_eq!(input.available(), 2);
    }

    #[test]
    fn mark_and_reset_roundtrip_to_marked_offset() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3, 4]));
        let mut buf = [0u8; 2];
        input.read(&mut buf).unwrap();
        input.mark(0); // readlimit is ignored, mirroring Java
        input.read(&mut buf).unwrap();
        assert_eq!(input.available(), 0);
        input.reset().unwrap();
        assert_eq!(input.available(), 2);
        let mut after_reset = [0u8; 2];
        input.read(&mut after_reset).unwrap();
        assert_eq!(after_reset, [3, 4]);
    }

    #[test]
    fn reset_without_prior_mark_errors_with_no_mark_message() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3]));
        let err = input.reset().expect_err("expected reset without a mark to fail");
        assert_eq!(err.to_string(), "No mark");
    }

    #[test]
    fn mark_supported_is_always_true() {
        let input = DBBufferInputStream::new(buffer_with(&[]));
        assert!(input.mark_supported());
    }

    #[test]
    fn skip_advances_offset_and_caps_at_available() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3, 4, 5]));
        assert_eq!(input.skip(3).unwrap(), 3);
        assert_eq!(input.available(), 2);
        // Requesting more than remains caps at what's actually available.
        assert_eq!(input.skip(100).unwrap(), 2);
        assert_eq!(input.available(), 0);
    }

    #[test]
    fn skip_negative_returns_zero_without_advancing() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3]));
        assert_eq!(input.skip(-5).unwrap(), 0);
        assert_eq!(input.available(), 3);
    }

    #[test]
    fn read_all_bytes_reads_remainder_and_reaches_eof() {
        let mut input = DBBufferInputStream::new(buffer_with(&[9, 8, 7, 6]));
        let mut buf = [0u8; 1];
        input.read(&mut buf).unwrap();
        let rest = input.read_all_bytes().unwrap();
        assert_eq!(rest, vec![8, 7, 6]);
        assert_eq!(input.available(), 0);
    }

    #[test]
    fn read_n_bytes_caps_at_available() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3]));
        let result = input.read_n_bytes(10).unwrap();
        assert_eq!(result, vec![1, 2, 3]);
        assert_eq!(input.available(), 0);
    }

    #[test]
    fn read_n_bytes_reads_only_the_requested_amount_when_more_is_available() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2, 3, 4, 5]));
        let result = input.read_n_bytes(2).unwrap();
        assert_eq!(result, vec![1, 2]);
        assert_eq!(input.available(), 3);
    }

    #[test]
    fn read_with_buffer_larger_than_available_returns_only_what_remains() {
        let mut input = DBBufferInputStream::new(buffer_with(&[1, 2]));
        let mut buf = [0u8; 10];
        let n = input.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[1, 2]);
    }

    #[test]
    fn empty_read_at_eof_returns_ok_zero_not_an_error() {
        // See module docs: this is the case where Java's buggy `-1` and the contract-correct `0`
        // are indistinguishable once translated, because Rust's Read::read has no `-1` sentinel.
        let mut input = DBBufferInputStream::new(buffer_with(&[1]));
        let mut buf = [0u8; 1];
        input.read(&mut buf).unwrap();
        assert_eq!(input.available(), 0);
        let mut empty: [u8; 0] = [];
        assert_eq!(input.read(&mut empty).unwrap(), 0);
    }
}
