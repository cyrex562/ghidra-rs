//! Port of `ghidra.util.database.DBBufferOutputStream`: an output stream backed by a database
//! chained buffer.
//!
//! The Java class `extends OutputStream` overriding `write(byte[])`, `write(byte[], int, int)`,
//! `write(int)`, and `close()`. Per this crate's convention of preferring native Rust traits
//! where the semantics allow it, this is expressed as [`std::io::Write`] over a composed
//! [`Box<dyn DBBuffer>`](crate::framework::db::DBBuffer) (the already-ported
//! [`DBBufferImpl`](crate::framework::db::DBBufferImpl) being the real-world implementor) rather
//! than a hand-rolled `OutputStream`-shaped trait. `close()` has no `std::io::Write` equivalent,
//! so it's kept as an explicit consuming method, mirroring
//! [`JarWriter::close`](crate::generic::io::JarWriter::close)'s use of the same pattern for an
//! identical "Java `close()`, no `Write`-trait analogue" situation.
//!
//! # A genuine Java bug, reproduced faithfully
//!
//! `checkExpand(int add)` (lines 39-44 of the original) is:
//! ```java
//! void checkExpand(int add) throws IOException {
//!     int len = offset + add;
//!     if (buffer.length() < len) {
//!         buffer.setSize(buffer.length() + increment, true);
//!     }
//! }
//! ```
//! It grows the buffer by exactly `increment` bytes -- *not* by however much is actually needed
//! to fit `len`. Every `write` overload calls `checkExpand` exactly once per call, so a single
//! `write(byte[])` whose array is longer than `increment` bytes leaves the buffer too small,
//! and the subsequent `buffer.put(...)` call fails. This port keeps that same one-shot,
//! possibly-insufficient growth (see [`check_expand`](DBBufferOutputStream::check_expand) and
//! its test) rather than silently upgrading it to a loop that grows until big enough.

use std::io;

use crate::framework::db::DBBuffer;

/// The default `increment`, matching Java's single-argument constructor
/// `DBBufferOutputStream(DBBuffer)`, which delegates to `this(buffer, 1024)`.
const DEFAULT_INCREMENT: usize = 1024;

/// An output stream backed by a database chained buffer. Mirrors
/// `ghidra.util.database.DBBufferOutputStream`.
pub struct DBBufferOutputStream {
    buffer: Box<dyn DBBuffer>,
    increment: usize,
    offset: usize,
}

impl DBBufferOutputStream {
    /// Mirrors `DBBufferOutputStream(DBBuffer)`, which uses a 1024-byte growth increment.
    pub fn new(buffer: Box<dyn DBBuffer>) -> Self {
        Self::with_increment(buffer, DEFAULT_INCREMENT)
    }

    /// Mirrors `DBBufferOutputStream(DBBuffer, int)`.
    pub fn with_increment(buffer: Box<dyn DBBuffer>, increment: usize) -> Self {
        Self { buffer, increment, offset: 0 }
    }

    /// Mirrors the package-private `checkExpand(int)`, including its bug: growth is by exactly
    /// `increment` bytes, regardless of how large `add` actually is (see module docs).
    fn check_expand(&mut self, add: usize) -> io::Result<()> {
        let len = self.offset + add;
        if self.buffer.length() < len {
            self.buffer.set_size(self.buffer.length() + self.increment, true)?;
        }
        Ok(())
    }

    /// Finishes writing, truncating the buffer to exactly the bytes written so far, and hands
    /// the finalized buffer back to the caller. Mirrors `close()`: Java's version returns
    /// nothing because the caller already holds its own reference to the shared `DBBuffer`
    /// object, but this port's `buffer` is an owned `Box<dyn DBBuffer>` consumed by the stream,
    /// so it's returned here instead -- the same "hand the finalized resource back on close"
    /// shape as [`JarWriter::close`](crate::generic::io::JarWriter::close).
    pub fn close(mut self) -> io::Result<Box<dyn DBBuffer>> {
        self.buffer.set_size(self.offset, true)?;
        Ok(self.buffer)
    }
}

impl io::Write for DBBufferOutputStream {
    /// Mirrors `write(byte[], int, int)` (the general case Rust's `Write::write` corresponds to:
    /// a partial slice write that returns the count written).
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_expand(buf.len())?;
        self.buffer.put_all(self.offset, buf)?;
        self.offset += buf.len();
        Ok(buf.len())
    }

    /// The Java class has no `flush()` override (so `OutputStream`'s own no-op default applies);
    /// every write already goes straight through to the backing `DBBuffer`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Minimal in-memory `DBBuffer` mock, same shape as the one in `db_buffer.rs`'s own tests.
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

    fn empty_buffer() -> Box<dyn DBBuffer> {
        Box::new(MockDBBuffer { data: Vec::new() })
    }

    fn read_all(buffer: &dyn DBBuffer) -> Vec<u8> {
        let mut out = vec![0u8; buffer.length()];
        buffer.get_all(0, &mut out).unwrap();
        out
    }

    #[test]
    fn write_appends_bytes_in_order_across_multiple_calls() {
        let mut out = DBBufferOutputStream::with_increment(empty_buffer(), 8);
        out.write_all(&[1, 2, 3, 4]).unwrap();
        out.write_all(&[5, 6]).unwrap();
        let buffer = out.close().unwrap();
        assert_eq!(read_all(buffer.as_ref()), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn close_truncates_buffer_to_exact_bytes_written() {
        // A large increment means the backing buffer grows well past what's actually written
        // (64, not 3); close() must shrink it back down to exactly `offset`.
        let mut out = DBBufferOutputStream::with_increment(empty_buffer(), 64);
        out.write_all(&[1, 2, 3]).unwrap();
        let buffer = out.close().unwrap();
        assert_eq!(buffer.length(), 3);
        assert_eq!(read_all(buffer.as_ref()), vec![1, 2, 3]);
    }

    #[test]
    fn default_increment_matches_single_arg_constructor() {
        // `new` should behave identically to `with_increment(_, 1024)`: writing fewer than 1024
        // bytes should trigger exactly one growth to 1024.
        let mut out = DBBufferOutputStream::new(empty_buffer());
        out.write_all(&[9; 100]).unwrap();
        assert_eq!(out.buffer.length(), DEFAULT_INCREMENT);
    }

    /// Faithfully reproduces the genuine Java bug in `checkExpand` (see module docs): a single
    /// write larger than `increment` bytes only grows the buffer by `increment`, which can leave
    /// it too small to hold the write, causing the subsequent `put` to fail.
    #[test]
    fn write_larger_than_increment_fails_due_to_insufficient_growth() {
        let mut out = DBBufferOutputStream::with_increment(empty_buffer(), 4);
        // checkExpand(10) sees offset(0) + add(10) = 10 > buffer.length()(0), so it grows the
        // buffer to 0 + increment(4) = 4 bytes -- still far short of the 10 bytes about to be
        // written. The `put` that follows must then fail with an out-of-bounds error, exactly
        // as Java's `buffer.put(offset, b)` would throw an `IOException` in the same situation.
        let result = out.write(&[0u8; 10]);
        assert!(result.is_err(), "expected the under-grown buffer to reject the oversized write");
    }

    /// Contrast case: a write no larger than `increment` always succeeds, since one `increment`
    /// worth of growth is always enough to cover it.
    #[test]
    fn write_no_larger_than_increment_succeeds() {
        let mut out = DBBufferOutputStream::with_increment(empty_buffer(), 8);
        let result = out.write(&[0u8; 8]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 8);
    }
}
