//! Port of `db.DBBuffer`.
//!
//! In Java, `DBBuffer` is a concrete class that wraps a `DBHandle` and a `ChainedBuffer`,
//! synchronizing every access on the handle and checking transaction/closed state before each
//! mutation or read. That coupling (`DBBuffer` -> `DBHandle` -> ... -> `DBBuffer`) is exactly the
//! cycle this port needs to cut, so the public API is modeled here as an object-safe trait instead
//! of a struct tied to concrete `DBHandle`/`ChainedBuffer` types. Implementations are expected to
//! own whatever locking/transaction-checking they need internally (mirroring the
//! `synchronized (dbh)` blocks and `dbh.checkTransaction()`/`dbh.checkIsClosed()` calls in the
//! original); this trait only captures the buffer-shaped operations callers actually use.
//!
//! `split` and `append` operate on `Box<dyn DBBuffer>` rather than a concrete type, since the
//! Java methods take/return `DBBuffer` itself.

use std::io;

/// Facilitates synchronized access to a chained buffer, mirroring `db.DBBuffer`.
pub trait DBBuffer {
    /// Split this buffer into two separate buffers. This buffer remains valid but its new size
    /// is equal to `offset`. The newly created buffer (holding everything from `offset` onward)
    /// is returned. Mirrors `DBBuffer.split(int)`.
    fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>>;

    /// Set the new size for this buffer. If `preserve_data` is true, existing data is preserved
    /// at the original offsets. Mirrors `DBBuffer.setSize(int, boolean)`.
    fn set_size(&mut self, size: usize, preserve_data: bool) -> io::Result<()>;

    /// Returns this buffer's length. Mirrors `DBBuffer.length()`.
    fn length(&self) -> usize;

    /// Get the first buffer ID associated with this chained buffer. Mirrors `DBBuffer.getId()`.
    fn get_id(&self) -> i32;

    /// Fill the buffer over `[start_offset, end_offset)` with `fill_byte`. Mirrors
    /// `DBBuffer.fill(int, int, byte)`.
    fn fill(&mut self, start_offset: usize, end_offset: usize, fill_byte: u8) -> io::Result<()>;

    /// Append the contents of `buffer` onto the end of this buffer. This buffer's size increases
    /// by the size of `buffer`. When the operation completes, `buffer` is no longer valid and
    /// must not be used. Mirrors `DBBuffer.append(DBBuffer)`.
    fn append(&mut self, buffer: Box<dyn DBBuffer>) -> io::Result<()>;

    /// Get the 8-bit byte value located at `offset`. Mirrors `DBBuffer.getByte(int)`.
    fn get_byte(&self, offset: usize) -> io::Result<u8>;

    /// Get `length` bytes located at `offset` and store into `data` starting at `data_offset`.
    /// Mirrors `DBBuffer.get(int, byte[], int, int)`.
    fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()>;

    /// Get the byte data located at `offset`, filling all of `data`. Mirrors
    /// `DBBuffer.get(int, byte[])`.
    fn get_all(&self, offset: usize, data: &mut [u8]) -> io::Result<()> {
        let length = data.len();
        self.get(offset, data, 0, length)
    }

    /// Fill the buffer with data read from `reader`. If the reader is exhausted before the
    /// buffer is full, the remainder of the buffer is filled with 0's. Mirrors
    /// `DBBuffer.fill(InputStream)`.
    fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()>;

    /// Put `length` bytes from `bytes` starting at `data_offset` into the buffer at `offset`.
    /// Mirrors `DBBuffer.put(int, byte[], int, int)`.
    fn put(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> io::Result<()>;

    /// Put all of `bytes` into the buffer at `offset`. Mirrors `DBBuffer.put(int, byte[])`.
    fn put_all(&mut self, offset: usize, bytes: &[u8]) -> io::Result<()> {
        let length = bytes.len();
        self.put(offset, bytes, 0, length)
    }

    /// Put the 8-bit byte value `b` into the buffer at `offset`. Mirrors
    /// `DBBuffer.putByte(int, byte)`.
    fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()>;

    /// Delete and release all underlying data buffers. Mirrors `DBBuffer.delete()`.
    fn delete(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory mock proving `DBBuffer` is object-safe and exercising real
    /// bounds-checked read/write/append/split behavior, standing in for the real
    /// `DBHandle`/`ChainedBuffer`-backed implementation.
    struct MockDBBuffer {
        id: i32,
        data: Vec<u8>,
    }

    impl MockDBBuffer {
        fn new(id: i32, size: usize) -> Self {
            Self {
                id,
                data: vec![0u8; size],
            }
        }
    }

    fn bounds_err() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "index out of bounds")
    }

    impl DBBuffer for MockDBBuffer {
        fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
            if offset >= self.data.len() {
                return Err(bounds_err());
            }
            let tail = self.data.split_off(offset);
            Ok(Box::new(MockDBBuffer {
                id: self.id + 1,
                data: tail,
            }))
        }

        fn set_size(&mut self, size: usize, _preserve_data: bool) -> io::Result<()> {
            self.data.resize(size, 0);
            Ok(())
        }

        fn length(&self) -> usize {
            self.data.len()
        }

        fn get_id(&self) -> i32 {
            self.id
        }

        fn fill(&mut self, start_offset: usize, end_offset: usize, fill_byte: u8) -> io::Result<()> {
            if start_offset > end_offset || end_offset > self.data.len() {
                return Err(bounds_err());
            }
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

        fn get(
            &self,
            offset: usize,
            data: &mut [u8],
            data_offset: usize,
            length: usize,
        ) -> io::Result<()> {
            if offset + length > self.data.len() || data_offset + length > data.len() {
                return Err(bounds_err());
            }
            data[data_offset..data_offset + length]
                .copy_from_slice(&self.data[offset..offset + length]);
            Ok(())
        }

        fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
            let mut buf = vec![0u8; self.data.len()];
            let mut total = 0;
            while total < buf.len() {
                let n = reader.read(&mut buf[total..])?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            self.data.copy_from_slice(&buf);
            Ok(())
        }

        fn put(
            &mut self,
            offset: usize,
            bytes: &[u8],
            data_offset: usize,
            length: usize,
        ) -> io::Result<()> {
            if offset + length > self.data.len() || data_offset + length > bytes.len() {
                return Err(bounds_err());
            }
            self.data[offset..offset + length]
                .copy_from_slice(&bytes[data_offset..data_offset + length]);
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

    fn boxed(id: i32, size: usize) -> Box<dyn DBBuffer> {
        Box::new(MockDBBuffer::new(id, size))
    }

    #[test]
    fn test_object_safety_via_trait_object() {
        let buf: Box<dyn DBBuffer> = boxed(1, 16);
        assert_eq!(buf.get_id(), 1);
        assert_eq!(buf.length(), 16);
    }

    #[test]
    fn test_put_and_get_roundtrip() {
        let mut buf = boxed(1, 16);
        buf.put_all(2, &[1, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        buf.get_all(2, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn test_put_byte_and_get_byte() {
        let mut buf = boxed(1, 8);
        buf.put_byte(3, 0xAB).unwrap();
        assert_eq!(buf.get_byte(3).unwrap(), 0xAB);
    }

    #[test]
    fn test_get_byte_out_of_bounds_errors() {
        let buf = boxed(1, 4);
        assert!(buf.get_byte(4).is_err());
    }

    #[test]
    fn test_fill_range() {
        let mut buf = boxed(1, 8);
        buf.fill(2, 6, 0x7F).unwrap();
        let mut out = [0u8; 8];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0x7F, 0x7F, 0x7F, 0x7F, 0, 0]);
    }

    #[test]
    fn test_set_size_grow_zero_fills_new_region() {
        let mut buf = boxed(1, 4);
        buf.put_all(0, &[1, 2, 3, 4]).unwrap();
        buf.set_size(8, true).unwrap();
        assert_eq!(buf.length(), 8);
        let mut out = [0u8; 8];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_split_moves_tail_into_new_buffer() {
        let mut buf = boxed(1, 8);
        buf.put_all(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let tail = buf.split(5).unwrap();
        assert_eq!(buf.length(), 5);
        assert_eq!(tail.length(), 3);
        let mut head_out = [0u8; 5];
        buf.get_all(0, &mut head_out).unwrap();
        assert_eq!(head_out, [1, 2, 3, 4, 5]);
        let mut tail_out = [0u8; 3];
        tail.get_all(0, &mut tail_out).unwrap();
        assert_eq!(tail_out, [6, 7, 8]);
    }

    #[test]
    fn test_append_concatenates_and_invalidates_source() {
        let mut buf = boxed(1, 4);
        buf.put_all(0, &[1, 2, 3, 4]).unwrap();
        let mut other = boxed(2, 3);
        other.put_all(0, &[9, 8, 7]).unwrap();

        buf.append(other).unwrap();
        assert_eq!(buf.length(), 7);
        let mut out = [0u8; 7];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 9, 8, 7]);
    }

    #[test]
    fn test_fill_from_reader_zero_fills_remainder_on_exhaustion() {
        let mut buf = boxed(1, 6);
        let mut reader: &[u8] = &[10, 20, 30];
        buf.fill_from_reader(&mut reader).unwrap();
        let mut out = [0u8; 6];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [10, 20, 30, 0, 0, 0]);
    }

    #[test]
    fn test_delete_clears_buffer() {
        let mut buf = boxed(1, 4);
        buf.delete().unwrap();
        assert_eq!(buf.length(), 0);
    }
}
