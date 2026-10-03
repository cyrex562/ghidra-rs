//! Real, `ChainedBuffer`-backed implementation of the [`DBBuffer`] trait.
//!
//! `db_buffer.rs`'s module docs note that its trait is modeled directly off Java's concrete
//! `db.DBBuffer` class, and that every implementor in this crate up to now has been an in-memory
//! test mock "standing in for the real `DBHandle`/`ChainedBuffer`-backed implementation". This
//! module is that real implementation: a thin wrapper around [`ChainedBuffer`] (which already owns
//! the actual paging/allocation logic over a [`BufferMgr`](super::buffer_mgr::BufferMgr)),
//! constructed via [`DBHandle::create_buffer`](super::db_handle::DBHandle::create_buffer) and
//! [`DBHandle::get_buffer`](super::db_handle::DBHandle::get_buffer).
//!
//! `append` is implemented by copying the other buffer's bytes through its public `DBBuffer`
//! surface (`length`/`get_all`) rather than downcasting it to a `ChainedBuffer`, mirroring the same
//! workaround already used by
//! [`BufferSubMemoryBlock::join`](crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock::join)
//! for an identical "need to consume a `Box<dyn Trait>`'s private concrete state" problem: `append`
//! only needs the other buffer's bytes (to concatenate them and then discard the source), and
//! `DBBuffer`'s own public methods already provide that without any unsafe downcasting.

use std::io;

use super::buffer::Buffer;
use super::chained_buffer::ChainedBuffer;
use super::db_buffer::DBBuffer;

/// Wraps a [`ChainedBuffer`] to implement [`DBBuffer`]. Mirrors `db.DBBuffer`.
pub struct DBBufferImpl {
    chained: ChainedBuffer,
}

impl DBBufferImpl {
    /// Wraps an already-constructed `ChainedBuffer`. Used by
    /// [`DBHandle::create_buffer`](super::db_handle::DBHandle::create_buffer) and
    /// [`DBHandle::get_buffer`](super::db_handle::DBHandle::get_buffer).
    pub(crate) fn new(chained: ChainedBuffer) -> Self {
        Self { chained }
    }

    fn bounds_err() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "index out of bounds")
    }

    fn check_bounds(&self, offset: usize, length: usize) -> io::Result<()> {
        if offset.checked_add(length).map(|end| end > self.chained.length()).unwrap_or(true) {
            return Err(Self::bounds_err());
        }
        Ok(())
    }
}

impl DBBuffer for DBBufferImpl {
    fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
        let tail = self.chained.split(offset)?;
        Ok(Box::new(DBBufferImpl::new(tail)))
    }

    fn set_size(&mut self, size: usize, preserve_data: bool) -> io::Result<()> {
        self.chained.set_size(size, preserve_data)
    }

    fn length(&self) -> usize {
        self.chained.length()
    }

    fn get_id(&self) -> i32 {
        self.chained.get_id()
    }

    fn fill(&mut self, start_offset: usize, end_offset: usize, fill_byte: u8) -> io::Result<()> {
        if start_offset > end_offset {
            return Err(Self::bounds_err());
        }
        self.check_bounds(start_offset, end_offset - start_offset)?;
        let data = vec![fill_byte; end_offset - start_offset];
        if self.chained.put(start_offset, &data) < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer full"));
        }
        Ok(())
    }

    fn append(&mut self, mut buffer: Box<dyn DBBuffer>) -> io::Result<()> {
        let len = buffer.length();
        let mut tail = vec![0u8; len];
        buffer.get_all(0, &mut tail)?;
        let old_size = self.chained.length();
        self.chained.set_size(old_size + len, true)?;
        if self.chained.put(old_size, &tail) < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer full"));
        }
        buffer.delete()
    }

    fn get_byte(&self, offset: usize) -> io::Result<u8> {
        self.check_bounds(offset, 1)?;
        Ok(self.chained.get_byte(offset))
    }

    fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()> {
        self.check_bounds(offset, length)?;
        if data_offset.checked_add(length).map(|end| end > data.len()).unwrap_or(true) {
            return Err(Self::bounds_err());
        }
        self.chained.get_into(offset, data, data_offset, length);
        Ok(())
    }

    fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
        let len = self.chained.length();
        let mut buf = vec![0u8; len];
        let mut total = 0usize;
        while total < len {
            let n = reader.read(&mut buf[total..])?;
            if n == 0 {
                break;
            }
            total += n;
        }
        if self.chained.put(0, &buf) < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer full"));
        }
        Ok(())
    }

    fn put(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> io::Result<()> {
        self.check_bounds(offset, length)?;
        if data_offset.checked_add(length).map(|end| end > bytes.len()).unwrap_or(true) {
            return Err(Self::bounds_err());
        }
        if self
            .chained
            .put_from(offset, bytes, data_offset, length)
            < 0
        {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer full"));
        }
        Ok(())
    }

    fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()> {
        self.check_bounds(offset, 1)?;
        if self.chained.put_byte(offset, b) < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer full"));
        }
        Ok(())
    }

    fn delete(&mut self) -> io::Result<()> {
        self.chained.delete()
    }
}

#[cfg(test)]
mod tests {
    use super::super::buffer_mgr::BufferMgr;
    use super::*;
    use std::sync::{Arc, RwLock};

    fn mgr() -> Arc<RwLock<BufferMgr>> {
        Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)))
    }

    fn make(len: usize) -> (Arc<RwLock<BufferMgr>>, DBBufferImpl) {
        let m = mgr();
        let cb = ChainedBuffer::new(len, false, None, 0, m.clone()).unwrap();
        (m, DBBufferImpl::new(cb))
    }

    #[test]
    fn put_and_get_round_trip() {
        let (_m, mut buf) = make(16);
        buf.put_all(2, &[1, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        buf.get_all(2, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn newly_created_buffer_is_zero_filled() {
        let (_m, buf) = make(8);
        let mut out = [0u8; 8];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0u8; 8]);
    }

    #[test]
    fn fill_range_sets_bytes() {
        let (_m, mut buf) = make(8);
        buf.fill(2, 6, 0x7F).unwrap();
        let mut out = [0u8; 8];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0x7F, 0x7F, 0x7F, 0x7F, 0, 0]);
    }

    #[test]
    fn split_moves_tail_into_new_real_buffer() {
        let (_m, mut buf) = make(8);
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
    fn append_concatenates_across_two_real_buffers() {
        let m = mgr();
        let cb1 = ChainedBuffer::new(4, false, None, 0, m.clone()).unwrap();
        let cb2 = ChainedBuffer::new(3, false, None, 0, m.clone()).unwrap();
        let mut buf: Box<dyn DBBuffer> = Box::new(DBBufferImpl::new(cb1));
        let mut other: Box<dyn DBBuffer> = Box::new(DBBufferImpl::new(cb2));
        buf.put_all(0, &[1, 2, 3, 4]).unwrap();
        other.put_all(0, &[9, 8, 7]).unwrap();

        buf.append(other).unwrap();
        assert_eq!(buf.length(), 7);
        let mut out = [0u8; 7];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 9, 8, 7]);
    }

    #[test]
    fn get_byte_out_of_bounds_errors_instead_of_panicking() {
        let (_m, buf) = make(4);
        assert!(buf.get_byte(4).is_err());
    }

    #[test]
    fn set_size_grow_zero_fills_new_region() {
        let (_m, mut buf) = make(4);
        buf.put_all(0, &[1, 2, 3, 4]).unwrap();
        buf.set_size(8, true).unwrap();
        assert_eq!(buf.length(), 8);
        let mut out = [0u8; 8];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn delete_clears_buffer() {
        let (_m, mut buf) = make(4);
        buf.delete().unwrap();
        assert_eq!(buf.length(), 0);
    }
}
