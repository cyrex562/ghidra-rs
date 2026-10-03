//! Port of the class `ghidra.program.database.mem.FileBytes`.
//!
//! `file_bytes.rs`'s [`FileBytes`](crate::program::database::mem::file_bytes::FileBytes) trait
//! deliberately left the concrete, `DBBuffer`-backed implementation for later, "whatever concrete,
//! DB-backed implementor is written later". This is that implementor, constructed by
//! [`FileBytesAdapterV0`](crate::program::database::mem::file_bytes_adapter_v0::FileBytesAdapterV0).
//!
//! Java's real `FileBytes` splits the original bytes across an array of `DBBuffer` chains (one per
//! `MAX_BUF_SIZE`-sized chunk, since a single `ChainedBuffer` cannot grow past its implementation
//! limit) and maintains a second, parallel array of "layered" buffers used to record modifications
//! without disturbing the originals. This port keeps the chunking (`buffers`/`layered_buffers`
//! indexed by `offset / max_buf_size`) but creates each layered buffer as an eager byte-for-byte
//! copy of its corresponding original buffer at construction time, rather than Java's real
//! copy-on-write scheme (`DBHandle.createBuffer(DBBuffer sourceBuffer)`, which defers unallocated
//! pages to the source buffer lazily). This is intentionally simplified, not a stub: since original
//! bytes are documented as immutable after creation (`FileBytes.putByte`: "the original byte can
//! still be accessed... If the byte is changed more than once, only the original value is
//! preserved"), an eager copy is *observationally identical* to Java's lazy fallback for every
//! caller-visible read/write -- the only implementation difference is when the copy happens.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::framework::db::DBBuffer;
use crate::program::database::mem::file_bytes::{FileBytes, FileBytesError};

/// Concrete, `DBBuffer`-backed implementation of [`FileBytes`]. Mirrors
/// `ghidra.program.database.mem.FileBytes`.
pub struct FileBytesDB {
    key: i64,
    filename: String,
    file_offset: i64,
    size: i64,
    max_buf_size: i64,
    /// Original (immutable) bytes, chunked into one `DBBuffer` per `max_buf_size`-sized piece.
    buffers: Vec<Box<dyn DBBuffer>>,
    /// Modified bytes, chunked the same way; guarded by a `Mutex` since `FileBytes`'s mutating
    /// methods take `&self` (see that trait's module docs for why).
    layered_buffers: Mutex<Vec<Box<dyn DBBuffer>>>,
    invalid: AtomicBool,
}

impl FileBytesDB {
    /// Constructs a `FileBytesDB` from already-populated original and layered buffer chains.
    /// `layered_buffers` is expected to already contain a byte-for-byte copy of `buffers`'
    /// contents (see this module's docs for why that is a safe substitute for Java's real
    /// copy-on-write layered buffers). Mirrors `FileBytes(FileBytesAdapter, DBRecord)` (minus the
    /// `DBRecord`/adapter coupling that port's module docs explain is cut here).
    pub fn new(
        key: i64,
        filename: String,
        file_offset: i64,
        size: i64,
        max_buf_size: i64,
        buffers: Vec<Box<dyn DBBuffer>>,
        layered_buffers: Vec<Box<dyn DBBuffer>>,
    ) -> Self {
        Self {
            key,
            filename,
            file_offset,
            size,
            max_buf_size,
            buffers,
            layered_buffers: Mutex::new(layered_buffers),
            invalid: AtomicBool::new(false),
        }
    }

    /// The database record key identifying this `FileBytes` to its owning adapter. Mirrors the
    /// package-private `getId()`.
    pub fn key(&self) -> i64 {
        self.key
    }

    /// Marks this `FileBytes` as invalid, causing all subsequent access to fail. Mirrors
    /// `FileBytes.invalidate()`.
    pub fn invalidate(&self) {
        self.invalid.store(true, Ordering::SeqCst);
    }

    fn check_valid(&self) -> Result<(), FileBytesError> {
        if self.invalid.load(Ordering::SeqCst) {
            Err(FileBytesError::Invalidated)
        } else {
            Ok(())
        }
    }

    fn check_offset(&self, offset: i64) -> Result<(), FileBytesError> {
        if offset < 0 || offset >= self.size {
            return Err(FileBytesError::IndexOutOfBounds(offset.to_string()));
        }
        Ok(())
    }

    fn locate(&self, offset: i64) -> (usize, usize) {
        let index = (offset / self.max_buf_size) as usize;
        let in_buf = (offset % self.max_buf_size) as usize;
        (index, in_buf)
    }

    fn range_read(
        &self,
        offset: i64,
        b: &mut [u8],
        off: usize,
        length: usize,
        from_layered: bool,
    ) -> Result<usize, FileBytesError> {
        self.check_valid()?;
        if offset < 0 {
            return Err(FileBytesError::IndexOutOfBounds(offset.to_string()));
        }
        let available = (self.size - offset).max(0) as usize;
        let len = length.min(available);
        let mut total = 0usize;
        let mut cur = offset;
        let layered = self.layered_buffers.lock().unwrap();
        while total < len {
            let (index, in_buf) = self.locate(cur);
            let buf: &dyn DBBuffer = if from_layered {
                layered.get(index).ok_or_else(|| FileBytesError::IndexOutOfBounds(cur.to_string()))?.as_ref()
            } else {
                self.buffers.get(index).ok_or_else(|| FileBytesError::IndexOutOfBounds(cur.to_string()))?.as_ref()
            };
            let chunk_available = buf.length() - in_buf;
            let n = (len - total).min(chunk_available);
            buf.get(in_buf, b, off + total, n)?;
            total += n;
            cur += n as i64;
        }
        Ok(total)
    }
}

impl FileBytes for FileBytesDB {
    fn get_filename(&self) -> &str {
        &self.filename
    }

    fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    fn get_size(&self) -> i64 {
        self.size
    }

    fn get_id(&self) -> i64 {
        self.key
    }

    fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
        self.check_valid()?;
        self.check_offset(offset)?;
        let (index, in_buf) = self.locate(offset);
        let layered = self.layered_buffers.lock().unwrap();
        let buf = layered
            .get(index)
            .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))?;
        Ok(buf.get_byte(in_buf)?)
    }

    fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
        self.check_valid()?;
        self.check_offset(offset)?;
        let (index, in_buf) = self.locate(offset);
        let buf = self
            .buffers
            .get(index)
            .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))?;
        Ok(buf.get_byte(in_buf)?)
    }

    fn get_modified_bytes_range(
        &self,
        offset: i64,
        b: &mut [u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError> {
        self.range_read(offset, b, off, length, true)
    }

    fn get_original_bytes_range(
        &self,
        offset: i64,
        b: &mut [u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError> {
        self.range_read(offset, b, off, length, false)
    }

    fn put_byte(&self, offset: i64, b: u8) -> Result<(), FileBytesError> {
        self.check_valid()?;
        self.check_offset(offset)?;
        let (index, in_buf) = self.locate(offset);
        let mut layered = self.layered_buffers.lock().unwrap();
        let buf = layered
            .get_mut(index)
            .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))?;
        buf.put_byte(in_buf, b)?;
        Ok(())
    }

    fn put_bytes_range(
        &self,
        offset: i64,
        b: &[u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError> {
        self.check_valid()?;
        if offset < 0 {
            return Err(FileBytesError::IndexOutOfBounds(offset.to_string()));
        }
        let available = (self.size - offset).max(0) as usize;
        let len = length.min(available);
        let mut total = 0usize;
        let mut cur = offset;
        let mut layered = self.layered_buffers.lock().unwrap();
        while total < len {
            let (index, in_buf) = self.locate(cur);
            let buf = layered
                .get_mut(index)
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(cur.to_string()))?;
            let chunk_available = buf.length() - in_buf;
            let n = (len - total).min(chunk_available);
            buf.put(in_buf, b, off + total, n)?;
            total += n;
            cur += n as i64;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBBuffer};
    use std::sync::{Arc, RwLock};

    fn make_buffers(handle: &Arc<RwLock<DBHandle>>, chunk_sizes: &[usize], fill: &[u8]) -> Vec<Box<dyn DBBuffer>> {
        let mut buffers = Vec::new();
        let mut cursor = 0;
        for &len in chunk_sizes {
            let mut buf = handle.write().unwrap().create_buffer(len).unwrap();
            buf.put_all(0, &fill[cursor..cursor + len]).unwrap();
            cursor += len;
            buffers.push(buf);
        }
        buffers
    }

    fn make_layered(handle: &Arc<RwLock<DBHandle>>, chunk_sizes: &[usize], fill: &[u8]) -> Vec<Box<dyn DBBuffer>> {
        // eager copy, mirroring FileBytesAdapterV0::create_file_bytes
        make_buffers(handle, chunk_sizes, fill)
    }

    fn small_file_bytes(handle: &Arc<RwLock<DBHandle>>) -> FileBytesDB {
        let data = vec![10u8, 20, 30, 40, 50, 60];
        let buffers = make_buffers(handle, &[6], &data);
        let layered = make_layered(handle, &[6], &data);
        FileBytesDB::new(1, "orig.bin".to_string(), 0, 6, 1_000_000_000, buffers, layered)
    }

    #[test]
    fn original_and_modified_reads_agree_before_any_write() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = small_file_bytes(&handle);
        for i in 0..6 {
            assert_eq!(fb.get_original_byte(i).unwrap(), fb.get_modified_byte(i).unwrap());
        }
    }

    #[test]
    fn put_byte_changes_modified_but_not_original() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = small_file_bytes(&handle);
        fb.put_byte(2, 0xFF).unwrap();
        assert_eq!(fb.get_modified_byte(2).unwrap(), 0xFF);
        assert_eq!(fb.get_original_byte(2).unwrap(), 30);
    }

    #[test]
    fn range_reads_clamp_to_available_length() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = small_file_bytes(&handle);
        let mut out = [0u8; 10];
        let n = fb.get_original_bytes_range(4, &mut out, 0, 10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&out[..2], &[50, 60]);
    }

    #[test]
    fn multi_chunk_reads_span_buffer_boundaries() {
        // max_buf_size = 4, so offsets 0..4 live in buffer 0 and 4..6 live in buffer 1.
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let data = vec![1u8, 2, 3, 4, 5, 6];
        let buffers = make_buffers(&handle, &[4, 2], &data);
        let layered = make_layered(&handle, &[4, 2], &data);
        let fb = FileBytesDB::new(1, "a.bin".to_string(), 0, 6, 4, buffers, layered);

        let mut out = [0u8; 6];
        let n = fb.get_original_bytes_range(0, &mut out, 0, 6).unwrap();
        assert_eq!(n, 6);
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);

        // A write spanning the chunk boundary lands correctly in both chunks.
        let n = fb.put_bytes_range(3, &[0xAA, 0xBB, 0xCC], 0, 3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(fb.get_modified_byte(3).unwrap(), 0xAA);
        assert_eq!(fb.get_modified_byte(4).unwrap(), 0xBB);
        assert_eq!(fb.get_modified_byte(5).unwrap(), 0xCC);
        // Originals are unaffected.
        assert_eq!(fb.get_original_byte(3).unwrap(), 4);
        assert_eq!(fb.get_original_byte(4).unwrap(), 5);
    }

    #[test]
    fn out_of_bounds_offset_is_index_error() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = small_file_bytes(&handle);
        assert!(matches!(fb.get_original_byte(6), Err(FileBytesError::IndexOutOfBounds(_))));
        assert!(matches!(fb.get_original_byte(-1), Err(FileBytesError::IndexOutOfBounds(_))));
    }

    #[test]
    fn invalidated_file_bytes_reject_all_access() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = small_file_bytes(&handle);
        fb.invalidate();
        assert!(matches!(fb.get_original_byte(0), Err(FileBytesError::Invalidated)));
        assert!(matches!(fb.put_byte(0, 1), Err(FileBytesError::Invalidated)));
    }

    #[test]
    fn key_returns_constructor_supplied_id() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let fb = FileBytesDB::new(42, "x.bin".to_string(), 0, 1, 100, make_buffers(&handle, &[1], &[9]), make_layered(&handle, &[1], &[9]));
        assert_eq!(fb.key(), 42);
    }
}
