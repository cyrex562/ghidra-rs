//! Trait ported from the abstract class `ghidra.program.database.mem.FileBytesAdapter`.
//!
//! In Java, `FileBytesAdapter` is a package-private abstract base class that reads/writes the
//! "File Bytes" table backing a `MemoryMapDB`'s original-file-byte storage, and is implemented by
//! `FileBytesAdapterV0` (the current schema) and `FileBytesAdapterNoTable` (a stand-in used when no
//! table exists yet), selected at open time via the static `getAdapter` factory based on the
//! on-disk schema version. It holds a `protected MemoryMapDB memMap` field alongside `FileBytes`
//! creation/lookup methods -- exactly the coupling (`MemoryMapDB` -> `FileBytesAdapter` ->
//! `FileBytes`/`MemoryMapDB`) this port needs to cut. That `memMap` field is never read or written
//! anywhere in this base class's own methods (only by not-yet-ported subclasses), so no trait
//! method models it. The static factory methods (`getAdapter`, `findReadOnlyAdapter`, `upgrade`)
//! construct concrete `FileBytesAdapterV0`/`FileBytesAdapterNoTable` instances, and the V0-schema
//! column constants (`FILENAME_COL`, `OFFSET_COL`, etc.) belong to that not-yet-ported subclass, so
//! only the instance-level abstract methods -- the adapter's actual public contract -- are mapped
//! onto this trait. The test-only `getMaxBufferSize`/`setMaxBufferSize` statics are likewise
//! omitted as out of scope for the trait's contract.
//!
//! `FileBytes` is exposed through the [`FileBytes`](crate::program::database::mem::file_bytes::FileBytes)
//! trait object rather than a concrete struct, so that neither `MemoryMapDB` nor `FileBytes` need
//! to depend on this trait to remain independently portable/testable.

use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Arc;

use crate::framework::db::DBBuffer;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::util::exception::IOCancelledException;
use crate::util::task::TaskMonitor;

/// Error type aggregating the exceptions thrown by Java's `FileBytesAdapter.createFileBytes`
/// (`IOException`, and the unchecked `IOCancelledException` raised if `monitor` is cancelled
/// mid-read).
#[derive(Debug)]
pub enum FileBytesAdapterError {
    /// Mirrors `IOException`: a database or stream I/O error occurred.
    Io(io::Error),
    /// Mirrors `IOCancelledException`: the read was cancelled via the task monitor.
    Cancelled(IOCancelledException),
}

impl fmt::Display for FileBytesAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Cancelled(err) => write!(f, "{err}"),
        }
    }
}

impl Error for FileBytesAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Cancelled(err) => Some(err),
        }
    }
}

impl From<io::Error> for FileBytesAdapterError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<IOCancelledException> for FileBytesAdapterError {
    fn from(err: IOCancelledException) -> Self {
        Self::Cancelled(err)
    }
}

/// Reads/writes the "File Bytes" table backing a `MemoryMapDB`'s original-file-byte storage.
pub trait FileBytesAdapter: Send + Sync {
    /// Creates a `FileBytes` from the specified input stream: `offset` is the position of `is`
    /// within the original file (or 0 if there is no file), and `size` is the number of bytes to
    /// read from `is` for the stored file bytes. `monitor` reports progress and allows
    /// cancellation, though it is ignored while `is` is itself already monitored. Mirrors
    /// `FileBytesAdapter.createFileBytes(String, long, long, InputStream, TaskMonitor)`.
    fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn io::Read,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, FileBytesAdapterError>;

    /// Returns the `DBBuffer` for the given database buffer id, or `None` if `buffer_id` is
    /// negative. Mirrors `FileBytesAdapter.getBuffer(int)`.
    fn get_buffer(&self, buffer_id: i32) -> io::Result<Option<Box<dyn DBBuffer>>>;

    /// Returns a layered `DBBuffer` for the given database buffer id using `shadow_buffer` for
    /// byte values not explicitly set in this buffer, or `None` if `buffer_id` is negative.
    /// Mirrors `FileBytesAdapter.getBuffer(int, DBBuffer)`.
    fn get_buffer_with_shadow(
        &self,
        buffer_id: i32,
        shadow_buffer: Box<dyn DBBuffer>,
    ) -> io::Result<Option<Box<dyn DBBuffer>>>;

    /// Returns all stored `FileBytes`. Mirrors `FileBytesAdapter.getAllFileBytes()`.
    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>>;

    /// Reloads file bytes state from the database. Mirrors `FileBytesAdapter.refresh()`.
    fn refresh(&mut self) -> io::Result<()>;

    /// Deletes the given `FileBytes`, returning `true` if it was found and deleted. Mirrors
    /// `FileBytesAdapter.deleteFileBytes(FileBytes)`.
    fn delete_file_bytes(&mut self, file_bytes: &Arc<dyn FileBytes>) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::file_bytes::FileBytesError;
    use std::collections::HashMap;

    /// Minimal in-memory `DBBuffer` used only to exercise `get_buffer` round-tripping.
    struct MockBuffer {
        id: i32,
        data: Vec<u8>,
    }

    impl DBBuffer for MockBuffer {
        fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
            let tail = self.data.split_off(offset);
            Ok(Box::new(MockBuffer {
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
            Ok(self.data[offset])
        }
        fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()> {
            data[data_offset..data_offset + length].copy_from_slice(&self.data[offset..offset + length]);
            Ok(())
        }
        fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
            let mut total = 0;
            while total < self.data.len() {
                let n = reader.read(&mut self.data[total..])?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            Ok(())
        }
        fn put(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> io::Result<()> {
            self.data[offset..offset + length].copy_from_slice(&bytes[data_offset..data_offset + length]);
            Ok(())
        }
        fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()> {
            self.data[offset] = b;
            Ok(())
        }
        fn delete(&mut self) -> io::Result<()> {
            self.data.clear();
            Ok(())
        }
    }

    /// A minimal in-memory `FileBytes` record used only by these adapter smoke tests; the byte
    /// access contract itself is exercised in more depth by `file_bytes`'s own tests.
    struct MockFileBytesEntry {
        filename: String,
        data: Vec<u8>,
    }

    impl FileBytes for MockFileBytesEntry {
        fn get_filename(&self) -> &str {
            &self.filename
        }
        fn get_file_offset(&self) -> i64 {
            0
        }
        fn get_size(&self) -> i64 {
            self.data.len() as i64
        }
        fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.get_original_byte(offset)
        }
        fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))
        }
        fn get_modified_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.get_original_bytes_range(offset, b, off, length)
        }
        fn get_original_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            let start = offset as usize;
            let available = self.data.len().saturating_sub(start);
            let n = length.min(available);
            b[off..off + n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn put_byte(&self, _offset: i64, _b: u8) -> Result<(), FileBytesError> {
            Err(FileBytesError::Invalidated)
        }
        fn put_bytes_range(
            &self,
            _offset: i64,
            _b: &[u8],
            _off: usize,
            _length: usize,
        ) -> Result<usize, FileBytesError> {
            Err(FileBytesError::Invalidated)
        }
    }

    /// A minimal `FileBytesAdapter` proving the trait is object-safe and that its methods behave
    /// sensibly against real (non-trivial) in-memory state, standing in for the real
    /// DB-backed `FileBytesAdapterV0`.
    struct MockAdapter {
        entries: Vec<Arc<dyn FileBytes>>,
        buffers: HashMap<i32, Vec<u8>>,
        next_buffer_id: i32,
    }

    impl MockAdapter {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
                buffers: HashMap::new(),
                next_buffer_id: 0,
            }
        }
    }

    impl FileBytesAdapter for MockAdapter {
        fn create_file_bytes(
            &mut self,
            filename: &str,
            _offset: i64,
            size: i64,
            is: &mut dyn io::Read,
            monitor: &dyn TaskMonitor,
        ) -> Result<Arc<dyn FileBytes>, FileBytesAdapterError> {
            let mut bytes = vec![0u8; size as usize];
            let mut total = 0usize;
            while total < bytes.len() {
                if monitor.is_cancelled() {
                    return Err(IOCancelledException::new().into());
                }
                let n = is.read(&mut bytes[total..])?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            let buffer_id = self.next_buffer_id;
            self.next_buffer_id += 1;
            self.buffers.insert(buffer_id, bytes.clone());
            let entry: Arc<dyn FileBytes> = Arc::new(MockFileBytesEntry {
                filename: filename.to_string(),
                data: bytes,
            });
            self.entries.push(entry.clone());
            Ok(entry)
        }

        fn get_buffer(&self, buffer_id: i32) -> io::Result<Option<Box<dyn DBBuffer>>> {
            if buffer_id < 0 {
                return Ok(None);
            }
            let data = self
                .buffers
                .get(&buffer_id)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such buffer"))?;
            Ok(Some(Box::new(MockBuffer { id: buffer_id, data })))
        }

        fn get_buffer_with_shadow(
            &self,
            buffer_id: i32,
            _shadow_buffer: Box<dyn DBBuffer>,
        ) -> io::Result<Option<Box<dyn DBBuffer>>> {
            self.get_buffer(buffer_id)
        }

        fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
            self.entries.clone()
        }

        fn refresh(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn delete_file_bytes(&mut self, file_bytes: &Arc<dyn FileBytes>) -> io::Result<bool> {
            let before = self.entries.len();
            self.entries.retain(|e| !Arc::ptr_eq(e, file_bytes));
            Ok(self.entries.len() < before)
        }
    }

    struct AlwaysCancelledMonitor;

    impl TaskMonitor for AlwaysCancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Err(crate::util::exception::CancelledException::default())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    struct NeverCancelledMonitor;

    impl TaskMonitor for NeverCancelledMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn create_file_bytes_reads_stream_and_registers_buffer() {
        let mut adapter = MockAdapter::new();
        let mut reader: &[u8] = &[1, 2, 3, 4];
        let monitor = NeverCancelledMonitor;
        let fb = adapter
            .create_file_bytes("orig.bin", 0, 4, &mut reader, &monitor)
            .unwrap();
        assert_eq!(adapter.get_all_file_bytes().len(), 1);
        assert!(Arc::ptr_eq(&fb, &adapter.get_all_file_bytes()[0]));
    }

    #[test]
    fn create_file_bytes_propagates_cancellation() {
        let mut adapter = MockAdapter::new();
        let mut reader: &[u8] = &[1, 2, 3, 4];
        let monitor = AlwaysCancelledMonitor;
        let result = adapter.create_file_bytes("orig.bin", 0, 4, &mut reader, &monitor);
        match result {
            Err(FileBytesAdapterError::Cancelled(_)) => {}
            other => panic!("expected Cancelled error, got {}", other.is_ok()),
        }
    }

    #[test]
    fn get_all_file_bytes_reflects_creates_and_deletes() {
        let mut adapter = MockAdapter::new();
        let monitor = NeverCancelledMonitor;
        let mut r1: &[u8] = &[1, 2];
        let mut r2: &[u8] = &[3, 4];
        adapter
            .create_file_bytes("a.bin", 0, 2, &mut r1, &monitor)
            .unwrap();
        let fb2 = adapter
            .create_file_bytes("b.bin", 0, 2, &mut r2, &monitor)
            .unwrap();
        assert_eq!(adapter.get_all_file_bytes().len(), 2);

        assert!(adapter.delete_file_bytes(&fb2).unwrap());
        assert_eq!(adapter.get_all_file_bytes().len(), 1);
        assert!(!adapter.delete_file_bytes(&fb2).unwrap());
    }

    #[test]
    fn get_buffer_negative_id_returns_none() {
        let adapter = MockAdapter::new();
        assert!(adapter.get_buffer(-1).unwrap().is_none());
    }

    #[test]
    fn get_buffer_round_trips_created_data() {
        let mut adapter = MockAdapter::new();
        let monitor = NeverCancelledMonitor;
        let mut reader: &[u8] = &[0xAB, 0xCD];
        adapter
            .create_file_bytes("a.bin", 0, 2, &mut reader, &monitor)
            .unwrap();
        let buf = adapter.get_buffer(0).unwrap().unwrap();
        let mut out = [0u8; 2];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0xAB, 0xCD]);
    }

    #[test]
    fn get_buffer_with_shadow_delegates() {
        let mut adapter = MockAdapter::new();
        let monitor = NeverCancelledMonitor;
        let mut reader: &[u8] = &[9, 9];
        adapter
            .create_file_bytes("a.bin", 0, 2, &mut reader, &monitor)
            .unwrap();
        let shadow: Box<dyn DBBuffer> = Box::new(MockBuffer {
            id: 999,
            data: vec![0, 0],
        });
        let buf = adapter.get_buffer_with_shadow(0, shadow).unwrap().unwrap();
        assert_eq!(buf.length(), 2);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut adapter: Box<dyn FileBytesAdapter> = Box::new(MockAdapter::new());
        adapter.refresh().unwrap();
        assert!(adapter.get_all_file_bytes().is_empty());
    }
}
