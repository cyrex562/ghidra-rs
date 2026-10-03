//! Port of the class `ghidra.program.database.mem.FileBytesAdapterV0`.
//!
//! Current (and only ever) schema version of the "File Bytes" table: `[Filename: String, Offset:
//! Long, Size: Long, Chain Buffer IDs: Binary, Layered Chain Buffer IDs: Binary]`. The two
//! `Binary` columns hold big-endian-encoded `i32` arrays -- one buffer id per `max_buf_size`-sized
//! chunk -- standing in for Java's `BinaryCodedField(int[])`, whose exact on-disk byte layout this
//! port does not need to match since both the encoder and decoder live here.
//!
//! **Real, `DBHandle`-backed buffers.** [`create_file_bytes`](FileBytesAdapterV0::create_file_bytes)
//! creates real, chunked [`DBBuffer`] chains via `DBHandle::create_buffer` (see
//! `db_buffer_impl.rs`'s module docs), matching Java's `createBuffers`/`createLayeredBuffers`
//! chunking logic (splitting into `ceil(size / max_buf_size)` pieces). The "layered" buffers are
//! populated with an eager copy of the original bytes rather than Java's lazy copy-on-write scheme;
//! see [`FileBytesDB`](crate::program::database::mem::file_bytes_db::FileBytesDB)'s module docs for
//! why that is a safe, observationally-identical simplification.
//!
//! **Cancellation.** Java's `createBuffers` wraps `is` in a `MonitoredInputStream` and lets
//! `DBBuffer.fill(InputStream)` do the chunked reading/cancellation-checking internally. This
//! port's [`DBBuffer::fill_from_reader`](crate::framework::db::DBBuffer::fill_from_reader) has no
//! cancellation hook, so [`create_file_bytes`](FileBytesAdapterV0::create_file_bytes) instead reads
//! `is` in fixed-size chunks itself, checking `monitor.is_cancelled()` between chunks and returning
//! [`FileBytesAdapterError::Cancelled`] if so -- the same observable cancellation granularity Java
//! provides (checked periodically during the read, not byte-by-byte).
//!
//! **`getMaxBufferSize`/`setMaxBufferSize`.** Java shadows these as a *static* field on the whole
//! `FileBytesAdapter` class (a well-known test-only global, per that field's own "shadowed so that
//! it can be changed for testing" comment). This port instead makes `max_buf_size` a per-adapter
//! constructor parameter (defaulting to [`DEFAULT_MAX_BUFFER_SIZE`], matching Java's
//! `MAX_BUF_SIZE`), avoiding a mutable global while still letting tests exercise multi-buffer
//! chunking with a small value.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBBuffer, DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::file_bytes_adapter::{FileBytesAdapter, FileBytesAdapterError};
use crate::program::database::mem::file_bytes_db::FileBytesDB;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the database table used to store file bytes. Mirrors `FileBytesAdapterV0.TABLE_NAME`.
pub const TABLE_NAME: &str = "File Bytes";

/// Schema version. Mirrors `FileBytesAdapterV0.VERSION`.
pub const VERSION: i32 = 0;

/// Mirrors `FileBytesAdapterV0.V0_FILENAME_COL`.
pub const V0_FILENAME_COL: usize = 0;
/// Mirrors `FileBytesAdapterV0.V0_OFFSET_COL`.
pub const V0_OFFSET_COL: usize = 1;
/// Mirrors `FileBytesAdapterV0.V0_SIZE_COL`.
pub const V0_SIZE_COL: usize = 2;
/// Mirrors `FileBytesAdapterV0.V0_BUF_IDS_COL`.
pub const V0_BUF_IDS_COL: usize = 3;
/// Mirrors `FileBytesAdapterV0.V0_LAYERED_BUF_IDS_COL`.
pub const V0_LAYERED_BUF_IDS_COL: usize = 4;

/// Mirrors `FileBytesAdapter.MAX_BUF_SIZE`.
pub const DEFAULT_MAX_BUFFER_SIZE: i64 = 1_000_000_000;

/// Size of each chunk read from the input stream between cancellation checks. Not present in Java
/// (whose `MonitoredInputStream` checks cancellation on every read call); chosen small enough to
/// give responsive cancellation without a syscall/lock-check per byte.
const READ_CHUNK_SIZE: usize = 64 * 1024;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String,
            FieldType::Long,
            FieldType::Long,
            FieldType::Binary,
            FieldType::Binary,
        ],
        vec![
            "Filename".to_string(),
            "Offset".to_string(),
            "Size".to_string(),
            "Chain Buffer IDs".to_string(),
            "Layered Chain Buffer IDs".to_string(),
        ],
        vec![],
    ))
}

fn encode_ids(ids: &[i32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ids.len() * 4);
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

fn decode_ids(bytes: &[u8]) -> Vec<i32> {
    bytes
        .chunks_exact(4)
        .map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Splits `size` into `max_buf_size`-sized chunks, mirroring the chunk-count/last-chunk-size math
/// in Java's `FileBytesAdapterV0.createBuffers`.
fn chunk_sizes(size: i64, max_buf_size: i64) -> Vec<usize> {
    if size == 0 {
        return Vec::new();
    }
    let mut buf_count = (size / max_buf_size) as usize;
    let mut last = (size % max_buf_size) as usize;
    if last > 0 {
        buf_count += 1;
    } else {
        last = max_buf_size as usize;
    }
    let mut sizes = vec![max_buf_size as usize; buf_count.saturating_sub(1)];
    sizes.push(last);
    sizes
}

/// Current schema version of the "File Bytes" table. Mirrors
/// `ghidra.program.database.mem.FileBytesAdapterV0`.
pub struct FileBytesAdapterV0 {
    handle: Arc<RwLock<DBHandle>>,
    table: Arc<RwLock<Table>>,
    max_buf_size: i64,
    file_bytes_list: Vec<(i64, Arc<dyn FileBytes>)>,
}

impl FileBytesAdapterV0 {
    /// Opens (or creates) the "File Bytes" table. Mirrors `FileBytesAdapterV0(DBHandle, boolean)`,
    /// with `max_buf_size` as an explicit parameter (see this module's docs for why).
    ///
    /// # Errors
    /// Returns a [`VersionException`] if `create` is false and the table is missing or its schema
    /// version does not match [`VERSION`].
    pub fn new(handle: Arc<RwLock<DBHandle>>, create: bool, max_buf_size: i64) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .write()
                .unwrap()
                .create_table(TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .read()
                .unwrap()
                .get_table(TABLE_NAME)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != VERSION {
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };

        let mut file_bytes_list = Vec::new();
        {
            let table_ref = table.read().unwrap();
            let mut it = table_ref.get_record_iterator().map_err(|e| VersionException::with_message(e.to_string()))?;
            while let Some(rec) = it.next().map_err(|e| VersionException::with_message(e.to_string()))? {
                let key = match rec.get_key() {
                    Field::Long(Some(k)) => *k,
                    _ => 0,
                };
                let fb = Self::build_file_bytes(&handle, &rec, key, max_buf_size)
                    .map_err(|e| VersionException::with_message(e.to_string()))?;
                file_bytes_list.push((key, fb));
            }
        }

        Ok(Self {
            handle,
            table,
            max_buf_size,
            file_bytes_list,
        })
    }

    fn build_file_bytes(
        handle: &Arc<RwLock<DBHandle>>,
        rec: &DBRecord,
        key: i64,
        max_buf_size: i64,
    ) -> io::Result<Arc<dyn FileBytes>> {
        let filename = rec.get_string(V0_FILENAME_COL).unwrap_or("").to_string();
        let offset = rec.get_long(V0_OFFSET_COL).unwrap_or(0);
        let size = rec.get_long(V0_SIZE_COL).unwrap_or(0);
        let buf_ids = decode_ids(rec.get_field(V0_BUF_IDS_COL).get_binary_data().unwrap_or(&[]));
        let layered_ids = decode_ids(rec.get_field(V0_LAYERED_BUF_IDS_COL).get_binary_data().unwrap_or(&[]));

        let h = handle.read().unwrap();
        let buffers: Vec<Box<dyn DBBuffer>> = buf_ids.iter().map(|&id| h.get_buffer(id)).collect::<io::Result<_>>()?;
        let layered: Vec<Box<dyn DBBuffer>> = layered_ids.iter().map(|&id| h.get_buffer(id)).collect::<io::Result<_>>()?;

        Ok(Arc::new(FileBytesDB::new(key, filename, offset, size, max_buf_size, buffers, layered)))
    }

    fn read_all_cancellable(
        &self,
        is: &mut dyn io::Read,
        size: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<u8>, FileBytesAdapterError> {
        let mut data = vec![0u8; size as usize];
        let mut total = 0usize;
        while total < data.len() {
            if monitor.is_cancelled() {
                return Err(crate::util::exception::IOCancelledException::new().into());
            }
            let end = (total + READ_CHUNK_SIZE).min(data.len());
            let n = is.read(&mut data[total..end])?;
            if n == 0 {
                break; // remainder stays zero-filled, mirroring DBBuffer.fill(InputStream)
            }
            total += n;
        }
        Ok(data)
    }
}

impl FileBytesAdapter for FileBytesAdapterV0 {
    fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn io::Read,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, FileBytesAdapterError> {
        monitor.initialize(size);
        let data = self.read_all_cancellable(is, size, monitor)?;

        let sizes = chunk_sizes(size, self.max_buf_size);
        let mut buffers: Vec<Box<dyn DBBuffer>> = Vec::with_capacity(sizes.len());
        let mut layered: Vec<Box<dyn DBBuffer>> = Vec::with_capacity(sizes.len());
        let mut buf_ids = Vec::with_capacity(sizes.len());
        let mut layered_ids = Vec::with_capacity(sizes.len());
        let mut cursor = 0usize;
        for &chunk_len in &sizes {
            let mut buf = self.handle.write().unwrap().create_buffer(chunk_len)?;
            buf.put_all(0, &data[cursor..cursor + chunk_len])?;
            buf_ids.push(buf.get_id());

            // Eager copy for the layered (modified-bytes) buffer -- see this module's docs.
            let mut layer = self.handle.write().unwrap().create_buffer(chunk_len)?;
            layer.put_all(0, &data[cursor..cursor + chunk_len])?;
            layered_ids.push(layer.get_id());

            buffers.push(buf);
            layered.push(layer);
            cursor += chunk_len;
        }

        let key = self.table.write().unwrap().get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_string(V0_FILENAME_COL, Some(filename.to_string()));
        record.set_long(V0_OFFSET_COL, offset);
        record.set_long(V0_SIZE_COL, size);
        record.set_field(V0_BUF_IDS_COL, Field::Binary(Some(encode_ids(&buf_ids))));
        record.set_field(V0_LAYERED_BUF_IDS_COL, Field::Binary(Some(encode_ids(&layered_ids))));
        self.table.write().unwrap().put_record(record)?;

        let file_bytes: Arc<dyn FileBytes> =
            Arc::new(FileBytesDB::new(key, filename.to_string(), offset, size, self.max_buf_size, buffers, layered));
        self.file_bytes_list.push((key, file_bytes.clone()));
        Ok(file_bytes)
    }

    fn get_buffer(&self, buffer_id: i32) -> io::Result<Option<Box<dyn DBBuffer>>> {
        if buffer_id >= 0 {
            return Ok(Some(self.handle.read().unwrap().get_buffer(buffer_id)?));
        }
        Ok(None)
    }

    fn get_buffer_with_shadow(
        &self,
        buffer_id: i32,
        shadow_buffer: Box<dyn DBBuffer>,
    ) -> io::Result<Option<Box<dyn DBBuffer>>> {
        // The layered buffer this adapter creates already contains an eager copy of the shadow
        // buffer's bytes (see this module's docs), so there is nothing further to layer here;
        // `shadow_buffer` is accepted (matching the trait/Java signature) but not needed.
        let _ = shadow_buffer;
        self.get_buffer(buffer_id)
    }

    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        self.file_bytes_list.iter().map(|(_, fb)| fb.clone()).collect()
    }

    fn refresh(&mut self) -> io::Result<()> {
        let mut new_list = Vec::new();
        {
            let table_ref = self.table.read().unwrap();
            let mut it = table_ref.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                let key = match rec.get_key() {
                    Field::Long(Some(k)) => *k,
                    _ => 0,
                };
                if let Some((_, existing)) = self.file_bytes_list.iter().find(|(k, _)| *k == key) {
                    new_list.push((key, existing.clone()));
                } else {
                    let fb = Self::build_file_bytes(&self.handle, &rec, key, self.max_buf_size)?;
                    new_list.push((key, fb));
                }
            }
        }
        self.file_bytes_list = new_list;
        Ok(())
    }

    fn delete_file_bytes(&mut self, file_bytes: &Arc<dyn FileBytes>) -> io::Result<bool> {
        let before = self.file_bytes_list.len();
        let mut deleted_key = None;
        self.file_bytes_list.retain(|(k, fb)| {
            if Arc::ptr_eq(fb, file_bytes) {
                deleted_key = Some(*k);
                false
            } else {
                true
            }
        });
        if let Some(key) = deleted_key {
            self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        }
        Ok(self.file_bytes_list.len() < before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    fn open_create(max_buf_size: i64) -> (Arc<RwLock<DBHandle>>, FileBytesAdapterV0) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = FileBytesAdapterV0::new(handle.clone(), true, max_buf_size).unwrap();
        (handle, adapter)
    }

    #[test]
    fn new_with_create_false_and_no_table_is_version_exception() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let err = FileBytesAdapterV0::new(handle, false, DEFAULT_MAX_BUFFER_SIZE).err().unwrap();
        assert!(err.is_upgradable());
    }

    #[test]
    fn create_file_bytes_round_trips_through_real_buffers() {
        let (_h, mut adapter) = open_create(DEFAULT_MAX_BUFFER_SIZE);
        let mut reader: &[u8] = &[1, 2, 3, 4, 5];
        let monitor = DummyMonitor;
        let fb = adapter.create_file_bytes("orig.bin", 0x10, 5, &mut reader, &monitor).unwrap();
        assert_eq!(fb.get_filename(), "orig.bin");
        assert_eq!(fb.get_file_offset(), 0x10);
        assert_eq!(fb.get_size(), 5);
        for i in 0..5 {
            assert_eq!(fb.get_original_byte(i).unwrap(), (i + 1) as u8);
            assert_eq!(fb.get_modified_byte(i).unwrap(), (i + 1) as u8);
        }
    }

    #[test]
    fn create_file_bytes_zero_fills_remainder_on_stream_exhaustion() {
        let (_h, mut adapter) = open_create(DEFAULT_MAX_BUFFER_SIZE);
        let mut reader: &[u8] = &[9, 9];
        let monitor = DummyMonitor;
        let fb = adapter.create_file_bytes("a.bin", 0, 5, &mut reader, &monitor).unwrap();
        assert_eq!(fb.get_original_byte(0).unwrap(), 9);
        assert_eq!(fb.get_original_byte(1).unwrap(), 9);
        assert_eq!(fb.get_original_byte(2).unwrap(), 0);
        assert_eq!(fb.get_original_byte(4).unwrap(), 0);
    }

    #[test]
    fn create_file_bytes_chunks_across_multiple_buffers() {
        // 4-byte max chunk, 10-byte file -> 3 chunks (4, 4, 2).
        let (_h, mut adapter) = open_create(4);
        let data: Vec<u8> = (0u8..10).collect();
        let mut reader: &[u8] = &data;
        let monitor = DummyMonitor;
        let fb = adapter.create_file_bytes("a.bin", 0, 10, &mut reader, &monitor).unwrap();
        let mut out = [0u8; 10];
        let n = fb.get_original_bytes(0, &mut out).unwrap();
        assert_eq!(n, 10);
        assert_eq!(out.to_vec(), data);
    }

    #[test]
    fn get_all_file_bytes_reflects_creates_and_deletes() {
        let (_h, mut adapter) = open_create(DEFAULT_MAX_BUFFER_SIZE);
        let monitor = DummyMonitor;
        let mut r1: &[u8] = &[1, 2];
        let mut r2: &[u8] = &[3, 4];
        adapter.create_file_bytes("a.bin", 0, 2, &mut r1, &monitor).unwrap();
        let fb2 = adapter.create_file_bytes("b.bin", 0, 2, &mut r2, &monitor).unwrap();
        assert_eq!(adapter.get_all_file_bytes().len(), 2);

        assert!(adapter.delete_file_bytes(&fb2).unwrap());
        assert_eq!(adapter.get_all_file_bytes().len(), 1);
        assert!(!adapter.delete_file_bytes(&fb2).unwrap());
    }

    #[test]
    fn refresh_reloads_from_table_and_reuses_still_present_entries() {
        let (_h, mut adapter) = open_create(DEFAULT_MAX_BUFFER_SIZE);
        let monitor = DummyMonitor;
        let mut r1: &[u8] = &[1, 2, 3];
        let fb = adapter.create_file_bytes("a.bin", 0, 3, &mut r1, &monitor).unwrap();
        adapter.refresh().unwrap();
        let after = adapter.get_all_file_bytes();
        assert_eq!(after.len(), 1);
        assert!(Arc::ptr_eq(&fb, &after[0]));
    }

    #[test]
    fn reopening_existing_table_reconstructs_file_bytes() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let key;
        {
            let mut adapter = FileBytesAdapterV0::new(handle.clone(), true, DEFAULT_MAX_BUFFER_SIZE).unwrap();
            let mut reader: &[u8] = &[7, 8, 9];
            let monitor = DummyMonitor;
            let fb = adapter.create_file_bytes("a.bin", 0, 3, &mut reader, &monitor).unwrap();
            key = adapter.file_bytes_list[0].0;
            let _ = fb;
        }
        let reopened = FileBytesAdapterV0::new(handle, false, DEFAULT_MAX_BUFFER_SIZE).unwrap();
        let all = reopened.get_all_file_bytes();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].get_filename(), "a.bin");
        assert_eq!(all[0].get_original_byte(0).unwrap(), 7);
        assert_eq!(reopened.file_bytes_list[0].0, key);
    }

    #[test]
    fn create_file_bytes_reports_cancellation() {
        struct AlwaysCancelled;
        impl TaskMonitor for AlwaysCancelled {
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

        let (_h, mut adapter) = open_create(DEFAULT_MAX_BUFFER_SIZE);
        let mut reader: &[u8] = &[1, 2, 3];
        let monitor = AlwaysCancelled;
        let result = adapter.create_file_bytes("a.bin", 0, 3, &mut reader, &monitor);
        assert!(matches!(result, Err(FileBytesAdapterError::Cancelled(_))));
    }

    #[test]
    fn chunk_sizes_matches_java_math() {
        assert_eq!(chunk_sizes(10, 4), vec![4, 4, 2]);
        assert_eq!(chunk_sizes(8, 4), vec![4, 4]);
        assert_eq!(chunk_sizes(3, 100), vec![3]);
        assert_eq!(chunk_sizes(0, 100), Vec::<usize>::new());
    }
}
