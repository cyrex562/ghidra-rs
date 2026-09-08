//! Port of the class `ghidra.program.database.mem.FileBytesSubMemoryBlock`.
//!
//! Implementation of `SubMemoryBlock` for blocks whose bytes are backed by a
//! [`FileBytes`](crate::program::database::mem::file_bytes::FileBytes) object at some offset into
//! it.
//!
//! Java's constructor resolves `fileBytes` via
//! `adapter.getMemoryMap().getLayeredFileBytes(fileBytesID)` -- a `MemoryMapDB`-specific,
//! package-private method. This crate's
//! [`MemoryMapDBAdapter::get_memory_map`](crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter::get_memory_map)
//! deliberately returns the generic
//! [`Memory`](crate::program::model::mem::Memory) trait rather than the concrete `MemoryMapDB`,
//! specifically to cut the `MemoryMapDBAdapter` <-> `MemoryMapDB` back-reference cycle (see that
//! trait's module docs), so `getLayeredFileBytes` isn't reachable from here. Per this crate's
//! "explicit parameters instead of virtual calls" convention, [`new`](FileBytesSubMemoryBlock::new)
//! instead takes the already-resolved `file_bytes` directly from its caller (who has it already,
//! e.g. from `MemoryMapDBAdapter::create_file_bytes_block`, which is handed an `Arc<dyn
//! FileBytes>` up front) rather than re-resolving it through a lookup this crate has no route to.
//!
//! `get_source_info` cannot yet be implemented for the same reason documented in
//! `uninitialized_sub_memory_block`: it requires `MemoryBlockSourceInfoDB`, which has not been
//! ported yet.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::program::database::mem::file_bytes::{FileBytes, FileBytesError};
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
use crate::program::database::mem::sub_block_header::{SubBlockHeader, SUB_INT_DATA1_COL, SUB_LONG_DATA2_COL, SUB_TYPE_FILE_BYTES};
use crate::program::database::mem::sub_memory_block::{SubMemoryBlock, SubMemoryBlockError};
use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryBlockSourceInfo};

/// Converts a [`FileBytesError`] into the [`SubMemoryBlockError`] the trait's byte-access methods
/// need to return. `SubMemoryBlockError` has no `FileBytes`-specific variant (it aggregates the
/// checked exceptions `SubMemoryBlock`'s own methods declare in Java: `IndexOutOfBoundsException`,
/// `IllegalArgumentException`, `MemoryAccessException`, `IOException`), so `Invalidated` -- Java's
/// unchecked `ConcurrentModificationException` for a `FileBytes` whose backing block was removed
/// -- maps onto `MemoryAccess`, matching how this crate reports "can no longer be read/written"
/// conditions elsewhere in this trait (e.g. `UninitializedSubMemoryBlock`).
fn to_sub_error(err: FileBytesError) -> SubMemoryBlockError {
    match err {
        FileBytesError::Io(e) => SubMemoryBlockError::Io(e),
        FileBytesError::IndexOutOfBounds(msg) => SubMemoryBlockError::IndexOutOfBounds(msg),
        FileBytesError::Invalidated => {
            SubMemoryBlockError::MemoryAccess(MemoryAccessException::new("FileBytes has been invalidated"))
        }
    }
}

/// Implementation of `SubMemoryBlock` for blocks whose bytes are backed by a `FileBytes` object.
/// Mirrors `ghidra.program.database.mem.FileBytesSubMemoryBlock`.
pub struct FileBytesSubMemoryBlock {
    header: SubBlockHeader,
    file_bytes: Arc<dyn FileBytes>,
    file_bytes_id: i32,
    file_bytes_offset: i64,
}

impl FileBytesSubMemoryBlock {
    /// Mirrors `FileBytesSubMemoryBlock(MemoryMapDBAdapter, DBRecord)`. See this module's docs
    /// for why `file_bytes` is supplied directly rather than resolved from `record`'s stored id.
    pub fn new(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord, file_bytes: Arc<dyn FileBytes>) -> Self {
        let file_bytes_id = record.get_int(SUB_INT_DATA1_COL).unwrap_or(0);
        let file_bytes_offset = record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0);
        Self {
            header: SubBlockHeader::new(adapter, record),
            file_bytes,
            file_bytes_id,
            file_bytes_offset,
        }
    }

    /// Mirrors `getFileBytes()`.
    pub fn get_file_bytes(&self) -> Arc<dyn FileBytes> {
        self.file_bytes.clone()
    }

    /// Mirrors `getFileBytesOffset()`.
    pub fn get_file_bytes_offset(&self) -> i64 {
        self.file_bytes_offset
    }
}

impl SubMemoryBlock for FileBytesSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        true
    }

    fn get_parent_block_id(&self) -> i64 {
        self.header.get_parent_block_id()
    }

    fn get_starting_offset(&self) -> i64 {
        self.header.get_starting_offset()
    }

    fn get_length(&self) -> i64 {
        self.header.get_length()
    }

    fn get_byte(&self, offset_in_mem_block: i64) -> Result<u8, SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        self.file_bytes
            .get_modified_byte(self.file_bytes_offset + offset_in_sub_block)
            .map_err(to_sub_error)
    }

    fn get_bytes(
        &self,
        offset_in_mem_block: i64,
        b: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        let available = self.header.get_length() - offset_in_sub_block;
        let len = (len as i64).min(available.max(0)) as usize;
        self.file_bytes
            .get_modified_bytes_range(self.file_bytes_offset + offset_in_sub_block, b, off, len)
            .map_err(to_sub_error)
    }

    fn put_byte(&mut self, offset_in_mem_block: i64, b: u8) -> Result<(), SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        self.file_bytes
            .put_byte(self.file_bytes_offset + offset_in_sub_block, b)
            .map_err(to_sub_error)
    }

    fn put_bytes(
        &mut self,
        offset_in_mem_block: i64,
        b: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        let offset_in_sub_block = offset_in_mem_block - self.header.get_starting_offset();
        let available = self.header.get_length() - offset_in_sub_block;
        let len = (len as i64).min(available.max(0)) as usize;
        self.file_bytes
            .put_bytes_range(self.file_bytes_offset + offset_in_sub_block, b, off, len)
            .map_err(to_sub_error)
    }

    fn delete(&mut self) -> io::Result<()> {
        self.header.delete()
    }

    fn set_length(&mut self, length: i64) -> io::Result<()> {
        self.header.set_length(length)
    }

    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> io::Result<bool> {
        let Some(other_ref) = other.as_any().downcast_ref::<FileBytesSubMemoryBlock>() else {
            return Ok(false);
        };
        if !Arc::ptr_eq(&self.file_bytes, &other_ref.file_bytes) {
            return Ok(false);
        }
        // are the two blocks consecutive in the fileBytes space?
        if other_ref.file_bytes_offset != self.file_bytes_offset + self.header.get_length() {
            return Ok(false);
        }
        let other_len = other_ref.get_length();
        let other_key = other_ref.header.key();

        let new_length = self.header.get_length() + other_len;
        self.header.set_length(new_length)?;
        self.header.adapter().write().unwrap().delete_sub_block(other_key)?;
        Ok(true)
    }

    fn get_source_info(&self, _block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
        unimplemented!("source info construction requires MemoryBlockSourceInfoDB, not yet ported")
    }

    fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
        let offset = mem_block_offset - self.header.get_starting_offset();
        let new_length = self.header.get_length() - offset;
        self.header.set_length(offset)?;

        let new_record = self.header.adapter().write().unwrap().create_sub_block_record(
            0,
            0,
            new_length,
            SUB_TYPE_FILE_BYTES,
            self.file_bytes_id,
            self.file_bytes_offset + offset,
        )?;

        Ok(Box::new(FileBytesSubMemoryBlock::new(
            self.header.adapter().clone(),
            new_record,
            self.file_bytes.clone(),
        )))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.header.set_parent_id_and_starting_offset(key, starting_offset)
    }

    fn get_description(&self) -> String {
        format!(
            "{}[{:#x}, {:#x}]",
            self.file_bytes.get_filename(),
            self.file_bytes_offset + self.file_bytes.get_file_offset(),
            self.header.get_length()
        )
    }

    fn uses(&self, file_bytes: &dyn FileBytes) -> bool {
        std::ptr::eq(self.file_bytes.as_ref(), file_bytes)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::file_bytes::FileBytesError;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, MockAdapter};
    use std::sync::Mutex;

    struct MockFileBytes {
        filename: String,
        file_offset: i64,
        data: Mutex<Vec<u8>>,
    }

    impl MockFileBytes {
        fn new(filename: &str, file_offset: i64, data: Vec<u8>) -> Self {
            Self {
                filename: filename.to_string(),
                file_offset,
                data: Mutex::new(data),
            }
        }
    }

    impl FileBytes for MockFileBytes {
        fn get_filename(&self) -> &str {
            &self.filename
        }
        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }
        fn get_size(&self) -> i64 {
            self.data.lock().unwrap().len() as i64
        }
        fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.data
                .lock()
                .unwrap()
                .get(offset as usize)
                .copied()
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))
        }
        fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.get_modified_byte(offset)
        }
        fn get_modified_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            let data = self.data.lock().unwrap();
            let start = offset as usize;
            let available = data.len().saturating_sub(start);
            let n = length.min(available);
            b[off..off + n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        }
        fn get_original_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.get_modified_bytes_range(offset, b, off, length)
        }
        fn put_byte(&self, offset: i64, b: u8) -> Result<(), FileBytesError> {
            let mut data = self.data.lock().unwrap();
            if offset < 0 || offset as usize >= data.len() {
                return Err(FileBytesError::IndexOutOfBounds(offset.to_string()));
            }
            data[offset as usize] = b;
            Ok(())
        }
        fn put_bytes_range(
            &self,
            offset: i64,
            b: &[u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            let mut data = self.data.lock().unwrap();
            let start = offset as usize;
            let available = data.len().saturating_sub(start);
            let n = length.min(available);
            data[start..start + n].copy_from_slice(&b[off..off + n]);
            Ok(n)
        }
    }

    fn adapter() -> Arc<RwLock<MockAdapter>> {
        Arc::new(RwLock::new(MockAdapter::new()))
    }

    fn block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        file_bytes: Arc<dyn FileBytes>,
        file_bytes_offset: i64,
    ) -> FileBytesSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, 0, file_bytes_offset);
        FileBytesSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, file_bytes)
    }

    #[test]
    fn is_always_initialized() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![1, 2, 3, 4]));
        let b = block(&a, 1, 0, 4, fb, 0);
        assert!(b.is_initialized());
    }

    #[test]
    fn get_and_put_byte_round_trip_through_a_nonzero_file_offset() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![0; 16]));
        let mut b = block(&a, 1, 100, 8, fb.clone(), 5);

        b.put_byte(100, 0xAA).unwrap();
        b.put_byte(107, 0xBB).unwrap();
        assert_eq!(b.get_byte(100).unwrap(), 0xAA);
        assert_eq!(b.get_byte(107).unwrap(), 0xBB);
        // underlying FileBytes storage was touched at fileBytesOffset (5) + sub-block offset
        assert_eq!(fb.get_modified_byte(5).unwrap(), 0xAA);
        assert_eq!(fb.get_modified_byte(12).unwrap(), 0xBB);
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![1, 2, 3, 4]));
        let b = block(&a, 1, 0, 4, fb, 0);

        let mut dest = [0u8; 10];
        let n = b.get_bytes(2, &mut dest, 0, 10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], &[3, 4]);
    }

    #[test]
    fn description_includes_filename_and_file_offset() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("orig.bin", 0x1000, vec![0; 16]));
        let b = block(&a, 1, 0, 0x10, fb, 5);
        assert_eq!(b.get_description(), "orig.bin[0x1005, 0x10]");
    }

    #[test]
    fn uses_identifies_the_backing_file_bytes_by_identity() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![0; 4]));
        let other_fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![0; 4]));
        let b = block(&a, 1, 0, 4, fb.clone(), 0);

        assert!(b.uses(fb.as_ref()));
        assert!(!b.uses(other_fb.as_ref()));
    }

    #[test]
    fn join_merges_consecutive_ranges_of_the_same_file_bytes() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![1, 2, 3, 4]));
        let mut first = block(&a, 1, 0, 2, fb.clone(), 0);
        let mut second = block(&a, 2, 2, 2, fb.clone(), 2);

        assert!(first.join(&mut second).unwrap());
        assert_eq!(first.get_length(), 4);
        assert_eq!(a.read().unwrap().deleted_sub_blocks, vec![2]);
    }

    #[test]
    fn join_rejects_non_consecutive_file_bytes_offsets() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![0; 16]));
        let mut first = block(&a, 1, 0, 2, fb.clone(), 0);
        let mut second = block(&a, 2, 2, 2, fb.clone(), 10); // not consecutive (would need offset 2)

        assert!(!first.join(&mut second).unwrap());
        assert_eq!(first.get_length(), 2);
    }

    #[test]
    fn join_rejects_different_file_bytes_objects() {
        let a = adapter();
        let fb1: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f1.bin", 0, vec![0; 4]));
        let fb2: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f2.bin", 0, vec![0; 4]));
        let mut first = block(&a, 1, 0, 2, fb1, 0);
        let mut second = block(&a, 2, 2, 2, fb2, 2);

        assert!(!first.join(&mut second).unwrap());
    }

    #[test]
    fn split_preserves_file_bytes_identity_and_advances_the_offset() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![10, 20, 30, 40]));
        let mut first = block(&a, 1, 100, 4, fb.clone(), 0);

        let mut back = first.split(102).unwrap();
        assert_eq!(first.get_length(), 2);
        assert_eq!(back.get_length(), 2);

        let back_concrete = back.as_any().downcast_ref::<FileBytesSubMemoryBlock>().unwrap();
        assert!(Arc::ptr_eq(&back_concrete.get_file_bytes(), &fb));
        assert_eq!(back_concrete.get_file_bytes_offset(), 2);

        let mut out = [0u8; 2];
        back.get_bytes(0, &mut out, 0, 2).unwrap();
        assert_eq!(out, [30, 40]);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let a = adapter();
        let fb: Arc<dyn FileBytes> = Arc::new(MockFileBytes::new("f.bin", 0, vec![1, 2, 3]));
        let boxed: Box<dyn SubMemoryBlock> = Box::new(block(&a, 1, 0, 3, fb, 0));
        assert!(boxed.is_initialized());
        assert_eq!(boxed.get_description(), "f.bin[0x0, 0x3]");
    }
}
