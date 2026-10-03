//! Port of the class `ghidra.program.database.mem.MemoryBlockSourceInfoDB`.
//!
//! Java's `MemoryBlockSourceInfoDB` is a thin, always-live view: it stores a `MemoryBlock`
//! reference plus a `SubMemoryBlock` reference and delegates every query straight through to the
//! `SubMemoryBlock` (including `instanceof` checks against `FileBytesSubMemoryBlock`,
//! `BitMappedSubMemoryBlock`, and `ByteMappedSubMemoryBlock` for the FileBytes/mapped-range/byte-
//! mapping-scheme accessors), so a live change to the underlying `subBlock` (e.g. its length
//! after a `setLength` call) is reflected on every subsequent call.
//!
//! This port cannot hold a live reference to the originating `SubMemoryBlock` the same way:
//! [`SubMemoryBlock::get_source_info`](super::sub_memory_block::SubMemoryBlock::get_source_info)
//! takes `&self` and must return an owned `Arc<dyn MemoryBlockSourceInfo>` with no lifetime tied
//! to that borrow. So [`MemoryBlockSourceInfoDB::new`] instead resolves and stores everything it
//! needs (offset, length, description, and the FileBytes/mapped-range/byte-mapping-scheme
//! `instanceof` results) once, at construction time -- the same "eagerly resolved value object"
//! shape [`AddressSourceInfo`](super::address_source_info::AddressSourceInfo)'s module docs
//! describe for the analogous problem. Every concrete `SubMemoryBlock` in this crate builds its
//! source info fresh, from live state, each time `get_source_info` is called, so this snapshot is
//! exactly what Java's live delegation would have observed had it been called at that same
//! instant; it only stops tracking further mutations to the sub block afterward, which Java's own
//! callers never rely on either (every `getSourceInfos()`/`getSourceInfoForAddress()` call site
//! re-fetches a fresh `MemoryBlockSourceInfoDB`).
//!
//! The `instanceof SubMemoryBlock` subtype checks (`FileBytesSubMemoryBlock`,
//! `BitMappedSubMemoryBlock`, `ByteMappedSubMemoryBlock`) are replicated via
//! [`AsAny::as_any`](super::sub_memory_block::AsAny::as_any) downcasting, the same pattern the
//! six concrete `SubMemoryBlock` implementors already use for `join`'s sibling-type checks.

use std::fmt;
use std::sync::Arc;

use crate::program::database::mem::bit_mapped_sub_memory_block::BitMappedSubMemoryBlock;
use crate::program::database::mem::byte_mapped_sub_memory_block::ByteMappedSubMemoryBlock;
use crate::program::database::mem::byte_mapping_scheme::ByteMappingScheme;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::file_bytes_sub_memory_block::FileBytesSubMemoryBlock;
use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::{MemoryBlock, MemoryBlockSourceInfo};
use crate::program::seam_stubs;

/// Class for describing the source of bytes for a memory block. Mirrors
/// `ghidra.program.database.mem.MemoryBlockSourceInfoDB`.
pub struct MemoryBlockSourceInfoDB {
    block: Arc<dyn MemoryBlock>,
    sub_block_offset: i64,
    sub_block_length: i64,
    description: String,
    file_bytes: Option<Arc<dyn FileBytes>>,
    file_bytes_offset: i64,
    mapped_range: Option<AddressRange>,
    byte_mapping_scheme: Option<ByteMappingScheme>,
}

impl MemoryBlockSourceInfoDB {
    /// Mirrors `MemoryBlockSourceInfoDB(MemoryBlock, SubMemoryBlock)`. Resolves and stores
    /// everything this needs from `sub_block` immediately, since `sub_block` is only borrowed for
    /// the duration of this call -- see this module's docs for why.
    pub fn new(block: Arc<dyn MemoryBlock>, sub_block: &dyn SubMemoryBlock) -> Self {
        let file_bytes_sub = sub_block.as_any().downcast_ref::<FileBytesSubMemoryBlock>();
        let file_bytes = file_bytes_sub.map(FileBytesSubMemoryBlock::get_file_bytes);
        let file_bytes_offset = file_bytes_sub
            .map(FileBytesSubMemoryBlock::get_file_bytes_offset)
            .unwrap_or(-1);

        let bit_mapped = sub_block.as_any().downcast_ref::<BitMappedSubMemoryBlock>();
        let byte_mapped = sub_block.as_any().downcast_ref::<ByteMappedSubMemoryBlock>();

        let mapped_range = bit_mapped
            .and_then(BitMappedSubMemoryBlock::get_mapped_range)
            .or_else(|| byte_mapped.map(ByteMappedSubMemoryBlock::get_mapped_range));

        let byte_mapping_scheme = byte_mapped.map(ByteMappedSubMemoryBlock::get_byte_mapping_scheme);

        Self {
            block,
            sub_block_offset: sub_block.get_starting_offset(),
            sub_block_length: sub_block.get_length(),
            description: sub_block.get_description(),
            file_bytes,
            file_bytes_offset,
            mapped_range,
            byte_mapping_scheme,
        }
    }
}

impl MemoryBlockSourceInfo for MemoryBlockSourceInfoDB {
    fn get_length(&self) -> i64 {
        self.sub_block_length
    }

    fn get_min_address(&self) -> Address {
        self.block
            .get_start()
            .add(self.sub_block_offset)
            .expect("sub-block offset should stay within its owning block's address space")
    }

    fn get_max_address(&self) -> Address {
        self.block
            .get_start()
            .add(self.sub_block_offset + self.sub_block_length - 1)
            .expect("sub-block range should stay within its owning block's address space")
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn get_file_bytes(&self) -> Option<Arc<dyn FileBytes>> {
        self.file_bytes.clone()
    }

    fn get_file_bytes_offset(&self) -> i64 {
        self.file_bytes_offset
    }

    fn get_file_bytes_offset_for_address(&self, address: &Address) -> i64 {
        if self.file_bytes.is_none() || !self.contains(address) {
            return -1;
        }
        let min_address = self.get_min_address();
        let sub_block_offset = address.subtract(&min_address);
        self.file_bytes_offset + sub_block_offset
    }

    fn get_mapped_range(&self) -> Option<AddressRange> {
        self.mapped_range.clone()
    }

    fn get_byte_mapping_scheme(&self) -> Option<Arc<dyn seam_stubs::ByteMappingScheme>> {
        self.byte_mapping_scheme
            .map(|scheme| Arc::new(scheme) as Arc<dyn seam_stubs::ByteMappingScheme>)
    }

    fn get_memory_block(&self) -> Arc<dyn MemoryBlock> {
        self.block.clone()
    }

    fn contains(&self, address: &Address) -> bool {
        let min_address = self.get_min_address();
        let max_address = self.get_max_address();
        address >= &min_address && address <= &max_address
    }
}

impl fmt::Display for MemoryBlockSourceInfoDB {
    /// Mirrors `MemoryBlockSourceInfoDB.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryBlockSourceInfoDB: StartAddress = {}, length = {}",
            self.get_min_address(),
            self.get_length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock;
    use crate::program::database::mem::file_bytes::FileBytesError;
    use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, test_addr, MockAdapter};
    use crate::program::model::mem::MemoryBlockStub;
    use std::sync::RwLock;

    fn adapter() -> Arc<RwLock<MockAdapter>> {
        Arc::new(RwLock::new(MockAdapter::new()))
    }

    fn owning_block(start_offset: i64, length: i64) -> Arc<dyn MemoryBlock> {
        let start = test_addr(start_offset);
        let end = test_addr(start_offset + length - 1);
        Arc::new(MemoryBlockStub::new(start, end))
    }

    fn buffer_sub_block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
    ) -> BufferSubMemoryBlock {
        let buffer_id = adapter.write().unwrap().register_buffer(vec![0u8; length as usize]);
        let record = make_record(key, 1, starting_offset, length, buffer_id, 0);
        BufferSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record)
            .expect("buffer sub block construction should succeed")
    }

    struct MockFileBytes {
        filename: String,
        file_offset: i64,
    }

    impl FileBytes for MockFileBytes {
        fn get_filename(&self) -> &str {
            &self.filename
        }
        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }
        fn get_size(&self) -> i64 {
            0
        }
        fn get_modified_byte(&self, _offset: i64) -> Result<u8, FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
        fn get_original_byte(&self, _offset: i64) -> Result<u8, FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
        fn get_modified_bytes_range(
            &self,
            _offset: i64,
            _b: &mut [u8],
            _off: usize,
            _length: usize,
        ) -> Result<usize, FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
        fn get_original_bytes_range(
            &self,
            _offset: i64,
            _b: &mut [u8],
            _off: usize,
            _length: usize,
        ) -> Result<usize, FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
        fn put_byte(&self, _offset: i64, _b: u8) -> Result<(), FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
        fn put_bytes_range(
            &self,
            _offset: i64,
            _b: &[u8],
            _off: usize,
            _length: usize,
        ) -> Result<usize, FileBytesError> {
            unimplemented!("not exercised by MemoryBlockSourceInfoDB tests")
        }
    }

    fn file_bytes_sub_block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        file_bytes_offset: i64,
    ) -> FileBytesSubMemoryBlock {
        let file_bytes: Arc<dyn FileBytes> = Arc::new(MockFileBytes {
            filename: "orig.bin".to_string(),
            file_offset: 0,
        });
        let record = make_record(key, 1, starting_offset, length, 0, file_bytes_offset);
        FileBytesSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, file_bytes)
    }

    fn byte_mapped_sub_block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        mapped_address: Address,
    ) -> ByteMappedSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, 0, 0);
        ByteMappedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, mapped_address)
            .expect("1:1 byte mapping scheme should construct")
    }

    fn bit_mapped_sub_block(
        adapter: &Arc<RwLock<MockAdapter>>,
        key: i64,
        starting_offset: i64,
        length: i64,
        mapped_address: Address,
    ) -> BitMappedSubMemoryBlock {
        let record = make_record(key, 1, starting_offset, length, 0, 0);
        BitMappedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record, mapped_address)
    }

    #[test]
    fn address_range_reflects_a_nonzero_offset_within_the_parent_block() {
        let a = adapter();
        // Owning block starts at 0x1000; this sub block starts 0x20 into it and is 0x10 long.
        let block = owning_block(0x1000, 0x100);
        let sub = buffer_sub_block(&a, 1, 0x20, 0x10);

        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        assert_eq!(info.get_length(), 0x10);
        assert_eq!(info.get_min_address(), test_addr(0x1020));
        assert_eq!(info.get_max_address(), test_addr(0x102f));
    }

    #[test]
    fn contains_respects_the_computed_address_range() {
        let a = adapter();
        let block = owning_block(0x1000, 0x100);
        let sub = buffer_sub_block(&a, 1, 0x20, 0x10);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        assert!(!info.contains(&test_addr(0x101f)));
        assert!(info.contains(&test_addr(0x1020)));
        assert!(info.contains(&test_addr(0x102f)));
        assert!(!info.contains(&test_addr(0x1030)));
    }

    #[test]
    fn description_delegates_to_the_sub_block() {
        let a = adapter();
        let block = owning_block(0, 0x10);
        let sub = buffer_sub_block(&a, 1, 0, 0x10);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        assert_eq!(info.get_description(), "init[0x10]");
    }

    #[test]
    fn plain_buffer_backed_sub_block_reports_no_file_bytes_or_mapping() {
        let a = adapter();
        let block = owning_block(0, 0x10);
        let sub = buffer_sub_block(&a, 1, 0, 0x10);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        assert!(info.get_file_bytes().is_none());
        assert_eq!(info.get_file_bytes_offset(), -1);
        assert_eq!(info.get_file_bytes_offset_for_address(&test_addr(0)), -1);
        assert!(info.get_mapped_range().is_none());
        assert!(info.get_byte_mapping_scheme().is_none());
    }

    #[test]
    fn file_bytes_backed_sub_block_reports_file_bytes_and_offset() {
        let a = adapter();
        let block = owning_block(0x2000, 0x100);
        // Sub block starts 0x8 into the owning block, is 0x10 long, and reads from fileBytes
        // starting at offset 0x50 within the FileBytes object.
        let sub = file_bytes_sub_block(&a, 1, 0x8, 0x10, 0x50);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        let file_bytes = info.get_file_bytes().expect("file-bytes-backed sub block should report FileBytes");
        assert_eq!(file_bytes.get_filename(), "orig.bin");
        assert_eq!(info.get_file_bytes_offset(), 0x50);

        // Address at the very start of the sub block maps to fileBytesOffset (0x50).
        assert_eq!(info.get_file_bytes_offset_for_address(&test_addr(0x2008)), 0x50);
        // An address 4 bytes into the sub block maps to fileBytesOffset + 4.
        assert_eq!(info.get_file_bytes_offset_for_address(&test_addr(0x200c)), 0x54);
        // An address outside the sub block's range reports -1.
        assert_eq!(info.get_file_bytes_offset_for_address(&test_addr(0x2020)), -1);

        assert!(info.get_mapped_range().is_none());
        assert!(info.get_byte_mapping_scheme().is_none());
    }

    #[test]
    fn file_bytes_backed_sub_block_supports_default_file_offset_lookups() {
        let a = adapter();
        let block = owning_block(0x2000, 0x100);
        let sub = file_bytes_sub_block(&a, 1, 0, 0x10, 0x50);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        // Default trait methods, exercised against this concrete implementation's file-bytes
        // accessors.
        assert!(info.contains_file_offset(0x50));
        assert!(info.contains_file_offset(0x5f));
        assert!(!info.contains_file_offset(0x60));

        let located = info
            .locate_address_for_file_offset(0x55)
            .expect("0x55 is within the sub block's file offset range");
        assert_eq!(located, test_addr(0x2005));
    }

    #[test]
    fn byte_mapped_sub_block_reports_mapped_range_and_scheme() {
        let a = adapter();
        let block = owning_block(0, 0x10);
        let sub = byte_mapped_sub_block(&a, 1, 0, 0x10, test_addr(0x500));
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        let range = info.get_mapped_range().expect("byte-mapped sub block should report a mapped range");
        assert_eq!(range.min_address(), &test_addr(0x500));
        assert_eq!(range.max_address(), &test_addr(0x50f));

        assert!(info.get_byte_mapping_scheme().is_some());
        assert!(info.get_file_bytes().is_none());
        assert_eq!(info.get_file_bytes_offset(), -1);
    }

    #[test]
    fn bit_mapped_sub_block_reports_mapped_range_but_no_byte_mapping_scheme() {
        let a = adapter();
        let block = owning_block(0, 0x40);
        let sub = bit_mapped_sub_block(&a, 1, 0, 0x20, test_addr(0x700));
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        let range = info.get_mapped_range().expect("bit-mapped sub block should report a mapped range");
        assert_eq!(range.min_address(), &test_addr(0x700));
        assert_eq!(range.max_address(), &test_addr(0x703)); // (0x20 - 1) / 8 = 3

        // Bit-mapped blocks have no byte mapping scheme (that's ByteMappedSubMemoryBlock only).
        assert!(info.get_byte_mapping_scheme().is_none());
    }

    #[test]
    fn get_memory_block_returns_the_same_owning_block() {
        let a = adapter();
        let block = owning_block(0, 0x10);
        let sub = buffer_sub_block(&a, 1, 0, 0x10);
        let expected = block.clone();
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        assert!(Arc::ptr_eq(&info.get_memory_block(), &expected));
    }

    #[test]
    fn display_matches_java_tostring_format() {
        let a = adapter();
        let block = owning_block(0x1000, 0x100);
        let sub = buffer_sub_block(&a, 1, 0x20, 0x10);
        let info = MemoryBlockSourceInfoDB::new(block, &sub);

        let text = format!("{info}");
        assert!(text.starts_with("MemoryBlockSourceInfoDB: StartAddress = "));
        assert!(text.contains("length = 16"));
    }

    #[test]
    fn source_info_object_is_usable_through_the_trait_object() {
        let a = adapter();
        let block = owning_block(0, 0x10);
        let sub = buffer_sub_block(&a, 1, 0, 0x10);
        let info: Arc<dyn MemoryBlockSourceInfo> = Arc::new(MemoryBlockSourceInfoDB::new(block, &sub));

        assert_eq!(info.get_length(), 0x10);
        assert!(info.get_file_bytes().is_none());
    }
}
