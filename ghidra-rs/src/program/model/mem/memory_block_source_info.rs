//! Describes the source of bytes for a memory block.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::MemoryBlock;
use crate::program::seam_stubs::{ByteMappingScheme, FileBytes};

pub trait MemoryBlockSourceInfo {
    /// Returns the length of this block byte source.
    fn get_length(&self) -> i64;

    /// Returns the start address where this byte source is mapped.
    fn get_min_address(&self) -> Address;

    /// Returns the end address where this byte source is mapped.
    fn get_max_address(&self) -> Address;

    /// Returns a description of this SourceInfo object.
    fn get_description(&self) -> String;

    /// Returns the `FileBytes` object if it is the byte source for this section, otherwise
    /// `None`.
    fn get_file_bytes(&self) -> Option<Arc<dyn FileBytes>>;

    /// Returns the offset into the underlying `FileBytes` object where this sub-block starts
    /// getting its bytes from, or -1 if this sub-block does not have an associated `FileBytes`
    /// or a complex bit/byte-mapping is used.
    fn get_file_bytes_offset(&self) -> i64;

    /// Returns the offset into the `FileBytes` object for the given address, or -1 if the
    /// address is out of range or this sub-block does not have an associated `FileBytes`, or a
    /// complex bit/byte-mapping is used.
    fn get_file_bytes_offset_for_address(&self, address: &Address) -> i64;

    /// Returns the mapped address range if this is a mapped memory block (bit mapped or byte
    /// mapped), otherwise `None`.
    fn get_mapped_range(&self) -> Option<AddressRange>;

    /// Returns the `ByteMappingScheme` employed if this is a byte-mapped memory block, otherwise
    /// `None`.
    fn get_byte_mapping_scheme(&self) -> Option<Arc<dyn ByteMappingScheme>>;

    /// Returns the containing Memory Block.
    fn get_memory_block(&self) -> Arc<dyn MemoryBlock>;

    /// Returns true if this SourceInfo object applies to the given address.
    fn contains(&self, address: &Address) -> bool;

    /// Determine if this block source contains the specified file offset.
    ///
    /// `file_offset` is a file offset within the underlying `FileBytes` (if applicable) within
    /// the loaded range associated with this source info. Returns true if the file offset is
    /// within the loaded range of the corresponding `FileBytes`, else false if not supported by
    /// the sub-block type (e.g. bit/byte-mapped sub-block).
    fn contains_file_offset(&self, file_offset: i64) -> bool {
        let start_offset = self.get_file_bytes_offset();
        if start_offset < 0 || file_offset < 0 {
            return false;
        }
        // NOTE: logic does not handle bit/byte-mapped blocks (assumes 1:1 mapping)
        let end_offset = start_offset + (self.get_length() - 1);
        file_offset >= start_offset && file_offset <= end_offset
    }

    /// Get the address within this sub-block which corresponds to the specified file offset, or
    /// `None` if the file offset is out of range or not supported by the sub-block type (e.g.
    /// bit/byte-mapped sub-block).
    fn locate_address_for_file_offset(&self, file_offset: i64) -> Option<Address> {
        let start_offset = self.get_file_bytes_offset();
        if !self.contains_file_offset(file_offset) {
            return None;
        }
        // NOTE: logic does not handle bit/byte-mapped blocks (assumes 1:1 mapping)
        let offset = file_offset - start_offset;
        if offset >= self.get_length() {
            return None;
        }
        self.get_min_address().add(offset).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockMemoryBlock;

    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_start(&self) -> Address {
            mock_address(0)
        }
        fn get_end(&self) -> Address {
            mock_address(0xff)
        }
        fn get_size(&self) -> u64 {
            0x100
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(
            &self,
            _addr: &Address,
        ) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(
            &mut self,
            _addr: &Address,
            _source: &[u8],
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
    }

    struct MockSourceInfo {
        file_bytes_offset: i64,
        length: i64,
    }

    impl MemoryBlockSourceInfo for MockSourceInfo {
        fn get_length(&self) -> i64 {
            self.length
        }
        fn get_min_address(&self) -> Address {
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address((self.length - 1) as i64)
        }
        fn get_description(&self) -> String {
            "mock source".to_string()
        }
        fn get_file_bytes(&self) -> Option<Arc<dyn FileBytes>> {
            None
        }
        fn get_file_bytes_offset(&self) -> i64 {
            self.file_bytes_offset
        }
        fn get_file_bytes_offset_for_address(&self, _address: &Address) -> i64 {
            self.file_bytes_offset
        }
        fn get_mapped_range(&self) -> Option<AddressRange> {
            None
        }
        fn get_byte_mapping_scheme(&self) -> Option<Arc<dyn ByteMappingScheme>> {
            None
        }
        fn get_memory_block(&self) -> Arc<dyn MemoryBlock> {
            Arc::new(MockMemoryBlock)
        }
        fn contains(&self, address: &Address) -> bool {
            address.offset() >= 0 && address.offset() < self.length
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("mock", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn contains_and_locates_file_offset() {
        let info = MockSourceInfo {
            file_bytes_offset: 0x10,
            length: 0x20,
        };

        assert!(info.contains_file_offset(0x10));
        assert!(info.contains_file_offset(0x2f));
        assert!(!info.contains_file_offset(0x30));
        assert!(!info.contains_file_offset(-1));

        let located = info.locate_address_for_file_offset(0x11).unwrap();
        assert_eq!(located.offset(), 1);

        assert!(info.locate_address_for_file_offset(0x30).is_none());
    }
}
