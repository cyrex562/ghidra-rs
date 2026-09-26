//! Trait ported from the class `ghidra.program.database.mem.AddressSourceInfo`.
//!
//! In Java, `AddressSourceInfo` is a small, eagerly-resolved value object: its constructor takes
//! a `Memory`/`Address`/`MemoryBlock` triple, looks up the containing
//! `MemoryBlockSourceInfo`, and -- if that source info reports a mapped range (bit/byte-mapped
//! block) -- recursively constructs another `AddressSourceInfo` for the mapped-from address via
//! `Memory.getBlock(Address)`. That last step is exactly the cycle this port needs to cut
//! (`AddressSourceInfo` -> `Memory` -> ... -> `AddressSourceInfo`), so instead of porting the
//! constructor's resolution logic here, the resolved `mappedInfo` and `fileBytes` fields are
//! exposed as trait methods ([`get_mapped_info`](AddressSourceInfo::get_mapped_info) and
//! [`get_file_bytes`](AddressSourceInfo::get_file_bytes)) that a concrete, `Memory`-aware
//! implementor is expected to resolve once (mirroring the Java constructor) and then report
//! cheaply thereafter. The remaining public methods (`getFileOffset`, `getFileName`,
//! `getOriginalValue`) are provided as default methods that replicate Java's field-based logic
//! purely in terms of those two accessors plus [`get_address`](AddressSourceInfo::get_address)
//! and [`get_memory_block_source_info`](AddressSourceInfo::get_memory_block_source_info).

use std::sync::Arc;

use crate::program::database::mem::file_bytes::{FileBytes, FileBytesError};
use crate::program::model::address::Address;
use crate::program::model::mem::MemoryBlockSourceInfo;

/// Provides information about the source of a byte value at an address including the file it
/// came from, the offset into that file, and the original value of that byte.
///
/// Not bound by `Send + Sync`: it wraps [`MemoryBlockSourceInfo`], which is likewise unbound,
/// so requiring thread-safety here would be unenforceable through that dependency.
pub trait AddressSourceInfo {
    /// Returns the address for which this object provides byte source information. Mirrors
    /// `AddressSourceInfo.getAddress()`.
    fn get_address(&self) -> Address;

    /// Returns the `MemoryBlockSourceInfo` for the region surrounding this info's location.
    /// Mirrors `AddressSourceInfo.getMemoryBlockSourceInfo()`.
    fn get_memory_block_source_info(&self) -> Arc<dyn MemoryBlockSourceInfo>;

    /// Returns the `AddressSourceInfo` this location is mapped from, if this address lies
    /// within a mapped (bit/byte-mapped) memory block. Mirrors the private `mappedInfo` field,
    /// which Java's constructor resolves eagerly via `getMappedSourceInfo` (using `Memory` to
    /// look up the mapped-from block). Defaults to `None`, matching an unmapped location.
    fn get_mapped_info(&self) -> Option<Arc<dyn AddressSourceInfo>> {
        None
    }

    /// Returns the `FileBytes` supplying this address' byte value, if any. Mirrors the private
    /// `fileBytes` field, which Java's constructor resolves eagerly from
    /// `sourceInfo.getFileBytes()`. Defaults to delegating to
    /// [`get_memory_block_source_info`](Self::get_memory_block_source_info).
    fn get_file_bytes(&self) -> Option<Arc<dyn FileBytes>> {
        self.get_memory_block_source_info().get_file_bytes()
    }

    /// Returns the offset into the originally imported file that provided the byte value for
    /// the associated address, or -1 if there is no source information for this location.
    /// Mirrors `AddressSourceInfo.getFileOffset()`.
    fn get_file_offset(&self) -> i64 {
        if let Some(mapped) = self.get_mapped_info() {
            return mapped.get_file_offset();
        }
        match self.get_file_bytes() {
            Some(file_bytes) => {
                let address = self.get_address();
                self.get_memory_block_source_info()
                    .get_file_bytes_offset_for_address(&address)
                    + file_bytes.get_file_offset()
            }
            None => -1,
        }
    }

    /// Returns the filename of the originally imported file that provided the byte value for
    /// the associated address, or `None` if there is no source information for this location.
    /// Mirrors `AddressSourceInfo.getFileName()`.
    fn get_file_name(&self) -> Option<String> {
        if let Some(mapped) = self.get_mapped_info() {
            return mapped.get_file_name();
        }
        self.get_file_bytes()
            .map(|file_bytes| file_bytes.get_filename().to_string())
    }

    /// Returns the original byte value from the imported file that provided the byte value for
    /// the associated address, or 0 if there is no source information for this location.
    /// Mirrors `AddressSourceInfo.getOriginalValue()`, which throws `IOException`.
    fn get_original_value(&self) -> Result<u8, FileBytesError> {
        if let Some(mapped) = self.get_mapped_info() {
            return mapped.get_original_value();
        }
        match self.get_file_bytes() {
            Some(file_bytes) => file_bytes.get_original_byte(self.get_file_offset()),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryBlock;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("mock", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockFileBytes {
        filename: String,
        file_offset: i64,
        original: Vec<u8>,
    }

    impl FileBytes for MockFileBytes {
        fn get_filename(&self) -> &str {
            &self.filename
        }
        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }
        fn get_size(&self) -> i64 {
            self.original.len() as i64
        }
        fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.get_original_byte(offset)
        }
        fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.original
                .get(offset as usize)
                .copied()
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))
        }
        fn get_modified_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            b_off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.get_original_bytes_range(offset, b, b_off, length)
        }
        fn get_original_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            b_off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            for i in 0..length {
                b[b_off + i] = self.get_original_byte(offset + i as i64)?;
            }
            Ok(length)
        }
        fn put_byte(&self, _offset: i64, _b: u8) -> Result<(), FileBytesError> {
            Err(FileBytesError::Invalidated)
        }
        fn put_bytes_range(
            &self,
            _offset: i64,
            _b: &[u8],
            _b_off: usize,
            _length: usize,
        ) -> Result<usize, FileBytesError> {
            Err(FileBytesError::Invalidated)
        }
    }

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
        file_bytes: Option<Arc<dyn FileBytes>>,
        file_bytes_offset: i64,
    }

    impl MemoryBlockSourceInfo for MockSourceInfo {
        fn get_length(&self) -> i64 {
            0x100
        }
        fn get_min_address(&self) -> Address {
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0xff)
        }
        fn get_description(&self) -> String {
            "mock source".to_string()
        }
        fn get_file_bytes(&self) -> Option<Arc<dyn FileBytes>> {
            self.file_bytes.clone()
        }
        fn get_file_bytes_offset(&self) -> i64 {
            self.file_bytes_offset
        }
        fn get_file_bytes_offset_for_address(&self, address: &Address) -> i64 {
            self.file_bytes_offset + address.offset()
        }
        fn get_mapped_range(&self) -> Option<AddressRange> {
            None
        }
        fn get_byte_mapping_scheme(
            &self,
        ) -> Option<Arc<dyn crate::program::seam_stubs::ByteMappingScheme>> {
            None
        }
        fn get_memory_block(&self) -> Arc<dyn MemoryBlock> {
            Arc::new(MockMemoryBlock)
        }
        fn contains(&self, _address: &Address) -> bool {
            true
        }
    }

    /// A direct (unmapped) source: proves the object-safe trait's default methods correctly
    /// thread `get_address`/`get_memory_block_source_info` through to real `FileBytes` data.
    struct DirectInfo {
        address: Address,
        source_info: Arc<dyn MemoryBlockSourceInfo>,
    }

    impl AddressSourceInfo for DirectInfo {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_memory_block_source_info(&self) -> Arc<dyn MemoryBlockSourceInfo> {
            self.source_info.clone()
        }
    }

    /// A mapped source: proves `get_mapped_info` correctly redirects `get_file_offset`,
    /// `get_file_name`, and `get_original_value` to the mapped-from info, per
    /// `AddressSourceInfo.getFileOffset()`/`getFileName()`/`getOriginalValue()`.
    struct MappedInfo {
        address: Address,
        source_info: Arc<dyn MemoryBlockSourceInfo>,
        mapped_info: Arc<dyn AddressSourceInfo>,
    }

    impl AddressSourceInfo for MappedInfo {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_memory_block_source_info(&self) -> Arc<dyn MemoryBlockSourceInfo> {
            self.source_info.clone()
        }
        fn get_mapped_info(&self) -> Option<Arc<dyn AddressSourceInfo>> {
            Some(self.mapped_info.clone())
        }
    }

    fn direct_info() -> DirectInfo {
        // Mirrors `FileBytes.getOriginalByte`, which indexes its buffer directly by the value
        // `getFileOffset()` computes (`sourceInfo.getFileBytesOffset(address) +
        // fileBytes.getFileOffset()`) -- so the sum of all three components below must stay
        // within `original`'s bounds, same as it must in the real Java constructor's caller.
        let file_bytes: Arc<dyn FileBytes> = Arc::new(MockFileBytes {
            filename: "imported.bin".to_string(),
            file_offset: 5,
            original: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xcc],
        });
        let source_info: Arc<dyn MemoryBlockSourceInfo> = Arc::new(MockSourceInfo {
            file_bytes: Some(file_bytes),
            file_bytes_offset: 3,
        });
        DirectInfo {
            address: mock_address(2),
            source_info,
        }
    }

    #[test]
    fn direct_info_resolves_offset_name_and_value_from_file_bytes() {
        let info = direct_info();

        // file_bytes_offset (3) + address offset (2) + file_offset (5)
        assert_eq!(info.get_file_offset(), 3 + 2 + 5);
        assert_eq!(info.get_file_name().as_deref(), Some("imported.bin"));
        assert_eq!(info.get_original_value().unwrap(), 0xcc);
    }

    #[test]
    fn info_without_file_bytes_reports_sentinel_values() {
        let source_info: Arc<dyn MemoryBlockSourceInfo> = Arc::new(MockSourceInfo {
            file_bytes: None,
            file_bytes_offset: -1,
        });
        let info = DirectInfo {
            address: mock_address(0),
            source_info,
        };

        assert_eq!(info.get_file_offset(), -1);
        assert_eq!(info.get_file_name(), None);
        assert_eq!(info.get_original_value().unwrap(), 0);
    }

    #[test]
    fn mapped_info_delegates_to_the_mapped_from_info() {
        let mapped: Arc<dyn AddressSourceInfo> = Arc::new(direct_info());
        let source_info: Arc<dyn MemoryBlockSourceInfo> = Arc::new(MockSourceInfo {
            file_bytes: None,
            file_bytes_offset: -1,
        });
        let info = MappedInfo {
            address: mock_address(0x50),
            source_info,
            mapped_info: mapped,
        };

        assert_eq!(info.get_file_offset(), 3 + 2 + 5);
        assert_eq!(info.get_file_name().as_deref(), Some("imported.bin"));
        assert_eq!(info.get_original_value().unwrap(), 0xcc);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let boxed: Box<dyn AddressSourceInfo> = Box::new(direct_info());
        assert_eq!(boxed.get_address().offset(), 2);
        assert_eq!(boxed.get_file_offset(), 3 + 2 + 5);
    }
}
