//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo`.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::segment_constants::{PROTECTION_R, PROTECTION_W, PROTECTION_X};
use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::format::seam_stubs::{DWordPlaceholderDataType, QWordPlaceholderDataType};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;

/// Represents a `dyld_cache_mapping_info` structure.
///
/// See `dyld3/shared-cache/dyld_cache_format.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DyldCacheMappingInfo {
    address: i64,
    size: i64,
    file_offset: i64,
    max_prot: i32,
    init_prot: i32,
}

impl DyldCacheMappingInfo {
    /// Size in bytes of the on-disk `dyld_cache_mapping_info` structure.
    pub const SIZE: usize = 32;

    /// Builds a mapping info from already-decoded field values.
    pub fn new(address: i64, size: i64, file_offset: i64, max_prot: i32, init_prot: i32) -> Self {
        DyldCacheMappingInfo { address, size, file_offset, max_prot, init_prot }
    }

    /// Reads a `dyld_cache_mapping_info` at the reader's current position.
    ///
    /// Port of `DyldCacheMappingInfo(BinaryReader)`.
    pub fn from_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(DyldCacheMappingInfo {
            address: reader.read_next_long()?,
            size: reader.read_next_long()?,
            file_offset: reader.read_next_long()?,
            max_prot: reader.read_next_int()?,
            init_prot: reader.read_next_int()?,
        })
    }

    /// Port of `getAddress()`.
    pub fn get_address(&self) -> i64 {
        self.address
    }

    /// Port of `getSize()`.
    pub fn get_size(&self) -> i64 {
        self.size
    }

    /// Port of `getFileOffset()`.
    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    /// Port of `isRead()`: tests the initial protection.
    pub fn is_read(&self) -> bool {
        (self.init_prot as u32) & PROTECTION_R != 0
    }

    /// Port of `isWrite()`: tests the initial protection.
    pub fn is_write(&self) -> bool {
        (self.init_prot as u32) & PROTECTION_W != 0
    }

    /// Port of `isExecute()`: tests the initial protection.
    pub fn is_execute(&self) -> bool {
        (self.init_prot as u32) & PROTECTION_X != 0
    }

    /// Port of `getMaxProtection()`.
    pub fn get_max_protection(&self) -> i32 {
        self.max_prot
    }

    /// Port of `getInitialProtection()`.
    pub fn get_initial_protection(&self) -> i32 {
        self.init_prot
    }

    /// Returns true if the mapping contains `addr`: a memory address when `is_addr`, otherwise a
    /// file offset. Comparisons are unsigned, as in Java's `Long.compareUnsigned`.
    ///
    /// Port of `contains(long, boolean)`.
    pub fn contains(&self, addr: i64, is_addr: bool) -> bool {
        let base = if is_addr { self.address } else { self.file_offset };
        let addr = addr as u64;
        addr >= base as u64 && addr < base.wrapping_add(self.size) as u64
    }

    /// Builds the concrete `dyld_cache_mapping_info` structure; see [`StructConverter`].
    pub fn to_structure(&self) -> StructureDataType {
        let cp = CategoryPath::parse(DATA_TYPE_CATEGORY).expect("valid Mach-O category path");
        let mut s = StructureDataType::new(cp, "dyld_cache_mapping_info", 0);
        for name in ["address", "size", "fileOffset"] {
            s.add(Arc::new(QWordPlaceholderDataType), 8, Some(name.to_string()), Some(String::new()));
        }
        for name in ["maxProt", "initProt"] {
            s.add(Arc::new(DWordPlaceholderDataType), 4, Some(name.to_string()), Some(String::new()));
        }
        s
    }
}

impl StructConverter for DyldCacheMappingInfo {
    /// Port of `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::dyld::test_support::VecReader;

    fn bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x1_8000_0000u64.to_le_bytes()); // address
        b.extend_from_slice(&0x4000u64.to_le_bytes()); // size
        b.extend_from_slice(&0x2000u64.to_le_bytes()); // fileOffset
        b.extend_from_slice(&7u32.to_le_bytes()); // maxProt rwx
        b.extend_from_slice(&5u32.to_le_bytes()); // initProt r-x
        b
    }

    #[test]
    fn parses_little_endian_structure() {
        let mut reader = VecReader::new(bytes(), true);
        let m = DyldCacheMappingInfo::from_reader(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), DyldCacheMappingInfo::SIZE as u64);
        assert_eq!(m.get_address(), 0x1_8000_0000);
        assert_eq!(m.get_size(), 0x4000);
        assert_eq!(m.get_file_offset(), 0x2000);
        assert_eq!(m.get_max_protection(), 7);
        assert_eq!(m.get_initial_protection(), 5);
        assert!(m.is_read());
        assert!(!m.is_write());
        assert!(m.is_execute());
    }

    #[test]
    fn truncated_input_errors() {
        let mut reader = VecReader::new(bytes()[..30].to_vec(), true);
        assert!(DyldCacheMappingInfo::from_reader(&mut reader).is_err());
    }

    #[test]
    fn contains_address_and_file_offset_bounds() {
        let m = DyldCacheMappingInfo::new(0x1000, 0x100, 0x40, 0, 0);
        assert!(m.contains(0x1000, true));
        assert!(m.contains(0x10ff, true));
        assert!(!m.contains(0x1100, true));
        assert!(!m.contains(0xfff, true));
        assert!(m.contains(0x40, false));
        assert!(!m.contains(0x140, false));
        assert!(!m.contains(0x1000, false));
    }

    #[test]
    fn contains_is_unsigned() {
        // A kernel-style high address: signed comparison would put it below everything.
        let m = DyldCacheMappingInfo::new(0xffff_fff0_0000_0000u64 as i64, 0x1000, 0, 0, 0);
        assert!(m.contains(0xffff_fff0_0000_0800u64 as i64, true));
        assert!(!m.contains(0x10, true));
    }

    #[test]
    fn data_type_layout() {
        let s = DyldCacheMappingInfo::default().to_structure();
        assert_eq!(s.get_name(), "dyld_cache_mapping_info");
        assert_eq!(s.get_length(), DyldCacheMappingInfo::SIZE as i32);
        assert_eq!(s.get_category_path().to_string(), "/MachO");
        let names: Vec<_> = s.components.iter().map(|c| c.field_name.clone().unwrap()).collect();
        assert_eq!(names, ["address", "size", "fileOffset", "maxProt", "initProt"]);
        assert_eq!(s.components[3].offset, 24);
        let dt = DyldCacheMappingInfo::default().to_data_type().unwrap();
        assert_eq!(dt.get_length(), 32);
    }
}
