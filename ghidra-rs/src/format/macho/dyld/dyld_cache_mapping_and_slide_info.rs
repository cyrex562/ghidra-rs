//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo`.

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

/// Represents a `dyld_cache_mapping_and_slide_info` structure.
///
/// See `dyld3/shared-cache/dyld_cache_format.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DyldCacheMappingAndSlideInfo {
    address: i64,
    size: i64,
    file_offset: i64,
    slide_info_file_offset: i64,
    slide_info_file_size: i64,
    flags: i64,
    max_prot: i32,
    init_prot: i32,
}

impl DyldCacheMappingAndSlideInfo {
    pub const DYLD_CACHE_MAPPING_AUTH_DATA: i64 = 0x1;
    pub const DYLD_CACHE_MAPPING_DIRTY_DATA: i64 = 0x2;
    pub const DYLD_CACHE_MAPPING_CONST_DATA: i64 = 0x4;
    pub const DYLD_CACHE_MAPPING_TEXT_STUBS: i64 = 0x8;
    pub const DYLD_CACHE_DYNAMIC_CONFIG_DATA: i64 = 0x10;
    pub const DYLD_CACHE_READ_ONLY_DATA: i64 = 0x20;
    pub const DYLD_CACHE_MAPPING_CONST_TPRO_DATA: i64 = 0x40;

    /// Size in bytes of the on-disk `dyld_cache_mapping_and_slide_info` structure.
    pub const SIZE: usize = 56;

    /// Builds a mapping from already-decoded field values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: i64,
        size: i64,
        file_offset: i64,
        slide_info_file_offset: i64,
        slide_info_file_size: i64,
        flags: i64,
        max_prot: i32,
        init_prot: i32,
    ) -> Self {
        DyldCacheMappingAndSlideInfo {
            address,
            size,
            file_offset,
            slide_info_file_offset,
            slide_info_file_size,
            flags,
            max_prot,
            init_prot,
        }
    }

    /// Reads a `dyld_cache_mapping_and_slide_info` at the reader's current position.
    ///
    /// Port of `DyldCacheMappingAndSlideInfo(BinaryReader)`.
    pub fn from_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(DyldCacheMappingAndSlideInfo {
            address: reader.read_next_long()?,
            size: reader.read_next_long()?,
            file_offset: reader.read_next_long()?,
            slide_info_file_offset: reader.read_next_long()?,
            slide_info_file_size: reader.read_next_long()?,
            flags: reader.read_next_long()?,
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

    /// Port of `getSlideInfoFileOffset()`.
    pub fn get_slide_info_file_offset(&self) -> i64 {
        self.slide_info_file_offset
    }

    /// Port of `getSlideInfoFileSize()`.
    pub fn get_slide_info_file_size(&self) -> i64 {
        self.slide_info_file_size
    }

    /// Port of `getFlags()`.
    pub fn get_flags(&self) -> i64 {
        self.flags
    }

    /// Port of `getMaxProtection()`.
    pub fn get_max_protection(&self) -> i32 {
        self.max_prot
    }

    /// Port of `getInitialProtection()`.
    pub fn get_initial_protection(&self) -> i32 {
        self.init_prot
    }

    /// Port of `isAuthData()`.
    pub fn is_auth_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_AUTH_DATA != 0
    }

    /// Port of `isDirtyData()`.
    pub fn is_dirty_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_DIRTY_DATA != 0
    }

    /// Port of `isConstData()`.
    pub fn is_const_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_CONST_DATA != 0
    }

    /// Port of `isTextStubs()`.
    pub fn is_text_stubs(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_TEXT_STUBS != 0
    }

    /// Port of `isConfigData()`.
    pub fn is_config_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_DYNAMIC_CONFIG_DATA != 0
    }

    /// Port of `isReadOnlyData()`.
    pub fn is_read_only_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_READ_ONLY_DATA != 0
    }

    /// Port of `isConstTproData()`.
    pub fn is_const_tpro_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_CONST_TPRO_DATA != 0
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

    /// Returns true if the mapping contains `addr`: a memory address when `is_addr`, otherwise a
    /// file offset. Comparisons are unsigned, as in Java's `Long.compareUnsigned`.
    ///
    /// Port of `contains(long, boolean)`.
    pub fn contains(&self, addr: i64, is_addr: bool) -> bool {
        let base = if is_addr { self.address } else { self.file_offset };
        let addr = addr as u64;
        addr >= base as u64 && addr < base.wrapping_add(self.size) as u64
    }

    /// Builds the concrete `dyld_cache_mapping_and_slide_info` structure; see
    /// [`StructConverter`].
    pub fn to_structure(&self) -> StructureDataType {
        let cp = CategoryPath::parse(DATA_TYPE_CATEGORY).expect("valid Mach-O category path");
        let mut s = StructureDataType::new(cp, "dyld_cache_mapping_and_slide_info", 0);
        for name in ["address", "size", "fileOffset", "slideInfoFileOffset", "slideInfoFileSize", "flags"] {
            s.add(Arc::new(QWordPlaceholderDataType), 8, Some(name.to_string()), Some(String::new()));
        }
        for name in ["maxProt", "initProt"] {
            s.add(Arc::new(DWordPlaceholderDataType), 4, Some(name.to_string()), Some(String::new()));
        }
        s
    }
}

impl StructConverter for DyldCacheMappingAndSlideInfo {
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
        for v in [0x1_8000_0000u64, 0x8000, 0x4000, 0x10_0000, 0x200, 0x41] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&3u32.to_le_bytes()); // maxProt rw-
        b.extend_from_slice(&3u32.to_le_bytes()); // initProt rw-
        b
    }

    #[test]
    fn parses_little_endian_structure() {
        let mut reader = VecReader::new(bytes(), true);
        let m = DyldCacheMappingAndSlideInfo::from_reader(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), DyldCacheMappingAndSlideInfo::SIZE as u64);
        assert_eq!(m.get_address(), 0x1_8000_0000);
        assert_eq!(m.get_size(), 0x8000);
        assert_eq!(m.get_file_offset(), 0x4000);
        assert_eq!(m.get_slide_info_file_offset(), 0x10_0000);
        assert_eq!(m.get_slide_info_file_size(), 0x200);
        assert_eq!(m.get_flags(), 0x41);
        assert_eq!(m.get_max_protection(), 3);
        assert!(m.is_read() && m.is_write() && !m.is_execute());
    }

    #[test]
    fn truncated_input_errors() {
        let mut reader = VecReader::new(bytes()[..50].to_vec(), true);
        assert!(DyldCacheMappingAndSlideInfo::from_reader(&mut reader).is_err());
    }

    #[test]
    fn flag_predicates() {
        let m = |flags| DyldCacheMappingAndSlideInfo::new(0, 0, 0, 0, 0, flags, 0, 0);
        assert!(m(0x41).is_auth_data());
        assert!(m(0x41).is_const_tpro_data());
        assert!(!m(0x41).is_dirty_data());
        assert!(m(0x2).is_dirty_data());
        assert!(m(0x4).is_const_data());
        assert!(m(0x8).is_text_stubs());
        assert!(m(0x10).is_config_data());
        assert!(m(0x20).is_read_only_data());
        assert!(!m(0).is_auth_data());
    }

    #[test]
    fn contains_bounds() {
        let m = DyldCacheMappingAndSlideInfo::new(0x1000, 0x100, 0x40, 0, 0, 0, 0, 0);
        assert!(m.contains(0x1000, true));
        assert!(!m.contains(0x1100, true));
        assert!(m.contains(0x13f, false));
        assert!(!m.contains(0x140, false));
    }

    #[test]
    fn data_type_layout() {
        let s = DyldCacheMappingAndSlideInfo::default().to_structure();
        assert_eq!(s.get_name(), "dyld_cache_mapping_and_slide_info");
        assert_eq!(s.get_length(), DyldCacheMappingAndSlideInfo::SIZE as i32);
        assert_eq!(s.get_category_path().to_string(), "/MachO");
        assert_eq!(s.components.len(), 8);
        assert_eq!(s.components[6].field_name.as_deref(), Some("maxProt"));
        assert_eq!(s.components[6].offset, 48);
    }
}
