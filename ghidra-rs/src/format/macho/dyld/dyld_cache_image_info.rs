//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageInfo`.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::dyld::dyld_cache_image::DyldCacheImage;
use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::format::seam_stubs::{DWordPlaceholderDataType, QWordPlaceholderDataType};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;

/// Represents a `dyld_cache_image_info` structure.
///
/// See `dyld3/shared-cache/dyld_cache_format.h`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DyldCacheImageInfo {
    address: u64,
    mod_time: i64,
    inode: i64,
    path_file_offset: i32,
    pad: i32,
    path: String,
}

impl DyldCacheImageInfo {
    /// Size in bytes of the on-disk `dyld_cache_image_info` structure.
    pub const SIZE: usize = 32;

    /// Reads a `dyld_cache_image_info` at the reader's current position, then resolves its
    /// NUL-terminated path at `pathFileOffset` (without moving the reader).
    ///
    /// Port of `DyldCacheImageInfo(BinaryReader)`.
    pub fn from_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let address = reader.read_next_long()? as u64;
        let mod_time = reader.read_next_long()?;
        let inode = reader.read_next_long()?;
        let path_file_offset = reader.read_next_int()?;
        let pad = reader.read_next_int()?;
        // Java passes the int straight to readAsciiString(long), so it sign-extends.
        let path = reader.read_ascii_string(path_file_offset as i64 as u64)?;
        Ok(DyldCacheImageInfo { address, mod_time, inode, path_file_offset, pad, path })
    }

    /// Port of `getAddress()`.
    pub fn get_address(&self) -> u64 {
        self.address
    }

    /// Port of `getPath()`.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// The `modTime` field.
    pub fn mod_time(&self) -> i64 {
        self.mod_time
    }

    /// The `inode` field.
    pub fn inode(&self) -> i64 {
        self.inode
    }

    /// The `pathFileOffset` field.
    pub fn path_file_offset(&self) -> i32 {
        self.path_file_offset
    }

    /// Builds the concrete `dyld_cache_image_info` structure; see [`StructConverter`].
    pub fn to_structure(&self) -> StructureDataType {
        let cp = CategoryPath::parse(DATA_TYPE_CATEGORY).expect("valid Mach-O category path");
        let mut s = StructureDataType::new(cp, "dyld_cache_image_info", 0);
        for name in ["address", "modTime", "inode"] {
            s.add(Arc::new(QWordPlaceholderDataType), 8, Some(name.to_string()), Some(String::new()));
        }
        for name in ["pathFileOffset", "pad"] {
            s.add(Arc::new(DWordPlaceholderDataType), 4, Some(name.to_string()), Some(String::new()));
        }
        s
    }
}

impl DyldCacheImage for DyldCacheImageInfo {
    fn address(&self) -> u64 {
        self.address
    }

    fn path(&self) -> &str {
        &self.path
    }
}

impl StructConverter for DyldCacheImageInfo {
    /// Port of `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::dyld::test_support::VecReader;

    /// An image-info record at offset 0 whose path string lives at offset 0x20.
    fn bytes(path_offset: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x1_8010_0000u64.to_le_bytes()); // address
        b.extend_from_slice(&0x5f00_0000u64.to_le_bytes()); // modTime
        b.extend_from_slice(&42u64.to_le_bytes()); // inode
        b.extend_from_slice(&path_offset.to_le_bytes()); // pathFileOffset
        b.extend_from_slice(&0u32.to_le_bytes()); // pad
        b.extend_from_slice(b"/usr/lib/libSystem.B.dylib\0");
        b
    }

    #[test]
    fn parses_record_and_path() {
        let mut reader = VecReader::new(bytes(0x20), true);
        let info = DyldCacheImageInfo::from_reader(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), DyldCacheImageInfo::SIZE as u64);
        assert_eq!(info.get_address(), 0x1_8010_0000);
        assert_eq!(info.mod_time(), 0x5f00_0000);
        assert_eq!(info.inode(), 42);
        assert_eq!(info.path_file_offset(), 0x20);
        assert_eq!(info.get_path(), "/usr/lib/libSystem.B.dylib");
        let image: &dyn DyldCacheImage = &info;
        assert_eq!(image.address(), 0x1_8010_0000);
        assert_eq!(image.path(), "/usr/lib/libSystem.B.dylib");
    }

    #[test]
    fn path_offset_out_of_range_errors() {
        let mut reader = VecReader::new(bytes(0x1000), true);
        assert!(DyldCacheImageInfo::from_reader(&mut reader).is_err());
    }

    #[test]
    fn data_type_layout() {
        let s = DyldCacheImageInfo::default().to_structure();
        assert_eq!(s.get_name(), "dyld_cache_image_info");
        assert_eq!(s.get_length(), DyldCacheImageInfo::SIZE as i32);
        assert_eq!(s.get_category_path().to_string(), "/MachO");
        let names: Vec<_> = s.components.iter().map(|c| c.field_name.clone().unwrap()).collect();
        assert_eq!(names, ["address", "modTime", "inode", "pathFileOffset", "pad"]);
    }
}
