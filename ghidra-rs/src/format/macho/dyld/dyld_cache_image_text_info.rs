//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageTextInfo`.
//!
//! Represents a `dyld_cache_image_text_info` structure. See
//! `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::dyld::dyld_cache_image::DyldCacheImage;
use crate::format::macho::struct_builder::{array_with_element_length, byte, dword, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheImageTextInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldCacheImageTextInfo {
    uuid: Vec<u8>,
    load_address: i64,
    text_segment_size: i32,
    path_offset: i32,
    path: String,
}

impl DyldCacheImageTextInfo {
    /// Java: `DyldCacheImageTextInfo(BinaryReader)`. The path is read from the absolute
    /// `pathOffset`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let uuid = reader.read_next_byte_array(16)?;
        let load_address = reader.read_next_long()?;
        let text_segment_size = reader.read_next_int()?;
        let path_offset = reader.read_next_int()?;
        let path = reader.read_ascii_string(path_offset as i64 as u64)?;
        Ok(DyldCacheImageTextInfo { uuid, load_address, text_segment_size, path_offset, path })
    }

    /// The image's UUID (Java keeps it private).
    pub fn get_uuid(&self) -> &[u8] {
        &self.uuid
    }

    /// The `__TEXT` segment size (Java keeps it private).
    pub fn get_text_segment_size(&self) -> i32 {
        self.text_segment_size
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_image_text_info");
        s.add(array_with_element_length(byte(), 16, 1)?, "uuid", Some(""))?;
        s.add(qword(), "loadAddress", Some(""))?;
        s.add(dword(), "textSegmentSize", Some(""))?;
        s.add(dword(), "pathOffset", Some(""))?;
        s.finish_structure()
    }
}

impl DyldCacheImage for DyldCacheImageTextInfo {
    /// Java: `getAddress()`.
    fn address(&self) -> u64 {
        self.load_address as u64
    }

    /// Java: `getPath()`.
    fn path(&self) -> &str {
        &self.path
    }
}

impl StructConverter for DyldCacheImageTextInfo {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;

    #[test]
    fn reads_entry_and_path() {
        let mut b = Bytes::new(true);
        b.raw(&[7u8; 16]).u64(0x1_8000_0000).u32(0x4000).u32(32).name("/usr/lib/libz.dylib", 24);
        let t = DyldCacheImageTextInfo::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(t.address(), 0x1_8000_0000);
        assert_eq!(t.path(), "/usr/lib/libz.dylib");
        assert_eq!(t.get_text_segment_size(), 0x4000);
        assert_eq!(t.to_structure().unwrap().get_length(), 32);
    }
}
