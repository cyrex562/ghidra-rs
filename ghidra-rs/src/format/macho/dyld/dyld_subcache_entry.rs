//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldSubcacheEntry`.
//!
//! Represents a `dyld_subcache_entry` (with the optional 32-byte file extension of newer caches).
//! See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{array_with_element_length, ascii, byte, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::seam_stubs::NumericUtilities;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldSubcacheEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldSubcacheEntry {
    uuid: Vec<u8>,
    cache_vm_offset: i64,
    cache_extension: Option<Vec<u8>>,
}

impl DyldSubcacheEntry {
    /// Java: `DyldSubcacheEntry(BinaryReader)`. The extension is present when the byte after the
    /// offset is `'.'`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let uuid = reader.read_next_byte_array(16)?;
        let cache_vm_offset = reader.read_next_long()?;
        let cache_extension = if reader.read_byte(reader.get_pointer_index())? == b'.' {
            Some(reader.read_next_byte_array(32)?)
        } else {
            None
        };
        Ok(DyldSubcacheEntry { uuid, cache_vm_offset, cache_extension })
    }

    /// Java: `getUuid()`, the UUID as hex.
    pub fn get_uuid(&self) -> String {
        NumericUtilities::convert_bytes_to_string(&self.uuid, "")
    }

    /// Java: `getCacheVMOffset()`.
    pub fn get_cache_vm_offset(&self) -> i64 {
        self.cache_vm_offset
    }

    /// Java: `getCacheExtension()`, up to its NUL; `None` for older caches.
    pub fn get_cache_extension(&self) -> Option<String> {
        self.cache_extension.as_ref().map(|ext| {
            let end = ext.iter().position(|&b| b == 0).unwrap_or(ext.len());
            ext[..end].iter().map(|&b| if b.is_ascii() { b as char } else { '\u{fffd}' }).collect()
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_subcache_entry");
        s.add(array_with_element_length(byte(), 16, 1)?, "uuid", Some("The UUID of the subCache file"))?;
        s.add(qword(), "cacheVMOffset", Some("The offset of this subcache from the main cache base address"))?;
        if self.cache_extension.is_some() {
            s.add(
                array_with_element_length(ascii()?, 32, 1)?,
                "cacheExtension",
                Some("The extension of the subCache file"),
            )?;
        }
        s.finish_structure()
    }
}

impl StructConverter for DyldSubcacheEntry {
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
    fn with_and_without_extension() {
        let mut b = Bytes::new(true);
        b.raw(&[0xab; 16]).u64(0x400_0000).name(".01", 32);
        let e = DyldSubcacheEntry::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(e.get_uuid(), "ab".repeat(16));
        assert_eq!(e.get_cache_vm_offset(), 0x400_0000);
        assert_eq!(e.get_cache_extension().as_deref(), Some(".01"));

        let mut b = Bytes::new(true);
        b.raw(&[1; 16]).u64(8).u8(0);
        let e = DyldSubcacheEntry::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert!(e.get_cache_extension().is_none());
        assert_eq!(e.to_structure().unwrap().get_length(), 24);
    }
}
