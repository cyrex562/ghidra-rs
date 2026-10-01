//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheRangeEntry`.
//!
//! Represents a `dyld_cache_range_entry` structure. See `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheRangeEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldCacheRangeEntry {
    start_address: i64,
    size: i32,
    image_index: i32,
}

impl DyldCacheRangeEntry {
    /// Java: `DyldCacheRangeEntry(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let start_address = reader.read_next_long()?;
        let size = reader.read_next_int()?;
        let image_index = reader.read_next_int()?;
        Ok(DyldCacheRangeEntry { start_address, size, image_index })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_range_entry");
        s.add(qword(), "startAddress", Some(""))?;
        s.add(dword(), "size", Some(""))?;
        s.add(dword(), "imageIndex", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheRangeEntry {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::fields;

    #[test]
    fn parses_in_order_and_lays_out_structure() {
        let mut b = Bytes::new(true);
        b.u64(1);
        b.u32(2);
        b.u32(3);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let v = DyldCacheRangeEntry::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 16);
        assert_eq!(v.start_address, 1);
        assert_eq!(v.image_index, 3);
        let s = v.to_structure().unwrap();
        assert_eq!(s.get_length(), 16);
        assert_eq!(fields(&s)[0].0, "startAddress");
    }
}
