//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsEntry`.
//!
//! Represents a `dyld_cache_local_symbols_entry` (or its 64-bit-offset variant). See
//! `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, qword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldCacheLocalSymbolsEntry {
    dylib_offset: i64,
    nlist_start_index: i32,
    nlist_count: i32,
    use64bit_offsets: bool,
}

impl DyldCacheLocalSymbolsEntry {
    /// Java: `DyldCacheLocalSymbolsEntry(BinaryReader, boolean)`. A 32-bit `dylibOffset` is
    /// sign-extended, as Java's `int`-to-`long` widening does.
    pub fn new(reader: &mut BinaryReader, use64bit_offsets: bool) -> io::Result<Self> {
        let dylib_offset =
            if use64bit_offsets { reader.read_next_long()? } else { reader.read_next_int()? as i64 };
        let nlist_start_index = reader.read_next_int()?;
        let nlist_count = reader.read_next_int()?;
        Ok(DyldCacheLocalSymbolsEntry { dylib_offset, nlist_start_index, nlist_count, use64bit_offsets })
    }

    /// Java: `getDylibOffset()`.
    pub fn get_dylib_offset(&self) -> i64 {
        self.dylib_offset
    }

    /// Java: `getNListStartIndex()`.
    pub fn get_nlist_start_index(&self) -> i32 {
        self.nlist_start_index
    }

    /// Java: `getNListCount()`.
    pub fn get_nlist_count(&self) -> i32 {
        self.nlist_count
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_local_symbols_entry");
        s.add(if self.use64bit_offsets { qword() } else { dword() }, "dylibOffset", Some(""))?;
        s.add(dword(), "nlistStartIndex", Some(""))?;
        s.add(dword(), "nlistCount", Some(""))?;
        s.finish_structure()
    }
}

impl StructConverter for DyldCacheLocalSymbolsEntry {
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
    fn reads_32_and_64_bit_offsets() {
        let mut b = Bytes::new(true);
        b.u32(0x8000_0000).u32(3).u32(4);
        let e = DyldCacheLocalSymbolsEntry::new(&mut BinaryReader::from_bytes(b.buf, true), false).unwrap();
        assert_eq!(e.get_dylib_offset(), -0x8000_0000, "sign-extended like Java");
        assert_eq!((e.get_nlist_start_index(), e.get_nlist_count()), (3, 4));
        assert_eq!(e.to_structure().unwrap().get_length(), 12);

        let mut b = Bytes::new(true);
        b.u64(0x1_0000_0000).u32(5).u32(6);
        let e = DyldCacheLocalSymbolsEntry::new(&mut BinaryReader::from_bytes(b.buf, true), true).unwrap();
        assert_eq!(e.get_dylib_offset(), 0x1_0000_0000);
        assert_eq!(e.to_structure().unwrap().get_length(), 16);
    }
}
