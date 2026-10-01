//! Port of `ghidra.app.util.bin.format.macho.commands.DataInCodeEntry`.
//!
//! Represents a `data_in_code_entry` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, word, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `data_in_code_entry`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DataInCodeEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataInCodeEntry {
    offset: i64,
    length: i32,
    kind: i16,
}

impl DataInCodeEntry {
    /// Java: `SIZE`, the entry's size in bytes.
    pub const SIZE: i32 = 8;

    /// Java: `DataInCodeEntry(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let offset = reader.read_next_unsigned_int()? as i64;
        let length = reader.read_next_unsigned_short()? as i32;
        let kind = reader.read_next_short()?;
        Ok(DataInCodeEntry { offset, length, kind })
    }

    /// Java: `getOffset()`, from the mach header to the start of the data range.
    pub fn get_offset(&self) -> i64 {
        self.offset
    }

    /// Java: `getLength()`, the number of bytes in the data range.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Java: `getKind()`.
    pub fn get_kind(&self) -> i16 {
        self.kind
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("data_in_code_entry");
        s.add(dword(), "offset", Some("from mach_header to start of data range"))?;
        s.add(word(), "length", Some("number of bytes in data range"))?;
        s.add(
            word(),
            "kind",
            Some("DICE_KIND_DATA=1, DICE_KIND_JUMP_TABLE8=2, DICE_KIND_JUMP_TABLE16=3, DICE_KIND_JUMP_TABLE32=4, DICE_KIND_ABS_JUMP_TABLE32=5"),
        )?;
        s.finish_structure()
    }
}

impl StructConverter for DataInCodeEntry {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entry() {
        let mut b = 0x8000_1000u32.to_le_bytes().to_vec();
        b.extend(0xfff0u16.to_le_bytes());
        b.extend(3u16.to_le_bytes());
        let e = DataInCodeEntry::new(&mut BinaryReader::from_bytes(b, true)).unwrap();
        assert_eq!(e.get_offset(), 0x8000_1000);
        assert_eq!(e.get_length(), 0xfff0);
        assert_eq!(e.get_kind(), 3);
        assert_eq!(e.to_structure().unwrap().get_length(), DataInCodeEntry::SIZE);
    }
}
