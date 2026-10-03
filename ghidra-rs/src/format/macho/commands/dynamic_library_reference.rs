//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryReference`.
//!
//! Represents a `dylib_reference` structure: a 24-bit symbol index and 8 bits of flags, whose
//! placement in the word depends on the byte order. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `dylib_reference`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryReference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicLibraryReference {
    isym: i32,
    flags: i32,
}

impl DynamicLibraryReference {
    /// Java: `DynamicLibraryReference(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_int()?;
        let (isym, flags) = if reader.is_little_endian() {
            (value & 0x00ff_ffff, (value & 0xff00_0000u32 as i32) >> 24)
        } else {
            ((value & 0xffff_ff00u32 as i32) >> 8, value & 0x0000_00ff)
        };
        Ok(DynamicLibraryReference { isym, flags })
    }

    /// Java: `getSymbolIndex()`.
    pub fn get_symbol_index(&self) -> i32 {
        self.isym
    }

    /// Java: `getFlags()`. An arithmetic shift, as in Java.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dylib_reference");
        s.dword("isym_flags")?;
        s.finish_structure()
    }
}

impl StructConverter for DynamicLibraryReference {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_placement_depends_on_endianness() {
        let le = DynamicLibraryReference::new(&mut BinaryReader::from_bytes(
            0x0312_3456u32.to_le_bytes().to_vec(),
            true,
        ))
        .unwrap();
        assert_eq!((le.get_symbol_index(), le.get_flags()), (0x12_3456, 3));
        let be = DynamicLibraryReference::new(&mut BinaryReader::from_bytes(
            0x1234_5603u32.to_be_bytes().to_vec(),
            false,
        ))
        .unwrap();
        assert_eq!((be.get_symbol_index(), be.get_flags()), (0x12_3456, 3));
        let neg = DynamicLibraryReference::new(&mut BinaryReader::from_bytes(
            0x8000_0001u32.to_le_bytes().to_vec(),
            true,
        ))
        .unwrap();
        assert_eq!(neg.get_flags(), -128, "sign-extending shift, as in Java");
    }
}
