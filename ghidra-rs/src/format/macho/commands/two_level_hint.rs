//! Port of `ghidra.app.util.bin.format.macho.commands.TwoLevelHint`.
//!
//! Represents a `twolevel_hint` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `twolevel_hint`: an 8-bit sub-image index and a 24-bit table-of-contents index packed
/// into one 32-bit word.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.TwoLevelHint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwoLevelHint {
    isub_image: i32,
    itoc: i32,
}

impl TwoLevelHint {
    /// Java: `SIZEOF`.
    pub const SIZEOF: i32 = 4;

    /// Java: `TwoLevelHint(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_int()?;
        Ok(TwoLevelHint { isub_image: value & 0xff, itoc: value >> 8 })
    }

    /// Java: `getSubImageIndex()`.
    pub fn get_sub_image_index(&self) -> i32 {
        self.isub_image
    }

    /// Java: `getTableOfContentsIndex()`. An arithmetic shift, as in Java.
    pub fn get_table_of_contents_index(&self) -> i32 {
        self.itoc
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("twolevel_hint");
        s.dword("isub_image_itoc")?;
        s.finish_structure()
    }
}

impl StructConverter for TwoLevelHint {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_indexes() {
        let mut r = BinaryReader::from_bytes(0x0012_3405u32.to_le_bytes().to_vec(), true);
        let h = TwoLevelHint::new(&mut r).unwrap();
        assert_eq!(h.get_sub_image_index(), 5);
        assert_eq!(h.get_table_of_contents_index(), 0x1234);
        let mut r = BinaryReader::from_bytes(0xffff_ff01u32.to_le_bytes().to_vec(), true);
        assert_eq!(TwoLevelHint::new(&mut r).unwrap().get_table_of_contents_index(), -1);
        assert_eq!(h.to_structure().unwrap().get_length(), TwoLevelHint::SIZEOF);
    }
}
