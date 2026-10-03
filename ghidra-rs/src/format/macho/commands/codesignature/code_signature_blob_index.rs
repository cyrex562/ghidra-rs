//! Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureBlobIndex`.
//!
//! Represents a `CS_BlobIndex` structure. See `osfmk/kern/cs_blobs.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::{dword, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `CS_BlobIndex`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureBlobIndex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSignatureBlobIndex {
    blob_type: i32,
    offset: i64,
}

impl CodeSignatureBlobIndex {
    /// Java: `CodeSignatureBlobIndex(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let blob_type = reader.read_next_int()?;
        let offset = reader.read_next_unsigned_int()? as i64;
        Ok(CodeSignatureBlobIndex { blob_type, offset })
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> i32 {
        self.blob_type
    }

    /// Java: `getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.offset
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("CS_BlobIndex");
        s.add(dword(), "type", Some("type of entry"))?;
        s.add(dword(), "offset", Some("offset of entry"))?;
        s.finish_structure()
    }
}

impl StructConverter for CodeSignatureBlobIndex {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_index() {
        let mut b = 2u32.to_be_bytes().to_vec();
        b.extend(0x8000_0010u32.to_be_bytes());
        let i = CodeSignatureBlobIndex::new(&mut BinaryReader::from_bytes(b, false)).unwrap();
        assert_eq!(i.get_type(), 2);
        assert_eq!(i.get_offset(), 0x8000_0010);
        assert_eq!(i.to_structure().unwrap().get_length(), 8);
    }
}
