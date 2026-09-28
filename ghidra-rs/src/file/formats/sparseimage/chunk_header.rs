//! Port of `ghidra.file.formats.sparseimage.ChunkHeader`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::dword_data_type::DWordDataType;
use crate::program::model::data::word_data_type::WordDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The 12-byte header preceding each chunk of an Android sparse image.
///
/// Mirrors `ghidra.file.formats.sparseimage.ChunkHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// One of the `CHUNK_TYPE_*` values in
    /// [`sparse_constants`](super::sparse_constants), as the signed Java `short`.
    pub chunk_type: i16,
    /// Reserved.
    pub reserved1: i16,
    /// Number of blocks in the output.
    pub chunk_sz: i32,
    /// Number of bytes in the chunk input file, including this header and data.
    pub total_sz: i32,
}

impl ChunkHeader {
    /// Reads a chunk header from `reader`'s current position.
    ///
    /// Mirrors `ChunkHeader(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(ChunkHeader {
            chunk_type: reader.read_next_short()?,
            reserved1: reader.read_next_short()?,
            chunk_sz: reader.read_next_int()?,
            total_sz: reader.read_next_int()?,
        })
    }
}

impl StructConverter for ChunkHeader {
    /// Mirrors `toDataType()`: a `chunk_header` structure of the fields above.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let fields: [(&str, Box<dyn DataType>); 4] = [
            ("chunk_type", Box::new(WordDataType::new(None))),
            ("reserved1", Box::new(WordDataType::new(None))),
            ("chunk_sz", Box::new(DWordDataType::new(None))),
            ("total_sz", Box::new(DWordDataType::new(None))),
        ];
        let mut structure = StructureDataTypeImpl::new("chunk_header", 0);
        for (name, dt) in fields {
            structure
                .add_with_name(dt, Some(name.to_string()), None)
                .map_err(|e| ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        }
        Ok(Box::new(structure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::sparseimage::sparse_constants::CHUNK_TYPE_FILL;
    use crate::format::macos::test_support::VecReader;

    #[test]
    fn reads_little_endian_fields() {
        let mut b = Vec::new();
        b.extend_from_slice(&CHUNK_TYPE_FILL.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&16u32.to_le_bytes());
        let mut reader = VecReader::little_endian(b);
        let h = ChunkHeader::new(&mut reader).unwrap();
        assert_eq!(h.chunk_type as u16, CHUNK_TYPE_FILL);
        assert_eq!(h.reserved1, 0);
        assert_eq!(h.chunk_sz, 2);
        assert_eq!(h.total_sz, 16);
        assert_eq!(reader.get_pointer_index(), 12);
    }

    #[test]
    fn data_type_is_12_byte_chunk_header() {
        let mut reader = VecReader::little_endian(vec![0; 12]);
        let dt = ChunkHeader::new(&mut reader).unwrap().to_data_type().unwrap();
        assert_eq!(dt.get_name(), "chunk_header");
        assert_eq!(dt.get_length(), 12);
    }
}
