//! Port of `ghidra.file.formats.sparseimage.SparseHeader`.

use std::io;

use crate::app::util::bin::binary_reader::LegacyBinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::dword_data_type::DWordDataType;
use crate::program::model::data::word_data_type::WordDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// The 28-byte header at the start of an Android sparse image.
///
/// Mirrors `ghidra.file.formats.sparseimage.SparseHeader`. Java reads it through a
/// little-endian `BinaryReader`; callers of [`SparseHeader::new`] supply one positioned at
/// the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseHeader {
    /// `0xED26FF3A`.
    pub magic: i32,
    /// `(0x1)` - reject images with higher major versions.
    pub major_version: i16,
    /// `(0x0)` - allow images with higher minor versions.
    pub minor_version: i16,
    /// 28 bytes for the first revision of the file format.
    pub file_hdr_sz: i16,
    /// 12 bytes for the first revision of the file format.
    pub chunk_hdr_sz: i16,
    /// Block size in bytes, must be a multiple of 4 (4096).
    pub blk_sz: i32,
    /// Total blocks in the non-sparse output image.
    pub total_blks: i32,
    /// Total chunks in the sparse input image.
    pub total_chunks: i32,
    /// CRC32 checksum of the original data, counting "don't care" as 0.
    pub image_checksum: i32,
}

impl SparseHeader {
    /// Reads the header from `reader`'s current position.
    ///
    /// Mirrors `SparseHeader(BinaryReader)`.
    pub fn new(reader: &mut dyn LegacyBinaryReader) -> io::Result<Self> {
        Ok(SparseHeader {
            magic: reader.read_next_int()?,
            major_version: reader.read_next_short()?,
            minor_version: reader.read_next_short()?,
            file_hdr_sz: reader.read_next_short()?,
            chunk_hdr_sz: reader.read_next_short()?,
            blk_sz: reader.read_next_int()?,
            total_blks: reader.read_next_int()?,
            total_chunks: reader.read_next_int()?,
            image_checksum: reader.read_next_int()?,
        })
    }
}

impl StructConverter for SparseHeader {
    /// Mirrors `toDataType()`: a `sparse_header` structure of the fields above.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let fields: [(&str, Box<dyn DataType>); 9] = [
            ("magic", Box::new(DWordDataType::new(None))),
            ("major_version", Box::new(WordDataType::new(None))),
            ("minor_version", Box::new(WordDataType::new(None))),
            ("file_hdr_sz", Box::new(WordDataType::new(None))),
            ("chunk_hdr_sz", Box::new(WordDataType::new(None))),
            ("blk_sz", Box::new(DWordDataType::new(None))),
            ("total_blks", Box::new(DWordDataType::new(None))),
            ("total_chunks", Box::new(DWordDataType::new(None))),
            ("image_checksum", Box::new(DWordDataType::new(None))),
        ];
        let mut structure = StructureDataType::new("sparse_header", 0);
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
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::macos::test_support::le_reader;

    fn header_bytes(blk_sz: u32, total_blks: u32, total_chunks: u32, crc: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xED26_FF3Au32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&28u16.to_le_bytes());
        b.extend_from_slice(&12u16.to_le_bytes());
        b.extend_from_slice(&blk_sz.to_le_bytes());
        b.extend_from_slice(&total_blks.to_le_bytes());
        b.extend_from_slice(&total_chunks.to_le_bytes());
        b.extend_from_slice(&crc.to_le_bytes());
        b
    }

    #[test]
    fn reads_little_endian_fields() {
        let mut reader = le_reader(header_bytes(4096, 10, 3, 0xCAFE_BABE));
        let h = SparseHeader::new(&mut reader).unwrap();
        assert_eq!(h.magic as u32, 0xED26_FF3A);
        assert_eq!(h.major_version, 1);
        assert_eq!(h.minor_version, 0);
        assert_eq!(h.file_hdr_sz, 28);
        assert_eq!(h.chunk_hdr_sz, 12);
        assert_eq!(h.blk_sz, 4096);
        assert_eq!(h.total_blks, 10);
        assert_eq!(h.total_chunks, 3);
        assert_eq!(h.image_checksum as u32, 0xCAFE_BABE);
        assert_eq!(reader.get_pointer_index(), 28);
    }

    #[test]
    fn short_input_errors() {
        let mut reader = le_reader(vec![0; 10]);
        assert!(SparseHeader::new(&mut reader).is_err());
    }

    #[test]
    fn data_type_is_28_byte_sparse_header() {
        let mut reader = le_reader(header_bytes(4096, 1, 1, 0));
        let dt = SparseHeader::new(&mut reader).unwrap().to_data_type().unwrap();
        assert_eq!(dt.get_name(), "sparse_header");
        assert_eq!(dt.get_length(), 28);
    }
}
