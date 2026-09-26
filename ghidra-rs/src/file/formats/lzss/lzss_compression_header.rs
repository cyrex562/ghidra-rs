//! Port of `ghidra.file.formats.lzss.LzssCompressionHeader`.

use std::io;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

use super::lzss_constants::{HEADER_LENGTH, PADDING_LENGTH, SIGNATURE_COMPRESSION, SIGNATURE_LZSS};

/// The header at the start of an LZSS-compressed container: five big-endian ints followed by
/// [`PADDING_LENGTH`] bytes of padding ([`HEADER_LENGTH`] bytes in all).
///
/// Mirrors `ghidra.file.formats.lzss.LzssCompressionHeader`; the Java getters are the public
/// fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzssCompressionHeader {
    /// The first int. Mirrors `getSignature()`.
    pub signature: i32,
    /// The second int. Mirrors `getCompressionType()`.
    pub compression_type: i32,
    /// Mirrors `getChecksum()`.
    pub checksum: i32,
    /// Mirrors `getDecompressedLength()`.
    pub decompressed_length: i32,
    /// Mirrors `getCompressedLength()`.
    pub compressed_length: i32,
    /// Mirrors `getPadding()`.
    pub padding: Vec<u8>,
}

/// Reads a big-endian int at `offset`, the way `BinaryReader(provider, false).readNextInt()`
/// does (an `EOFException` past the end of the provider).
fn read_be_int(provider: &dyn ByteProvider, offset: u64) -> io::Result<i32> {
    let bytes = read_exact(provider, offset, 4)?;
    Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_exact(provider: &dyn ByteProvider, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    if offset.checked_add(len).is_none_or(|end| end > provider.length()) {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected end of stream"));
    }
    provider.read_bytes(offset, len)
}

impl LzssCompressionHeader {
    /// `sizeof(signature) + sizeof(compressionType)`. Mirrors `PROBE_BYTES_NEEDED`.
    pub const PROBE_BYTES_NEEDED: usize = 8;

    /// Returns `true` if `start_bytes` begin with the magic signature of an
    /// `LzssCompressionHeader`.
    ///
    /// Mirrors `probe(byte[])` exactly: the first big-endian int must be
    /// [`SIGNATURE_LZSS`] (`"lzss"`) and the second [`SIGNATURE_COMPRESSION`] (`"comp"`). Note
    /// that this is the reverse of the `"comp"`,`"lzss"` order
    /// [`LzssUtil::is_lzss`](super::lzss_util::LzssUtil::is_lzss) checks; the Java source
    /// disagrees with itself here and this port keeps each side's behavior.
    pub fn probe(start_bytes: &[u8]) -> bool {
        if start_bytes.len() < Self::PROBE_BYTES_NEEDED {
            return false;
        }
        let signature = i32::from_be_bytes([start_bytes[0], start_bytes[1], start_bytes[2], start_bytes[3]]);
        let compression_type =
            i32::from_be_bytes([start_bytes[4], start_bytes[5], start_bytes[6], start_bytes[7]]);
        signature == SIGNATURE_LZSS as i32 && compression_type == SIGNATURE_COMPRESSION as i32
    }

    /// Reads the header from the start of `provider`.
    ///
    /// Mirrors `LzssCompressionHeader(ByteProvider)`.
    ///
    /// # Errors
    /// If `provider` is shorter than [`HEADER_LENGTH`] bytes, or on a read error.
    pub fn new(provider: &dyn ByteProvider) -> io::Result<Self> {
        Ok(LzssCompressionHeader {
            signature: read_be_int(provider, 0)?,
            compression_type: read_be_int(provider, 4)?,
            checksum: read_be_int(provider, 8)?,
            decompressed_length: read_be_int(provider, 12)?,
            compressed_length: read_be_int(provider, 16)?,
            padding: read_exact(provider, 20, PADDING_LENGTH as u64)?,
        })
    }
}

impl StructConverter for LzssCompressionHeader {
    /// Mirrors `toDataType()`, which is `StructConverterUtil.toDataType(this)`: a structure
    /// named after the class, one `dword` per int field and a byte array for the padding,
    /// named as the Java fields are.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let invalid = |e: String| ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, e));
        let mut structure = StructureDataTypeImpl::new("LzssCompressionHeader", 0);
        for name in ["signature", "compressionType", "checksum", "decompressedLength", "compressedLength"] {
            structure
                .add_with_name(PrimitiveDt::DWORD.boxed(), Some(name.to_string()), None)
                .map_err(invalid)?;
        }
        let byte = PrimitiveDt::BYTE;
        let padding = ArrayDataType::with_element_length(byte.boxed(), self.padding.len() as i32, byte.get_length())
            .map_err(invalid)?;
        structure
            .add_with_name(Box::new(padding), Some("padding".to_string()), None)
            .map_err(invalid)?;
        debug_assert_eq!(HEADER_LENGTH, 20 + PADDING_LENGTH);
        Ok(Box::new(structure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    fn header_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"lzss");
        b.extend_from_slice(b"comp");
        b.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        b.extend_from_slice(&1000u32.to_be_bytes());
        b.extend_from_slice(&600u32.to_be_bytes());
        b.extend((0..PADDING_LENGTH).map(|i| i as u8));
        b
    }

    #[test]
    fn probe_matches_java_signature_order() {
        assert!(LzssCompressionHeader::probe(b"lzsscomp"));
        assert!(LzssCompressionHeader::probe(&header_bytes()));
        assert!(!LzssCompressionHeader::probe(b"complzss"));
        assert!(!LzssCompressionHeader::probe(b"lzssco"), "fewer than PROBE_BYTES_NEEDED");
        assert_eq!(LzssCompressionHeader::PROBE_BYTES_NEEDED, 8);
    }

    #[test]
    fn reads_big_endian_fields_and_padding() {
        let p = ByteArrayProvider::new(header_bytes());
        let h = LzssCompressionHeader::new(&p).unwrap();
        assert_eq!(h.signature, SIGNATURE_LZSS as i32);
        assert_eq!(h.compression_type, SIGNATURE_COMPRESSION as i32);
        assert_eq!(h.checksum, 0x0102_0304);
        assert_eq!(h.decompressed_length, 1000);
        assert_eq!(h.compressed_length, 600);
        assert_eq!(h.padding.len(), 0x16c);
        assert_eq!(h.padding[1], 1);
    }

    #[test]
    fn truncated_header_is_eof() {
        let mut bytes = header_bytes();
        bytes.truncate(HEADER_LENGTH - 1);
        let err = LzssCompressionHeader::new(&ByteArrayProvider::new(bytes)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn data_type_matches_struct_converter_util() {
        let h = LzssCompressionHeader::new(&ByteArrayProvider::new(header_bytes())).unwrap();
        let dt = h.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "LzssCompressionHeader");
        assert_eq!(dt.get_length(), HEADER_LENGTH as i32);
    }
}
