use crate::filesystem::ghidra::g_string_utilities::convert_bytes_to_string;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::C13ChecksumType;

/// Base record size (offset, length, and checksum-type fields), excluding the checksum bytes
/// and any alignment padding.
pub const BASE_RECORD_SIZE: usize = 6;

/// PDB C13 Module File Checksum for one file.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.C13FileChecksum`. Modeled as a trait
/// (rather than a concrete struct) because this type was selected as a dependency-cycle
/// cut-point; [`DefaultC13FileChecksum`] is the parsed implementation used by the rest of the
/// crate.
pub trait C13FileChecksum: std::fmt::Debug {
    /// Returns the offset of the filename within the filename list.
    fn offset_filename(&self) -> u32;

    /// Returns the number of bytes of the checksum field.
    fn length(&self) -> u32;

    /// Returns the ID value of the checksum type used.
    fn checksum_type_value(&self) -> i32;

    /// Returns the checksum bytes.
    fn checksum_bytes(&self) -> &[u8];

    /// Returns the string representation of this checksum, mirroring Java's `toString()`.
    fn to_display_string(&self) -> String {
        let bytes = self.checksum_bytes();
        format!(
            "0x{:08x}, 0x{:02x} {}({:02x}): {}",
            self.offset_filename(),
            self.length(),
            C13ChecksumType::from_value(self.checksum_type_value()),
            self.checksum_type_value(),
            convert_bytes_to_string(bytes, bytes.len())
        )
    }
}

/// Parsed [`C13FileChecksum`] implementation.
#[derive(Debug, Clone)]
pub struct DefaultC13FileChecksum {
    offset_filename: u32,
    length: u32,
    checksum_type_value: i32,
    bytes: Vec<u8>,
}

impl DefaultC13FileChecksum {
    /// Parses a `DefaultC13FileChecksum` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the header, the checksum
    /// bytes, or the trailing alignment padding.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let offset_filename = reader.parse_unsigned_int_val()?;
        let length = reader.parse_unsigned_byte_val()? as u32;
        let checksum_type_value = reader.parse_unsigned_byte_val()? as i32;
        let bytes = reader.parse_bytes(length as usize)?;
        reader.align4();
        Ok(DefaultC13FileChecksum { offset_filename, length, checksum_type_value, bytes })
    }
}

impl C13FileChecksum for DefaultC13FileChecksum {
    fn offset_filename(&self) -> u32 {
        self.offset_filename
    }

    fn length(&self) -> u32 {
        self.length
    }

    fn checksum_type_value(&self) -> i32 {
        self.checksum_type_value
    }

    fn checksum_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes(offset: u32, length: u8, checksum_type: u8, bytes: &[u8]) -> Vec<u8> {
        let mut data = offset.to_le_bytes().to_vec();
        data.push(length);
        data.push(checksum_type);
        data.extend_from_slice(bytes);
        data
    }

    #[test]
    fn parse_reads_fields_and_aligns() {
        let mut data = record_bytes(0x1000, 4, 0x01, &[0xde, 0xad, 0xbe, 0xef]);
        // header(6) + 4 checksum bytes = 10, needs 2 pad bytes to reach 12 (align4)
        data.extend_from_slice(&[0xaa, 0xbb]);
        data.extend_from_slice(&[0x99]); // trailing byte after the record, untouched
        let mut reader = PdbByteReader::new(data);
        let checksum = DefaultC13FileChecksum::parse(&mut reader).unwrap();

        assert_eq!(checksum.offset_filename(), 0x1000);
        assert_eq!(checksum.length(), 4);
        assert_eq!(checksum.checksum_type_value(), 0x01);
        assert_eq!(checksum.checksum_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        // index should sit right after the align4 padding, before the trailing byte
        assert_eq!(reader.get_index(), 12);
    }

    #[test]
    fn parse_zero_length_checksum() {
        let data = record_bytes(0x20, 0, 0x00, &[]);
        let mut reader = PdbByteReader::new(data);
        let checksum = DefaultC13FileChecksum::parse(&mut reader).unwrap();
        assert_eq!(checksum.length(), 0);
        assert!(checksum.checksum_bytes().is_empty());
    }

    #[test]
    fn parse_insufficient_header_data_errors() {
        let data = vec![0x01, 0x02, 0x03];
        let mut reader = PdbByteReader::new(data);
        assert!(DefaultC13FileChecksum::parse(&mut reader).is_err());
    }

    #[test]
    fn parse_insufficient_checksum_bytes_errors() {
        // declares a 4-byte checksum but only supplies 2
        let data = record_bytes(0x10, 4, 0x02, &[0x01, 0x02]);
        let mut reader = PdbByteReader::new(data);
        assert!(DefaultC13FileChecksum::parse(&mut reader).is_err());
    }

    #[test]
    fn to_display_string_matches_expected_format() {
        let data = record_bytes(0x1000, 2, 0x01, &[0x0a, 0x0f]);
        let mut reader = PdbByteReader::new(data);
        let checksum = DefaultC13FileChecksum::parse(&mut reader).unwrap();
        assert_eq!(
            checksum.to_display_string(),
            "0x00001000, 0x02 Md5ChecksumType(01): 0a0f"
        );
    }

    #[test]
    fn to_display_string_unknown_checksum_type() {
        let data = record_bytes(0x0, 1, 0x7f, &[0xff]);
        let mut reader = PdbByteReader::new(data);
        let checksum = DefaultC13FileChecksum::parse(&mut reader).unwrap();
        assert_eq!(
            checksum.to_display_string(),
            "0x00000000, 0x01 UnknownChecksumType(7f): ff"
        );
    }

    /// Mock implementation (not backed by a parsed reader) proving the trait is object-safe and
    /// that its default `to_display_string` works through a `Box<dyn C13FileChecksum>`.
    #[derive(Debug)]
    struct MockFileChecksum {
        offset_filename: u32,
        length: u32,
        checksum_type_value: i32,
        bytes: Vec<u8>,
    }

    impl C13FileChecksum for MockFileChecksum {
        fn offset_filename(&self) -> u32 {
            self.offset_filename
        }

        fn length(&self) -> u32 {
            self.length
        }

        fn checksum_type_value(&self) -> i32 {
            self.checksum_type_value
        }

        fn checksum_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let checksum: Box<dyn C13FileChecksum> = Box::new(MockFileChecksum {
            offset_filename: 0x2020,
            length: 3,
            checksum_type_value: 0x03,
            bytes: vec![0x01, 0x02, 0x03],
        });

        assert_eq!(checksum.offset_filename(), 0x2020);
        assert_eq!(checksum.length(), 3);
        assert_eq!(checksum.checksum_type_value(), 0x03);
        assert_eq!(checksum.checksum_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(
            checksum.to_display_string(),
            "0x00002020, 0x03 Sha256ChecksumType(03): 010203"
        );
    }
}
