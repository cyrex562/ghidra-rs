use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// A PDB C13 Cross-Scope Import record
#[derive(Debug, Clone)]
pub struct C13CrossScopeImport {
    offset_object_file_path: i32,
    num_cross_references: u32,
    reference_ids: Vec<u32>,
}

impl C13CrossScopeImport {
    /// The base size of a C13 Cross-Scope Import record in bytes (without reference IDs).
    pub const BASE_RECORD_SIZE: usize = 8;

    /// Parses a `C13CrossScopeImport` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the offset, count, or reference IDs.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let offset_object_file_path = reader.parse_int()?;
        let num_cross_references = reader.parse_unsigned_int_val()?;
        let mut reference_ids = Vec::with_capacity(num_cross_references as usize);
        for _ in 0..num_cross_references {
            reference_ids.push(reader.parse_unsigned_int_val()?);
        }
        Ok(C13CrossScopeImport {
            offset_object_file_path,
            num_cross_references,
            reference_ids,
        })
    }

    /// Returns the offset to the module file pathname in the filename records.
    pub fn offset_object_file_path(&self) -> i32 {
        self.offset_object_file_path
    }

    /// Returns the number of cross references.
    pub fn num_cross_references(&self) -> u32 {
        self.num_cross_references
    }

    /// Returns the list of cross-reference IDs.
    pub fn reference_ids(&self) -> &[u32] {
        &self.reference_ids
    }
}

impl std::fmt::Display for C13CrossScopeImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}, {:5}", self.offset_object_file_path, self.num_cross_references)?;
        for id in &self.reference_ids {
            write!(f, " 0x{:08x}", id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record_no_references() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_object_file_path(), 0x78563412);
        assert_eq!(record.num_cross_references(), 0);
        assert_eq!(record.reference_ids().len(), 0);
    }

    #[test]
    fn parse_valid_record_with_references() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22,
            0x33, 0x44,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_object_file_path(), 0x78563412);
        assert_eq!(record.num_cross_references(), 2);
        assert_eq!(record.reference_ids().len(), 2);
        assert_eq!(record.reference_ids()[0], 0xddccbbaa);
        assert_eq!(record.reference_ids()[1], 0x44332211);
    }

    #[test]
    fn parse_zero_values() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_object_file_path(), 0);
        assert_eq!(record.num_cross_references(), 0);
        assert_eq!(record.reference_ids().len(), 0);
    }

    #[test]
    fn parse_max_offset_negative_in_java() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_object_file_path(), -1i32);
        assert_eq!(record.num_cross_references(), 0);
    }

    #[test]
    fn parse_insufficient_data_for_offset() {
        let bytes = vec![0x10];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_count() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_references() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn getters_return_parsed_values() {
        let bytes = vec![
            0x11, 0x22, 0x33, 0x44, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02,
            0x02, 0x02, 0x03, 0x03, 0x03, 0x03,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeImport::parse(&mut reader).unwrap();
        assert_eq!(record.offset_object_file_path(), 0x44332211);
        assert_eq!(record.num_cross_references(), 3);
        assert_eq!(record.reference_ids()[0], 0x01010101);
        assert_eq!(record.reference_ids()[1], 0x02020202);
        assert_eq!(record.reference_ids()[2], 0x03030303);
    }

    #[test]
    fn display_format_no_references() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeImport::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x78563412,     0");
    }

    #[test]
    fn display_format_with_references() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22,
            0x33, 0x44,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeImport::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x78563412,     2 0xddccbbaa 0x44332211");
    }

    #[test]
    fn debug_output() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeImport::parse(&mut reader).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C13CrossScopeImport"));
    }

    #[test]
    fn clone_semantics() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22,
            0x33, 0x44,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let record1 = C13CrossScopeImport::parse(&mut reader).unwrap();
        let record2 = record1.clone();
        assert_eq!(record1.offset_object_file_path(), record2.offset_object_file_path());
        assert_eq!(record1.num_cross_references(), record2.num_cross_references());
        assert_eq!(record1.reference_ids(), record2.reference_ids());
    }

    #[test]
    fn base_record_size() {
        assert_eq!(C13CrossScopeImport::BASE_RECORD_SIZE, 8);
    }

    #[test]
    fn large_number_of_references() {
        let mut bytes = vec![0x12, 0x34, 0x56, 0x78, 0x0a, 0x00, 0x00, 0x00];
        for i in 0..10 {
            bytes.extend_from_slice(&(i as u32).to_le_bytes());
        }
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeImport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.num_cross_references(), 10);
        assert_eq!(record.reference_ids().len(), 10);
        for i in 0..10 {
            assert_eq!(record.reference_ids()[i], i as u32);
        }
    }
}
