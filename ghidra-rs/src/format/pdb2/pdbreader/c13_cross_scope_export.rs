use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// A PDB C13 Cross-Scope Export record
#[derive(Debug, Clone, Copy)]
pub struct C13CrossScopeExport {
    local_id: u32,
    global_id: u32,
}

impl C13CrossScopeExport {
    /// The base size of a C13 Cross-Scope Export record in bytes.
    pub const BASE_RECORD_SIZE: usize = 8;

    /// Parses a `C13CrossScopeExport` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the local and global IDs.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let local_id = reader.parse_unsigned_int_val()?;
        let global_id = reader.parse_unsigned_int_val()?;
        Ok(C13CrossScopeExport { local_id, global_id })
    }

    /// Returns the local ID.
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Returns the global ID.
    pub fn global_id(&self) -> u32 {
        self.global_id
    }
}

impl std::fmt::Display for C13CrossScopeExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}, 0x{:08x}", self.local_id, self.global_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeExport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.local_id(), 0x04030201);
        assert_eq!(record.global_id(), 0x08070605);
    }

    #[test]
    fn parse_zero_values() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeExport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.local_id(), 0);
        assert_eq!(record.global_id(), 0);
    }

    #[test]
    fn parse_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeExport::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.local_id(), u32::MAX);
        assert_eq!(record.global_id(), u32::MAX);
    }

    #[test]
    fn parse_insufficient_data_for_local_id() {
        let bytes = vec![0x10];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeExport::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_global_id() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13CrossScopeExport::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn getters_return_parsed_values() {
        let bytes = vec![0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeExport::parse(&mut reader).unwrap();
        assert_eq!(record.local_id(), 0xddccbbaa);
        assert_eq!(record.global_id(), 0x44332211);
    }

    #[test]
    fn display_format() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeExport::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x78563412, 0x00efcdab");
    }

    #[test]
    fn display_format_with_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeExport::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0xffffffff, 0xffffffff");
    }

    #[test]
    fn debug_output() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13CrossScopeExport::parse(&mut reader).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C13CrossScopeExport"));
    }

    #[test]
    fn clone_and_copy_semantics() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = PdbByteReader::new(bytes);
        let record1 = C13CrossScopeExport::parse(&mut reader).unwrap();
        let record2 = record1;
        let record3 = record1.clone();
        assert_eq!(record1.local_id(), record2.local_id());
        assert_eq!(record1.local_id(), record3.local_id());
        assert_eq!(record1.global_id(), record2.global_id());
        assert_eq!(record1.global_id(), record3.global_id());
    }

    #[test]
    fn base_record_size() {
        assert_eq!(C13CrossScopeExport::BASE_RECORD_SIZE, 8);
    }
}
