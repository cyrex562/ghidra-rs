use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// A PDB C13 inlinee source line record
#[derive(Debug, Clone, Copy)]
pub struct C13InlineeSourceLine {
    inlinee: u32,
    file_id: i32,
    source_line_num: i32,
}

impl C13InlineeSourceLine {
    /// The base size of a C13 Inlinee Source Line record in bytes.
    pub const BASE_RECORD_SIZE: usize = 12;

    /// Parses a `C13InlineeSourceLine` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the required fields.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let inlinee = reader.parse_unsigned_int_val()?;
        let file_id = reader.parse_int()?;
        let source_line_num = reader.parse_int()?;
        Ok(C13InlineeSourceLine { inlinee, file_id, source_line_num })
    }

    /// Returns the inlinee value. The interpretation of this value is unclear.
    pub fn inlinee(&self) -> u32 {
        self.inlinee
    }

    /// Returns the file ID.
    pub fn file_id(&self) -> i32 {
        self.file_id
    }

    /// Returns the source line number.
    pub fn source_line_num(&self) -> i32 {
        self.source_line_num
    }
}

impl std::fmt::Display for C13InlineeSourceLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:09x}, 0x{:06x}, {}", self.inlinee, self.file_id, self.source_line_num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0x78563412);
        assert_eq!(record.file_id(), 0xf0debc9a_u32 as i32);
        assert_eq!(record.source_line_num(), 0x44332211);
    }

    #[test]
    fn parse_zero_values() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0);
        assert_eq!(record.file_id(), 0);
        assert_eq!(record.source_line_num(), 0);
    }

    #[test]
    fn parse_max_unsigned_inlinee() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), u32::MAX);
        assert_eq!(record.file_id(), 0);
        assert_eq!(record.source_line_num(), 0);
    }

    #[test]
    fn parse_max_signed_file_id() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0);
        assert_eq!(record.file_id(), i32::MAX);
        assert_eq!(record.source_line_num(), 0);
    }

    #[test]
    fn parse_negative_file_id() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0);
        assert_eq!(record.file_id(), -1);
        assert_eq!(record.source_line_num(), 0);
    }

    #[test]
    fn parse_max_signed_source_line_num() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0);
        assert_eq!(record.file_id(), 0);
        assert_eq!(record.source_line_num(), i32::MAX);
    }

    #[test]
    fn parse_negative_source_line_num() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.inlinee(), 0);
        assert_eq!(record.file_id(), 0);
        assert_eq!(record.source_line_num(), -1);
    }

    #[test]
    fn parse_insufficient_data() {
        let bytes = vec![0x12, 0x34, 0x56];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_exactly_12_bytes() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13InlineeSourceLine::parse(&mut reader);
        assert!(result.is_ok());
        assert_eq!(reader.get_index(), 12);
    }

    #[test]
    fn display_format() {
        let bytes = vec![0x12, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13InlineeSourceLine::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x000000012, 0x000034, 120");
    }

    #[test]
    fn display_format_with_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13InlineeSourceLine::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x0ffffffff, 0xffffffff, -1");
    }

    #[test]
    fn clone_and_copy_semantics() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let record1 = C13InlineeSourceLine::parse(&mut reader).unwrap();
        let record2 = record1; // Copy semantics
        let record3 = record1.clone(); // Clone semantics
        assert_eq!(record1.inlinee(), record2.inlinee());
        assert_eq!(record1.inlinee(), record3.inlinee());
        assert_eq!(record1.file_id(), record2.file_id());
        assert_eq!(record1.file_id(), record3.file_id());
        assert_eq!(record1.source_line_num(), record2.source_line_num());
        assert_eq!(record1.source_line_num(), record3.source_line_num());
    }

    #[test]
    fn debug_output() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13InlineeSourceLine::parse(&mut reader).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C13InlineeSourceLine"));
    }
}
