use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// A PDB C13 Line Number Column Record
#[derive(Debug, Clone, Copy)]
pub struct C13ColumnRecord {
    offset_column_start: u16,
    offset_column_end: u16,
}

impl C13ColumnRecord {
    /// Parses a `C13ColumnRecord` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the start and end values.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let offset_column_start = reader.parse_unsigned_short_val()?;
        let offset_column_end = reader.parse_unsigned_short_val()?;
        Ok(C13ColumnRecord { offset_column_start, offset_column_end })
    }

    /// Returns the column start for the offset.
    pub fn offset_column_start(&self) -> u16 {
        self.offset_column_start
    }

    /// Returns the column end for the offset.
    pub fn offset_column_end(&self) -> u16 {
        self.offset_column_end
    }
}

impl std::fmt::Display for C13ColumnRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start: 0x{:04x}, End: 0x{:04x}",
            self.offset_column_start, self.offset_column_end
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13ColumnRecord::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_column_start(), 0x2010);
        assert_eq!(record.offset_column_end(), 0x4030);
    }

    #[test]
    fn parse_zero_values() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13ColumnRecord::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_column_start(), 0);
        assert_eq!(record.offset_column_end(), 0);
    }

    #[test]
    fn parse_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13ColumnRecord::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.offset_column_start(), u16::MAX);
        assert_eq!(record.offset_column_end(), u16::MAX);
    }

    #[test]
    fn parse_insufficient_data_for_start() {
        let bytes = vec![0x10];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13ColumnRecord::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_end() {
        let bytes = vec![0x10, 0x20, 0x30];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13ColumnRecord::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn getters_return_parsed_values() {
        let bytes = vec![0x11, 0x22, 0x33, 0x44];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13ColumnRecord::parse(&mut reader).unwrap();
        assert_eq!(record.offset_column_start(), 0x2211);
        assert_eq!(record.offset_column_end(), 0x4433);
    }

    #[test]
    fn display_format() {
        let bytes = vec![0x10, 0x00, 0x20, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13ColumnRecord::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "Start: 0x0010, End: 0x0020");
    }

    #[test]
    fn display_format_with_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13ColumnRecord::parse(&mut reader).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "Start: 0xffff, End: 0xffff");
    }

    #[test]
    fn debug_output() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PdbByteReader::new(bytes);
        let record = C13ColumnRecord::parse(&mut reader).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C13ColumnRecord"));
    }

    #[test]
    fn clone_and_copy_semantics() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PdbByteReader::new(bytes);
        let record1 = C13ColumnRecord::parse(&mut reader).unwrap();
        let record2 = record1; // Copy semantics
        let record3 = record1.clone(); // Clone semantics
        assert_eq!(record1.offset_column_start(), record2.offset_column_start());
        assert_eq!(record1.offset_column_start(), record3.offset_column_start());
        assert_eq!(record1.offset_column_end(), record2.offset_column_end());
        assert_eq!(record1.offset_column_end(), record3.offset_column_end());
    }
}
