use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// An individual PDB C11 Line Start/End record (think these are offsets in a segment).
#[derive(Debug, Clone, Copy)]
pub struct C11LinesStartEnd {
    start: u32,
    end: u32,
}

impl C11LinesStartEnd {
    /// Parses a `C11LinesStartEnd` record from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the start and end values.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let start = reader.parse_unsigned_int_val()?;
        let end = reader.parse_unsigned_int_val()?;
        Ok(C11LinesStartEnd { start, end })
    }

    /// Returns the start line value.
    pub fn start(&self) -> u32 {
        self.start
    }

    /// Returns the end line value.
    pub fn end(&self) -> u32 {
        self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let mut reader = PdbByteReader::new(bytes);
        let result = C11LinesStartEnd::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.start(), 0x4030_2010);
        assert_eq!(record.end(), 0x8070_6050);
    }

    #[test]
    fn parse_zero_values() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let result = C11LinesStartEnd::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.start(), 0);
        assert_eq!(record.end(), 0);
    }

    #[test]
    fn parse_max_values() {
        let bytes = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut reader = PdbByteReader::new(bytes);
        let result = C11LinesStartEnd::parse(&mut reader);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.start(), u32::MAX);
        assert_eq!(record.end(), u32::MAX);
    }

    #[test]
    fn parse_insufficient_data_for_start() {
        let bytes = vec![0x10, 0x20];
        let mut reader = PdbByteReader::new(bytes);
        let result = C11LinesStartEnd::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_end() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let mut reader = PdbByteReader::new(bytes);
        let result = C11LinesStartEnd::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn getters_return_parsed_values() {
        let bytes = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut reader = PdbByteReader::new(bytes);
        let record = C11LinesStartEnd::parse(&mut reader).unwrap();
        assert_eq!(record.start(), 0x4433_2211);
        assert_eq!(record.end(), 0x8877_6655);
    }

    #[test]
    fn debug_output() {
        let bytes = vec![0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record = C11LinesStartEnd::parse(&mut reader).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C11LinesStartEnd"));
        assert!(debug_str.contains("16"));
        assert!(debug_str.contains("32"));
    }

    #[test]
    fn clone_and_copy_semantics() {
        let bytes = vec![0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        let mut reader = PdbByteReader::new(bytes);
        let record1 = C11LinesStartEnd::parse(&mut reader).unwrap();
        let record2 = record1; // Copy semantics
        let record3 = record1.clone(); // Clone semantics
        assert_eq!(record1.start(), record2.start());
        assert_eq!(record1.start(), record3.start());
    }
}
