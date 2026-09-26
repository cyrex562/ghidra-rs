use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::section_contribution::SectionContribution;

/// The v2.00 version of [`SectionContribution`] for Microsoft PDB.
#[derive(Debug, Clone, Default)]
pub struct SectionContribution200 {
    isect: u16,
    offset: i32,
    length: i32,
    imod: u16,
    characteristics: u32,
}

impl SectionContribution200 {
    /// Creates a new, empty `SectionContribution200`.
    pub fn new() -> Self {
        SectionContribution200::default()
    }
}

impl SectionContribution for SectionContribution200 {
    fn section(&self) -> u16 {
        self.isect
    }

    fn offset(&self) -> i32 {
        self.offset
    }

    fn length(&self) -> i32 {
        self.length
    }

    fn module(&self) -> u16 {
        self.imod
    }

    fn characteristics(&self) -> u32 {
        self.characteristics
    }

    fn deserialize(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException> {
        self.isect = reader.parse_unsigned_short_val()?;
        self.offset = reader.parse_int()?;
        self.length = reader.parse_int()?;
        self.imod = reader.parse_unsigned_short_val()?;
        Ok(())
    }

    fn dump_internals(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        write!(writer, "isect: {}", self.isect)?;
        write!(writer, "\noffset: {}", self.offset)?;
        write!(writer, "\nlength: {}", self.length)?;
        write!(writer, "\nimod: {}", self.imod)?;
        writeln!(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes() -> Vec<u8> {
        vec![
            0x01, 0x00, // isect = 1
            0x00, 0x10, 0x00, 0x00, // offset = 0x1000
            0x00, 0x02, 0x00, 0x00, // length = 0x200
            0x02, 0x00, // imod = 2
        ]
    }

    #[test]
    fn deserialize_parses_all_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution200::new();
        record.deserialize(&mut reader).unwrap();
        assert_eq!(record.section(), 1);
        assert_eq!(record.offset(), 0x1000);
        assert_eq!(record.length(), 0x200);
        assert_eq!(record.module(), 2);
    }

    #[test]
    fn deserialize_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let mut record = SectionContribution200::new();
        assert!(record.deserialize(&mut reader).is_err());
    }

    #[test]
    fn characteristics_defaults_to_zero() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution200::new();
        record.deserialize(&mut reader).unwrap();
        assert_eq!(record.characteristics(), 0);
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution200::new();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with("SectionContribution200"));
        assert!(output.contains("isect: 1"));
        assert!(output.contains("offset: 4096"));
        assert!(output.contains("length: 512"));
        assert!(output.contains("imod: 2"));
        assert!(output.contains("End SectionContribution200"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn to_display_string_matches_dump() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution200::new();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let expected = String::from_utf8(buf).unwrap();

        assert_eq!(record.to_display_string(), expected);
    }
}
