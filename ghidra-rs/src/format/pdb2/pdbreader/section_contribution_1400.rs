use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::section_contribution::SectionContribution;

/// The v14.00 version of [`SectionContribution`] for Microsoft PDB.
#[derive(Debug, Clone, Default)]
pub struct SectionContribution1400 {
    isect: u16,
    offset: i32,
    length: i32,
    characteristics: u32,
    imod: u16,
    data_crc: u32,
    relocation_crc: u32,
    unknown_section_contribution_field: u32,
}

impl SectionContribution1400 {
    /// Creates a new, empty `SectionContribution1400`.
    pub fn new() -> Self {
        SectionContribution1400::default()
    }
}

impl SectionContribution for SectionContribution1400 {
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
        reader.parse_bytes(2)?;
        self.offset = reader.parse_int()?;
        self.length = reader.parse_int()?;
        self.characteristics = reader.parse_unsigned_int_val()?;
        self.imod = reader.parse_unsigned_short_val()?;
        reader.align4();
        self.data_crc = reader.parse_unsigned_int_val()?;
        self.relocation_crc = reader.parse_unsigned_int_val()?;
        self.unknown_section_contribution_field = reader.parse_unsigned_int_val()?;
        Ok(())
    }

    fn dump_internals(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        write!(writer, "isect: {}", self.isect)?;
        write!(writer, "\noffset: {}", self.offset)?;
        write!(writer, "\nlength: {}", self.length)?;
        write!(writer, "\ncharacteristics: 0X{:08X}", self.characteristics)?;
        write!(writer, "\nimod: {}", self.imod)?;
        write!(writer, "\ndataCrc: {}", self.data_crc)?;
        write!(writer, "\nrelocationCrc: {}", self.relocation_crc)?;
        write!(writer, "\nunknownSectionContributionField: {}", self.unknown_section_contribution_field)?;
        writeln!(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes() -> Vec<u8> {
        vec![
            0x01, 0x00, // isect = 1
            0x00, 0x00, // padding
            0x00, 0x10, 0x00, 0x00, // offset = 0x1000
            0x00, 0x02, 0x00, 0x00, // length = 0x200
            0x20, 0x00, 0x00, 0x00, // characteristics = 0x20
            0x02, 0x00, // imod = 2
            0x00, 0x00, // align4 padding
            0x03, 0x00, 0x00, 0x00, // dataCrc = 3
            0x04, 0x00, 0x00, 0x00, // relocationCrc = 4
            0x05, 0x00, 0x00, 0x00, // unknownSectionContributionField = 5
        ]
    }

    #[test]
    fn deserialize_parses_all_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution1400::new();
        record.deserialize(&mut reader).unwrap();
        assert_eq!(record.section(), 1);
        assert_eq!(record.offset(), 0x1000);
        assert_eq!(record.length(), 0x200);
        assert_eq!(record.characteristics(), 0x20);
        assert_eq!(record.module(), 2);
        assert_eq!(record.data_crc, 3);
        assert_eq!(record.relocation_crc, 4);
        assert_eq!(record.unknown_section_contribution_field, 5);
    }

    #[test]
    fn deserialize_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let mut record = SectionContribution1400::new();
        assert!(record.deserialize(&mut reader).is_err());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution1400::new();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with("SectionContribution1400"));
        assert!(output.contains("isect: 1"));
        assert!(output.contains("offset: 4096"));
        assert!(output.contains("length: 512"));
        assert!(output.contains("characteristics: 0X00000020"));
        assert!(output.contains("imod: 2"));
        assert!(output.contains("dataCrc: 3"));
        assert!(output.contains("relocationCrc: 4"));
        assert!(output.contains("unknownSectionContributionField: 5"));
        assert!(output.contains("End SectionContribution1400"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn to_display_string_matches_dump() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = SectionContribution1400::new();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let expected = String::from_utf8(buf).unwrap();

        assert_eq!(record.to_display_string(), expected);
    }
}
