use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::pdb_reader_utils::{dump_head, dump_tail, simple_type_name};

/// Trait for the Section Contribution component of a PDB file. Implementors are only
/// suitable for reading; not for writing or modifying a PDB.
///
/// We have intended to implement according to the Microsoft PDB API (source); see the API for
/// truth.
///
/// Each PDB version stores a different subset of fields, so [`deserialize`](Self::deserialize)
/// and [`dump_internals`](Self::dump_internals) are left to the version-specific implementor;
/// this mirrors the abstract `deserialize`/`dumpInternals` methods on the Java base class.
pub trait SectionContribution {
    /// Returns the section.
    fn section(&self) -> u16;

    /// Returns the offset.
    fn offset(&self) -> i32;

    /// Returns the length.
    fn length(&self) -> i32;

    /// Returns the module.
    fn module(&self) -> u16;

    /// Returns the characteristics. Believe these to be documented at:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header>
    fn characteristics(&self) -> u32;

    /// Deserializes the Section Contribution.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    fn deserialize(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException>;

    /// Dumps the version-specific internals. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    fn dump_internals(&self, writer: &mut impl std::io::Write) -> std::io::Result<()>;

    /// Dumps the Section Contribution. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    fn dump(&self, writer: &mut impl std::io::Write) -> std::io::Result<()>
    where
        Self: Sized,
    {
        let name = simple_type_name::<Self>();
        dump_head(writer, name)?;
        self.dump_internals(writer)?;
        dump_tail(writer, name)
    }

    /// Returns the string representation of this Section Contribution by delegating to
    /// [`dump`](Self::dump), mirroring Java's `toString()`.
    fn to_display_string(&self) -> String
    where
        Self: Sized,
    {
        let mut buf = Vec::new();
        match self.dump(&mut buf) {
            Ok(()) => String::from_utf8_lossy(&buf).into_owned(),
            Err(e) => format!(
                "Issue in {} toString(): {}",
                simple_type_name::<Self>(),
                e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestSectionContribution {
        isect: u16,
        offset: i32,
        length: i32,
        imod: u16,
        characteristics: u32,
        data_crc: u32,
        relocation_crc: u32,
    }

    impl SectionContribution for TestSectionContribution {
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
            writeln!(writer)
        }
    }

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
        ]
    }

    #[test]
    fn deserialize_parses_all_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = TestSectionContribution::default();
        record.deserialize(&mut reader).unwrap();
        assert_eq!(record.section(), 1);
        assert_eq!(record.offset(), 0x1000);
        assert_eq!(record.length(), 0x200);
        assert_eq!(record.characteristics(), 0x20);
        assert_eq!(record.module(), 2);
        assert_eq!(record.data_crc, 3);
        assert_eq!(record.relocation_crc, 4);
    }

    #[test]
    fn deserialize_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let mut record = TestSectionContribution::default();
        assert!(record.deserialize(&mut reader).is_err());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = TestSectionContribution::default();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with("TestSectionContribution"));
        assert!(output.contains("isect: 1"));
        assert!(output.contains("offset: 4096"));
        assert!(output.contains("length: 512"));
        assert!(output.contains("characteristics: 0X00000020"));
        assert!(output.contains("imod: 2"));
        assert!(output.contains("dataCrc: 3"));
        assert!(output.contains("relocationCrc: 4"));
        assert!(output.contains("End TestSectionContribution"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn to_display_string_matches_dump() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut record = TestSectionContribution::default();
        record.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let expected = String::from_utf8(buf).unwrap();

        assert_eq!(record.to_display_string(), expected);
    }
}
