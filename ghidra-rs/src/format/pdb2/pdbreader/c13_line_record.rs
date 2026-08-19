use crate::format::pdb2::pdbreader::c13_column_record::C13ColumnRecord;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// A PDB C13 Line Record that is part of a File Record
#[derive(Debug, Clone, Copy)]
pub struct C13LineRecord {
    offset: u32,
    bit_vals: u32,
    column_record: Option<C13ColumnRecord>,
}

impl C13LineRecord {
    /// Parses a `C13LineRecord` from the given readers.
    ///
    /// `column_reader` should be `Some` when the containing file record has columns.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the offset and bit values,
    /// or the column record when `column_reader` is present.
    pub fn parse(
        line_reader: &mut PdbByteReader,
        column_reader: Option<&mut PdbByteReader>,
    ) -> Result<Self, PdbException> {
        let offset = line_reader.parse_unsigned_int_val()?;
        let bit_vals = line_reader.parse_unsigned_int_val()?;
        let column_record = match column_reader {
            Some(reader) => Some(C13ColumnRecord::parse(reader)?),
            None => None,
        };
        Ok(C13LineRecord { offset, bit_vals, column_record })
    }

    /// Returns the offset within the segment for this line record.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the line number start for this record.
    pub fn line_num_start(&self) -> u32 {
        self.bit_vals & 0xff_ffff
    }

    /// Returns the delta between the line number start and the line number end (used to
    /// calculate the line number end).
    pub fn delta_line_end(&self) -> u32 {
        (self.bit_vals >> 24) & 0x7f
    }

    /// Returns the column record, or `None` if one does not exist.
    pub fn column_record(&self) -> Option<&C13ColumnRecord> {
        self.column_record.as_ref()
    }

    /// Returns `true` if the line number is that of a statement; else is expression.
    pub fn is_statement(&self) -> bool {
        (self.bit_vals & 0x8000_0000) != 0
    }

    /// Returns `true` if the line number is that of an expression; else is statement.
    pub fn is_expression(&self) -> bool {
        !self.is_statement()
    }

    /// Returns `true` if this is a special line (start is `0xfeefee` or `0xf00f00`).
    /// We do not know how to interpret either of these special line values at this time.
    pub fn is_special_line(&self) -> bool {
        let start = self.line_num_start();
        start == 0x00fe_efee || start == 0x00f0_0f00
    }

    /// Dumps the `C13LineRecord`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    pub(crate) fn dump(
        &self,
        writer: &mut impl std::io::Write,
        off_con: u32,
    ) -> std::io::Result<()> {
        let line_start = if self.is_special_line() {
            format!("{:06x}", self.line_num_start())
        }
        else {
            format!("{}", self.line_num_start())
        };
        let statement_str = if self.is_statement() { "Statement" } else { "Expression" };
        match &self.column_record {
            Some(column_record) if column_record.offset_column_end() != 0 => {
                write!(
                    writer,
                    "{:5}:{:5}-{:5}-{:5} 0x{:08x} {}",
                    self.line_num_start(),
                    column_record.offset_column_start(),
                    self.line_num_start() + self.delta_line_end(),
                    column_record.offset_column_end(),
                    self.offset.wrapping_add(off_con),
                    statement_str
                )
            }
            Some(column_record) => {
                write!(
                    writer,
                    "{}-{:5} 0x{:08x} {}",
                    line_start,
                    column_record.offset_column_start(),
                    self.offset.wrapping_add(off_con),
                    statement_str
                )
            }
            None => {
                write!(
                    writer,
                    "{} 0x{:08x} {}",
                    line_start,
                    self.offset.wrapping_add(off_con),
                    statement_str
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_bytes(offset: u32, bit_vals: u32) -> Vec<u8> {
        let mut bytes = offset.to_le_bytes().to_vec();
        bytes.extend_from_slice(&bit_vals.to_le_bytes());
        bytes
    }

    #[test]
    fn parse_without_column_record() {
        let bytes = line_bytes(0x1000, 0x8000_002a);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert_eq!(record.offset(), 0x1000);
        assert_eq!(record.line_num_start(), 0x2a);
        assert!(record.column_record().is_none());
    }

    #[test]
    fn parse_with_column_record() {
        let bytes = line_bytes(0x2000, 0x0000_0064);
        let mut reader = PdbByteReader::new(bytes);
        let column_bytes = vec![0x01, 0x00, 0x02, 0x00];
        let mut column_reader = PdbByteReader::new(column_bytes);
        let record = C13LineRecord::parse(&mut reader, Some(&mut column_reader)).unwrap();
        assert_eq!(record.offset(), 0x2000);
        let column_record = record.column_record().unwrap();
        assert_eq!(column_record.offset_column_start(), 1);
        assert_eq!(column_record.offset_column_end(), 2);
    }

    #[test]
    fn parse_insufficient_data() {
        let bytes = vec![0x10, 0x20, 0x30];
        let mut reader = PdbByteReader::new(bytes);
        let result = C13LineRecord::parse(&mut reader, None);
        assert!(result.is_err());
    }

    #[test]
    fn line_num_start_masks_low_24_bits() {
        let bytes = line_bytes(0, 0xffff_ffff);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert_eq!(record.line_num_start(), 0x00ff_ffff);
    }

    #[test]
    fn delta_line_end_masks_7_bits_after_shift() {
        let bytes = line_bytes(0, 0xffff_ffff);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert_eq!(record.delta_line_end(), 0x7f);
    }

    #[test]
    fn is_statement_true_when_high_bit_set() {
        let bytes = line_bytes(0, 0x8000_0000);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert!(record.is_statement());
        assert!(!record.is_expression());
    }

    #[test]
    fn is_expression_true_when_high_bit_clear() {
        let bytes = line_bytes(0, 0x0000_0000);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert!(!record.is_statement());
        assert!(record.is_expression());
    }

    #[test]
    fn is_special_line_detects_feefee() {
        let bytes = line_bytes(0, 0x00fe_efee);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert!(record.is_special_line());
    }

    #[test]
    fn is_special_line_detects_f00f00() {
        let bytes = line_bytes(0, 0x00f0_0f00);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert!(record.is_special_line());
    }

    #[test]
    fn is_special_line_false_for_normal_line() {
        let bytes = line_bytes(0, 42);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        assert!(!record.is_special_line());
    }

    #[test]
    fn dump_without_column_record() {
        let bytes = line_bytes(0x10, 0x8000_0005);
        let mut reader = PdbByteReader::new(bytes);
        let record = C13LineRecord::parse(&mut reader, None).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf, 0x100).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "5 0x00000110 Statement");
    }

    #[test]
    fn dump_with_column_record_no_end() {
        let bytes = line_bytes(0x10, 0x0000_0005);
        let mut reader = PdbByteReader::new(bytes);
        let column_bytes = vec![0x07, 0x00, 0x00, 0x00];
        let mut column_reader = PdbByteReader::new(column_bytes);
        let record = C13LineRecord::parse(&mut reader, Some(&mut column_reader)).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf, 0).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "5-    7 0x00000010 Expression");
    }

    #[test]
    fn dump_with_column_record_and_end() {
        let bytes = line_bytes(0x10, 0x0300_0005);
        let mut reader = PdbByteReader::new(bytes);
        let column_bytes = vec![0x07, 0x00, 0x09, 0x00];
        let mut column_reader = PdbByteReader::new(column_bytes);
        let record = C13LineRecord::parse(&mut reader, Some(&mut column_reader)).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf, 0).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "    5:    7-    8-    9 0x00000010 Expression");
    }
}
