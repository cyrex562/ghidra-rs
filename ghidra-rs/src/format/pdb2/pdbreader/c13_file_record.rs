use crate::format::pdb2::pdbreader::c13_line_record::C13LineRecord;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::util::task::TaskMonitor;

/// A PDB C13 File Record pertaining to source line information.
#[derive(Debug, Clone)]
pub struct C13FileRecord {
    file_id: u32,
    n_lines: u32,
    len_file_block: u32,
    line_records: Vec<C13LineRecord>,
}

impl C13FileRecord {
    /// Parses a `C13FileRecord` from the given reader.
    ///
    /// `has_column` indicates whether the file's line records also carry column records.
    /// `monitor` is accepted for parity with the Java source but is not consulted during
    /// parsing.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data for the header or the line/column
    /// records, or if the declared block length is inconsistent with the number of lines.
    pub fn parse(
        reader: &mut PdbByteReader,
        has_column: bool,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Self, PdbException> {
        if reader.num_remaining() < 12 {
            return Err(PdbException::new("Not enough data for FileRecord header"));
        }
        let file_id = reader.parse_unsigned_int_val()?;
        let n_lines = reader.parse_unsigned_int_val()?;
        let len_file_block = reader.parse_unsigned_int_val()?;

        let len_minus_header = len_file_block as i64 - 12; // 12 is size of header
        let size_lines = n_lines as i64 * 8;
        let size_columns = n_lines as i64 * if has_column { 4 } else { 0 };
        let size_required = size_lines + size_columns;

        // was test ">" but both are suspect... not all records might have the columns
        if len_minus_header != size_required {
            return Err(PdbException::new("Corrupt FileRecord"));
        }
        if (reader.num_remaining() as i64) < size_required {
            return Err(PdbException::new("Not enough data for FileRecord records"));
        }

        let mut line_reader = reader.get_sub_pdb_byte_reader(size_lines as usize)?;
        let mut column_reader = if has_column {
            Some(reader.get_sub_pdb_byte_reader(size_columns as usize)?)
        }
        else {
            None
        };

        let mut line_records = Vec::with_capacity(n_lines as usize);
        for _ in 0..n_lines {
            let line_record =
                C13LineRecord::parse(&mut line_reader, column_reader.as_mut())?;
            line_records.push(line_record);
        }

        Ok(C13FileRecord { file_id, n_lines, len_file_block, line_records })
    }

    /// Returns the file ID.
    pub fn file_id(&self) -> u32 {
        self.file_id
    }

    /// Returns the number of lines for the file record.
    pub fn n_lines(&self) -> u32 {
        self.n_lines
    }

    /// Returns the length of the block of records.
    pub fn len_file_block(&self) -> u32 {
        self.len_file_block
    }

    /// Returns the list of line records for the file record.
    pub fn line_records(&self) -> &[C13LineRecord] {
        &self.line_records
    }

    /// Dumps the `C13FileRecord`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    pub(crate) fn dump(
        &self,
        writer: &mut impl std::io::Write,
        off_con: u32,
    ) -> std::io::Result<()> {
        writeln!(
            writer,
            "fileId: {:06x}, nLines: {}, lenFileBlock: {}",
            self.file_id, self.n_lines, self.len_file_block
        )?;
        for record in &self.line_records {
            record.dump(writer, off_con)?;
            writeln!(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    fn header_bytes(file_id: u32, n_lines: u32, len_file_block: u32) -> Vec<u8> {
        let mut bytes = file_id.to_le_bytes().to_vec();
        bytes.extend_from_slice(&n_lines.to_le_bytes());
        bytes.extend_from_slice(&len_file_block.to_le_bytes());
        bytes
    }

    fn line_bytes(offset: u32, bit_vals: u32) -> Vec<u8> {
        let mut bytes = offset.to_le_bytes().to_vec();
        bytes.extend_from_slice(&bit_vals.to_le_bytes());
        bytes
    }

    #[test]
    fn parse_without_columns() {
        let mut bytes = header_bytes(0x10, 2, 12 + 16);
        bytes.extend(line_bytes(0x1000, 0x8000_0001));
        bytes.extend(line_bytes(0x2000, 0x8000_0002));
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let record = C13FileRecord::parse(&mut reader, false, &monitor).unwrap();
        assert_eq!(record.file_id(), 0x10);
        assert_eq!(record.n_lines(), 2);
        assert_eq!(record.len_file_block(), 28);
        assert_eq!(record.line_records().len(), 2);
        assert!(record.line_records()[0].column_record().is_none());
    }

    #[test]
    fn parse_with_columns() {
        let mut bytes = header_bytes(0x20, 1, 12 + 8 + 4);
        bytes.extend(line_bytes(0x3000, 0x0000_0005));
        bytes.extend_from_slice(&[0x01, 0x00, 0x02, 0x00]);
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let record = C13FileRecord::parse(&mut reader, true, &monitor).unwrap();
        assert_eq!(record.line_records().len(), 1);
        let column_record = record.line_records()[0].column_record().unwrap();
        assert_eq!(column_record.offset_column_start(), 1);
        assert_eq!(column_record.offset_column_end(), 2);
    }

    #[test]
    fn parse_insufficient_header_data() {
        let bytes = vec![0x01, 0x02, 0x03];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let result = C13FileRecord::parse(&mut reader, false, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_corrupt_block_length() {
        let bytes = header_bytes(0x10, 2, 12 + 8);
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let result = C13FileRecord::parse(&mut reader, false, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_record_data() {
        let mut bytes = header_bytes(0x10, 2, 12 + 16);
        bytes.extend(line_bytes(0x1000, 1));
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let result = C13FileRecord::parse(&mut reader, false, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_zero_lines() {
        let bytes = header_bytes(0x30, 0, 12);
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let record = C13FileRecord::parse(&mut reader, false, &monitor).unwrap();
        assert_eq!(record.n_lines(), 0);
        assert!(record.line_records().is_empty());
    }

    #[test]
    fn dump_output() {
        let mut bytes = header_bytes(0x10, 1, 12 + 8);
        bytes.extend(line_bytes(0x10, 0x8000_0005));
        let mut reader = PdbByteReader::new(bytes);
        let monitor = DummyMonitor;
        let record = C13FileRecord::parse(&mut reader, false, &monitor).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf, 0x100).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "fileId: 000010, nLines: 1, lenFileBlock: 20\n5 0x00000110 Statement\n");
    }
}
