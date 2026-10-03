use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::pdb_reader_utils::{dump_head, dump_tail};

/// Segment Map Description component of a PDB file. This is only suitable for reading; not
/// for writing or modifying a PDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMapDescription {
    flags: u16,
    ovl: u16,
    group: u16,
    frame: u16,
    seg_name_index: u16,
    class_name_index: u16,
    seg_offset: u32,
    seg_length: u32,
}

impl SegmentMapDescription {
    /// Parses a `SegmentMapDescription` from the given reader.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the record.
    pub fn parse(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        if reader.num_remaining() < 20 {
            return Err(PdbException::new("Not enough data for SegmentMapDescription"));
        }
        let flags = reader.parse_unsigned_short_val()?;
        let ovl = reader.parse_unsigned_short_val()?;
        let group = reader.parse_unsigned_short_val()?;
        let frame = reader.parse_unsigned_short_val()?;
        let seg_name_index = reader.parse_unsigned_short_val()?;
        let class_name_index = reader.parse_unsigned_short_val()?;
        let seg_offset = reader.parse_unsigned_int_val()?;
        let seg_length = reader.parse_unsigned_int_val()?;

        Ok(SegmentMapDescription {
            flags,
            ovl,
            group,
            frame,
            seg_name_index,
            class_name_index,
            seg_offset,
            seg_length,
        })
    }

    /// Returns the flags.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Returns the ovl (overlay?).
    pub fn ovl(&self) -> u16 {
        self.ovl
    }

    /// Returns the group.
    pub fn group(&self) -> u16 {
        self.group
    }

    /// Returns the frame.
    pub fn frame(&self) -> u16 {
        self.frame
    }

    /// Returns the segNameIndex.
    pub fn seg_name_index(&self) -> u16 {
        self.seg_name_index
    }

    /// Returns the classNameIndex.
    pub fn class_name_index(&self) -> u16 {
        self.class_name_index
    }

    /// Returns the segment offset.
    pub fn offset(&self) -> u32 {
        self.seg_offset
    }

    /// Returns the segment offset.
    pub fn segment_offset(&self) -> u32 {
        self.seg_offset
    }

    /// Returns the segment length.
    pub fn length(&self) -> u32 {
        self.seg_length
    }

    /// Dumps the `SegmentMapDescription`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    pub(crate) fn dump(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        dump_head(writer, "SegmentMapDescription")?;
        write!(writer, "\nflags: 0x{:04x}", self.flags)?;
        write!(writer, "\novl: {}", self.ovl)?;
        write!(writer, "\ngroup: {}", self.group)?;
        write!(writer, "\nframe: {}", self.frame)?;
        write!(writer, "\nsegNameIndex: {}", self.seg_name_index)?;
        write!(writer, "; classNameIndex: {}", self.class_name_index)?;
        write!(writer, "; segOffset: {}", self.seg_offset)?;
        write!(writer, "; segLength: {}", self.seg_length)?;
        writer.write_all(b"\n")?;
        dump_tail(writer, "SegmentMapDescription")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes() -> Vec<u8> {
        vec![
            0x01, 0x00, // flags = 1
            0x02, 0x00, // ovl = 2
            0x03, 0x00, // group = 3
            0x04, 0x00, // frame = 4
            0x05, 0x00, // segNameIndex = 5
            0x06, 0x00, // classNameIndex = 6
            0x00, 0x10, 0x00, 0x00, // segOffset = 0x1000
            0x00, 0x02, 0x00, 0x00, // segLength = 0x200
        ]
    }

    #[test]
    fn parse_valid_record() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = SegmentMapDescription::parse(&mut reader).unwrap();
        assert_eq!(record.flags(), 1);
        assert_eq!(record.ovl(), 2);
        assert_eq!(record.group(), 3);
        assert_eq!(record.frame(), 4);
        assert_eq!(record.seg_name_index(), 5);
        assert_eq!(record.class_name_index(), 6);
        assert_eq!(record.offset(), 0x1000);
        assert_eq!(record.segment_offset(), 0x1000);
        assert_eq!(record.length(), 0x200);
    }

    #[test]
    fn parse_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PdbByteReader::new(bytes);
        let result = SegmentMapDescription::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn parse_exactly_20_bytes_succeeds() {
        let bytes = vec![0x00; 20];
        let mut reader = PdbByteReader::new(bytes);
        let result = SegmentMapDescription::parse(&mut reader);
        assert!(result.is_ok());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let record = SegmentMapDescription::parse(&mut reader).unwrap();
        let mut buf = Vec::new();
        record.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("SegmentMapDescription"));
        assert!(output.contains("flags: 0x0001"));
        assert!(output.contains("ovl: 2"));
        assert!(output.contains("group: 3"));
        assert!(output.contains("frame: 4"));
        assert!(output.contains("segNameIndex: 5"));
        assert!(output.contains("classNameIndex: 6"));
        assert!(output.contains("segOffset: 4096"));
        assert!(output.contains("segLength: 512"));
        assert!(output.contains("End SegmentMapDescription"));
        assert!(output.ends_with('\n'));
    }
}
