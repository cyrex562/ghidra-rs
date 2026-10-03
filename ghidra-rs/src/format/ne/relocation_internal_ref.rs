use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// A relocation entry for an internal fixed or moveable segment reference.
///
/// Mirrors `RelocationInternalRef` from the original Ghidra Java source.
/// Stores a segment number (or 0xff for moveable segments), padding, and an offset
/// (which may be either an offset into a fixed segment or an ordinal into the entry table
/// for moveable segments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationInternalRef {
    segment: i8,
    zeropad: i8,
    offset: i16,
}

impl RelocationInternalRef {
    /// Constructs a new relocation internal reference by reading from the given binary reader.
    ///
    /// Reads one byte (segment), one byte (padding), and one i16 (offset).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let segment = reader.read_next_byte()? as i8;
        let zeropad = reader.read_next_byte()? as i8;
        let offset = reader.read_next_short()?;

        Ok(RelocationInternalRef {
            segment,
            zeropad,
            offset,
        })
    }

    /// Returns true if this relocation refers to a moveable segment.
    ///
    /// A moveable segment is indicated by segment number 0xff.
    pub fn is_moveable(&self) -> bool {
        self.segment == -1i8
    }

    /// Returns the segment number.
    ///
    /// For fixed segments, this is the segment number. For moveable segments, this is 0xff.
    pub fn segment(&self) -> i8 {
        self.segment
    }

    /// Returns the padding byte.
    pub fn pad(&self) -> i8 {
        self.zeropad
    }

    /// Returns the offset.
    ///
    /// For fixed segments, this is the offset into the segment.
    /// For moveable segments, this is the ordinal number into the entry table.
    pub fn offset(&self) -> i16 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_fixed_segment() {
        let mut data = Vec::new();
        data.push(1);
        data.push(0);
        data.extend_from_slice(&(0x1000u16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), 1);
        assert_eq!(rel.pad(), 0);
        assert_eq!(rel.offset(), 0x1000);
        assert!(!rel.is_moveable());
    }

    #[test]
    fn reads_moveable_segment() {
        let mut data = Vec::new();
        data.push(0xff);
        data.push(0);
        data.extend_from_slice(&(42i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), -1i8);
        assert_eq!(rel.pad(), 0);
        assert_eq!(rel.offset(), 42);
        assert!(rel.is_moveable());
    }

    #[test]
    fn reads_zero_offset() {
        let mut data = Vec::new();
        data.push(2);
        data.push(0);
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), 2);
        assert_eq!(rel.offset(), 0);
    }

    #[test]
    fn reads_negative_offset() {
        let mut data = Vec::new();
        data.push(3);
        data.push(0);
        data.extend_from_slice(&(-1i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), 3);
        assert_eq!(rel.offset(), -1);
    }

    #[test]
    fn reads_nonzero_padding() {
        let mut data = Vec::new();
        data.push(1);
        data.push(5);
        data.extend_from_slice(&(0x2000i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), 1);
        assert_eq!(rel.pad(), 5);
        assert_eq!(rel.offset(), 0x2000);
    }

    #[test]
    fn updates_reader_position() {
        let mut data = Vec::new();
        data.push(1);
        data.push(0);
        data.extend_from_slice(&(100i16).to_le_bytes());
        data.push(99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = RelocationInternalRef::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_different_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 3]);
        data.push(7);
        data.push(0);
        data.extend_from_slice(&(77i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(3);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert_eq!(rel.segment(), 7);
        assert_eq!(rel.offset(), 77);
    }

    #[test]
    fn copy_semantics() {
        let mut data = Vec::new();
        data.push(3);
        data.push(0);
        data.extend_from_slice(&(9i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data.clone(), true);
        let rel1 = RelocationInternalRef::new(&mut r).unwrap();
        let rel2 = rel1;

        assert_eq!(rel1, rel2);
        assert_eq!(rel1.segment(), rel2.segment());
        assert_eq!(rel1.offset(), rel2.offset());
    }

    #[test]
    fn equality_between_different_constructions() {
        let mut data1 = Vec::new();
        data1.push(15);
        data1.push(0);
        data1.extend_from_slice(&(20i16).to_le_bytes());

        let mut r1 = BinaryReader::from_bytes(data1, true);
        let rel1 = RelocationInternalRef::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.push(15);
        data2.push(0);
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = BinaryReader::from_bytes(data2, true);
        let rel2 = RelocationInternalRef::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }

    #[test]
    fn isnt_moveable_boundary() {
        let mut data = Vec::new();
        data.push(0xfe);
        data.push(0);
        data.extend_from_slice(&(100i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert!(!rel.is_moveable());
    }
}
