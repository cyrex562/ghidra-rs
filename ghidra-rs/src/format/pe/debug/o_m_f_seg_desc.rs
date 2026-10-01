use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) Segment Descriptor data structure.
/// Information describing each segment in a module.
///
/// Mirrors the `OMFSegDesc` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct OMFSegDesc {
///     unsigned short  Seg;            // segment index
///     unsigned short  pad;            // pad to maintain alignment
///     unsigned long   Off;            // offset of code in segment
///     unsigned long   cbSeg;          // number of bytes in segment
/// } OMFSegDesc;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSegDesc {
    seg: i16,
    pad: i16,
    offset: i32,
    cb_seg: i32,
}

impl OmfSegDesc {
    /// The on-disk size, in bytes, of the `OMFSegDesc` structure.
    pub const IMAGE_SIZEOF_OMF_SEG_DESC: usize = 12;

    /// Creates a new `OmfSegDesc` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `index` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &BinaryReader, index: u64) -> io::Result<Self> {
        let mut index = index;

        let seg = reader.read_short(index)?;
        index += 2;
        let pad = reader.read_short(index)?;
        index += 2;
        let offset = reader.read_short(index)? as i32;
        index += 2;
        let cb_seg = reader.read_short(index)? as i32;

        Ok(OmfSegDesc {
            seg,
            pad,
            offset,
            cb_seg,
        })
    }

    /// Returns the segment index.
    pub fn segment_index(&self) -> i16 {
        self.seg
    }

    /// Returns the pad to maintain alignment.
    pub fn alignment_pad(&self) -> i16 {
        self.pad
    }

    /// Returns the offset of code in segment.
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Returns the number of bytes in segment.
    pub fn number_of_bytes(&self) -> i32 {
        self.cb_seg
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x01, 0x00, // seg = 1
            0x00, 0x00, // pad = 0
            0x10, 0x00, // offset = 0x10
            0x20, 0x00, // cb_seg = 0x20
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc = OmfSegDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.segment_index(), 1);
        assert_eq!(desc.alignment_pad(), 0);
        assert_eq!(desc.offset(), 0x10);
        assert_eq!(desc.number_of_bytes(), 0x20);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x02, // seg = 2
            0x00, 0x00, // pad = 0
            0x00, 0x30, // offset = 0x30
            0x00, 0x40, // cb_seg = 0x40
        ];

        let reader = BinaryReader::from_bytes(data, false);
        let desc = OmfSegDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.segment_index(), 2);
        assert_eq!(desc.offset(), 0x30);
        assert_eq!(desc.number_of_bytes(), 0x40);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // padding
            0x03, 0x00, // seg = 3 at offset 4
            0x00, 0x00, // pad = 0
            0x05, 0x00, // offset = 5
            0x06, 0x00, // cb_seg = 6
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc = OmfSegDesc::new(&reader, 4).expect("failed to read");

        assert_eq!(desc.segment_index(), 3);
        assert_eq!(desc.offset(), 5);
        assert_eq!(desc.number_of_bytes(), 6);
    }

    #[test]
    fn negative_short_values_sign_extend() {
        // The Java source reads Off/cbSeg via readShort into int fields, so a
        // negative short value sign-extends into the wider int, mirroring the
        // original (buggy) behavior faithfully.
        let data = vec![
            0x00, 0x00, // seg = 0
            0x00, 0x00, // pad = 0
            0xFF, 0xFF, // offset = -1 as short
            0xFE, 0xFF, // cb_seg = -2 as short
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc = OmfSegDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.offset(), -1);
        assert_eq!(desc.number_of_bytes(), -2);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc1 = OmfSegDesc::new(&reader, 0).expect("failed to read");
        let desc2 = desc1.clone();

        assert_eq!(desc1, desc2);
    }
}
