use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) Segment Mapping Descriptor data structure.
///
/// Mirrors the `OMFSegMapDesc` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct OMFSegMapDesc {
///     unsigned short  flags;       // descriptor flags bit field
///     unsigned short  ovl;         // the logical overlay number
///     unsigned short  group;       // group index into the descriptor array
///     unsigned short  frame;       // logical segment index - interpreted via flags
///     unsigned short  iSegName;    // segment or group name - index into sstSegName
///     unsigned short  iClassName;  // class name - index into sstSegName
///     unsigned long   offset;      // byte offset of the logical within the physical segment
///     unsigned long   cbSeg;       // byte count of the logical segment or group
/// } OMFSegMapDesc;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSegMapDesc {
    flags: i16,
    ovl: i16,
    group: i16,
    frame: i16,
    i_seg_name: i16,
    i_class_name: i16,
    offset: i32,
    cb_seg: i32,
}

impl OmfSegMapDesc {
    /// The on-disk size, in bytes, of the `OMFSegMapDesc` structure.
    pub const IMAGE_SIZEOF_OMF_SEG_MAP_DESC: usize = 20;

    /// Creates a new `OmfSegMapDesc` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &BinaryReader, ptr: u64) -> io::Result<Self> {
        let mut ptr = ptr;

        let flags = reader.read_short(ptr)?;
        ptr += 2;
        let ovl = reader.read_short(ptr)?;
        ptr += 2;
        let group = reader.read_short(ptr)?;
        ptr += 2;
        let frame = reader.read_short(ptr)?;
        ptr += 2;
        let i_seg_name = reader.read_short(ptr)?;
        ptr += 2;
        let i_class_name = reader.read_short(ptr)?;
        ptr += 2;
        let offset = reader.read_int(ptr)?;
        ptr += 4;
        let cb_seg = reader.read_int(ptr)?;

        Ok(OmfSegMapDesc {
            flags,
            ovl,
            group,
            frame,
            i_seg_name,
            i_class_name,
            offset,
            cb_seg,
        })
    }

    /// Returns the descriptor flags bit field.
    pub fn flags(&self) -> i16 {
        self.flags
    }

    /// Returns the logical overlay number.
    pub fn logical_overlay_number(&self) -> i16 {
        self.ovl
    }

    /// Returns the group index into the descriptor array.
    pub fn group_index(&self) -> i16 {
        self.group
    }

    /// Returns the logical segment index - interpreted via flags.
    pub fn logical_segment_index(&self) -> i16 {
        self.frame
    }

    /// Returns the segment or group name - index into sstSegName.
    pub fn segment_name(&self) -> i16 {
        self.i_seg_name
    }

    /// Returns the class name - index into sstSegName.
    pub fn class_name(&self) -> i16 {
        self.i_class_name
    }

    /// Returns the byte offset of the logical within the physical segment.
    pub fn byte_offset(&self) -> i32 {
        self.offset
    }

    /// Returns the byte count of the logical segment or group.
    pub fn byte_count(&self) -> i32 {
        self.cb_seg
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x01, 0x00, // flags = 1
            0x02, 0x00, // ovl = 2
            0x03, 0x00, // group = 3
            0x04, 0x00, // frame = 4
            0x05, 0x00, // iSegName = 5
            0x06, 0x00, // iClassName = 6
            0x10, 0x00, 0x00, 0x00, // offset = 0x10
            0x20, 0x00, 0x00, 0x00, // cbSeg = 0x20
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc = OmfSegMapDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.flags(), 1);
        assert_eq!(desc.logical_overlay_number(), 2);
        assert_eq!(desc.group_index(), 3);
        assert_eq!(desc.logical_segment_index(), 4);
        assert_eq!(desc.segment_name(), 5);
        assert_eq!(desc.class_name(), 6);
        assert_eq!(desc.byte_offset(), 0x10);
        assert_eq!(desc.byte_count(), 0x20);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x01, // flags = 1
            0x00, 0x02, // ovl = 2
            0x00, 0x03, // group = 3
            0x00, 0x04, // frame = 4
            0x00, 0x05, // iSegName = 5
            0x00, 0x06, // iClassName = 6
            0x00, 0x00, 0x00, 0x10, // offset = 0x10
            0x00, 0x00, 0x00, 0x20, // cbSeg = 0x20
        ];

        let reader = BinaryReader::from_bytes(data, false);
        let desc = OmfSegMapDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.flags(), 1);
        assert_eq!(desc.byte_offset(), 0x10);
        assert_eq!(desc.byte_count(), 0x20);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xFF; 4];
        data.extend_from_slice(&[
            0x01, 0x00, // flags = 1
            0x02, 0x00, // ovl = 2
            0x03, 0x00, // group = 3
            0x04, 0x00, // frame = 4
            0x05, 0x00, // iSegName = 5
            0x06, 0x00, // iClassName = 6
            0x10, 0x00, 0x00, 0x00, // offset = 0x10
            0x20, 0x00, 0x00, 0x00, // cbSeg = 0x20
        ]);

        let reader = BinaryReader::from_bytes(data, true);
        let desc = OmfSegMapDesc::new(&reader, 4).expect("failed to read");

        assert_eq!(desc.flags(), 1);
        assert_eq!(desc.byte_offset(), 0x10);
        assert_eq!(desc.byte_count(), 0x20);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let desc1 = OmfSegMapDesc::new(&reader, 0).expect("failed to read");
        let desc2 = desc1.clone();

        assert_eq!(desc1, desc2);
    }
}
