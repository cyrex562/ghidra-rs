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
    pub fn new(reader: &dyn BinaryReader, ptr: u64) -> io::Result<Self> {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }

        fn is_little_endian(&self) -> bool {
            self.little_endian
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

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

        let reader = MockReader::new(data, true);
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

        let reader = MockReader::new(data, false);
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

        let reader = MockReader::new(data, true);
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

        let reader = MockReader::new(data, true);
        let desc1 = OmfSegMapDesc::new(&reader, 0).expect("failed to read");
        let desc2 = desc1.clone();

        assert_eq!(desc1, desc2);
    }
}
