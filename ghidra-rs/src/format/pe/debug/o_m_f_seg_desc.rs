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
    pub fn new(reader: &dyn BinaryReader, index: u64) -> io::Result<Self> {
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
            0x01, 0x00, // seg = 1
            0x00, 0x00, // pad = 0
            0x10, 0x00, // offset = 0x10
            0x20, 0x00, // cb_seg = 0x20
        ];

        let reader = MockReader::new(data, true);
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

        let reader = MockReader::new(data, false);
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

        let reader = MockReader::new(data, true);
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

        let reader = MockReader::new(data, true);
        let desc = OmfSegDesc::new(&reader, 0).expect("failed to read");

        assert_eq!(desc.offset(), -1);
        assert_eq!(desc.number_of_bytes(), -2);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
        ];

        let reader = MockReader::new(data, true);
        let desc1 = OmfSegDesc::new(&reader, 0).expect("failed to read");
        let desc2 = desc1.clone();

        assert_eq!(desc1, desc2);
    }
}
