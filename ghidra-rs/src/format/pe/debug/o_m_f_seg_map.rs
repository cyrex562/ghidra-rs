use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::debug::o_m_f_seg_map_desc::OmfSegMapDesc;

/// Represents the Object Module Format (OMF) Segment Map data structure.
///
/// Mirrors the `OMFSegMap` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct OMFSegMap {
///     unsigned short  cSeg;        // total number of segment descriptors
///     unsigned short  cSegLog;     // number of logical segment descriptors
///     OMFSegMapDesc   rgDesc[0];   // array of segment descriptors
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSegMap {
    c_seg: i16,
    c_seg_log: i16,
    segment_map_desc: Vec<OmfSegMapDesc>,
}

impl OmfSegMap {
    /// Creates a new `OmfSegMap` by reading from the given binary reader at the
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
        let mut index = ptr;

        let c_seg = reader.read_short(index)?;
        index += 2;
        let c_seg_log = reader.read_short(index)?;
        index += 2;

        let seg_count = c_seg as usize;
        let mut segment_map_desc = Vec::with_capacity(seg_count);

        for _ in 0..seg_count {
            segment_map_desc.push(OmfSegMapDesc::new(reader, index)?);
            index += OmfSegMapDesc::IMAGE_SIZEOF_OMF_SEG_MAP_DESC as u64;
        }

        Ok(OmfSegMap {
            c_seg,
            c_seg_log,
            segment_map_desc,
        })
    }

    /// Returns the total number of segment descriptors.
    pub fn segment_descriptor_count(&self) -> i16 {
        self.c_seg
    }

    /// Returns the number of logical segment descriptors.
    pub fn logical_segment_descriptor_count(&self) -> i16 {
        self.c_seg_log
    }

    /// Returns the array of segment descriptors.
    pub fn segment_descriptors(&self) -> &[OmfSegMapDesc] {
        &self.segment_map_desc
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
    fn read_structure_with_no_segments() {
        let data = vec![
            0x00, 0x00, // cSeg = 0
            0x00, 0x00, // cSegLog = 0
        ];

        let reader = MockReader::new(data, true);
        let seg_map = OmfSegMap::new(&reader, 0).expect("failed to read");

        assert_eq!(seg_map.segment_descriptor_count(), 0);
        assert_eq!(seg_map.logical_segment_descriptor_count(), 0);
        assert!(seg_map.segment_descriptors().is_empty());
    }

    #[test]
    fn read_structure_little_endian() {
        let mut data = vec![
            0x02, 0x00, // cSeg = 2
            0x01, 0x00, // cSegLog = 1
        ];
        // First OMFSegMapDesc (20 bytes each)
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
        // Second OMFSegMapDesc
        data.extend_from_slice(&[
            0x07, 0x00, // flags = 7
            0x08, 0x00, // ovl = 8
            0x09, 0x00, // group = 9
            0x0A, 0x00, // frame = 10
            0x0B, 0x00, // iSegName = 11
            0x0C, 0x00, // iClassName = 12
            0x30, 0x00, 0x00, 0x00, // offset = 0x30
            0x40, 0x00, 0x00, 0x00, // cbSeg = 0x40
        ]);

        let reader = MockReader::new(data, true);
        let seg_map = OmfSegMap::new(&reader, 0).expect("failed to read");

        assert_eq!(seg_map.segment_descriptor_count(), 2);
        assert_eq!(seg_map.logical_segment_descriptor_count(), 1);
        assert_eq!(seg_map.segment_descriptors().len(), 2);
        assert_eq!(seg_map.segment_descriptors()[0].flags(), 1);
        assert_eq!(seg_map.segment_descriptors()[0].byte_count(), 0x20);
        assert_eq!(seg_map.segment_descriptors()[1].flags(), 7);
        assert_eq!(seg_map.segment_descriptors()[1].byte_count(), 0x40);
    }

    #[test]
    fn read_structure_big_endian() {
        let mut data = vec![
            0x00, 0x02, // cSeg = 2
            0x00, 0x01, // cSegLog = 1
        ];
        // First OMFSegMapDesc
        data.extend_from_slice(&[
            0x00, 0x01, // flags = 1
            0x00, 0x02, // ovl = 2
            0x00, 0x03, // group = 3
            0x00, 0x04, // frame = 4
            0x00, 0x05, // iSegName = 5
            0x00, 0x06, // iClassName = 6
            0x00, 0x00, 0x00, 0x10, // offset = 0x10
            0x00, 0x00, 0x00, 0x20, // cbSeg = 0x20
        ]);
        // Second OMFSegMapDesc
        data.extend_from_slice(&[
            0x00, 0x07, // flags = 7
            0x00, 0x08, // ovl = 8
            0x00, 0x09, // group = 9
            0x00, 0x0A, // frame = 10
            0x00, 0x0B, // iSegName = 11
            0x00, 0x0C, // iClassName = 12
            0x00, 0x00, 0x00, 0x30, // offset = 0x30
            0x00, 0x00, 0x00, 0x40, // cbSeg = 0x40
        ]);

        let reader = MockReader::new(data, false);
        let seg_map = OmfSegMap::new(&reader, 0).expect("failed to read");

        assert_eq!(seg_map.segment_descriptor_count(), 2);
        assert_eq!(seg_map.logical_segment_descriptor_count(), 1);
        assert_eq!(seg_map.segment_descriptors().len(), 2);
        assert_eq!(seg_map.segment_descriptors()[0].flags(), 1);
        assert_eq!(seg_map.segment_descriptors()[1].flags(), 7);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xFF; 4];
        data.extend_from_slice(&[
            0x01, 0x00, // cSeg = 1
            0x00, 0x00, // cSegLog = 0
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
        let seg_map = OmfSegMap::new(&reader, 4).expect("failed to read");

        assert_eq!(seg_map.segment_descriptor_count(), 1);
        assert_eq!(seg_map.logical_segment_descriptor_count(), 0);
        assert_eq!(seg_map.segment_descriptors().len(), 1);
        assert_eq!(seg_map.segment_descriptors()[0].byte_offset(), 0x10);
    }

    #[test]
    fn clone_and_equality() {
        let mut data = vec![
            0x01, 0x00, // cSeg = 1
            0x01, 0x00, // cSegLog = 1
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
        let seg_map1 = OmfSegMap::new(&reader, 0).expect("failed to read");
        let seg_map2 = seg_map1.clone();

        assert_eq!(seg_map1, seg_map2);
    }
}
