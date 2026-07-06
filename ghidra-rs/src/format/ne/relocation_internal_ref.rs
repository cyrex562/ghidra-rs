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
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
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
    fn reads_fixed_segment() {
        let mut data = Vec::new();
        data.push(1);
        data.push(0);
        data.extend_from_slice(&(0x1000u16).to_le_bytes());

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data);
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

        let mut r = MockReader::new(data.clone());
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

        let mut r1 = MockReader::new(data1);
        let rel1 = RelocationInternalRef::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.push(15);
        data2.push(0);
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = MockReader::new(data2);
        let rel2 = RelocationInternalRef::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }

    #[test]
    fn isnt_moveable_boundary() {
        let mut data = Vec::new();
        data.push(0xfe);
        data.push(0);
        data.extend_from_slice(&(100i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationInternalRef::new(&mut r).unwrap();

        assert!(!rel.is_moveable());
    }
}
