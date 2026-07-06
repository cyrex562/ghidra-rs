use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// A relocation entry for an operating system fixup.
///
/// Mirrors `RelocationOSFixup` from the original Ghidra Java source.
/// Stores a fixup type and padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationOSFixup {
    fixup_type: i16,
    zeropad: i16,
}

impl RelocationOSFixup {
    /// Constructs a new relocation OS fixup by reading from the given binary reader.
    ///
    /// Reads two i16 values: the fixup type and a padding value.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let fixup_type = reader.read_next_short()?;
        let zeropad = reader.read_next_short()?;

        Ok(RelocationOSFixup {
            fixup_type,
            zeropad,
        })
    }

    /// Returns the fixup type.
    pub fn fixup_type(&self) -> i16 {
        self.fixup_type
    }

    /// Returns the padding value.
    pub fn pad(&self) -> i16 {
        self.zeropad
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
    fn reads_simple_fixup() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 5);
        assert_eq!(rel.pad(), 0);
    }

    #[test]
    fn reads_zero_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 0);
        assert_eq!(rel.pad(), 0);
    }

    #[test]
    fn reads_negative_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i16).to_le_bytes());
        data.extend_from_slice(&(-100i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), -1);
        assert_eq!(rel.pad(), -100);
    }

    #[test]
    fn reads_large_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&(32767i16).to_le_bytes());
        data.extend_from_slice(&(32767i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 32767);
        assert_eq!(rel.pad(), 32767);
    }

    #[test]
    fn updates_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(10i16).to_le_bytes());
        data.extend_from_slice(&(20i16).to_le_bytes());
        data.push(99);

        let mut r = MockReader::new(data);
        let _ = RelocationOSFixup::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_different_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&(7i16).to_le_bytes());
        data.extend_from_slice(&(77i16).to_le_bytes());

        let mut r = MockReader::new(data);
        r.set_pointer_index(3);
        let rel = RelocationOSFixup::new(&mut r).unwrap();

        assert_eq!(rel.fixup_type(), 7);
        assert_eq!(rel.pad(), 77);
    }

    #[test]
    fn copy_semantics() {
        let mut data = Vec::new();
        data.extend_from_slice(&(3i16).to_le_bytes());
        data.extend_from_slice(&(9i16).to_le_bytes());

        let mut r = MockReader::new(data.clone());
        let rel1 = RelocationOSFixup::new(&mut r).unwrap();
        let rel2 = rel1;

        assert_eq!(rel1, rel2);
        assert_eq!(rel1.fixup_type(), rel2.fixup_type());
        assert_eq!(rel1.pad(), rel2.pad());
    }

    #[test]
    fn equality_between_different_constructions() {
        let mut data1 = Vec::new();
        data1.extend_from_slice(&(15i16).to_le_bytes());
        data1.extend_from_slice(&(20i16).to_le_bytes());

        let mut r1 = MockReader::new(data1);
        let rel1 = RelocationOSFixup::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.extend_from_slice(&(15i16).to_le_bytes());
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = MockReader::new(data2);
        let rel2 = RelocationOSFixup::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }
}
