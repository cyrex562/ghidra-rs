use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// A relocation entry for an imported name from an imported module.
///
/// Mirrors `RelocationImportedName` from the original Ghidra Java source.
/// Stores an index into the module reference table and an offset into the
/// imported names table for a procedure name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationImportedName {
    index: i16,
    offset: i16,
}

impl RelocationImportedName {
    /// Constructs a new relocation imported name by reading from the given binary reader.
    ///
    /// Reads two i16 values: the module index and the name offset.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let index = reader.read_next_short()?;
        let offset = reader.read_next_short()?;

        Ok(RelocationImportedName { index, offset })
    }

    /// Returns the index into the module reference table for the imported module.
    pub fn index(&self) -> i16 {
        self.index
    }

    /// Returns the offset within the imported names table for the procedure name.
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
    fn reads_simple_relocation() {
        let mut data = Vec::new();
        data.extend_from_slice(&(1i16).to_le_bytes());
        data.extend_from_slice(&(42i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationImportedName::new(&mut r).unwrap();

        assert_eq!(rel.index(), 1);
        assert_eq!(rel.offset(), 42);
    }

    #[test]
    fn reads_zero_indices() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationImportedName::new(&mut r).unwrap();

        assert_eq!(rel.index(), 0);
        assert_eq!(rel.offset(), 0);
    }

    #[test]
    fn reads_negative_indices() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i16).to_le_bytes());
        data.extend_from_slice(&(-100i16).to_le_bytes());

        let mut r = MockReader::new(data);
        let rel = RelocationImportedName::new(&mut r).unwrap();

        assert_eq!(rel.index(), -1);
        assert_eq!(rel.offset(), -100);
    }

    #[test]
    fn updates_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5i16).to_le_bytes());
        data.extend_from_slice(&(10i16).to_le_bytes());
        data.push(99);

        let mut r = MockReader::new(data);
        let _ = RelocationImportedName::new(&mut r).unwrap();
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
        let rel = RelocationImportedName::new(&mut r).unwrap();

        assert_eq!(rel.index(), 7);
        assert_eq!(rel.offset(), 77);
    }

    #[test]
    fn copy_semantics() {
        let mut data = Vec::new();
        data.extend_from_slice(&(3i16).to_le_bytes());
        data.extend_from_slice(&(9i16).to_le_bytes());

        let mut r = MockReader::new(data.clone());
        let rel1 = RelocationImportedName::new(&mut r).unwrap();
        let rel2 = rel1;

        assert_eq!(rel1, rel2);
        assert_eq!(rel1.index(), rel2.index());
        assert_eq!(rel1.offset(), rel2.offset());
    }

    #[test]
    fn equality_between_different_constructions() {
        let mut data1 = Vec::new();
        data1.extend_from_slice(&(15i16).to_le_bytes());
        data1.extend_from_slice(&(20i16).to_le_bytes());

        let mut r1 = MockReader::new(data1);
        let rel1 = RelocationImportedName::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.extend_from_slice(&(15i16).to_le_bytes());
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = MockReader::new(data2);
        let rel2 = RelocationImportedName::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }
}
