use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_set::LengthStringSet;

/// Stores a resource name in a new-executable (NE) format file.
///
/// A resource name consists of a length-prefixed string and an index marking
/// its position in the file.
///
/// Mirrors `ResourceName` from the original Ghidra Java source.
#[derive(Debug, Clone)]
pub struct ResourceName {
    lns: LengthStringSet,
    index: u64,
}

impl ResourceName {
    /// Constructs a new resource name by reading from the given binary reader.
    ///
    /// Captures the current pointer index before reading the length-string pair,
    /// then reads and stores the length and name data.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let index = reader.get_pointer_index();
        let lns = LengthStringSet::new(reader)?;

        Ok(ResourceName { lns, index })
    }

    /// Returns the length of the resource name.
    pub fn length(&self) -> u8 {
        self.lns.length()
    }

    /// Returns the name string, or an empty string if no name was present.
    pub fn name(&self) -> String {
        self.lns.name().unwrap_or("").to_string()
    }

    /// Returns the byte index of this resource name, relative to the beginning of the file.
    pub fn index(&self) -> u64 {
        self.index
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
    fn constructs_with_zero_length_name() {
        let mut r = MockReader::new(vec![0]);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 0);
        assert_eq!(rn.name(), "");
    }

    #[test]
    fn constructs_with_nonempty_name() {
        let data = vec![5, b'a', b'l', b'i', b'a', b's'];
        let mut r = MockReader::new(data);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 5);
        assert_eq!(rn.name(), "alias");
    }

    #[test]
    fn constructs_with_single_char_name() {
        let data = vec![1, b'x'];
        let mut r = MockReader::new(data);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 0);
        assert_eq!(rn.length(), 1);
        assert_eq!(rn.name(), "x");
    }

    #[test]
    fn preserves_index_from_reader_position() {
        let data = vec![0, 0, 0, 3, b'r', b'e', b's'];
        let mut r = MockReader::new(data);
        r.set_pointer_index(3);
        let rn = ResourceName::new(&mut r).unwrap();
        assert_eq!(rn.index(), 3);
        assert_eq!(rn.length(), 3);
        assert_eq!(rn.name(), "res");
    }

    #[test]
    fn updates_reader_position_after_construction() {
        let data = vec![2, b'n', b'a', 99];
        let mut r = MockReader::new(data);
        let _ = ResourceName::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 3);
    }

    #[test]
    fn cloning_preserves_data() {
        let data = vec![4, b't', b'e', b's', b't'];
        let mut r = MockReader::new(data);
        let rn1 = ResourceName::new(&mut r).unwrap();
        let rn2 = rn1.clone();

        assert_eq!(rn1.index(), rn2.index());
        assert_eq!(rn1.length(), rn2.length());
        assert_eq!(rn1.name(), rn2.name());
    }
}
