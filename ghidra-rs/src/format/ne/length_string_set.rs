use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Stores a length/string pair where the string is not null-terminated
/// and the length field determines the string length.
///
/// Mirrors `LengthStringSet` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthStringSet {
    index: u64,
    length: u8,
    name: Option<String>,
}

impl LengthStringSet {
    /// Constructs a new length/string set by reading from the given binary reader.
    ///
    /// Reads a single byte for the length, then if the length is non-zero,
    /// reads that many ASCII bytes for the name (not null-terminated).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let index = reader.get_pointer_index();
        let length = reader.read_next_byte()?;

        let name = if length == 0 {
            None
        } else {
            let s = reader.read_next_ascii_string_fixed(length as usize)?;
            Some(s)
        };

        Ok(LengthStringSet {
            index,
            length,
            name,
        })
    }

    /// Returns the byte index of this string, relative to the beginning of the file.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the length of the string.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Returns the string, or `None` if the length was zero.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
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
    fn reads_zero_length_string() {
        let mut r = MockReader::new(vec![0]);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 0);
        assert_eq!(s.name(), None);
    }

    #[test]
    fn reads_nonempty_string() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let mut r = MockReader::new(data);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 5);
        assert_eq!(s.name(), Some("hello"));
    }

    #[test]
    fn reads_single_char_string() {
        let data = vec![1, b'x'];
        let mut r = MockReader::new(data);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 0);
        assert_eq!(s.length(), 1);
        assert_eq!(s.name(), Some("x"));
    }

    #[test]
    fn updates_reader_position() {
        let data = vec![3, b'a', b'b', b'c', 99];
        let mut r = MockReader::new(data);
        let _ = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn tracks_index_at_different_position() {
        let data = vec![0, 0, 0, 2, b'h', b'i'];
        let mut r = MockReader::new(data);
        r.set_pointer_index(3);
        let s = LengthStringSet::new(&mut r).unwrap();
        assert_eq!(s.index(), 3);
        assert_eq!(s.length(), 2);
        assert_eq!(s.name(), Some("hi"));
    }

    #[test]
    fn clone_equality() {
        let data = vec![4, b't', b'e', b's', b't'];
        let mut r = MockReader::new(data.clone());
        let s1 = LengthStringSet::new(&mut r).unwrap();

        let mut r2 = MockReader::new(data);
        let s2 = LengthStringSet::new(&mut r2).unwrap();

        assert_eq!(s1, s2);
    }

    #[test]
    fn zero_length_vs_nonzero_inequality() {
        let mut r1 = MockReader::new(vec![0]);
        let s1 = LengthStringSet::new(&mut r1).unwrap();

        let data2 = vec![1, b'x'];
        let mut r2 = MockReader::new(data2);
        let s2 = LengthStringSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }
}
