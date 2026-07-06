use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_set::LengthStringSet;

/// Stores a length/string/ordinal triplet.
///
/// Extends `LengthStringSet` by adding an ordinal (short integer) that is read
/// only if the length field is non-zero.
///
/// Mirrors `LengthStringOrdinalSet` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthStringOrdinalSet {
    length_string_set: LengthStringSet,
    ordinal: Option<i16>,
}

impl LengthStringOrdinalSet {
    /// Constructs a new length/string/ordinal set by reading from the given binary reader.
    ///
    /// Reads the length/string pair from the parent `LengthStringSet`, then if the
    /// length is non-zero, reads a 2-byte signed integer for the ordinal value.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let length_string_set = LengthStringSet::new(reader)?;

        let ordinal = if length_string_set.length() == 0 {
            None
        } else {
            Some(reader.read_next_short()?)
        };

        Ok(LengthStringOrdinalSet {
            length_string_set,
            ordinal,
        })
    }

    /// Returns the ordinal value if the length was non-zero.
    pub fn ordinal(&self) -> Option<i16> {
        self.ordinal
    }

    /// Returns a reference to the underlying `LengthStringSet`.
    pub fn length_string_set(&self) -> &LengthStringSet {
        &self.length_string_set
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
    fn reads_zero_length_no_ordinal() {
        let mut r = MockReader::new(vec![0]);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 0);
        assert_eq!(s.length_string_set().name(), None);
        assert_eq!(s.ordinal(), None);
    }

    #[test]
    fn reads_nonzero_length_with_ordinal() {
        let mut data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        data.extend_from_slice(&42i16.to_le_bytes());
        let mut r = MockReader::new(data);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 5);
        assert_eq!(s.length_string_set().name(), Some("hello"));
        assert_eq!(s.ordinal(), Some(42));
    }

    #[test]
    fn reads_single_char_with_ordinal() {
        let mut data = vec![1, b'x'];
        data.extend_from_slice(&100i16.to_le_bytes());
        let mut r = MockReader::new(data);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 1);
        assert_eq!(s.length_string_set().name(), Some("x"));
        assert_eq!(s.ordinal(), Some(100));
    }

    #[test]
    fn reads_negative_ordinal() {
        let mut data = vec![2, b'a', b'b'];
        data.extend_from_slice(&(-5i16).to_le_bytes());
        let mut r = MockReader::new(data);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.length_string_set().length(), 2);
        assert_eq!(s.length_string_set().name(), Some("ab"));
        assert_eq!(s.ordinal(), Some(-5));
    }

    #[test]
    fn updates_reader_position_with_ordinal() {
        let mut data = vec![3, b'a', b'b', b'c'];
        data.extend_from_slice(&99i16.to_le_bytes());
        data.push(255);
        let mut r = MockReader::new(data);
        let _ = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn zero_length_no_ordinal_read() {
        let mut data = vec![0];
        data.extend_from_slice(&42i16.to_le_bytes());
        let mut r = MockReader::new(data);
        let s = LengthStringOrdinalSet::new(&mut r).unwrap();
        assert_eq!(s.ordinal(), None);
        assert_eq!(r.get_pointer_index(), 1);
    }

    #[test]
    fn clone_equality() {
        let mut data = vec![4, b't', b'e', b's', b't'];
        data.extend_from_slice(&200i16.to_le_bytes());
        let data_clone = data.clone();
        let mut r = MockReader::new(data);
        let s1 = LengthStringOrdinalSet::new(&mut r).unwrap();

        let mut r2 = MockReader::new(data_clone);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_eq!(s1, s2);
    }

    #[test]
    fn zero_length_vs_nonzero_inequality() {
        let mut r1 = MockReader::new(vec![0]);
        let s1 = LengthStringOrdinalSet::new(&mut r1).unwrap();

        let mut data2 = vec![1, b'x'];
        data2.extend_from_slice(&42i16.to_le_bytes());
        let mut r2 = MockReader::new(data2);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }

    #[test]
    fn same_string_different_ordinal_inequality() {
        let mut data1 = vec![3, b'f', b'o', b'o'];
        data1.extend_from_slice(&10i16.to_le_bytes());
        let mut r1 = MockReader::new(data1);
        let s1 = LengthStringOrdinalSet::new(&mut r1).unwrap();

        let mut data2 = vec![3, b'f', b'o', b'o'];
        data2.extend_from_slice(&20i16.to_le_bytes());
        let mut r2 = MockReader::new(data2);
        let s2 = LengthStringOrdinalSet::new(&mut r2).unwrap();

        assert_ne!(s1, s2);
    }
}
