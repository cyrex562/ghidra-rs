use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_ordinal_set::LengthStringOrdinalSet;

/// Represents the non-resident name table in a new-executable (NE) format file.
///
/// The non-resident name table stores exported names and their ordinals, along with
/// an optional module title. This struct provides access to those names and the title.
///
/// Mirrors `NonResidentNameTable` from the original Ghidra Java source.
pub struct NonResidentNameTable {
    title: String,
    names: Vec<LengthStringOrdinalSet>,
}

impl NonResidentNameTable {
    /// Constructs a new non-resident name table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The byte offset where the non-resident name table begins
    /// * `byte_count` - The number of bytes in the non-resident name table (unused,
    ///                  for compatibility with Java signature)
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(
        reader: &mut dyn BinaryReader,
        index: u64,
        _byte_count: i16,
    ) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut names = Vec::new();
        let mut title = "<not set>".to_string();

        loop {
            let lsos = LengthStringOrdinalSet::new(reader)?;
            if lsos.length_string_set().length() == 0 {
                break;
            }
            if lsos.ordinal() == Some(0) {
                if let Some(name) = lsos.length_string_set().name() {
                    title = name.to_string();
                }
            }
            names.push(lsos);
        }

        reader.set_pointer_index(old_index);

        Ok(NonResidentNameTable { title, names })
    }

    /// Returns the non-resident name table title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the array of names defined in the non-resident name table.
    pub fn names(&self) -> &[LengthStringOrdinalSet] {
        &self.names
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
    fn creates_table_with_default_title() {
        let data = vec![0];
        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 1).unwrap();
        assert_eq!(table.title(), "<not set>");
        assert_eq!(table.names().len(), 0);
    }

    #[test]
    fn reads_single_named_entry() {
        let mut data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        data.extend_from_slice(&42i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.title(), "<not set>");
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("hello"));
        assert_eq!(table.names()[0].ordinal(), Some(42));
    }

    #[test]
    fn extracts_title_from_ordinal_zero() {
        let mut data = vec![5, b'T', b'i', b't', b'l', b'e'];
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.title(), "Title");
        assert_eq!(table.names().len(), 1);
    }

    #[test]
    fn reads_multiple_entries() {
        let mut data = Vec::new();
        data.push(5);
        data.extend_from_slice(b"title");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo1");
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo2");
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "title");
        assert_eq!(table.names().len(), 3);
        assert_eq!(table.names()[0].ordinal(), Some(0));
        assert_eq!(table.names()[1].ordinal(), Some(1));
        assert_eq!(table.names()[2].ordinal(), Some(2));
    }

    #[test]
    fn restores_reader_position() {
        let mut data = vec![0, 0xFF, 0xFF];
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(2);
        NonResidentNameTable::new(&mut reader, 0, 1).unwrap();
        assert_eq!(reader.get_pointer_index(), 2);
    }

    #[test]
    fn handles_table_starting_at_nonzero_offset() {
        let mut data = vec![0xFF, 0xFF];
        data.push(3);
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&5i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 2, 16).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("abc"));
        assert_eq!(table.names()[0].ordinal(), Some(5));
    }

    #[test]
    fn skips_zero_length_ordinal() {
        let mut data = vec![0];
        data.push(4);
        data.extend_from_slice(b"skip");
        data.extend_from_slice(&99i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("skip"));
        assert_eq!(table.names()[0].ordinal(), Some(99));
    }

    #[test]
    fn title_from_first_ordinal_zero_entry() {
        let mut data = Vec::new();
        data.push(5);
        data.extend_from_slice(b"first");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(6);
        data.extend_from_slice(b"second");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "first");
        assert_eq!(table.names().len(), 2);
    }

    #[test]
    fn mixed_ordinals_with_title() {
        let mut data = Vec::new();
        data.push(3);
        data.extend_from_slice(b"app");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(b"x1");
        data.extend_from_slice(&10i16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(b"x2");
        data.extend_from_slice(&20i16.to_le_bytes());
        data.push(0);

        let mut reader = MockReader::new(data);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "app");
        assert_eq!(table.names().len(), 3);
        assert_eq!(
            table.names().iter().map(|n| n.ordinal()).collect::<Vec<_>>(),
            vec![Some(0), Some(10), Some(20)]
        );
    }
}
