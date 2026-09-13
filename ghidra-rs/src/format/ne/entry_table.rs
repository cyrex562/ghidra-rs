use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::entry_table_bundle::EntryTableBundle;
use std::io;

/// Represents a new-executable (NE) entry table.
///
/// Mirrors `EntryTable` from the original Ghidra Java source.
pub struct EntryTable {
    bundles: Vec<EntryTableBundle>,
}

impl EntryTable {
    /// Constructs a new entry table.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `index` - the index where the entry table begins
    /// * `byte_count` - the length in bytes of the entry table. Unused: mirrors the Java
    ///   constructor, whose `byteCount` parameter is likewise never read in the constructor body
    ///   (the bundle list is instead terminated by a zero-count bundle).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut dyn BinaryReader, index: u64, _byte_count: i16) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut bundles = Vec::new();
        loop {
            let etb = EntryTableBundle::new(reader)?;
            if etb.get_count() == 0 {
                break;
            }
            bundles.push(etb);
        }

        reader.set_pointer_index(old_index);

        Ok(EntryTable { bundles })
    }

    /// Returns the entry table bundles in this entry table.
    pub fn get_bundles(&self) -> &[EntryTableBundle] {
        &self.bundles
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
    fn empty_table_stops_at_sentinel() {
        let data = vec![0x00u8]; // single sentinel bundle (count == 0)
        let mut reader = MockReader::new(data);

        let table = EntryTable::new(&mut reader, 0, 0).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
    }

    #[test]
    fn reads_multiple_bundles_until_sentinel() {
        let data = vec![
            // bundle 1: count=1, type=CONSTANT(0xfe), one non-moveable entry
            0x01, 0xfe, 0x03, 0x10, 0x00, // bundle 2: count=1, type=MOVEABLE(0xff), one
            // moveable entry
            0x01, 0xff, 0x04, 0xAA, 0xBB, 0x02, 0x20, 0x00, // sentinel
            0x00,
        ];
        let mut reader = MockReader::new(data);

        let table = EntryTable::new(&mut reader, 0, 0).unwrap();

        let bundles = table.get_bundles();
        assert_eq!(bundles.len(), 2);
        assert!(bundles[0].is_constant());
        assert!(bundles[1].is_moveable());
    }

    #[test]
    fn honors_starting_index_and_restores_pointer() {
        let mut data = vec![0xAA, 0xBB, 0xCC]; // filler before the table
        data.push(0x00); // sentinel at index 3
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(1);

        let table = EntryTable::new(&mut reader, 3, 0).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
        assert_eq!(reader.get_pointer_index(), 1);
    }

    #[test]
    fn byte_count_argument_is_ignored() {
        // Mirrors the Java quirk where `byteCount` is accepted but never consulted; passing a
        // nonsensical value must not change parsing.
        let data = vec![0x00u8];
        let mut reader = MockReader::new(data);

        let table = EntryTable::new(&mut reader, 0, i16::MAX).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
    }
}
