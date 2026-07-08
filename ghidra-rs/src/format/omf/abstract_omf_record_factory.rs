use crate::app::util::bin::binary_reader::BinaryReader;

use super::OmfRecord;

/// A factory for reading various flavors of the OMF format.
///
/// Mirrors Ghidra's `AbstractOmfRecordFactory`. Implementations of this trait can read various
/// flavors of the OMF format by overriding the abstract methods to customize record parsing
/// and validation.
pub trait AbstractOmfRecordFactory {
    /// Returns a mutable reference to the underlying reader.
    fn reader_mut(&mut self) -> &mut dyn BinaryReader;

    /// Returns an immutable reference to the underlying reader.
    fn reader(&self) -> &dyn BinaryReader;

    /// Reads the next [`OmfRecord`] pointed to by the reader.
    ///
    /// # Errors
    /// Returns an error if there was an IO-related error or a problem with the OMF specification.
    fn read_next_record(&mut self) -> Result<OmfRecord, Box<dyn std::error::Error>>;

    /// Gets a list of valid record types that can start a supported OMF binary.
    fn get_start_record_types(&self) -> Vec<i32>;

    /// Gets a valid record type that can end a supported OMF binary.
    fn get_end_record_type(&self) -> i32;

    /// Resets this factory's reader to index 0.
    fn reset(&mut self) {
        self.reader_mut().set_pointer_index(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;
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

    struct TestFactory {
        reader: Box<dyn BinaryReader>,
        start_types: Vec<i32>,
        end_type: i32,
    }

    impl TestFactory {
        fn new(data: Vec<u8>, start_types: Vec<i32>, end_type: i32) -> Self {
            TestFactory {
                reader: Box::new(MockReader::new(data)),
                start_types,
                end_type,
            }
        }
    }

    impl AbstractOmfRecordFactory for TestFactory {
        fn reader_mut(&mut self) -> &mut dyn BinaryReader {
            &mut *self.reader
        }
        fn reader(&self) -> &dyn BinaryReader {
            &*self.reader
        }
        fn read_next_record(&mut self) -> Result<OmfRecord, Box<dyn std::error::Error>> {
            Err("test factory".into())
        }
        fn get_start_record_types(&self) -> Vec<i32> {
            self.start_types.clone()
        }
        fn get_end_record_type(&self) -> i32 {
            self.end_type
        }
    }

    #[test]
    fn test_reset() {
        let data = vec![0u8; 100];
        let mut factory = TestFactory::new(data, vec![1, 2], 99);

        factory.reader_mut().set_pointer_index(50);
        assert_eq!(factory.reader().get_pointer_index(), 50);

        factory.reset();
        assert_eq!(factory.reader().get_pointer_index(), 0);
    }

    #[test]
    fn test_get_start_record_types() {
        let data = vec![0u8; 100];
        let factory = TestFactory::new(data, vec![1, 2, 3], 99);

        assert_eq!(factory.get_start_record_types(), vec![1, 2, 3]);
    }

    #[test]
    fn test_get_end_record_type() {
        let data = vec![0u8; 100];
        let factory = TestFactory::new(data, vec![1], 42);

        assert_eq!(factory.get_end_record_type(), 42);
    }

    #[test]
    fn test_reader_methods() {
        let data = vec![0u8; 100];
        let mut factory = TestFactory::new(data, vec![], 0);

        let reader_ref = factory.reader();
        assert_eq!(reader_ref.get_pointer_index(), 0);

        factory.reader_mut().set_pointer_index(25);
        assert_eq!(factory.reader().get_pointer_index(), 25);
    }
}
