use crate::app::util::bin::binary_reader::BinaryReader;

use super::OmfRecord;

/// A factory for reading various flavors of the OMF format.
///
/// Mirrors Ghidra's `AbstractOmfRecordFactory`. Implementations of this trait can read various
/// flavors of the OMF format by overriding the abstract methods to customize record parsing
/// and validation.
pub trait AbstractOmfRecordFactory {
    /// Returns a mutable reference to the underlying reader.
    fn reader_mut(&mut self) -> &mut BinaryReader;

    /// Returns an immutable reference to the underlying reader.
    fn reader(&self) -> &BinaryReader;

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
    use std::io;


    struct TestFactory {
        reader: BinaryReader,
        start_types: Vec<i32>,
        end_type: i32,
    }

    impl TestFactory {
        fn new(data: Vec<u8>, start_types: Vec<i32>, end_type: i32) -> Self {
            TestFactory {
                reader: BinaryReader::from_bytes(data, true),
                start_types,
                end_type,
            }
        }
    }

    impl AbstractOmfRecordFactory for TestFactory {
        fn reader_mut(&mut self) -> &mut BinaryReader {
            &mut self.reader
        }
        fn reader(&self) -> &BinaryReader {
            &self.reader
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
