use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Format of resource data for a single resource.
///
/// Mirrors `SingleResourceData` from the original Ghidra Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleResourceData {
    length: i32,
    data: Vec<u8>,
}

impl SingleResourceData {
    /// Creates a new `SingleResourceData` by reading from the given reader.
    ///
    /// Reads an int for the length, followed by that many bytes of data.
    ///
    /// # Errors
    /// Returns an error if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let length = reader.read_next_int()?;
        let data = if length > 0 {
            reader.read_next_byte_array(length as usize)?
        } else {
            Vec::new()
        };

        Ok(SingleResourceData { length, data })
    }

    /// Returns the length of the following resource.
    pub fn length(&self) -> i32 {
        self.length
    }

    /// Returns the resource data for this resource.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                position: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }

        fn get_pointer_index(&self) -> u64 {
            self.position as u64
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.position;
            self.position = index as usize;
            old as u64
        }

        fn is_little_endian(&self) -> bool {
            false
        }

        fn set_little_endian(&mut self, _is_little_endian: bool) {}

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "index out of range"))
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(n_elements).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "overflow")
            })?;
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "range out of bounds"));
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn get_byte_provider(
            &self,
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            panic!("not implemented for mock")
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(Self {
                bytes: self.bytes.clone(),
                position: new_index as usize,
            })
        }
    }

    #[test]
    fn reads_length_and_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&5i32.to_be_bytes());
        data.extend_from_slice(b"hello");

        let mut reader = MockReader::new(data);
        let resource = SingleResourceData::new(&mut reader).unwrap();

        assert_eq!(resource.length(), 5);
        assert_eq!(resource.data(), b"hello");
    }

    #[test]
    fn reads_empty_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_be_bytes());

        let mut reader = MockReader::new(data);
        let resource = SingleResourceData::new(&mut reader).unwrap();

        assert_eq!(resource.length(), 0);
        assert!(resource.data().is_empty());
    }

    #[test]
    fn reads_multiple_resources() {
        let mut data = Vec::new();
        data.extend_from_slice(&3i32.to_be_bytes());
        data.extend_from_slice(b"foo");
        data.extend_from_slice(&4i32.to_be_bytes());
        data.extend_from_slice(b"test");

        let mut reader = MockReader::new(data);

        let resource1 = SingleResourceData::new(&mut reader).unwrap();
        assert_eq!(resource1.length(), 3);
        assert_eq!(resource1.data(), b"foo");

        let resource2 = SingleResourceData::new(&mut reader).unwrap();
        assert_eq!(resource2.length(), 4);
        assert_eq!(resource2.data(), b"test");
    }

    #[test]
    fn errors_on_truncated_length() {
        let data = vec![0x00, 0x00];
        let mut reader = MockReader::new(data);

        assert!(SingleResourceData::new(&mut reader).is_err());
    }

    #[test]
    fn errors_on_truncated_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&10i32.to_be_bytes());
        data.extend_from_slice(b"short");

        let mut reader = MockReader::new(data);

        assert!(SingleResourceData::new(&mut reader).is_err());
    }

    #[test]
    fn large_resource_data() {
        let large_size = 1000i32;
        let mut data = Vec::new();
        data.extend_from_slice(&large_size.to_be_bytes());
        data.extend_from_slice(&vec![0xAAu8; 1000]);

        let mut reader = MockReader::new(data);
        let resource = SingleResourceData::new(&mut reader).unwrap();

        assert_eq!(resource.length(), 1000);
        assert_eq!(resource.data().len(), 1000);
        assert!(resource.data().iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn clone_and_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&5i32.to_be_bytes());
        data.extend_from_slice(b"hello");

        let mut reader = MockReader::new(data);
        let resource1 = SingleResourceData::new(&mut reader).unwrap();
        let resource2 = resource1.clone();

        assert_eq!(resource1, resource2);
    }

    #[test]
    fn debug_format() {
        let mut data = Vec::new();
        data.extend_from_slice(&2i32.to_be_bytes());
        data.extend_from_slice(b"ab");

        let mut reader = MockReader::new(data);
        let resource = SingleResourceData::new(&mut reader).unwrap();

        let debug_str = format!("{:?}", resource);
        assert!(debug_str.contains("SingleResourceData"));
        assert!(debug_str.contains("2"));
    }
}
