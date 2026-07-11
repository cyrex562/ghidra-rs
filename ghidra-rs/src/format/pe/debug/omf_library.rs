use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) Library data structure.
///
/// Mirrors the `OMFLibrary` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfLibrary {
    libs: Vec<String>,
}

impl OmfLibrary {
    /// Creates a new `OmfLibrary` by reading from the given binary reader at the
    /// specified pointer, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    /// * `num_bytes` - The total number of bytes to read.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, ptr: u64, num_bytes: u64) -> io::Result<Self> {
        let mut libs = Vec::new();
        let mut current_ptr = ptr;
        let mut remaining_bytes = num_bytes;

        while remaining_bytes > 0 {
            let len = reader.read_byte(current_ptr)?;
            current_ptr += 1;
            remaining_bytes -= 1;

            let length = len as usize;
            let lib = reader.read_ascii_string_fixed(current_ptr, length)?;
            current_ptr += length as u64;
            remaining_bytes -= length as u64;

            libs.push(lib);
        }

        Ok(OmfLibrary { libs })
    }

    /// Returns the array of library names.
    pub fn libraries(&self) -> &[String] {
        &self.libs
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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
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
    fn read_single_library() {
        let data = vec![
            0x03, // length = 3
            b'a', b'd', b'b', // "adb"
        ];

        let reader = MockReader::new(data, true);
        let lib = OmfLibrary::new(&reader, 0, 4).expect("failed to read");

        assert_eq!(lib.libraries(), &["adb".to_string()]);
    }

    #[test]
    fn read_multiple_libraries() {
        let data = vec![
            0x03, // length = 3
            b'a', b'd', b'b', // "adb"
            0x02, // length = 2
            b'o', b's', // "os"
            0x01, // length = 1
            b'c', // "c"
        ];

        let reader = MockReader::new(data, true);
        let lib = OmfLibrary::new(&reader, 0, 9).expect("failed to read");

        assert_eq!(lib.libraries(), &[
            "adb".to_string(),
            "os".to_string(),
            "c".to_string()
        ]);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, // padding
            0x02, // length = 2 at offset 2
            b'l', b'i', // "li"
        ];

        let reader = MockReader::new(data, true);
        let lib = OmfLibrary::new(&reader, 2, 3).expect("failed to read");

        assert_eq!(lib.libraries(), &["li".to_string()]);
    }

    #[test]
    fn read_empty() {
        let data = vec![];

        let reader = MockReader::new(data, true);
        let lib = OmfLibrary::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(lib.libraries(), &[] as &[String]);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x04, // length = 4
            b'l', b'i', b'b', b'c', // "libc"
        ];

        let reader = MockReader::new(data, true);
        let lib1 = OmfLibrary::new(&reader, 0, 5).expect("failed to read");
        let lib2 = lib1.clone();

        assert_eq!(lib1, lib2);
    }
}
