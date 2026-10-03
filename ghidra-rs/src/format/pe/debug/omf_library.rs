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
    pub fn new(reader: &BinaryReader, ptr: u64, num_bytes: u64) -> io::Result<Self> {
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


    #[test]
    fn read_single_library() {
        let data = vec![
            0x03, // length = 3
            b'a', b'd', b'b', // "adb"
        ];

        let reader = BinaryReader::from_bytes(data, true);
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

        let reader = BinaryReader::from_bytes(data, true);
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

        let reader = BinaryReader::from_bytes(data, true);
        let lib = OmfLibrary::new(&reader, 2, 3).expect("failed to read");

        assert_eq!(lib.libraries(), &["li".to_string()]);
    }

    #[test]
    fn read_empty() {
        let data = vec![];

        let reader = BinaryReader::from_bytes(data, true);
        let lib = OmfLibrary::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(lib.libraries(), &[] as &[String]);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x04, // length = 4
            b'l', b'i', b'b', b'c', // "libc"
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let lib1 = OmfLibrary::new(&reader, 0, 5).expect("failed to read");
        let lib2 = lib1.clone();

        assert_eq!(lib1, lib2);
    }
}
