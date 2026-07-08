use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::dex_constants::DexConstants;

/// Quick utility methods for reading DEX file headers.
///
/// Mirrors `ghidra.file.formats.android.dex.format.DexHeaderQuickMethods`.
pub struct DexHeaderQuickMethods;

impl DexHeaderQuickMethods {
    /// Reads the file size from a DEX file header.
    ///
    /// Reads the DEX magic bytes and version, then the checksum and signature,
    /// and finally the file size at offset 0x20.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic bytes don't match [`DexConstants::DEX_MAGIC_BASE`]
    /// or if reading from the reader fails.
    pub fn get_dex_length(reader: &mut dyn BinaryReader) -> io::Result<i32> {
        let magic = reader.read_next_byte_array(DexConstants::DEX_MAGIC_BASE.len())?;

        if String::from_utf8_lossy(&magic) != DexConstants::DEX_MAGIC_BASE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a dex file.",
            ));
        }

        reader.read_next_byte_array(DexConstants::DEX_VERSION_LENGTH as usize)?;

        reader.read_next_int()?;

        reader.read_next_byte_array(20)?;

        let file_size = reader.read_next_int()?;
        Ok(file_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, position: 0 }
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
            true
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
            let end = start
                .checked_add(n_elements)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
            if end > self.bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "range out of bounds",
                ));
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
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
    fn get_dex_length_returns_file_size() {
        let mut data = Vec::new();
        data.extend_from_slice(DexConstants::DEX_MAGIC_BASE.as_bytes());
        data.extend_from_slice(b"035\0");
        data.extend_from_slice(&0x12345678i32.to_le_bytes());
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(&0x1000i32.to_le_bytes());

        let mut reader = MockReader::new(data);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1000);
    }

    #[test]
    fn get_dex_length_rejects_invalid_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NOTDEX\n");
        data.extend_from_slice(b"035\0");

        let mut reader = MockReader::new(data);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "not a dex file."
        );
    }

    #[test]
    fn get_dex_length_handles_truncated_magic() {
        let data = Vec::from(&b"de"[..]);
        let mut reader = MockReader::new(data);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_err());
    }

    #[test]
    fn get_dex_length_advances_reader_pointer() {
        let mut data = Vec::new();
        data.extend_from_slice(DexConstants::DEX_MAGIC_BASE.as_bytes());
        data.extend_from_slice(b"035\0");
        data.extend_from_slice(&0x12345678i32.to_le_bytes());
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(&0x1000i32.to_le_bytes());

        let mut reader = MockReader::new(data);
        assert_eq!(reader.get_pointer_index(), 0);

        let _ = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert_eq!(reader.get_pointer_index() as usize, 4 + 4 + 4 + 20 + 4);
    }

    #[test]
    fn get_dex_length_large_file_size() {
        let mut data = Vec::new();
        data.extend_from_slice(DexConstants::DEX_MAGIC_BASE.as_bytes());
        data.extend_from_slice(b"039\0");
        data.extend_from_slice(&0xdeadbeef_u32.to_le_bytes());
        data.extend_from_slice(&[0xaa; 20]);
        data.extend_from_slice(&0x7fffffff_i32.to_le_bytes());

        let mut reader = MockReader::new(data);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x7fffffff);
    }
}
