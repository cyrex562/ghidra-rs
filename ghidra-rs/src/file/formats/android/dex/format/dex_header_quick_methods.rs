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
    pub fn get_dex_length(reader: &mut BinaryReader) -> io::Result<i32> {
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

    #[test]
    fn get_dex_length_returns_file_size() {
        let mut data = Vec::new();
        data.extend_from_slice(DexConstants::DEX_MAGIC_BASE.as_bytes());
        data.extend_from_slice(b"035\0");
        data.extend_from_slice(&0x12345678i32.to_le_bytes());
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(&0x1000i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(data, true);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1000);
    }

    #[test]
    fn get_dex_length_rejects_invalid_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(b"NOTDEX\n");
        data.extend_from_slice(b"035\0");

        let mut reader = BinaryReader::from_bytes(data, true);
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
        let mut reader = BinaryReader::from_bytes(data, true);
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

        let mut reader = BinaryReader::from_bytes(data, true);
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

        let mut reader = BinaryReader::from_bytes(data, true);
        let result = DexHeaderQuickMethods::get_dex_length(&mut reader);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x7fffffff);
    }
}
