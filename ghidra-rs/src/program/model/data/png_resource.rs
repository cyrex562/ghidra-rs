use thiserror::Error;

use crate::generic::hash::SimpleCRC32;
use crate::program::model::data::invalid_data_type_exception::InvalidDataTypeException;
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::MemoryAccessException;

/// Maximum size accepted for a single PNG chunk's data payload.
const MAX_CHUNK_SIZE: i32 = 10 * 1024 * 1024;

/// The 4-byte chunk type marking the end of a PNG stream.
const IEND: [u8; 4] = [b'I', b'E', b'N', b'D'];

/// PNG file signature (first 8 bytes of every PNG stream).
const PNG_SIGNATURE: u64 = 0x89504e470d0a1a0a;

/// Combines the checked exceptions declared on `PngResource`'s constructor.
#[derive(Error, Debug)]
pub enum PngResourceError {
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
    #[error(transparent)]
    InvalidData(#[from] InvalidDataTypeException),
}

/// Validates and measures a PNG image stored in program memory.
///
/// Port of `ghidra.program.model.data.PngResource`.
pub(crate) struct PngResource<'a> {
    buf: &'a dyn MemBuffer,
    buf_offset: i32,
}

impl<'a> PngResource<'a> {
    /// Reads and validates the PNG header and chunk stream starting at the buffer's origin.
    pub(crate) fn new(buf: &'a dyn MemBuffer) -> Result<Self, PngResourceError> {
        let mut resource = Self { buf, buf_offset: 0 };
        resource.read_header()?;
        resource.scan_contents()?;
        Ok(resource)
    }

    /// Returns the total length, in bytes, of the validated PNG stream.
    pub(crate) fn get_length(&self) -> i32 {
        self.buf_offset
    }

    fn scan_contents(&mut self) -> Result<(), InvalidDataTypeException> {
        let mut chunk_count = 0u32;
        let mut save_offset = self.buf_offset;
        loop {
            let len = self
                .read_int()
                .map_err(|_| InvalidDataTypeException::with_message("Invalid PNG Data - missing data"))?;
            if len < 0 || len > MAX_CHUNK_SIZE {
                return Err(InvalidDataTypeException::with_message("Invalid PNG Data - too big"));
            }
            let mut chunk_type = [0u8; 4];
            self.buf.get_bytes(&mut chunk_type, self.buf_offset);
            self.buf_offset += 4;
            let mut data = vec![0u8; len as usize];
            self.buf.get_bytes(&mut data, self.buf_offset);
            self.buf_offset += len;
            let crc = self
                .read_int()
                .map_err(|_| InvalidDataTypeException::with_message("Invalid PNG Data - missing data"))?
                as u32 as u64;
            if !Self::verify_crc(&chunk_type, &data, crc) {
                return Err(InvalidDataTypeException::with_message("Invalid PNG Data - bad CRC"));
            }
            save_offset = self.buf_offset;
            chunk_count += 1;
            if chunk_type == IEND {
                break;
            }
        }
        self.buf_offset = save_offset;
        if chunk_count == 0 {
            return Err(InvalidDataTypeException::with_message("Invalid PNG Data - no data"));
        }
        Ok(())
    }

    fn verify_crc(chunk_type: &[u8; 4], data: &[u8], crc: u64) -> bool {
        let mut hash: u32 = 0xFFFF_FFFF;
        for &b in chunk_type {
            hash = SimpleCRC32::hash_one_byte(hash, b as u32);
        }
        for &b in data {
            hash = SimpleCRC32::hash_one_byte(hash, b as u32);
        }
        let crc_val = (hash ^ 0xFFFF_FFFF) as u64;
        crc_val == crc
    }

    fn read_header(&mut self) -> Result<(), PngResourceError> {
        let sig = self.read_long()?;
        if sig != PNG_SIGNATURE {
            return Err(InvalidDataTypeException::with_message("Invalid PNG Data").into());
        }
        Ok(())
    }

    fn read_long(&mut self) -> Result<u64, MemoryAccessException> {
        let mut val: u64 = 0;
        for _ in 0..8 {
            val = (val << 8) | self.buf.get_byte(self.buf_offset)? as u64;
            self.buf_offset += 1;
        }
        Ok(val)
    }

    fn read_int(&mut self) -> Result<i32, MemoryAccessException> {
        let mut val: i32 = 0;
        for _ in 0..4 {
            val = (val << 8) | self.buf.get_byte(self.buf_offset)? as i32;
            self.buf_offset += 1;
        }
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;

    struct MockMemBuffer {
        data: Vec<u8>,
    }

    impl MockMemBuffer {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            Address::default()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let start = offset as usize;
            if start >= self.data.len() {
                return 0;
            }
            let available = self.data.len() - start;
            let to_read = std::cmp::min(buf.len(), available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    fn crc32_of(chunks: &[&[u8]]) -> u32 {
        let mut hash: u32 = 0xFFFF_FFFF;
        for chunk in chunks {
            for &b in *chunk {
                hash = SimpleCRC32::hash_one_byte(hash, b as u32);
            }
        }
        hash ^ 0xFFFF_FFFF
    }

    fn push_chunk(bytes: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&(data.len() as i32).to_be_bytes());
        bytes.extend_from_slice(chunk_type);
        bytes.extend_from_slice(data);
        let crc = crc32_of(&[chunk_type, data]);
        bytes.extend_from_slice(&crc.to_be_bytes());
    }

    fn minimal_valid_png() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE.to_be_bytes());
        push_chunk(&mut bytes, b"IHDR", &[1, 2, 3, 4]);
        push_chunk(&mut bytes, b"IEND", &[]);
        bytes
    }

    #[test]
    fn valid_png_parses_and_reports_length() {
        let bytes = minimal_valid_png();
        let expected_len = bytes.len() as i32;
        let mock = MockMemBuffer::new(bytes);

        let resource = PngResource::new(&mock).unwrap();

        assert_eq!(resource.get_length(), expected_len);
    }

    #[test]
    fn valid_png_stops_scanning_data_after_iend() {
        let mut bytes = minimal_valid_png();
        // Trailing garbage after IEND must not be included in the reported length.
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mock = MockMemBuffer::new(bytes.clone());

        let resource = PngResource::new(&mock).unwrap();

        assert_eq!(resource.get_length(), (bytes.len() - 4) as i32);
    }

    #[test]
    fn bad_signature_is_rejected() {
        let mut bytes = minimal_valid_png();
        bytes[0] = 0x00;
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }

    #[test]
    fn truncated_signature_is_a_memory_access_error() {
        let mock = MockMemBuffer::new(vec![0x89, 0x50, 0x4e]);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::MemoryAccess(_)));
    }

    #[test]
    fn bad_crc_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE.to_be_bytes());
        push_chunk(&mut bytes, b"IHDR", &[1, 2, 3, 4]);
        // Corrupt the CRC of the IHDR chunk.
        let crc_index = bytes.len() - 4;
        bytes[crc_index] ^= 0xff;
        push_chunk(&mut bytes, b"IEND", &[]);
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }

    #[test]
    fn oversized_chunk_length_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE.to_be_bytes());
        bytes.extend_from_slice(&(MAX_CHUNK_SIZE + 1).to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }

    #[test]
    fn negative_chunk_length_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE.to_be_bytes());
        bytes.extend_from_slice(&(-1i32).to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }

    #[test]
    fn missing_chunk_data_is_a_memory_access_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE.to_be_bytes());
        // Declare a chunk with data, but truncate before the CRC is present.
        bytes.extend_from_slice(&4i32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }

    #[test]
    fn stream_with_nothing_after_signature_is_rejected() {
        // A signature with no chunk data at all fails to read a chunk length.
        let bytes = PNG_SIGNATURE.to_be_bytes().to_vec();
        let mock = MockMemBuffer::new(bytes);

        let err = PngResource::new(&mock).unwrap_err();
        assert!(matches!(err, PngResourceError::InvalidData(_)));
    }
}
