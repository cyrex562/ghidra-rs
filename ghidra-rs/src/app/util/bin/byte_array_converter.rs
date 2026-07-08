use std::io;

use crate::util::DataConverter;

/// A trait for types that can convert themselves to a byte array.
///
/// Port of `ghidra.app.util.bin.ByteArrayConverter`.
pub trait ByteArrayConverter {
    /// Returns a byte array representing this implementor of this trait.
    ///
    /// # Arguments
    ///
    /// * `dc` - The data converter to use for byte-order conversions.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if byte array conversion fails.
    fn to_bytes(&self, dc: &dyn DataConverter) -> io::Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockByteArrayConverter {
        bytes: Vec<u8>,
    }

    impl MockByteArrayConverter {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
    }

    impl ByteArrayConverter for MockByteArrayConverter {
        fn to_bytes(&self, _dc: &dyn DataConverter) -> io::Result<Vec<u8>> {
            Ok(self.bytes.clone())
        }
    }

    struct MockDataConverter;

    impl DataConverter for MockDataConverter {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
            i16::from_be_bytes([b[offset], b[offset + 1]])
        }

        fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
            i32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        }

        fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&b[offset..offset + 8]);
            i64::from_be_bytes(buf)
        }

        fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
            let mut val: u64 = 0;
            for i in 0..size {
                val = (val << 8) | b[offset + i] as u64;
            }
            val
        }

        fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128 {
            let unsigned = self.get_value_at(b, offset, size) as i128;
            if signed && size < 16 && size > 0 {
                let shift_bits = (16 - size) * 8;
                (unsigned << shift_bits) >> shift_bits
            } else {
                unsigned
            }
        }

        fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
            b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }

        fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
            b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }

        fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }

        fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let converter: Box<dyn ByteArrayConverter> =
            Box::new(MockByteArrayConverter::new(vec![0x01, 0x02, 0x03]));
        let dc = MockDataConverter;
        let result = converter.to_bytes(&dc);
        assert!(result.is_ok());
    }

    #[test]
    fn to_bytes_returns_expected_bytes() {
        let expected = vec![0x01, 0x02, 0x03, 0x04];
        let converter = MockByteArrayConverter::new(expected.clone());
        let dc = MockDataConverter;
        let result = converter.to_bytes(&dc);
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn to_bytes_with_empty_array() {
        let converter = MockByteArrayConverter::new(vec![]);
        let dc = MockDataConverter;
        let result = converter.to_bytes(&dc);
        assert_eq!(result.unwrap(), vec![]);
    }

    #[test]
    fn to_bytes_with_various_byte_values() {
        let bytes = vec![0x00, 0x7f, 0x80, 0xff];
        let converter = MockByteArrayConverter::new(bytes.clone());
        let dc = MockDataConverter;
        let result = converter.to_bytes(&dc);
        assert_eq!(result.unwrap(), bytes);
    }
}
