use std::io::Write;

use crate::util::DataConverter;

/// A trait for types that can write their state to a random access file.
///
/// Port of `ghidra.app.util.bin.format.Writeable`. Types implementing this trait
/// can serialize themselves to binary form using a provided writer and data converter
/// for handling endianness.
pub trait Writeable {
    /// Writes this object to the specified writer using the data converter
    /// to handle endianness.
    ///
    /// # Arguments
    ///
    /// * `raf` - The writer to write to (mirrors `RandomAccessFile` from Java)
    /// * `dc` - The data converter for byte-order conversions
    ///
    /// # Errors
    ///
    /// Returns an I/O error if writing fails.
    fn write(&self, raf: &mut dyn Write, dc: &dyn DataConverter) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWriteable {
        data: Vec<u8>,
    }

    impl MockWriteable {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl Writeable for MockWriteable {
        fn write(&self, raf: &mut dyn Write, _dc: &dyn DataConverter) -> std::io::Result<()> {
            raf.write_all(&self.data)?;
            Ok(())
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
        let writeable: Box<dyn Writeable> = Box::new(MockWriteable::new(vec![0x01, 0x02, 0x03]));
        let mut buffer = Vec::new();
        let dc = MockDataConverter;
        let result = writeable.write(&mut buffer, &dc);
        assert!(result.is_ok());
    }

    #[test]
    fn write_outputs_expected_bytes() {
        let expected = vec![0x01, 0x02, 0x03, 0x04];
        let writeable = MockWriteable::new(expected.clone());
        let mut buffer = Vec::new();
        let dc = MockDataConverter;
        let result = writeable.write(&mut buffer, &dc);
        assert!(result.is_ok());
        assert_eq!(buffer, expected);
    }

    #[test]
    fn write_with_empty_data() {
        let writeable = MockWriteable::new(vec![]);
        let mut buffer = Vec::new();
        let dc = MockDataConverter;
        let result = writeable.write(&mut buffer, &dc);
        assert!(result.is_ok());
        assert!(buffer.is_empty());
    }

    #[test]
    fn write_with_various_byte_values() {
        let data = vec![0x00, 0x7f, 0x80, 0xff];
        let writeable = MockWriteable::new(data.clone());
        let mut buffer = Vec::new();
        let dc = MockDataConverter;
        let result = writeable.write(&mut buffer, &dc);
        assert!(result.is_ok());
        assert_eq!(buffer, data);
    }
}
