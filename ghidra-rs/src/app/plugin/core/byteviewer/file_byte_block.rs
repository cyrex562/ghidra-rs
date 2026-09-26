use crate::app::plugin::core::format::{ByteBlock, ByteBlockAccessException};
use crate::util::big_endian_data_converter::INSTANCE as BIG_ENDIAN;
use crate::util::little_endian_data_converter::INSTANCE as LITTLE_ENDIAN;
use crate::util::DataConverter;

/// `ByteBlock` for a byte buffer read from a file.
///
/// Port of `ghidra.app.plugin.core.byteviewer.FileByteBlock`.
pub struct FileByteBlock {
    buf: Vec<u8>,
    big_endian: bool,
    converter: &'static dyn DataConverter,
}

impl FileByteBlock {
    /// Constructs a new `FileByteBlock` wrapping the given buffer.
    ///
    /// Corresponds to `FileByteBlock(byte[] b)` in Java.
    pub fn new(b: Vec<u8>) -> Self {
        Self {
            buf: b,
            big_endian: false,
            converter: &LITTLE_ENDIAN,
        }
    }

    /// Returns the underlying buffer.
    ///
    /// Corresponds to the package-private `byte[] getBytes()` in Java.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl ByteBlock for FileByteBlock {
    fn get_location_representation(&self, index: i128) -> Result<String, ByteBlockAccessException> {
        if index < self.buf.len() as i128 {
            Ok(format!("{:08}", index))
        }
        else {
            Err(ByteBlockAccessException::new("Index out of bounds"))
        }
    }

    fn get_max_location_representation_size(&self) -> i32 {
        8
    }

    fn get_index_name(&self) -> String {
        "Bytes".to_string()
    }

    fn get_length(&self) -> i128 {
        self.buf.len() as i128
    }

    fn get_byte(&self, index: i128) -> Result<u8, ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            Ok(self.buf[index])
        }
        else {
            Ok(0)
        }
    }

    fn get_bytes(
        &self,
        bytes: &mut [u8],
        index: i128,
        count: usize,
    ) -> Result<usize, ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            let count = count.min(self.buf.len() - index);
            bytes[..count].copy_from_slice(&self.buf[index..index + count]);
            Ok(count)
        }
        else {
            Ok(0)
        }
    }

    fn get_short(&self, index: i128) -> Result<i16, ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            Ok(self.converter.get_short(&self.buf[index..index + 2]))
        }
        else {
            Ok(0)
        }
    }

    fn get_int(&self, index: i128) -> Result<i32, ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            Ok(self.converter.get_int(&self.buf[index..index + 4]))
        }
        else {
            Ok(0)
        }
    }

    fn get_long(&self, index: i128) -> Result<i64, ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            Ok(self.converter.get_long(&self.buf[index..index + 8]))
        }
        else {
            Ok(0)
        }
    }

    fn set_byte(&mut self, index: i128, value: u8) -> Result<(), ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            self.buf[index] = value;
        }
        Ok(())
    }

    fn set_short(&mut self, index: i128, value: i16) -> Result<(), ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            self.converter.put_short_at(&mut self.buf, index, value);
        }
        Ok(())
    }

    fn set_int(&mut self, index: i128, value: i32) -> Result<(), ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            self.converter.put_int_at(&mut self.buf, index, value);
        }
        Ok(())
    }

    fn set_long(&mut self, index: i128, value: i64) -> Result<(), ByteBlockAccessException> {
        let index = index as usize;
        if index < self.buf.len() {
            self.converter.put_long_at(&mut self.buf, index, value);
        }
        Ok(())
    }

    fn is_editable(&self) -> bool {
        false
    }

    fn set_big_endian(&mut self, big_endian: bool) {
        if self.big_endian != big_endian {
            self.big_endian = big_endian;
            self.converter = if big_endian { &BIG_ENDIAN } else { &LITTLE_ENDIAN };
        }
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    fn get_alignment(&self, _radix: i32) -> i32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_to_little_endian() {
        let block = FileByteBlock::new(vec![0x01, 0x02, 0x03]);
        assert!(!block.is_big_endian());
        assert!(!block.is_editable());
    }

    #[test]
    fn raw_bytes_returns_buffer() {
        let block = FileByteBlock::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(block.raw_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn get_location_representation_in_bounds() {
        let block = FileByteBlock::new(vec![0u8; 10]);
        assert_eq!(block.get_location_representation(5).unwrap(), "00000005");
    }

    #[test]
    fn get_location_representation_out_of_bounds() {
        let block = FileByteBlock::new(vec![0u8; 2]);
        assert!(block.get_location_representation(2).is_err());
    }

    #[test]
    fn get_max_location_representation_size_is_eight() {
        let block = FileByteBlock::new(vec![]);
        assert_eq!(block.get_max_location_representation_size(), 8);
    }

    #[test]
    fn get_index_name_is_bytes() {
        let block = FileByteBlock::new(vec![]);
        assert_eq!(block.get_index_name(), "Bytes");
    }

    #[test]
    fn get_length_matches_buffer_len() {
        let block = FileByteBlock::new(vec![0u8; 7]);
        assert_eq!(block.get_length(), 7);
    }

    #[test]
    fn get_byte_in_bounds() {
        let block = FileByteBlock::new(vec![0xAA, 0xBB]);
        assert_eq!(block.get_byte(1).unwrap(), 0xBB);
    }

    #[test]
    fn get_byte_out_of_bounds_returns_zero() {
        let block = FileByteBlock::new(vec![0xAA]);
        assert_eq!(block.get_byte(5).unwrap(), 0);
    }

    #[test]
    fn get_bytes_copies_requested_count() {
        let block = FileByteBlock::new(vec![0x01, 0x02, 0x03, 0x04]);
        let mut dest = [0u8; 2];
        let count = block.get_bytes(&mut dest, 1, 2).unwrap();
        assert_eq!(count, 2);
        assert_eq!(dest, [0x02, 0x03]);
    }

    #[test]
    fn get_bytes_clamps_count_to_remaining() {
        let block = FileByteBlock::new(vec![0x01, 0x02, 0x03]);
        let mut dest = [0u8; 5];
        let count = block.get_bytes(&mut dest, 1, 5).unwrap();
        assert_eq!(count, 2);
        assert_eq!(&dest[..2], &[0x02, 0x03]);
    }

    #[test]
    fn get_bytes_out_of_bounds_returns_zero() {
        let block = FileByteBlock::new(vec![0x01]);
        let mut dest = [0u8; 4];
        let count = block.get_bytes(&mut dest, 5, 4).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn get_short_little_endian_default() {
        let block = FileByteBlock::new(vec![0x34, 0x12]);
        assert_eq!(block.get_short(0).unwrap(), 0x1234);
    }

    #[test]
    fn get_short_out_of_bounds_returns_zero() {
        let block = FileByteBlock::new(vec![0x01]);
        assert_eq!(block.get_short(5).unwrap(), 0);
    }

    #[test]
    fn get_int_little_endian_default() {
        let block = FileByteBlock::new(vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(block.get_int(0).unwrap(), 0x1234_5678);
    }

    #[test]
    fn get_long_little_endian_default() {
        let block = FileByteBlock::new(vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(block.get_long(0).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn set_big_endian_switches_converter() {
        let mut block = FileByteBlock::new(vec![0x12, 0x34]);
        assert_eq!(block.get_short(0).unwrap(), 0x3412);
        block.set_big_endian(true);
        assert!(block.is_big_endian());
        assert_eq!(block.get_short(0).unwrap(), 0x1234);
    }

    #[test]
    fn set_big_endian_noop_when_unchanged() {
        let mut block = FileByteBlock::new(vec![0x00]);
        block.set_big_endian(false);
        assert!(!block.is_big_endian());
    }

    #[test]
    fn set_byte_writes_value() {
        let mut block = FileByteBlock::new(vec![0x00, 0x00]);
        block.set_byte(1, 0xFF).unwrap();
        assert_eq!(block.get_byte(1).unwrap(), 0xFF);
    }

    #[test]
    fn set_byte_out_of_bounds_is_noop() {
        let mut block = FileByteBlock::new(vec![0x00]);
        assert!(block.set_byte(5, 0xFF).is_ok());
    }

    #[test]
    fn set_short_round_trips() {
        let mut block = FileByteBlock::new(vec![0x00, 0x00]);
        block.set_short(0, 0x1234).unwrap();
        assert_eq!(block.get_short(0).unwrap(), 0x1234);
    }

    #[test]
    fn set_int_round_trips() {
        let mut block = FileByteBlock::new(vec![0x00; 4]);
        block.set_int(0, 0x1234_5678).unwrap();
        assert_eq!(block.get_int(0).unwrap(), 0x1234_5678);
    }

    #[test]
    fn set_long_round_trips() {
        let mut block = FileByteBlock::new(vec![0x00; 8]);
        block.set_long(0, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(block.get_long(0).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn is_editable_is_always_false() {
        let block = FileByteBlock::new(vec![]);
        assert!(!block.is_editable());
    }

    #[test]
    fn get_alignment_is_always_zero() {
        let block = FileByteBlock::new(vec![]);
        assert_eq!(block.get_alignment(4), 0);
        assert_eq!(block.get_alignment(16), 0);
    }
}
