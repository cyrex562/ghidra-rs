use std::fmt;
use std::io::{self, Read};

use crate::app::util::bin::binary_reader::LegacyBinaryReader;
use crate::app::util::bin::invalid_data_exception::InvalidDataException;
use crate::program::model::data::leb128::Leb128;

/// Adapts a [`BinaryReader`] into a [`Read`] stream, advancing the reader's pointer index one
/// byte at a time. Used to feed [`Leb128::read`], which only knows how to read from a stream.
struct ReaderAdapter<'a> {
    reader: &'a mut dyn LegacyBinaryReader,
}

impl<'a> Read for ReaderAdapter<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.reader.read_next_byte()?;
        Ok(1)
    }
}

/// Holds the result of reading a [`Leb128`] value, along with size and position metadata.
///
/// Mirrors `ghidra.app.util.bin.LEB128Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LEB128Info {
    offset: u64,
    value: i64,
    byte_length: i32,
}

impl LEB128Info {
    /// Reads an unsigned LEB128 value from `reader` and returns a `LEB128Info` instance
    /// that contains the value along with size and position metadata.
    pub fn unsigned(reader: &mut dyn LegacyBinaryReader) -> io::Result<Self> {
        Self::read_value(reader, false)
    }

    /// Reads a signed LEB128 value from `reader` and returns a `LEB128Info` instance
    /// that contains the value along with size and position metadata.
    pub fn signed(reader: &mut dyn LegacyBinaryReader) -> io::Result<Self> {
        Self::read_value(reader, true)
    }

    /// Reads a LEB128 value from `reader` and returns a `LEB128Info` instance that contains the
    /// value along with size and position metadata.
    pub fn read_value(reader: &mut dyn LegacyBinaryReader, is_signed: bool) -> io::Result<Self> {
        let offset = reader.get_pointer_index();
        let value = Leb128::read(&mut ReaderAdapter { reader }, is_signed)?;
        let byte_length = (reader.get_pointer_index() - offset) as i32;
        Ok(Self { offset, value, byte_length })
    }

    /// Returns the value as an unsigned int32. If the actual value is outside the positive
    /// range of a 32 bit int (ie. `0..=i32::MAX`), an error is returned.
    pub fn as_u_int32(&self) -> Result<u32, InvalidDataException> {
        if self.value < 0 || self.value > i32::MAX as i64 {
            return Err(InvalidDataException::with_message(format!(
                "Value out of range for positive java 32 bit unsigned int: {}",
                self.value as u64
            )));
        }
        Ok(self.value as u32)
    }

    /// Returns the value as a signed int32. If the actual value is outside the range of a 32
    /// bit int (ie. `i32::MIN..=i32::MAX`), an error is returned.
    pub fn as_int32(&self) -> Result<i32, InvalidDataException> {
        if self.value < i32::MIN as i64 || self.value > i32::MAX as i64 {
            return Err(InvalidDataException::with_message(format!(
                "Value out of range for java 32 bit signed int: {}",
                self.value
            )));
        }
        Ok(self.value as i32)
    }

    /// Returns the value as a 64 bit `i64`. Interpreting the signed-ness of the value depends
    /// on whether [`LEB128Info::signed`] or [`LEB128Info::unsigned`] was used to read it.
    pub fn as_long(&self) -> i64 {
        self.value
    }

    /// Returns the offset of the LEB128 value in the stream it was read from.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// Returns the number of bytes that were used to store the LEB128 value in the stream it
    /// was read from.
    pub fn get_length(&self) -> i32 {
        self.byte_length
    }
}

impl fmt::Display for LEB128Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LEB128: value: {}, offset: {}, byteLength: {}",
            self.value, self.offset, self.byte_length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;


    #[test]
    fn test_unsigned_read_value() {
        // 624485 = 0x98765 -> LEB128 unsigned: 0xE5 0x8E 0x26
        let mut reader = BinaryReader::from_bytes(vec![0xE5, 0x8E, 0x26, 0xFF], true);
        let info = LEB128Info::unsigned(&mut reader).unwrap();
        assert_eq!(info.as_long(), 624485);
        assert_eq!(info.get_offset(), 0);
        assert_eq!(info.get_length(), 3);
        assert_eq!(reader.get_pointer_index(), 3);
    }

    #[test]
    fn test_signed_read_value() {
        // -624485 -> LEB128 signed: 0x9B 0xF1 0x59
        let mut reader = BinaryReader::from_bytes(vec![0x9B, 0xF1, 0x59], true);
        let info = LEB128Info::signed(&mut reader).unwrap();
        assert_eq!(info.as_long(), -624485);
        assert_eq!(info.get_length(), 3);
    }

    #[test]
    fn test_offset_reflects_reader_position() {
        let mut reader = BinaryReader::from_bytes(vec![0x00, 0xE5, 0x8E, 0x26], true);
        reader.set_pointer_index(1);
        let info = LEB128Info::unsigned(&mut reader).unwrap();
        assert_eq!(info.get_offset(), 1);
        assert_eq!(info.as_long(), 624485);
    }

    #[test]
    fn test_as_u_int32_in_range() {
        let mut reader = BinaryReader::from_bytes(vec![0x01], true);
        let info = LEB128Info::unsigned(&mut reader).unwrap();
        assert_eq!(info.as_u_int32().unwrap(), 1);
    }

    #[test]
    fn test_as_u_int32_out_of_range_for_negative_value() {
        let mut reader = BinaryReader::from_bytes(vec![0x7F], true);
        let info = LEB128Info::signed(&mut reader).unwrap();
        assert_eq!(info.as_long(), -1);
        assert!(info.as_u_int32().is_err());
    }

    #[test]
    fn test_as_int32_in_range() {
        let mut reader = BinaryReader::from_bytes(vec![0x7F], true);
        let info = LEB128Info::signed(&mut reader).unwrap();
        assert_eq!(info.as_int32().unwrap(), -1);
    }

    #[test]
    fn test_as_int32_out_of_range() {
        // A value larger than i32::MAX encoded as unsigned LEB128.
        let encoded = Leb128::encode(i32::MAX as i64 + 1, false);
        let mut reader = BinaryReader::from_bytes(encoded, true);
        let info = LEB128Info::unsigned(&mut reader).unwrap();
        assert!(info.as_int32().is_err());
    }

    #[test]
    fn test_display() {
        let mut reader = BinaryReader::from_bytes(vec![0x01], true);
        let info = LEB128Info::unsigned(&mut reader).unwrap();
        assert_eq!(format!("{}", info), "LEB128: value: 1, offset: 0, byteLength: 1");
    }
}
