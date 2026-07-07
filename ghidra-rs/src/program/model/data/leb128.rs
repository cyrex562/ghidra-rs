use std::io::{self, Read, Write};

/// Logic for reading/writing LEB128 values.
///
/// LEB128 is a variable length integer encoding that uses 7 bits per byte, with the high bit
/// being reserved as a continuation flag, with the least significant bytes coming first
/// (**L**ittle **E**ndian **B**ase **128**).
///
/// This implementation only supports reading values that decode to at most 64 bits (to fit
/// into a `i64`).
///
/// When reading a value, you must already know if it was written as a signed or unsigned value
/// to be able to decode it correctly.
pub struct Leb128;

impl Leb128 {
    /// Max number of bytes that is supported by the deserialization code.
    pub const MAX_SUPPORTED_LENGTH: usize = 10;

    /// Reads an unsigned LEB128 variable length integer from the stream.
    pub fn unsigned<R: Read>(is: &mut R) -> io::Result<i64> {
        Self::read(is, false)
    }

    /// Reads a signed LEB128 variable length integer from the stream.
    pub fn signed<R: Read>(is: &mut R) -> io::Result<i64> {
        Self::read(is, true)
    }

    /// Reads a LEB128 number from the stream and returns it as a 64 bit int.
    ///
    /// Large unsigned integers that use all 64 bits are returned in a native `i64`,
    /// which is signed. It is up to the caller to treat the value as unsigned.
    ///
    /// Large integers that use more than 64 bits will cause an error to be returned.
    pub fn read<R: Read>(is: &mut R, is_signed: bool) -> io::Result<i64> {
        let mut next_byte: i32;
        let mut shift: u32 = 0;
        let mut value: i64 = 0;
        loop {
            let mut byte_buf = [0u8; 1];
            if is.read(&mut byte_buf)? == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            next_byte = byte_buf[0] as i32;

            if shift == 70 || (!is_signed && shift == 63 && next_byte > 1) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported LEB128 value, too large to fit in 64bit variable",
                ));
            }

            value |= ((next_byte & 0x7F) as i64) << shift;
            shift += 7;

            if (next_byte & 0x80) == 0 {
                break;
            }
        }
        if is_signed && (shift as usize) < 64 && (next_byte & 0x40) != 0 {
            // 0x40 is the new 'high' sign bit since 0x80 is the continuation flag.
            // bitwise-or in all the sign-extension bits we need for the value
            value |= -1i64 << shift;
        }

        Ok(value)
    }

    /// Returns the length of the variable length LEB128 value.
    ///
    /// Returns the length of the LEB128 value, or -1 if the end of the value is not found.
    pub fn get_length<R: Read>(is: &mut R) -> io::Result<i32> {
        let mut length: i32 = 0;
        let mut byte_buf = [0u8; 1];
        while (length as usize) < Self::MAX_SUPPORTED_LENGTH {
            if is.read(&mut byte_buf)? == 0 {
                return Ok(-1);
            }
            length += 1;
            if (byte_buf[0] & 0x80) == 0 {
                return Ok(length);
            }
        }
        Ok(-1)
    }

    /// Decodes a LEB128 number from a byte array and returns it as an `i64`.
    ///
    /// See [`Leb128::read`].
    pub fn decode(bytes: &[u8], offset: usize, is_signed: bool) -> io::Result<i64> {
        if offset > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "offset out of range",
            ));
        }
        let mut slice = &bytes[offset..];
        Self::read(&mut slice, is_signed)
    }

    /// Encodes a value into a sequence of LEB128 bytes.
    pub fn encode(value: i64, is_signed: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MAX_SUPPORTED_LENGTH);
        // Writing to a Vec<u8> cannot fail.
        Self::write(value, &mut buf, is_signed).expect("writing to Vec<u8> cannot fail");
        buf
    }

    /// Writes a value to the stream as a sequence of LEB128 bytes.
    ///
    /// Returns the count of bytes written to the stream.
    pub fn write<W: Write>(value: i64, os: &mut W, is_signed: bool) -> io::Result<i32> {
        if is_signed {
            Self::write_signed(value, os)
        } else {
            Self::write_unsigned(value, os)
        }
    }

    /// Writes a value to the stream as a sequence of unsigned LEB128 bytes.
    ///
    /// Returns the count of bytes written to the stream.
    pub fn write_unsigned<W: Write>(value: i64, os: &mut W) -> io::Result<i32> {
        let mut value = value as u64;
        let mut size = 0;
        loop {
            let mut b = (value & 0x7f) as u8;
            value >>= 7;
            let done = value == 0;
            if !done {
                b |= 0x80;
            }
            os.write_all(&[b])?;
            size += 1;
            if done {
                break;
            }
        }
        Ok(size)
    }

    /// Writes a value to the stream as a sequence of signed LEB128 bytes.
    ///
    /// Returns the count of bytes written to the stream.
    pub fn write_signed<W: Write>(value: i64, os: &mut W) -> io::Result<i32> {
        let mut value = value;
        let ending_val: i64 = if value < 0 { -1 } else { 0 };
        let hi_bit: u8 = if value < 0 { 0x40 } else { 0 };
        let mut size = 0;
        loop {
            let b_raw = (value & 0x7f) as u8;
            value >>= 7;
            let more = value != ending_val || ((b_raw & 0x40) != hi_bit);
            let mut b = b_raw;
            if more {
                b |= 0x80;
            }
            os.write_all(&[b])?;
            size += 1;
            if !more {
                break;
            }
        }
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_roundtrip_small() {
        for &v in &[0i64, 1, 2, 63, 64, 127, 128, 129, 300, 16384] {
            let encoded = Leb128::encode(v, false);
            let decoded = Leb128::decode(&encoded, 0, false).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn test_signed_roundtrip() {
        for &v in &[0i64, 1, -1, 63, -63, 64, -64, 127, -128, 300, -300, i64::MAX, i64::MIN] {
            let encoded = Leb128::encode(v, true);
            let decoded = Leb128::decode(&encoded, 0, true).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn test_unsigned_max_u64_value() {
        let v = -1i64; // all bits set, treated as unsigned u64::MAX
        let encoded = Leb128::encode(v, false);
        let decoded = Leb128::decode(&encoded, 0, false).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn test_known_unsigned_encoding() {
        // 624485 = 0x98765 -> LEB128 unsigned: 0xE5 0x8E 0x26
        let encoded = Leb128::encode(624485, false);
        assert_eq!(encoded, vec![0xE5, 0x8E, 0x26]);
        let decoded = Leb128::decode(&encoded, 0, false).unwrap();
        assert_eq!(decoded, 624485);
    }

    #[test]
    fn test_known_signed_encoding() {
        // -624485 -> LEB128 signed: 0x9B 0xF1 0x59
        let encoded = Leb128::encode(-624485, true);
        assert_eq!(encoded, vec![0x9B, 0xF1, 0x59]);
        let decoded = Leb128::decode(&encoded, 0, true).unwrap();
        assert_eq!(decoded, -624485);
    }

    #[test]
    fn test_get_length() {
        let encoded = Leb128::encode(624485, false);
        let mut slice = encoded.as_slice();
        let length = Leb128::get_length(&mut slice).unwrap();
        assert_eq!(length, encoded.len() as i32);
    }

    #[test]
    fn test_get_length_eof_returns_negative_one() {
        // continuation bit set but no following byte
        let data = [0x80u8];
        let mut slice = &data[..];
        let length = Leb128::get_length(&mut slice).unwrap();
        assert_eq!(length, -1);
    }

    #[test]
    fn test_read_eof_errors() {
        let data: [u8; 0] = [];
        let mut slice = &data[..];
        let result = Leb128::read(&mut slice, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_too_long_errors() {
        // 11 bytes all with continuation bit set - exceeds MAX_SUPPORTED_LENGTH
        let data = [0xFFu8; 11];
        let mut slice = &data[..];
        let result = Leb128::read(&mut slice, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_write_read_via_stream() {
        let mut buf: Vec<u8> = Vec::new();
        let count = Leb128::write(123456789, &mut buf, true).unwrap();
        assert_eq!(count as usize, buf.len());
        let mut slice = buf.as_slice();
        let value = Leb128::read(&mut slice, true).unwrap();
        assert_eq!(value, 123456789);
    }
}
