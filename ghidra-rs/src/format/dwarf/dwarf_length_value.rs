use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// A tuple of length (of a thing in a dwarf stream) and size of integers used in the dwarf
/// section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFLengthValue {
    length: i64,
    int_size: i32,
}

impl DWARFLengthValue {
    /// Returns the length of the following item.
    pub fn length(&self) -> i64 {
        self.length
    }

    /// Returns the size of integers used in the following item.
    pub fn int_size(&self) -> i32 {
        self.int_size
    }

    /// Reads a variable-length length value from the stream.
    ///
    /// The length value will either occupy 4 (int32) or 12 bytes (int32 flag + int64 length) and
    /// as a side-effect signals the size integer values occupy.
    ///
    /// Returns `Ok(None)` if the stream was just zero-padded data.
    pub fn read(
        reader: &mut BinaryReader,
        default_pointer_size: i32,
    ) -> io::Result<Option<DWARFLengthValue>> {
        let start_offset = reader.get_pointer_index();
        let mut length = reader.read_next_unsigned_int()? as i64;
        let mut int_size = 4;

        if length == 0xffff_ffff_i64 {
            // Length of 0xffffffff implies 64-bit DWARF format
            // Mostly untested as there is no easy way to force the compiler
            // to generate this
            length = reader.read_next_long()?;
            int_size = 8;
        } else if length >= 0xffff_fff0_i64 {
            // Length of 0xfffffff0 or greater is reserved for DWARF
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Reserved DWARF length value: {length:x}. Unknown extension."),
            ));
        } else if length == 0 {
            if is_all_zeros_until_eof(reader)? {
                // hack to handle trailing padding at end of section.  (similar to the check for
                // unexpectedTerminator in readDIEs(), when padding occurs inside the bounds
                // of the compile unit's range after the end of the root DIE's children)
                let len = reader.length()?;
                reader.set_pointer_index(len);
                return Ok(None);
            }

            // Test for special case of weird BE MIPS 64bit length value.
            // Instead of following DWARF std (a few lines above with length == MAX_INT),
            // it writes a raw 64bit long (BE). The upper 32 bits (already read as length) will
            // always be 0 since super-large binaries from that system weren't really possible.
            // The next 32 bits will be the remainder of the value.
            if reader.is_big_endian() && default_pointer_size == 8 {
                length = reader.read_next_unsigned_int()? as i64;
                int_size = 8;
            }

            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid DWARF length 0 at {start_offset:#x}"),
                ));
            }
        }

        Ok(Some(DWARFLengthValue { length, int_size }))
    }
}

fn is_all_zeros_until_eof(reader: &mut BinaryReader) -> io::Result<bool> {
    let mut clone = reader.clone_reader();
    while clone.has_next() {
        if clone.read_next_byte()? != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_standard_32bit_length() {
        let mut r = BinaryReader::from_bytes(vec![0x10, 0x00, 0x00, 0x00], true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap().unwrap();
        assert_eq!(v.length(), 0x10);
        assert_eq!(v.int_size(), 4);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_64bit_dwarf_format_length() {
        let mut data = vec![0xff, 0xff, 0xff, 0xff];
        data.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let mut r = BinaryReader::from_bytes(data, true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap().unwrap();
        assert_eq!(v.length(), 0x1_0000_0000);
        assert_eq!(v.int_size(), 8);
        assert_eq!(r.get_pointer_index(), 12);
    }

    #[test]
    fn rejects_reserved_length_values() {
        let mut r = BinaryReader::from_bytes(vec![0xf0, 0xff, 0xff, 0xff], true);
        let err = DWARFLengthValue::read(&mut r, 4).unwrap_err();
        assert!(err.to_string().contains("Reserved DWARF length value"));
    }

    #[test]
    fn zero_length_followed_by_all_zeros_is_padding() {
        let mut r = BinaryReader::from_bytes(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00], true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap();
        assert!(v.is_none());
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn zero_length_with_no_trailing_data_is_invalid() {
        // A zero length followed by non-zero (non-padding) data is not trailing
        // padding, so `read` must reject it with the "Invalid DWARF length 0" error
        // rather than treating it as an all-zeros-to-EOF pad.
        let mut r = BinaryReader::from_bytes(vec![0x00, 0x00, 0x00, 0x00, 0x01], true);
        let err = DWARFLengthValue::read(&mut r, 4).unwrap_err();
        assert!(err.to_string().contains("Invalid DWARF length 0"));
    }

    #[test]
    fn zero_length_big_endian_mips64_special_case() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&0x2Au32.to_be_bytes());
        let mut r = BinaryReader::from_bytes(data, false);
        let v = DWARFLengthValue::read(&mut r, 8).unwrap().unwrap();
        assert_eq!(v.length(), 0x2A);
        assert_eq!(v.int_size(), 8);
        assert_eq!(r.get_pointer_index(), 8);
    }
}
