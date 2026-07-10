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
        reader: &mut dyn BinaryReader,
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

fn is_all_zeros_until_eof(reader: &mut dyn BinaryReader) -> io::Result<bool> {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    /// Minimal [`BinaryReader`] impl backed by an in-memory [`VecProvider`], used only by
    /// these tests.
    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn reads_standard_32bit_length() {
        let mut r = MockReader::new(vec![0x10, 0x00, 0x00, 0x00], true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap().unwrap();
        assert_eq!(v.length(), 0x10);
        assert_eq!(v.int_size(), 4);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_64bit_dwarf_format_length() {
        let mut data = vec![0xff, 0xff, 0xff, 0xff];
        data.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let mut r = MockReader::new(data, true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap().unwrap();
        assert_eq!(v.length(), 0x1_0000_0000);
        assert_eq!(v.int_size(), 8);
        assert_eq!(r.get_pointer_index(), 12);
    }

    #[test]
    fn rejects_reserved_length_values() {
        let mut r = MockReader::new(vec![0xf0, 0xff, 0xff, 0xff], true);
        let err = DWARFLengthValue::read(&mut r, 4).unwrap_err();
        assert!(err.to_string().contains("Reserved DWARF length value"));
    }

    #[test]
    fn zero_length_followed_by_all_zeros_is_padding() {
        let mut r = MockReader::new(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00], true);
        let v = DWARFLengthValue::read(&mut r, 4).unwrap();
        assert!(v.is_none());
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn zero_length_with_no_trailing_data_is_invalid() {
        // A zero length followed by non-zero (non-padding) data is not trailing
        // padding, so `read` must reject it with the "Invalid DWARF length 0" error
        // rather than treating it as an all-zeros-to-EOF pad.
        let mut r = MockReader::new(vec![0x00, 0x00, 0x00, 0x00, 0x01], true);
        let err = DWARFLengthValue::read(&mut r, 4).unwrap_err();
        assert!(err.to_string().contains("Invalid DWARF length 0"));
    }

    #[test]
    fn zero_length_big_endian_mips64_special_case() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&0x2Au32.to_be_bytes());
        let mut r = MockReader::new(data, false);
        let v = DWARFLengthValue::read(&mut r, 8).unwrap().unwrap();
        assert_eq!(v.length(), 0x2A);
        assert_eq!(v.int_size(), 8);
        assert_eq!(r.get_pointer_index(), 8);
    }
}
