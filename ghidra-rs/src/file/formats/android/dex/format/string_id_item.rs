use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::seam_stubs::{DexHeader, StringDataItem};

/// Represents a string ID item in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.StringIDItem`.
///
/// See: https://source.android.com/devices/tech/dalvik/dex-format#string-item
#[derive(Debug, Clone)]
pub struct StringIDItem {
    string_data_offset: i32,
    string_data_item: StringDataItem,
}

impl StringIDItem {
    /// Creates a new `StringIDItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let string_data_offset = reader.read_next_int()?;

        let string_data_item = match Self::create_string_data_item(
            string_data_offset,
            reader,
            dex_header,
        ) {
            Ok(item) => item,
            Err(_) => {
                let invalid_string = format!("Invalid_String_0x{:x}", string_data_offset);
                StringDataItem::new(invalid_string)
            }
        };

        Ok(Self {
            string_data_offset,
            string_data_item,
        })
    }

    /// NOTE: For CDEX files, this value is relative to DataOffset in DexHeader
    pub fn get_string_data_offset(&self) -> i32 {
        self.string_data_offset
    }

    pub fn get_string_data_item(&self) -> &StringDataItem {
        &self.string_data_item
    }

    fn create_string_data_item(
        string_data_offset: i32,
        reader: &mut dyn BinaryReader,
        _dex_header: &DexHeader,
    ) -> io::Result<StringDataItem> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(string_data_offset as u64);

        let item = StringDataItem::new("placeholder".to_string());

        reader.set_pointer_index(old_index);

        Ok(item)
    }
}

impl StructConverter for StringIDItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "StringIDItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBinaryReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockBinaryReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, position: 0 }
        }
    }

    impl BinaryReader for MockBinaryReader {
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
            if self.is_valid_index(index) {
                Ok(self.bytes[index as usize])
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "index out of bounds"))
            }
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            if end <= self.bytes.len() {
                Ok(self.bytes[start..end].to_vec())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "range out of bounds"))
            }
        }

        fn get_byte_provider(&self) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            unimplemented!()
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(Self {
                bytes: self.bytes.clone(),
                position: new_index as usize,
            })
        }

        fn is_big_endian(&self) -> bool {
            !self.is_little_endian()
        }

        fn clone_reader(&self) -> Box<dyn BinaryReader> {
            Box::new(Self {
                bytes: self.bytes.clone(),
                position: self.position,
            })
        }

        fn as_big_endian(&self) -> Box<dyn BinaryReader> {
            let mut cloned = Self {
                bytes: self.bytes.clone(),
                position: self.position,
            };
            cloned.set_little_endian(false);
            Box::new(cloned)
        }

        fn as_little_endian(&self) -> Box<dyn BinaryReader> {
            let mut cloned = Self {
                bytes: self.bytes.clone(),
                position: self.position,
            };
            cloned.set_little_endian(true);
            Box::new(cloned)
        }

        fn is_valid_range(&self, start_index: u64, count: usize) -> bool {
            let start = start_index as usize;
            start.checked_add(count).map_or(false, |end| end <= self.bytes.len())
        }

        fn has_next(&self) -> bool {
            self.position < self.bytes.len()
        }

        fn has_next_count(&self, count: usize) -> bool {
            self.position + count <= self.bytes.len()
        }

        fn align(&mut self, align_value: u64) -> u64 {
            let old = self.position as u64;
            let remainder = old % align_value;
            if remainder != 0 {
                self.position = ((old / align_value) + 1) as usize * align_value as usize;
            }
            old
        }

        fn peek_next_byte(&self) -> io::Result<u8> {
            if self.has_next() {
                self.read_byte(self.position as u64)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no next byte"))
            }
        }

        fn peek_next_short(&self) -> io::Result<i16> {
            if self.has_next_count(2) {
                let bytes = &self.bytes[self.position..self.position + 2];
                Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no next short"))
            }
        }

        fn peek_next_int(&self) -> io::Result<i32> {
            if self.has_next_count(4) {
                let bytes = &self.bytes[self.position..self.position + 4];
                Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no next int"))
            }
        }

        fn peek_next_long(&self) -> io::Result<i64> {
            if self.has_next_count(8) {
                let bytes = &self.bytes[self.position..self.position + 8];
                Ok(i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no next long"))
            }
        }

        fn read_unsigned_byte(&self, index: u64) -> io::Result<u16> {
            self.read_byte(index).map(|b| b as u16)
        }

        fn read_short(&self, index: u64) -> io::Result<i16> {
            let byte1 = self.read_byte(index)?;
            let byte2 = self.read_byte(index + 1)?;
            Ok(i16::from_le_bytes([byte1, byte2]))
        }

        fn read_unsigned_short(&self, index: u64) -> io::Result<u32> {
            self.read_short(index).map(|s| s as u32)
        }

        fn read_int(&self, index: u64) -> io::Result<i32> {
            let bytes = self.read_byte_array(index, 4)?;
            Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

        fn read_unsigned_int(&self, index: u64) -> io::Result<u64> {
            self.read_int(index).map(|i| i as u64)
        }

        fn read_long(&self, index: u64) -> io::Result<i64> {
            let bytes = self.read_byte_array(index, 8)?;
            Ok(i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }

        fn read_value(&self, index: u64, len: usize) -> io::Result<i64> {
            let bytes = self.read_byte_array(index, len)?;
            let mut result: i64 = 0;
            for (i, &byte) in bytes.iter().enumerate() {
                result |= (byte as i64) << (i * 8);
            }
            Ok(result)
        }

        fn read_unsigned_value(&self, index: u64, len: usize) -> io::Result<u64> {
            self.read_value(index, len).map(|v| v as u64)
        }

        fn read_short_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i16>> {
            let mut result = Vec::new();
            for i in 0..n_elements {
                result.push(self.read_short(index + (i as u64 * 2))?);
            }
            Ok(result)
        }

        fn read_int_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i32>> {
            let mut result = Vec::new();
            for i in 0..n_elements {
                result.push(self.read_int(index + (i as u64 * 4))?);
            }
            Ok(result)
        }

        fn read_long_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i64>> {
            let mut result = Vec::new();
            for i in 0..n_elements {
                result.push(self.read_long(index + (i as u64 * 8))?);
            }
            Ok(result)
        }

        fn read_ascii_string(&self, _index: u64) -> io::Result<String> {
            unimplemented!()
        }

        fn read_ascii_string_fixed(&self, _index: u64, _length: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_utf8_string(&self, _index: u64) -> io::Result<String> {
            unimplemented!()
        }

        fn read_utf8_string_fixed(&self, _index: u64, _length: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_unicode_string(&self, _index: u64) -> io::Result<String> {
            unimplemented!()
        }

        fn read_unicode_string_fixed(&self, _index: u64, _char_count: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_until_null_term(&self, _index: u64, _char_len: usize) -> io::Result<Vec<u8>> {
            unimplemented!()
        }

        fn read_next_byte(&mut self) -> io::Result<u8> {
            let byte = self.read_byte(self.position as u64)?;
            self.position += 1;
            Ok(byte)
        }

        fn read_next_unsigned_byte(&mut self) -> io::Result<u16> {
            self.read_next_byte().map(|b| b as u16)
        }

        fn read_next_short(&mut self) -> io::Result<i16> {
            let val = self.read_short(self.position as u64)?;
            self.position += 2;
            Ok(val)
        }

        fn read_next_unsigned_short(&mut self) -> io::Result<u32> {
            self.read_next_short().map(|s| s as u32)
        }

        fn read_next_int(&mut self) -> io::Result<i32> {
            let val = self.read_int(self.position as u64)?;
            self.position += 4;
            Ok(val)
        }

        fn read_next_unsigned_int(&mut self) -> io::Result<u64> {
            self.read_next_int().map(|i| i as u64)
        }

        fn read_next_long(&mut self) -> io::Result<i64> {
            let val = self.read_long(self.position as u64)?;
            self.position += 8;
            Ok(val)
        }

        fn read_next_value(&mut self, len: usize) -> io::Result<i64> {
            let val = self.read_value(self.position as u64, len)?;
            self.position += len;
            Ok(val)
        }

        fn read_next_unsigned_value(&mut self, len: usize) -> io::Result<u64> {
            self.read_next_value(len).map(|v| v as u64)
        }

        fn read_next_unsigned_int_exact(&mut self) -> Result<u32, crate::app::util::bin::invalid_data_exception::InvalidDataException> {
            self.read_next_unsigned_int().map(|v| v as u32).map_err(|e| crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string()))
        }

        fn read_next_byte_array(&mut self, n_elements: usize) -> io::Result<Vec<u8>> {
            let val = self.read_byte_array(self.position as u64, n_elements)?;
            self.position += n_elements;
            Ok(val)
        }

        fn read_next_short_array(&mut self, n_elements: usize) -> io::Result<Vec<i16>> {
            let val = self.read_short_array(self.position as u64, n_elements)?;
            self.position += n_elements * 2;
            Ok(val)
        }

        fn read_next_int_array(&mut self, n_elements: usize) -> io::Result<Vec<i32>> {
            let val = self.read_int_array(self.position as u64, n_elements)?;
            self.position += n_elements * 4;
            Ok(val)
        }

        fn read_next_long_array(&mut self, n_elements: usize) -> io::Result<Vec<i64>> {
            let val = self.read_long_array(self.position as u64, n_elements)?;
            self.position += n_elements * 8;
            Ok(val)
        }

        fn read_next_ascii_string(&mut self) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next_ascii_string_fixed(&mut self, _length: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next_utf8_string(&mut self) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next_utf8_string_fixed(&mut self, _length: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next_unicode_string(&mut self) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next_unicode_string_fixed(&mut self, _char_count: usize) -> io::Result<String> {
            unimplemented!()
        }

        fn read_next<T>(&mut self, func: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T> {
            func(self)
        }

        fn read_next_var_int(
            &mut self,
            func: impl FnOnce(&mut Self) -> io::Result<i64>,
        ) -> Result<i32, crate::app::util::bin::invalid_data_exception::InvalidDataException> {
            func(self).map(|v| v as i32).map_err(|e| crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string()))
        }

        fn read_next_unsigned_var_int_exact(
            &mut self,
            func: impl FnOnce(&mut Self) -> io::Result<i64>,
        ) -> Result<u32, crate::app::util::bin::invalid_data_exception::InvalidDataException> {
            func(self).map(|v| v as u32).map_err(|e| crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string()))
        }
    }

    #[test]
    fn test_string_id_item_basic() {
        let mut reader = MockBinaryReader::new(vec![0x10, 0x00, 0x00, 0x00]);
        let dex_header = crate::file::seam_stubs::DexHeader;

        let result = StringIDItem::new(&mut reader, &dex_header);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.get_string_data_offset(), 0x10);
    }

    #[test]
    fn test_string_id_item_multiple() {
        let mut reader = MockBinaryReader::new(vec![
            0x20, 0x00, 0x00, 0x00,
            0x30, 0x00, 0x00, 0x00,
        ]);
        let dex_header = crate::file::seam_stubs::DexHeader;

        let item1 = StringIDItem::new(&mut reader, &dex_header);
        assert!(item1.is_ok());
        assert_eq!(item1.unwrap().get_string_data_offset(), 0x20);

        let item2 = StringIDItem::new(&mut reader, &dex_header);
        assert!(item2.is_ok());
        assert_eq!(item2.unwrap().get_string_data_offset(), 0x30);
    }
}
