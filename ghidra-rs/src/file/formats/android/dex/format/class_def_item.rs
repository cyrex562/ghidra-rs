use std::fmt::Write as _;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::access_flags::AccessFlags;
use crate::file::seam_stubs::{
    AnnotationsDirectoryItem, ClassDataItem, DexHeader, DexUtil, EncodedArrayItem, TypeList,
};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Represents a class definition in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.ClassDefItem`.
///
/// See: https://source.android.com/docs/core/runtime/dex-format#class-def-item
#[derive(Debug, Clone)]
pub struct ClassDefItem {
    class_index: i32,
    access_flags: i32,
    super_class_index: i32,
    interfaces_offset: i32,
    source_file_index: i32,
    annotations_offset: i32,
    class_data_offset: i32,
    static_values_offset: i32,

    interfaces: Option<TypeList>,
    annotations_directory_item: Option<AnnotationsDirectoryItem>,
    class_data_item: Option<ClassDataItem>,
    static_values: Option<EncodedArrayItem>,
}

impl ClassDefItem {
    /// Creates a new `ClassDefItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut dyn BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let class_index = reader.read_next_int()?;
        let access_flags = reader.read_next_int()?;
        let super_class_index = reader.read_next_int()?;
        let interfaces_offset = reader.read_next_int()?;
        let source_file_index = reader.read_next_int()?;
        let annotations_offset = reader.read_next_int()?;
        let class_data_offset = reader.read_next_int()?;
        let static_values_offset = reader.read_next_int()?;

        let mut interfaces = None;
        if interfaces_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(interfaces_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create a TypeList here, but it's a stub.
                // Once TypeList is ported, this should instantiate it.
                interfaces = Some(TypeList);
            }
            reader.set_pointer_index(old_index);
        }

        let mut annotations_directory_item = None;
        if annotations_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(annotations_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create an AnnotationsDirectoryItem here, but it's a stub.
                // Once AnnotationsDirectoryItem is ported, this should instantiate it.
                annotations_directory_item = Some(AnnotationsDirectoryItem);
            }
            reader.set_pointer_index(old_index);
        }

        let mut class_data_item = None;
        if class_data_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(class_data_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create a ClassDataItem here, but it's a stub.
                // Once ClassDataItem is ported, this should instantiate it.
                class_data_item = Some(ClassDataItem);
            }
            reader.set_pointer_index(old_index);
        }

        let mut static_values = None;
        if static_values_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(static_values_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create an EncodedArrayItem here, but it's a stub.
                // Once EncodedArrayItem is ported, this should instantiate it.
                static_values = Some(EncodedArrayItem);
            }
            reader.set_pointer_index(old_index);
        }

        Ok(Self {
            class_index,
            access_flags,
            super_class_index,
            interfaces_offset,
            source_file_index,
            annotations_offset,
            class_data_offset,
            static_values_offset,
            interfaces,
            annotations_directory_item,
            class_data_item,
            static_values,
        })
    }

    pub fn get_class_index(&self) -> i32 {
        self.class_index
    }

    pub fn get_access_flags(&self) -> i32 {
        self.access_flags
    }

    pub fn get_super_class_index(&self) -> i32 {
        self.super_class_index
    }

    pub fn get_interfaces_offset(&self) -> i32 {
        self.interfaces_offset
    }

    pub fn get_source_file_index(&self) -> i32 {
        self.source_file_index
    }

    /// NOTE: For CDEX files, this value is relative to `DataOffset` in `DexHeader`.
    pub fn get_annotations_offset(&self) -> i32 {
        self.annotations_offset
    }

    pub fn get_class_data_offset(&self) -> i32 {
        self.class_data_offset
    }

    pub fn get_static_values_offset(&self) -> i32 {
        self.static_values_offset
    }

    pub fn get_interfaces(&self) -> Option<&TypeList> {
        self.interfaces.as_ref()
    }

    pub fn get_annotations_directory_item(&self) -> Option<&AnnotationsDirectoryItem> {
        self.annotations_directory_item.as_ref()
    }

    pub fn get_class_data_item(&self) -> Option<&ClassDataItem> {
        self.class_data_item.as_ref()
    }

    pub fn get_static_values(&self) -> Option<&EncodedArrayItem> {
        self.static_values.as_ref()
    }

    /// Formats this class definition using `header` for name/string lookups.
    ///
    /// Mirrors `ClassDefItem.toString(DexHeader, int, TaskMonitor)`. Pass `-1` for `index` to
    /// omit the "Class Index" line.
    pub fn format(
        &self,
        header: &DexHeader,
        index: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, CancelledException> {
        let mut builder = String::new();
        if index != -1 {
            let _ = writeln!(builder, "Class Index: 0x{:x}", index);
        }
        let _ = writeln!(
            builder,
            "Class: {}",
            DexUtil::convert_type_index_to_string(header, self.get_class_index())
        );
        let _ = writeln!(
            builder,
            "Class Access Flags:\n{}",
            AccessFlags::to_string(self.get_access_flags() as u32)
        );
        let _ = writeln!(
            builder,
            "Superclass: {}",
            DexUtil::convert_type_index_to_string(header, self.get_super_class_index())
        );

        if self.get_interfaces_offset() > 0 {
            builder.push_str("Interfaces: \n");
            if let Some(interfaces) = self.get_interfaces() {
                for item in interfaces.get_items() {
                    monitor.check_cancelled()?;
                    let _ = writeln!(
                        builder,
                        "\t{}",
                        DexUtil::convert_type_index_to_string(header, item.get_type() as i32)
                    );
                }
            }
        }

        if self.get_source_file_index() > 0 {
            let _ = writeln!(
                builder,
                "Source File: {}",
                DexUtil::convert_to_string(header, self.get_source_file_index())
            );
        }

        Ok(builder)
    }
}

impl StructConverter for ClassDefItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        // Would call StructConverterUtil.toDataType(ClassDefItem.class), then set the category
        // path to "/dex". Since StructConverterUtil is a stub, we return an error.
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "ClassDefItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

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

        fn get_byte_provider(&self) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
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
            let aligned = ((self.position as u64 + align_value - 1) / align_value) * align_value;
            self.position = aligned as usize;
            old
        }

        fn peek_next_byte(&self) -> io::Result<u8> {
            if self.position < self.bytes.len() {
                Ok(self.bytes[self.position])
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more data"))
            }
        }

        fn peek_next_short(&self) -> io::Result<i16> {
            if self.position + 1 < self.bytes.len() {
                let bytes = [self.bytes[self.position], self.bytes[self.position + 1]];
                Ok(if self.is_little_endian() {
                    i16::from_le_bytes(bytes)
                } else {
                    i16::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"))
            }
        }

        fn peek_next_int(&self) -> io::Result<i32> {
            if self.position + 3 < self.bytes.len() {
                let bytes = [
                    self.bytes[self.position],
                    self.bytes[self.position + 1],
                    self.bytes[self.position + 2],
                    self.bytes[self.position + 3],
                ];
                Ok(if self.is_little_endian() {
                    i32::from_le_bytes(bytes)
                } else {
                    i32::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"))
            }
        }

        fn peek_next_long(&self) -> io::Result<i64> {
            if self.position + 7 < self.bytes.len() {
                let bytes = [
                    self.bytes[self.position],
                    self.bytes[self.position + 1],
                    self.bytes[self.position + 2],
                    self.bytes[self.position + 3],
                    self.bytes[self.position + 4],
                    self.bytes[self.position + 5],
                    self.bytes[self.position + 6],
                    self.bytes[self.position + 7],
                ];
                Ok(if self.is_little_endian() {
                    i64::from_le_bytes(bytes)
                } else {
                    i64::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"))
            }
        }

        fn read_unsigned_byte(&self, index: u64) -> io::Result<u16> {
            self.read_byte(index).map(|b| b as u16)
        }

        fn read_short(&self, index: u64) -> io::Result<i16> {
            let i = index as usize;
            if i + 1 < self.bytes.len() {
                let bytes = [self.bytes[i], self.bytes[i + 1]];
                Ok(if self.is_little_endian() {
                    i16::from_le_bytes(bytes)
                } else {
                    i16::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "out of bounds"))
            }
        }

        fn read_unsigned_short(&self, index: u64) -> io::Result<u32> {
            self.read_short(index).map(|s| s as u32)
        }

        fn read_int(&self, index: u64) -> io::Result<i32> {
            let i = index as usize;
            if i + 3 < self.bytes.len() {
                let bytes = [
                    self.bytes[i],
                    self.bytes[i + 1],
                    self.bytes[i + 2],
                    self.bytes[i + 3],
                ];
                Ok(if self.is_little_endian() {
                    i32::from_le_bytes(bytes)
                } else {
                    i32::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "out of bounds"))
            }
        }

        fn read_unsigned_int(&self, index: u64) -> io::Result<u64> {
            self.read_int(index).map(|i| i as u64)
        }

        fn read_long(&self, index: u64) -> io::Result<i64> {
            let i = index as usize;
            if i + 7 < self.bytes.len() {
                let bytes = [
                    self.bytes[i],
                    self.bytes[i + 1],
                    self.bytes[i + 2],
                    self.bytes[i + 3],
                    self.bytes[i + 4],
                    self.bytes[i + 5],
                    self.bytes[i + 6],
                    self.bytes[i + 7],
                ];
                Ok(if self.is_little_endian() {
                    i64::from_le_bytes(bytes)
                } else {
                    i64::from_be_bytes(bytes)
                })
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "out of bounds"))
            }
        }

        fn read_value(&self, index: u64, len: usize) -> io::Result<i64> {
            let i = index as usize;
            if i + len > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "out of bounds"));
            }
            let mut result = 0i64;
            if self.is_little_endian() {
                for (j, &byte) in self.bytes[i..i + len].iter().enumerate() {
                    result |= (byte as i64) << (j * 8);
                }
            } else {
                for (j, &byte) in self.bytes[i..i + len].iter().enumerate() {
                    result |= (byte as i64) << ((len - 1 - j) * 8);
                }
            }
            Ok(result)
        }

        fn read_unsigned_value(&self, index: u64, len: usize) -> io::Result<u64> {
            self.read_value(index, len).map(|v| v as u64)
        }

        fn read_short_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i16>> {
            let mut result = Vec::with_capacity(n_elements);
            for i in 0..n_elements {
                result.push(self.read_short(index + (i as u64) * 2)?);
            }
            Ok(result)
        }

        fn read_int_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i32>> {
            let mut result = Vec::with_capacity(n_elements);
            for i in 0..n_elements {
                result.push(self.read_int(index + (i as u64) * 4)?);
            }
            Ok(result)
        }

        fn read_long_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i64>> {
            let mut result = Vec::with_capacity(n_elements);
            for i in 0..n_elements {
                result.push(self.read_long(index + (i as u64) * 8)?);
            }
            Ok(result)
        }

        fn read_ascii_string(&self, index: u64) -> io::Result<String> {
            let mut end = index as usize;
            while end < self.bytes.len() && self.bytes[end] != 0 {
                end += 1;
            }
            Ok(String::from_utf8_lossy(&self.bytes[index as usize..end]).into_owned())
        }

        fn read_ascii_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
            let start = index as usize;
            let end = start + length;
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "out of bounds"));
            }
            Ok(String::from_utf8_lossy(&self.bytes[start..end]).into_owned())
        }

        fn read_utf8_string(&self, index: u64) -> io::Result<String> {
            self.read_ascii_string(index)
        }

        fn read_utf8_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
            self.read_ascii_string_fixed(index, length)
        }

        fn read_unicode_string(&self, index: u64) -> io::Result<String> {
            self.read_ascii_string(index)
        }

        fn read_unicode_string_fixed(&self, index: u64, char_count: usize) -> io::Result<String> {
            self.read_ascii_string_fixed(index, char_count * 2)
        }

        fn read_until_null_term(&self, index: u64, char_len: usize) -> io::Result<Vec<u8>> {
            let mut result = Vec::new();
            let mut pos = index as usize;
            loop {
                if pos + char_len > self.bytes.len() {
                    break;
                }
                let chunk: Vec<u8> = self.bytes[pos..pos + char_len].to_vec();
                if chunk.iter().all(|&b| b == 0) {
                    break;
                }
                result.extend_from_slice(&chunk);
                pos += char_len;
            }
            Ok(result)
        }

        fn read_next_byte(&mut self) -> io::Result<u8> {
            let result = self.read_byte(self.position as u64)?;
            self.position += 1;
            Ok(result)
        }

        fn read_next_unsigned_byte(&mut self) -> io::Result<u16> {
            let result = self.read_unsigned_byte(self.position as u64)?;
            self.position += 1;
            Ok(result)
        }

        fn read_next_short(&mut self) -> io::Result<i16> {
            let result = self.read_short(self.position as u64)?;
            self.position += 2;
            Ok(result)
        }

        fn read_next_unsigned_short(&mut self) -> io::Result<u32> {
            let result = self.read_unsigned_short(self.position as u64)?;
            self.position += 2;
            Ok(result)
        }

        fn read_next_int(&mut self) -> io::Result<i32> {
            let result = self.read_int(self.position as u64)?;
            self.position += 4;
            Ok(result)
        }

        fn read_next_unsigned_int(&mut self) -> io::Result<u64> {
            let result = self.read_unsigned_int(self.position as u64)?;
            self.position += 4;
            Ok(result)
        }

        fn read_next_long(&mut self) -> io::Result<i64> {
            let result = self.read_long(self.position as u64)?;
            self.position += 8;
            Ok(result)
        }

        fn read_next_value(&mut self, len: usize) -> io::Result<i64> {
            let result = self.read_value(self.position as u64, len)?;
            self.position += len;
            Ok(result)
        }

        fn read_next_unsigned_value(&mut self, len: usize) -> io::Result<u64> {
            let result = self.read_unsigned_value(self.position as u64, len)?;
            self.position += len;
            Ok(result)
        }

        fn read_next_unsigned_int_exact(&mut self) -> Result<u32, crate::app::util::bin::invalid_data_exception::InvalidDataException> {
            self.read_next_unsigned_int().map(|u| u as u32).map_err(|e| {
                crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string())
            })
        }

        fn read_next_byte_array(&mut self, n_elements: usize) -> io::Result<Vec<u8>> {
            let result = self.read_byte_array(self.position as u64, n_elements)?;
            self.position += n_elements;
            Ok(result)
        }

        fn read_next_short_array(&mut self, n_elements: usize) -> io::Result<Vec<i16>> {
            let result = self.read_short_array(self.position as u64, n_elements)?;
            self.position += n_elements * 2;
            Ok(result)
        }

        fn read_next_int_array(&mut self, n_elements: usize) -> io::Result<Vec<i32>> {
            let result = self.read_int_array(self.position as u64, n_elements)?;
            self.position += n_elements * 4;
            Ok(result)
        }

        fn read_next_long_array(&mut self, n_elements: usize) -> io::Result<Vec<i64>> {
            let result = self.read_long_array(self.position as u64, n_elements)?;
            self.position += n_elements * 8;
            Ok(result)
        }

        fn read_next_ascii_string(&mut self) -> io::Result<String> {
            let result = self.read_ascii_string(self.position as u64)?;
            self.position += result.len() + 1;
            Ok(result)
        }

        fn read_next_ascii_string_fixed(&mut self, length: usize) -> io::Result<String> {
            let result = self.read_ascii_string_fixed(self.position as u64, length)?;
            self.position += length;
            Ok(result)
        }

        fn read_next_utf8_string(&mut self) -> io::Result<String> {
            self.read_next_ascii_string()
        }

        fn read_next_utf8_string_fixed(&mut self, length: usize) -> io::Result<String> {
            self.read_next_ascii_string_fixed(length)
        }

        fn read_next_unicode_string(&mut self) -> io::Result<String> {
            self.read_next_ascii_string()
        }

        fn read_next_unicode_string_fixed(&mut self, char_count: usize) -> io::Result<String> {
            self.read_next_ascii_string_fixed(char_count * 2)
        }

        fn read_next<T>(&mut self, func: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T>
        where
            Self: Sized,
        {
            func(self)
        }

        fn read_next_var_int(
            &mut self,
            func: impl FnOnce(&mut Self) -> io::Result<i64>,
        ) -> Result<i32, crate::app::util::bin::invalid_data_exception::InvalidDataException>
        where
            Self: Sized,
        {
            func(self)
                .map(|v| v as i32)
                .map_err(|e| crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string()))
        }

        fn read_next_unsigned_var_int_exact(
            &mut self,
            func: impl FnOnce(&mut Self) -> io::Result<i64>,
        ) -> Result<u32, crate::app::util::bin::invalid_data_exception::InvalidDataException>
        where
            Self: Sized,
        {
            func(self)
                .map(|v| v as u32)
                .map_err(|e| crate::app::util::bin::invalid_data_exception::InvalidDataException::with_message(e.to_string()))
        }
    }

    fn header_bytes(
        class_index: i32,
        access_flags: i32,
        super_class_index: i32,
        interfaces_offset: i32,
        source_file_index: i32,
        annotations_offset: i32,
        class_data_offset: i32,
        static_values_offset: i32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for v in [
            class_index,
            access_flags,
            super_class_index,
            interfaces_offset,
            source_file_index,
            annotations_offset,
            class_data_offset,
            static_values_offset,
        ] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn new_reads_fields_with_no_offsets() {
        let bytes = header_bytes(7, 0x1, 0, 0, 0, 0, 0, 0);
        let mut reader = MockBinaryReader::new(bytes);
        let header = DexHeader;

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_class_index(), 7);
        assert_eq!(item.get_access_flags(), 0x1);
        assert_eq!(item.get_super_class_index(), 0);
        assert_eq!(item.get_interfaces_offset(), 0);
        assert_eq!(item.get_source_file_index(), 0);
        assert_eq!(item.get_annotations_offset(), 0);
        assert_eq!(item.get_class_data_offset(), 0);
        assert_eq!(item.get_static_values_offset(), 0);
        assert!(item.get_interfaces().is_none());
        assert!(item.get_annotations_directory_item().is_none());
        assert!(item.get_class_data_item().is_none());
        assert!(item.get_static_values().is_none());
        // Reader position is left just past the 32-byte fixed header.
        assert_eq!(reader.get_pointer_index(), 32);
    }

    #[test]
    fn new_populates_optional_items_and_restores_pointer() {
        let mut bytes = header_bytes(1, 0, 2, 32, 5, 32, 32, 32);
        bytes.push(0); // pad so offset 32 (just past the fixed header) is a valid index
        let mut reader = MockBinaryReader::new(bytes);
        let header = DexHeader;

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_interfaces_offset(), 32);
        assert!(item.get_interfaces().is_some());
        assert!(item.get_annotations_directory_item().is_some());
        assert!(item.get_class_data_item().is_some());
        assert!(item.get_static_values().is_some());
        // The reader pointer is restored to just past the fixed 32-byte header after each
        // offset lookup, matching Java's try/finally save-and-restore of oldIndex.
        assert_eq!(reader.get_pointer_index(), 32);
    }

    #[test]
    fn new_skips_invalid_offset() {
        // interfacesOffset points past the end of the buffer, so no TypeList is created.
        let bytes = header_bytes(0, 0, 0, 1000, 0, 0, 0, 0);
        let mut reader = MockBinaryReader::new(bytes);
        let header = DexHeader;

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_interfaces_offset(), 1000);
        assert!(item.get_interfaces().is_none());
    }
}
