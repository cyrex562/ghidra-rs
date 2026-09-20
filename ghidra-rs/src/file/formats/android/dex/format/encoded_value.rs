//! Port of `ghidra.file.formats.android.dex.format.EncodedValue`.
//!
//! The Java class is a concrete `class EncodedValue implements StructConverter` that nothing
//! extends, so per this crate's shape rules it ports to a `struct` + `impl`, not a trait.
//!
//! `EncodedValue`'s constructor and `toDataType()` sit on a dependency cycle: the `VALUE_ARRAY`
//! case constructs an `EncodedArray`, which itself decodes a sequence of `EncodedValue`s (a direct
//! self-cycle); the `VALUE_ANNOTATION` case constructs an `EncodedAnnotation`, whose
//! `List<AnnotationElement>` elements each wrap an `EncodedValue` (a cycle through
//! `AnnotationElement`). `EncodedArray`/`EncodedAnnotation` are cut at this forward reference via
//! minimal placeholders in
//! [`seam_stubs`](crate::file::formats::android::dex::format::seam_stubs) (see that module's docs
//! for exactly what is and isn't reproduced, and why `AnnotationElement`'s shape is inlined there
//! rather than stubbed a second time).

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::seam_stubs::{EncodedAnnotation, EncodedArray};
use crate::file::formats::android::dex::format::value_formats::ValueFormats;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;
use std::sync::Arc;

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.BYTE` (`ByteDataType.dataType`),
/// used for the leading `valueType` field of [`EncodedValue::to_data_type`]. See
/// [`crate::format::elf::info::elf_note`]'s `DWordPlaceholderDataType` for the identical situation
/// with a different leaf type.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_name(&self) -> String {
        "byte".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
}

/// Minimal stand-in for `new ArrayDataType(BYTE, length, BYTE.getLength())`, used for the fixed
/// primitive-value payload field of [`EncodedValue::to_data_type`].
struct ByteArrayPlaceholderDataType {
    length: i32,
}

impl DataType for ByteArrayPlaceholderDataType {
    fn get_name(&self) -> String {
        format!("byte[{}]", self.length.max(0))
    }
    fn get_length(&self) -> i32 {
        self.length
    }
}

/// Represents a single `encoded_value` item in the DEX format.
///
/// Port of `ghidra.file.formats.android.dex.format.EncodedValue`.
///
/// See: <https://source.android.com/devices/tech/dalvik/dex-format#encoding>
pub struct EncodedValue {
    value: u8,
    value_type: u8,
    value_args: u8,
    value_bytes: Option<Vec<u8>>,
    array: Option<EncodedArray>,
    annotation: Option<EncodedAnnotation>,
}

impl EncodedValue {
    /// Port of `EncodedValue(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_byte()?;
        let value_type = value & 0x1f;
        let value_args = (value & 0xe0) >> 5;

        let mut value_bytes = None;
        let mut array = None;
        let mut annotation = None;

        match value_type {
            ValueFormats::VALUE_BYTE
            | ValueFormats::VALUE_SHORT
            | ValueFormats::VALUE_CHAR
            | ValueFormats::VALUE_INT
            | ValueFormats::VALUE_LONG
            | ValueFormats::VALUE_FLOAT
            | ValueFormats::VALUE_DOUBLE
            | ValueFormats::VALUE_STRING
            | ValueFormats::VALUE_TYPE
            | ValueFormats::VALUE_FIELD
            | ValueFormats::VALUE_METHOD
            | ValueFormats::VALUE_ENUM => {
                value_bytes = Some(reader.read_next_byte_array(value_args as usize + 1)?);
            }
            ValueFormats::VALUE_ARRAY => {
                array = Some(EncodedArray::read(reader)?);
            }
            ValueFormats::VALUE_ANNOTATION => {
                annotation = Some(EncodedAnnotation::read(reader)?);
            }
            ValueFormats::VALUE_NULL | ValueFormats::VALUE_BOOLEAN => {
                // do nothing
            }
            _ => {
                // do nothing
            }
        }

        Ok(EncodedValue { value, value_type, value_args, value_bytes, array, annotation })
    }

    /// Port of `EncodedValue.getValueArgs()`.
    pub fn get_value_args(&self) -> u8 {
        self.value_args
    }

    /// Port of `EncodedValue.getValueType()`.
    pub fn get_value_type(&self) -> u8 {
        self.value_type
    }

    /// Port of `EncodedValue.getValueBytes()`.
    pub fn get_value_bytes(&self) -> Option<&[u8]> {
        self.value_bytes.as_deref()
    }

    /// Port of `EncodedValue.getValueByte()`.
    ///
    /// # Panics
    /// Panics if this value's type has no `valueBytes` payload, mirroring Java's
    /// `ArrayIndexOutOfBoundsException`/`NullPointerException` from `valueBytes[0]` on such a
    /// value.
    pub fn get_value_byte(&self) -> u8 {
        self.value_bytes.as_ref().expect("valueBytes is only absent for types with no byte payload")[0]
    }

    /// Port of `EncodedValue.getArray()`.
    pub fn get_array(&self) -> Option<&EncodedArray> {
        self.array.as_ref()
    }

    /// Port of `EncodedValue.getAnnotation()`.
    pub fn get_annotation(&self) -> Option<&EncodedAnnotation> {
        self.annotation.as_ref()
    }

    /// Port of `EncodedValue.isValueBoolean()`.
    pub fn is_value_boolean(&self) -> bool {
        self.value_args == 1
    }

    /// Port of the package-private `EncodedValue.getValue()`.
    pub(crate) fn get_value(&self) -> u8 {
        self.value
    }
}

impl StructConverter for EncodedValue {
    /// Port of `EncodedValue.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut name = format!("encoded_value_0x{:x}", self.value);
        let cp = CategoryPath::parse("/dex/encoded_value").expect("valid category path");
        let mut structure = StructureDataType::new(cp, &name, 0);
        structure.add(Arc::new(BytePlaceholderDataType), 1, Some("valueType".to_string()), None);

        match self.value_type {
            ValueFormats::VALUE_BYTE
            | ValueFormats::VALUE_SHORT
            | ValueFormats::VALUE_CHAR
            | ValueFormats::VALUE_INT
            | ValueFormats::VALUE_LONG
            | ValueFormats::VALUE_FLOAT
            | ValueFormats::VALUE_DOUBLE
            | ValueFormats::VALUE_STRING
            | ValueFormats::VALUE_TYPE
            | ValueFormats::VALUE_FIELD
            | ValueFormats::VALUE_METHOD
            | ValueFormats::VALUE_ENUM => {
                let length = (self.value_args & 0xff) as i32 + 1;
                structure.add(
                    Arc::new(ByteArrayPlaceholderDataType { length }),
                    length,
                    Some("value".to_string()),
                    None,
                );
                name.push_str(&format!("_{length}"));
            }
            ValueFormats::VALUE_ARRAY => {
                let array = self.array.as_ref().expect("VALUE_ARRAY implies array is Some");
                name.push_str(&format!("_{}", array.get_values().len()));
                let array_dt = array.to_data_type();
                let array_len = array_dt.get_length();
                structure.add(Arc::from(array_dt), array_len, Some("value".to_string()), None);
            }
            ValueFormats::VALUE_ANNOTATION => {
                let annotation = self.annotation.as_ref().expect("VALUE_ANNOTATION implies annotation is Some");
                let annotation_dt: Arc<dyn DataType> = Arc::from(annotation.to_data_type()?);
                name.push_str(&format!("_{}", annotation_dt.get_name()));
                let annotation_len = annotation_dt.get_length();
                structure.add(annotation_dt, annotation_len, Some("value".to_string()), None);
            }
            ValueFormats::VALUE_NULL | ValueFormats::VALUE_BOOLEAN => {
                // do nothing
            }
            _ => {
                // do nothing (matches Java's commented-out `default` throw)
            }
        }

        // The placeholder `StructureDataType` has no rename-after-construction operation, unlike
        // Java's `structure.setName(builder.toString())`; a fresh instance carrying every already
        // -added component plus the final name stands in for it. See
        // `EncodedAnnotation::to_data_type`'s docs for the identical constraint.
        let mut renamed = StructureDataType::new(structure.get_category_path(), &name, 0);
        for component in structure.components.clone() {
            renamed.add(component.data_type, component.length, component.field_name, component.comment);
        }

        Ok(Box::new(renamed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBinaryReader {
        bytes: Vec<u8>,
        position: usize,
        little_endian: bool,
    }

    impl MockBinaryReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockBinaryReader { bytes, position: 0, little_endian: true }
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
            let old = self.position as u64;
            self.position = index as usize;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn get_byte_provider(&self) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            unimplemented!("not exercised by these tests")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockBinaryReader { bytes: self.bytes.clone(), position: new_index as usize, little_endian: self.little_endian })
        }
        fn clone_reader(&self) -> Box<dyn BinaryReader> {
            Box::new(MockBinaryReader { bytes: self.bytes.clone(), position: self.position, little_endian: self.little_endian })
        }
        fn as_big_endian(&self) -> Box<dyn BinaryReader> {
            Box::new(MockBinaryReader { bytes: self.bytes.clone(), position: self.position, little_endian: false })
        }
        fn as_little_endian(&self) -> Box<dyn BinaryReader> {
            Box::new(MockBinaryReader { bytes: self.bytes.clone(), position: self.position, little_endian: true })
        }
    }

    fn sleb_unsigned_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    /// `VALUE_BYTE` (0x00) with `value_args == 0` (so a 1-byte payload): header byte encodes
    /// `valueType=VALUE_BYTE, valueArg=0` -> `0x00`, followed by the 1 payload byte.
    #[test]
    fn decodes_value_byte() {
        let mut reader = MockBinaryReader::new(vec![ValueFormats::VALUE_BYTE, 0x2A]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value_type(), ValueFormats::VALUE_BYTE);
        assert_eq!(ev.get_value_args(), 0);
        assert_eq!(ev.get_value_bytes(), Some([0x2A].as_slice()));
        assert_eq!(ev.get_value_byte(), 0x2A);
        assert!(ev.get_array().is_none());
        assert!(ev.get_annotation().is_none());
    }

    /// `VALUE_INT` (0x04) with `value_args == 3` (so a 4-byte payload): header byte = `(3 << 5) |
    /// 0x04` = `0x64`.
    #[test]
    fn decodes_value_int_with_multi_byte_payload() {
        let header = (3u8 << 5) | ValueFormats::VALUE_INT;
        let mut reader = MockBinaryReader::new(vec![header, 0x01, 0x02, 0x03, 0x04]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value_type(), ValueFormats::VALUE_INT);
        assert_eq!(ev.get_value_args(), 3);
        assert_eq!(ev.get_value_bytes(), Some([0x01, 0x02, 0x03, 0x04].as_slice()));
    }

    /// `VALUE_NULL`/`VALUE_BOOLEAN` consume no payload bytes at all.
    #[test]
    fn value_null_and_boolean_consume_no_payload() {
        let mut reader = MockBinaryReader::new(vec![ValueFormats::VALUE_NULL, 0xFF]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value_bytes(), None);
        assert_eq!(reader.get_pointer_index(), 1); // only the header byte was consumed

        let header_bool = (1u8 << 5) | ValueFormats::VALUE_BOOLEAN;
        let mut reader = MockBinaryReader::new(vec![header_bool]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert!(ev.is_value_boolean());
        assert_eq!(ev.get_value_bytes(), None);
    }

    /// `VALUE_ARRAY` (0x1c) containing one nested `VALUE_BYTE` element: `encoded_array` is
    /// `uleb128(size=1)` followed by `size` `encoded_value`s.
    #[test]
    fn decodes_value_array_and_advances_past_nested_values() {
        let mut bytes = vec![ValueFormats::VALUE_ARRAY];
        bytes.extend(sleb_unsigned_bytes(1)); // size = 1
        bytes.push(ValueFormats::VALUE_BYTE); // nested EncodedValue header
        bytes.push(0x7B); // nested EncodedValue payload
        bytes.push(0xAA); // trailing sentinel byte, should NOT be consumed

        let mut reader = MockBinaryReader::new(bytes);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value_type(), ValueFormats::VALUE_ARRAY);
        let array = ev.get_array().unwrap();
        // `values` is the raw re-read bytes covering just the nested EncodedValues (NOT the
        // leading uleb128 size), matching Java's `nBytes = evReader.pointer - reader.pointer`
        // computed *after* the uleb128 was already consumed from `reader`: 1 nested EncodedValue
        // header byte + 1 payload byte = 2.
        assert_eq!(array.get_values().len(), 2);
        // header(1) + uleb128(1) + values(2) == 4; the trailing sentinel is not consumed.
        assert_eq!(reader.get_pointer_index(), 4);
    }

    /// `VALUE_ANNOTATION` (0x1d) containing one element: `encoded_annotation` is
    /// `uleb128(typeIndex)` + `uleb128(size=1)` + `size` `annotation_element`s
    /// (`uleb128(nameIndex)` + `encoded_value`).
    #[test]
    fn decodes_value_annotation_and_advances_past_elements() {
        let mut bytes = vec![ValueFormats::VALUE_ANNOTATION];
        bytes.extend(sleb_unsigned_bytes(7)); // typeIndex
        bytes.extend(sleb_unsigned_bytes(1)); // size = 1
        bytes.extend(sleb_unsigned_bytes(2)); // element nameIndex
        bytes.push(ValueFormats::VALUE_BYTE); // element's EncodedValue header
        bytes.push(0x99); // element's EncodedValue payload

        let mut reader = MockBinaryReader::new(bytes);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value_type(), ValueFormats::VALUE_ANNOTATION);
        assert!(ev.get_annotation().is_some());
        // Every byte should have been consumed (no trailing bytes in this test's input).
        assert_eq!(reader.get_pointer_index(), reader.bytes.len() as u64);
    }

    #[test]
    fn to_data_type_names_primitive_value_by_type_and_length() {
        let mut reader = MockBinaryReader::new(vec![ValueFormats::VALUE_BYTE, 0x2A]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        let dt = ev.to_data_type().unwrap();
        assert_eq!(dt.get_name(), format!("encoded_value_0x{:x}_1", ValueFormats::VALUE_BYTE));
    }

    #[test]
    fn to_data_type_names_array_value_by_byte_count() {
        let mut bytes = vec![ValueFormats::VALUE_ARRAY];
        bytes.extend(sleb_unsigned_bytes(1));
        bytes.push(ValueFormats::VALUE_BYTE);
        bytes.push(0x7B);
        let mut reader = MockBinaryReader::new(bytes);
        let ev = EncodedValue::new(&mut reader).unwrap();
        let dt = ev.to_data_type().unwrap();
        assert_eq!(dt.get_name(), format!("encoded_value_0x{:x}_2", ValueFormats::VALUE_ARRAY));
    }

    #[test]
    fn to_data_type_is_empty_for_null_and_boolean() {
        let mut reader = MockBinaryReader::new(vec![ValueFormats::VALUE_NULL]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        let dt = ev.to_data_type().unwrap();
        assert_eq!(dt.get_name(), format!("encoded_value_0x{:x}", ValueFormats::VALUE_NULL));
        // Only the `valueType` component, no `value` field.
        assert_eq!(dt.get_length(), 1);
    }

    #[test]
    fn get_value_returns_the_raw_header_byte() {
        let header = (2u8 << 5) | ValueFormats::VALUE_SHORT;
        let mut reader = MockBinaryReader::new(vec![header, 0x01, 0x02, 0x03]);
        let ev = EncodedValue::new(&mut reader).unwrap();
        assert_eq!(ev.get_value(), header);
    }
}
