//! Port of `ghidra.file.formats.android.dex.format.AnnotationElement`.
//!
//! The Java class is a concrete `class AnnotationElement implements StructConverter` that nothing
//! extends, so per this crate's shape rules it ports to a `struct` + `impl`, not a trait. It was
//! chosen by recursive-descent order right after
//! [`EncodedValue`](crate::file::formats::android::dex::format::encoded_value::EncodedValue),
//! which it directly depends on (a `uleb128(nameIndex)` followed by one `EncodedValue`) -- no
//! forward reference or placeholder is needed here.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::encoded_value::EncodedValue;
use crate::program::model::data::unsigned_leb128_data_type::UnsignedLeb128DataType;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;

/// Represents an `annotation_element` item in the DEX format: a name index paired with an
/// [`EncodedValue`].
///
/// Port of `ghidra.file.formats.android.dex.format.AnnotationElement`.
///
/// See: <https://source.android.com/devices/tech/dalvik/dex-format#annotation-element>
pub struct AnnotationElement {
    name_index: i32,
    name_index_length: i32,
    value: EncodedValue,
}

impl AnnotationElement {
    /// Port of `AnnotationElement(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let leb128 = LEB128Info::unsigned(reader)?;
        let name_index = leb128.as_u_int32().map_err(io::Error::from)? as i32;
        let name_index_length = leb128.get_length();

        let value = EncodedValue::new(reader)?;

        Ok(AnnotationElement { name_index, name_index_length, value })
    }

    /// Port of `AnnotationElement.getNameIndex()`.
    pub fn get_name_index(&self) -> i32 {
        self.name_index
    }

    /// Port of `AnnotationElement.getValue()`.
    pub fn get_value(&self) -> &EncodedValue {
        &self.value
    }
}

impl StructConverter for AnnotationElement {
    /// Port of `AnnotationElement.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let encoded_value_dt: Arc<dyn DataType> = Arc::from(self.value.to_data_type()?);

        let name = format!("annotation_element_{}_{}", self.name_index_length, encoded_value_dt.get_name());
        let cp = CategoryPath::parse("/dex/annotation_element").expect("valid category path");

        let mut structure = StructureDataType::new(cp, &name, 0);
        structure.add(UnsignedLeb128DataType::data_type(), self.name_index_length, Some("nameIndex".to_string()), None);
        let value_len = encoded_value_dt.get_length();
        structure.add(encoded_value_dt, value_len, Some("value".to_string()), None);

        Ok(Box::new(structure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::android::dex::format::value_formats::ValueFormats;

    fn uleb_bytes(mut value: u64) -> Vec<u8> {
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

    #[test]
    fn decodes_name_index_and_value() {
        let mut bytes = uleb_bytes(300); // nameIndex, 2-byte uleb128
        bytes.push(ValueFormats::VALUE_BYTE); // EncodedValue header
        bytes.push(0x42); // EncodedValue payload

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let elem = AnnotationElement::new(&mut reader).unwrap();

        assert_eq!(elem.get_name_index(), 300);
        assert_eq!(elem.get_value().get_value_type(), ValueFormats::VALUE_BYTE);
        assert_eq!(elem.get_value().get_value_byte(), 0x42);
        assert_eq!(reader.get_pointer_index(), reader.length().unwrap());
    }

    #[test]
    fn to_data_type_name_includes_uleb_length_and_nested_value_name() {
        let mut bytes = uleb_bytes(5); // nameIndex, 1-byte uleb128
        bytes.push(ValueFormats::VALUE_BYTE);
        bytes.push(0x01);

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let elem = AnnotationElement::new(&mut reader).unwrap();
        let dt = elem.to_data_type().unwrap();

        let expected_value_name = format!("encoded_value_0x{:x}_1", ValueFormats::VALUE_BYTE);
        assert_eq!(dt.get_name(), format!("annotation_element_1_{expected_value_name}"));
        // nameIndex (1 byte, explicit uleb128 length) + value (1 byte valueType + 1 byte payload).
        assert_eq!(dt.get_length(), 3);
    }

    #[test]
    fn multi_byte_name_index_length_is_reflected_in_uleb_field_length() {
        let mut bytes = uleb_bytes(0x4000); // nameIndex, 3-byte uleb128
        bytes.push(ValueFormats::VALUE_NULL); // no payload

        let mut reader = BinaryReader::from_bytes(bytes, true);
        let elem = AnnotationElement::new(&mut reader).unwrap();
        let dt = elem.to_data_type().unwrap();

        assert!(dt.get_name().starts_with("annotation_element_3_"));
        // nameIndex (3 bytes) + value (1 byte valueType, no payload for VALUE_NULL).
        assert_eq!(dt.get_length(), 4);
    }
}
