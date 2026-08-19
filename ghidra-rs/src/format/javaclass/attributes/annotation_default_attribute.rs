//! The `AnnotationDefault` attribute structure.
//!
//! Ported from `ghidra.javaclass.format.attributes.AnnotationDefaultAttribute`.
//!
//! ```text
//! AnnotationDefault_attribute {
//!     u2 attribute_name_index;
//!     u4 attribute_length;
//!     element_value default_value;
//! }
//! ```

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::javaclass::attributes::annotation_element_value::AnnotationElementValue;
use crate::program::model::data::data_type::DataType;

/// The `AnnotationDefault` attribute, used to record the default value for an element
/// of an annotation type within a JVM class file.
///
/// Port of `ghidra.javaclass.format.attributes.AnnotationDefaultAttribute`.
pub struct AnnotationDefaultAttribute {
    offset: u64,
    attribute_name_index: u32,
    attribute_length: i32,
    default_value: AnnotationElementValue,
}

impl AnnotationDefaultAttribute {
    /// Reads an `AnnotationDefault_attribute` structure starting at the reader's current position,
    /// mirroring `AnnotationDefaultAttribute(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let offset = reader.get_pointer_index();
        let attribute_name_index = reader.read_next_unsigned_short()?;
        let attribute_length = reader.read_next_int()?;

        let default_value = AnnotationElementValue::new(reader)?;

        Ok(AnnotationDefaultAttribute {
            offset,
            attribute_name_index,
            attribute_length,
            default_value,
        })
    }

    /// The offset of this attribute in the file, in bytes.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// The index into the constant pool table for the name of this attribute.
    /// Matches the Java getter's `& 0xffff` masking.
    pub fn get_attribute_name_index(&self) -> u32 {
        self.attribute_name_index
    }

    /// The length of the attribute data following the 6-byte attribute header.
    pub fn get_attribute_length(&self) -> i32 {
        self.attribute_length
    }

    /// The default value for the annotation element represented by the method containing
    /// this attribute.
    pub fn get_default_value(&self) -> &AnnotationElementValue {
        &self.default_value
    }
}

/// Opaque placeholder returned by [`AnnotationDefaultAttribute::to_data_type`]. The real Java
/// body builds a `StructureDataType` including the attribute header fields and the nested
/// `element_value` structure, but since `StructureDataType` has no concrete Rust constructor yet,
/// this stands in with an opaque placeholder [`DataType`](crate::program::model::data::data_type::DataType)
/// instead, consistent with other not-yet-constructible `toDataType()` results in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnnotationDefaultAttributeDataType;

impl DataType for AnnotationDefaultAttributeDataType {}

impl StructConverter for AnnotationDefaultAttribute {
    /// `AnnotationDefaultAttribute.toDataType()`. See [`AnnotationDefaultAttributeDataType`] for why
    /// this returns an opaque placeholder rather than a real structure.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(AnnotationDefaultAttributeDataType))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReader {
        data: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { data, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            index < self.data.len() as u64
        }

        fn get_pointer_index(&self) -> u64 {
            self.pos
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.pos;
            self.pos = index;
            prev
        }

        fn is_little_endian(&self) -> bool {
            false
        }

        fn set_little_endian(&mut self, _is_little_endian: bool) {}

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.data.get(index as usize).copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "index out of bounds")
            })
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            unimplemented!()
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader { data: self.data.clone(), pos: new_index })
        }
    }

    /// Test reading an AnnotationDefault attribute with an int-tagged default value.
    /// Structure: u2 attribute_name_index (0x0001), u4 attribute_length (0x00000003),
    /// followed by an element_value with tag 'I' and const_value_index 0x0007.
    #[test]
    fn reads_attribute_header_and_default_value() {
        let mut reader = MockReader::new(vec![
            0x00, 0x01,             // attribute_name_index = 1
            0x00, 0x00, 0x00, 0x03, // attribute_length = 3
            b'I',                   // element_value tag = 'I' (int)
            0x00, 0x07,             // const_value_index = 7
        ]);

        let attr = AnnotationDefaultAttribute::new(&mut reader).expect("valid attribute");

        assert_eq!(attr.get_attribute_name_index(), 1);
        assert_eq!(attr.get_attribute_length(), 3);
        assert_eq!(attr.get_default_value().get_tag(), b'I');
        assert_eq!(attr.get_default_value().get_constant_value_index(), 7);
        assert_eq!(reader.get_pointer_index(), 9);
    }

    /// Test that to_data_type returns a valid result.
    #[test]
    fn to_data_type_returns_a_data_type() {
        let mut reader = MockReader::new(vec![
            0x00, 0x01,             // attribute_name_index = 1
            0x00, 0x00, 0x00, 0x03, // attribute_length = 3
            b'I',                   // element_value tag = 'I' (int)
            0x00, 0x07,             // const_value_index = 7
        ]);

        let attr = AnnotationDefaultAttribute::new(&mut reader).expect("valid attribute");
        assert!(attr.to_data_type().is_ok());
    }
}
