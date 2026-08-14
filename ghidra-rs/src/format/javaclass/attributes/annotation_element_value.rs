//! The `element_value` structure: a discriminated union representing the value of an
//! element-value pair, used by every attribute that describes annotations
//! (`RuntimeVisibleAnnotations`, `RuntimeInvisibleAnnotations`,
//! `RuntimeVisibleParameterAnnotations`, `RuntimeInvisibleParameterAnnotations`).
//!
//! Ported from `ghidra.javaclass.format.attributes.AnnotationElementValue`.
//!
//! ```text
//! element_value {
//!     u1 tag;
//!     union {
//!         u2 const_value_index;
//!         {
//!             u2 type_name_index;
//!             u2 const_name_index;
//!         } enum_const_value;
//!         u2 class_info_index;
//!         annotation annotation_value;
//!         {
//!             u2 num_values;
//!             element_value values[num_values];
//!         } array_value;
//!     } value;
//! }
//! ```

use std::io;

use crate::app::seam_stubs::descriptor_decoder;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::AnnotationJava;
use crate::program::model::data::data_type::DataType;

/// See the module-level documentation for the `element_value` structure layout.
///
/// Port of `ghidra.javaclass.format.attributes.AnnotationElementValue`.
pub struct AnnotationElementValue {
    tag: u8,
    constant_value_index: u32,
    type_name_index: u32,
    constant_name_index: u32,
    class_info_index: u32,
    annotation: Option<AnnotationJava>,
    values: Option<Vec<AnnotationElementValue>>,
}

impl AnnotationElementValue {
    /// Reads an `element_value` structure starting at the reader's current position, dispatching
    /// on `tag` exactly like `AnnotationElementValue(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let tag = reader.read_next_byte()?;

        let mut constant_value_index = 0;
        let mut type_name_index = 0;
        let mut constant_name_index = 0;
        let mut class_info_index = 0;
        let mut annotation = None;
        let mut values = None;

        if tag == descriptor_decoder::BASE_TYPE_BYTE
            || tag == descriptor_decoder::BASE_TYPE_CHAR
            || tag == descriptor_decoder::BASE_TYPE_INT
            || tag == descriptor_decoder::BASE_TYPE_SHORT
            || tag == descriptor_decoder::BASE_TYPE_LONG
            || tag == descriptor_decoder::BASE_TYPE_FLOAT
            || tag == descriptor_decoder::BASE_TYPE_DOUBLE
            || tag == descriptor_decoder::BASE_TYPE_BOOLEAN
            || tag == descriptor_decoder::BASE_TYPE_STRING
        {
            constant_value_index = reader.read_next_unsigned_short()?;
        } else if tag == descriptor_decoder::BASE_TYPE_ENUM {
            type_name_index = reader.read_next_unsigned_short()?;
            constant_name_index = reader.read_next_unsigned_short()?;
        } else if tag == descriptor_decoder::BASE_TYPE_CLASS {
            class_info_index = reader.read_next_unsigned_short()?;
        } else if tag == descriptor_decoder::BASE_TYPE_ANNOTATION {
            annotation = Some(AnnotationJava::new(reader)?);
        } else if tag == descriptor_decoder::BASE_TYPE_ARRAY {
            let number_of_values = reader.read_next_unsigned_short()?;
            let mut vals = Vec::with_capacity(number_of_values as usize);
            for _ in 0..number_of_values {
                vals.push(AnnotationElementValue::new(reader)?);
            }
            values = Some(vals);
        }

        Ok(AnnotationElementValue {
            tag,
            constant_value_index,
            type_name_index,
            constant_name_index,
            class_info_index,
            annotation,
            values,
        })
    }

    /// The tag item indicates the type of this annotation element-value pair.
    ///
    /// The letters 'B', 'C', 'D', 'F', 'I', 'J', 'S', and 'Z' indicate a primitive type; these
    /// are interpreted as `BaseType` characters. The other legal values are listed with their
    /// interpretations in JVMS Table 4.24.
    ///
    /// `AnnotationElementValue.getTag()`.
    pub fn get_tag(&self) -> u8 {
        self.tag
    }

    /// The `const_value_index` item is used if the tag item is one of 'B', 'C', 'D', 'F', 'I',
    /// 'J', 'S', 'Z', 's'. Must be a valid index into the constant pool table.
    ///
    /// `AnnotationElementValue.getConstantValueIndex()` (already masked to an unsigned 16-bit
    /// value, matching the Java getter's `& 0xffff`).
    pub fn get_constant_value_index(&self) -> u32 {
        self.constant_value_index
    }

    /// The `type_name_index` item, valid only if `tag` is `BASE_TYPE_ENUM` ('e'). Must be a
    /// valid index into the constant pool table, denoting the internal form of the binary name
    /// of the enum constant's type.
    ///
    /// `AnnotationElementValue.getTypeNameIndex()` (already masked to an unsigned 16-bit value,
    /// matching the Java getter's `& 0xffff`). Returns `Err` if `tag` is not `BASE_TYPE_ENUM`,
    /// standing in for the Java getter's `IllegalArgumentException`.
    pub fn get_type_name_index(&self) -> Result<u32, String> {
        if self.tag != descriptor_decoder::BASE_TYPE_ENUM {
            return Err("tag is not BASE_TYPE_ENUM".to_string());
        }
        Ok(self.type_name_index)
    }

    /// The `const_name_index` item, valid only if `tag` is `BASE_TYPE_ENUM` ('e'). Must be a
    /// valid index into the constant pool table, denoting the simple name of the enum constant.
    ///
    /// `AnnotationElementValue.getConstantNameIndex()` (already masked to an unsigned 16-bit
    /// value, matching the Java getter's `& 0xffff`). Returns `Err` if `tag` is not
    /// `BASE_TYPE_ENUM`, standing in for the Java getter's `IllegalArgumentException`.
    pub fn get_constant_name_index(&self) -> Result<u32, String> {
        if self.tag != descriptor_decoder::BASE_TYPE_ENUM {
            return Err("tag is not BASE_TYPE_ENUM".to_string());
        }
        Ok(self.constant_name_index)
    }

    /// The `class_info_index` item is used if `tag` is `BASE_TYPE_CLASS` ('c'). Must be a valid
    /// index into the constant pool table, denoting the return descriptor of the reified type
    /// (e.g. 'V' for `Void.class`, 'Ljava/lang/Object;' for `Object`).
    ///
    /// `AnnotationElementValue.getClassInfoIndex()` (already masked to an unsigned 16-bit value,
    /// matching the Java getter's `& 0xffff`).
    pub fn get_class_info_index(&self) -> u32 {
        self.class_info_index
    }

    /// The `annotation_value` item, used if `tag` is `BASE_TYPE_ANNOTATION` ('@'): a "nested"
    /// annotation. `None` for any other tag.
    ///
    /// `AnnotationElementValue.getAnnotation()`.
    pub fn get_annotation(&self) -> Option<&AnnotationJava> {
        self.annotation.as_ref()
    }

    /// The nested element value table for the array-typed value represented by this
    /// `element_value`, used if `tag` is `BASE_TYPE_ARRAY` ('['). `None` for any other tag. A
    /// maximum of 65535 elements are permitted.
    ///
    /// `AnnotationElementValue.getValues()`.
    pub fn get_values(&self) -> Option<&[AnnotationElementValue]> {
        self.values.as_deref()
    }
}

/// Opaque placeholder returned by [`AnnotationElementValue::to_data_type`]. The real Java body
/// (`AnnotationElementValue.toDataType()`) builds a `StructureDataType` named
/// `"element_value|<tag>|"` but its tag-dispatch branches are all empty upstream, so the real
/// return value is already just an empty, named structure; since
/// [`StructureDataType`](crate::program::model::data::structure_data_type::StructureDataType) has
/// no concrete Rust constructor yet, this stands in with an opaque placeholder
/// [`DataType`](crate::program::model::data::data_type::DataType) instead, consistent with other
/// not-yet-constructible `toDataType()` results in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnnotationElementValueDataType;

impl DataType for AnnotationElementValueDataType {}

impl StructConverter for AnnotationElementValue {
    /// `AnnotationElementValue.toDataType()`. See [`AnnotationElementValueDataType`] for why this
    /// returns an opaque placeholder rather than a real structure.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(AnnotationElementValueDataType))
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

    /// tag='I' (int), followed by a `const_value_index` of 0x0007, matching JVMS Table 4.24's
    /// "int" case.
    #[test]
    fn primitive_tag_reads_constant_value_index() {
        let mut reader = MockReader::new(vec![b'I', 0x00, 0x07]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        assert_eq!(value.get_tag(), b'I');
        assert_eq!(value.get_constant_value_index(), 7);
        assert!(value.get_annotation().is_none());
        assert!(value.get_values().is_none());
        assert_eq!(reader.get_pointer_index(), 3);
    }

    /// tag='e' (enum), followed by `type_name_index` 0x0001 and `const_name_index` 0x0002.
    #[test]
    fn enum_tag_reads_type_and_constant_name_index() {
        let mut reader = MockReader::new(vec![b'e', 0x00, 0x01, 0x00, 0x02]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        assert_eq!(value.get_tag(), b'e');
        assert_eq!(value.get_type_name_index(), Ok(1));
        assert_eq!(value.get_constant_name_index(), Ok(2));
    }

    /// A tag other than `BASE_TYPE_ENUM` makes `getTypeNameIndex`/`getConstantNameIndex` throw
    /// `IllegalArgumentException` in Java; ported as `Err`.
    #[test]
    fn non_enum_tag_rejects_enum_accessors() {
        let mut reader = MockReader::new(vec![b'I', 0x00, 0x07]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        assert!(value.get_type_name_index().is_err());
        assert!(value.get_constant_name_index().is_err());
    }

    /// tag='c' (class), followed by `class_info_index` 0x0003.
    #[test]
    fn class_tag_reads_class_info_index() {
        let mut reader = MockReader::new(vec![b'c', 0x00, 0x03]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        assert_eq!(value.get_class_info_index(), 3);
    }

    /// tag='@' (annotation) with a nested annotation whose header carries `type_index` 0x0005 and
    /// zero element-value pairs (avoiding the not-yet-ported `AnnotationElementValuePair` table).
    #[test]
    fn annotation_tag_reads_nested_annotation_header() {
        let mut reader = MockReader::new(vec![b'@', 0x00, 0x05, 0x00, 0x00]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        let annotation = value.get_annotation().expect("annotation tag sets annotation");
        assert_eq!(annotation.get_type_index(), 5);
        assert_eq!(annotation.get_number_of_element_value_pairs(), 0);
        assert_eq!(reader.get_pointer_index(), 5);
    }

    /// tag='[' (array) with `num_values` 0x0002 followed by two nested int-tagged element values.
    #[test]
    fn array_tag_reads_nested_values() {
        let mut reader =
            MockReader::new(vec![b'[', 0x00, 0x02, b'I', 0x00, 0x01, b'I', 0x00, 0x02]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        let values = value.get_values().expect("array tag sets values");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].get_constant_value_index(), 1);
        assert_eq!(values[1].get_constant_value_index(), 2);
        assert_eq!(reader.get_pointer_index(), 9);
    }

    #[test]
    fn to_data_type_returns_a_data_type() {
        let mut reader = MockReader::new(vec![b'I', 0x00, 0x07]);
        let value = AnnotationElementValue::new(&mut reader).expect("valid element_value");

        assert!(value.to_data_type().is_ok());
    }
}
