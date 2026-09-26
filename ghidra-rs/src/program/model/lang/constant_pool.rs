use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::ids::{
    ATTRIB_CONSTRUCTOR, ATTRIB_CONTENT, ATTRIB_LENGTH, ATTRIB_REF, ATTRIB_TAG, ELEM_CPOOLREC,
    ELEM_DATA, ELEM_TOKEN, ELEM_VALUE,
};
use crate::program::model::pcode::{Encoder, PcodeDataTypeManager};
use std::io;

/// Constant `-value-` of datatype `-type-`.
pub const PRIMITIVE: i32 = 0;
/// Constant reference to string in `-token-`.
pub const STRING_LITERAL: i32 = 1;
/// Reference to (system level) class object.
pub const CLASS_REFERENCE: i32 = 2;
/// Pointer to a method, name in `-token-`, signature in `-type-`.
pub const POINTER_METHOD: i32 = 3;
/// Pointer to a field, name in `-token-`, datatype in `-type-`.
pub const POINTER_FIELD: i32 = 4;
/// Integer length, `-token-` is language specific indicator, `-type-` is integral type.
pub const ARRAY_LENGTH: i32 = 5;
/// Boolean value, `-token-` is language specific indicator, `-type-` is boolean type.
pub const INSTANCE_OF: i32 = 6;
/// Pointer to object, new name in `-token-`, new datatype in `-type-`.
pub const CHECK_CAST: i32 = 7;

/// A single resolved entry from a constant pool.
///
/// Port of `ghidra.program.model.lang.ConstantPool.Record`.
pub struct ConstantPoolRecord {
    /// The type of the record; one of the tag constants above.
    pub tag: i32,
    /// Name or token associated with the object.
    pub token: String,
    /// Primitive value of the object (if `tag == PRIMITIVE`).
    pub value: i64,
    /// Raw byte payload, when present, encoded in place of `token`.
    pub byte_data: Option<Vec<u8>>,
    /// The datatype associated with this record.
    pub data_type: Box<dyn DataType>,
    /// Whether this record refers to a constructor.
    pub is_constructor: bool,
}

impl ConstantPoolRecord {
    /// Encode this record to the stream.
    ///
    /// Port of `ConstantPool.Record.encode(Encoder, long, PcodeDataTypeManager)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(
        &self,
        encoder: &mut dyn Encoder,
        reference: u64,
        dtmanage: &dyn PcodeDataTypeManager,
    ) -> io::Result<()> {
        encoder.open_element(ELEM_CPOOLREC)?;
        encoder.write_unsigned_integer(ATTRIB_REF, reference)?;
        let tag_name = match self.tag {
            STRING_LITERAL => "string",
            CLASS_REFERENCE => "classref",
            POINTER_METHOD => "method",
            POINTER_FIELD => "field",
            ARRAY_LENGTH => "arraylength",
            INSTANCE_OF => "instanceof",
            CHECK_CAST => "checkcast",
            _ => "primitive",
        };
        encoder.write_string(ATTRIB_TAG, tag_name)?;
        if self.is_constructor {
            encoder.write_bool(ATTRIB_CONSTRUCTOR, true)?;
        }
        if self.tag == PRIMITIVE {
            encoder.open_element(ELEM_VALUE)?;
            encoder.write_unsigned_integer(ATTRIB_CONTENT, self.value as u64)?;
            encoder.close_element(ELEM_VALUE)?;
        }
        if let Some(byte_data) = &self.byte_data {
            encoder.open_element(ELEM_DATA)?;
            encoder.write_signed_integer(ATTRIB_LENGTH, byte_data.len() as i64)?;
            let mut buf = String::new();
            let mut wrap = 0;
            for val in byte_data {
                let hival = (val >> 4) & 0xf;
                let loval = val & 0xf;
                buf.push(char::from_digit(hival as u32, 16).unwrap());
                buf.push(char::from_digit(loval as u32, 16).unwrap());
                buf.push(' ');
                wrap += 1;
                if wrap > 15 {
                    buf.push('\n');
                    wrap = 0;
                }
            }
            encoder.write_string(ATTRIB_CONTENT, &buf)?;
            encoder.close_element(ELEM_DATA)?;
        } else {
            encoder.open_element(ELEM_TOKEN)?;
            encoder.write_string(ATTRIB_CONTENT, &self.token)?;
            encoder.close_element(ELEM_TOKEN)?;
        }
        dtmanage.encode_type_ref(encoder, self.data_type.as_ref(), self.data_type.get_length())?;
        encoder.close_element(ELEM_CPOOLREC)
    }

    /// Set the raw byte payload from a UTF-8 string.
    ///
    /// Port of `ConstantPool.Record.setUTF8Data(String)`.
    pub fn set_utf8_data(&mut self, val: &str) {
        self.byte_data = Some(val.as_bytes().to_vec());
    }
}

/// Trait for manipulating "deferred" constant systems like the java virtual machine constant
/// pool.
///
/// Port of `ghidra.program.model.lang.ConstantPool`.
pub trait ConstantPool {
    /// Get the constant pool record referred to by the given reference.
    ///
    /// Port of `ConstantPool.getRecord(long[])`.
    fn get_record(&self, reference: &[i64]) -> ConstantPoolRecord;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    #[derive(Default)]
    struct MockEncoder {
        writes: Vec<String>,
    }

    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }

        fn write_bool(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: bool,
        ) -> io::Result<()> {
            self.writes.push(format!("bool:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.writes.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: u64,
        ) -> io::Result<()> {
            self.writes.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: &str,
        ) -> io::Result<()> {
            self.writes.push(format!("str:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("str[{}]:{}={}", index, attrib_id.name, val));
            Ok(())
        }

        fn write_space(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            self.writes
                .push(format!("space:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("space[{}]:{}={}", index, attrib_id.name, name));
            Ok(())
        }

        fn write_opcode(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}={:?}", attrib_id.name, opcode));
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            opcode: i32,
        ) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}=#{}", attrib_id.name, opcode));
            Ok(())
        }
    }

    struct MockPcodeDataTypeManager;

    impl PcodeDataTypeManager for MockPcodeDataTypeManager {
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by this smoke test")
        }

        fn decode_data_type(
            &self,
            _decoder: &dyn crate::program::model::pcode::Decoder,
        ) -> Result<Box<dyn DataType>, crate::program::model::pcode::DecoderException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn encode_name_id_attributes(
            &self,
            _encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
        ) -> io::Result<()> {
            unimplemented!("not exercised by this smoke test")
        }

        fn encode_type_ref(
            &self,
            encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
            size: i32,
        ) -> io::Result<()> {
            encoder.write_signed_integer(ATTRIB_LENGTH, size as i64)
        }

        fn encode_type(
            &self,
            _encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
            _size: i32,
        ) -> io::Result<()> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockConstantPool;

    impl ConstantPool for MockConstantPool {
        fn get_record(&self, reference: &[i64]) -> ConstantPoolRecord {
            let mut record = ConstantPoolRecord {
                tag: STRING_LITERAL,
                token: String::from("placeholder"),
                value: reference[0],
                byte_data: None,
                data_type: Box::new(MockDataType { length: 4 }),
                is_constructor: false,
            };
            record.set_utf8_data("hi");
            record
        }
    }

    #[test]
    fn smoke_test_string_literal_record_encodes_byte_data() {
        let pool: Box<dyn ConstantPool> = Box::new(MockConstantPool);
        let record = pool.get_record(&[7]);

        assert_eq!(record.tag, STRING_LITERAL);
        assert_eq!(record.byte_data.as_deref(), Some(b"hi".as_slice()));

        let mut encoder = MockEncoder::default();
        let dtmanage = MockPcodeDataTypeManager;
        record.encode(&mut encoder, 7, &dtmanage).unwrap();

        assert_eq!(encoder.writes[0], "open:cpoolrec");
        assert_eq!(encoder.writes[1], "uint:ref=7");
        assert_eq!(encoder.writes[2], "str:tag=string");
        assert!(encoder.writes.contains(&"open:data".to_string()));
        assert!(encoder.writes.contains(&"int:length=2".to_string()));
        assert!(encoder.writes.contains(&"str:XMLcontent=68 69 ".to_string()));
        assert!(encoder.writes.contains(&"int:length=4".to_string()));
        assert_eq!(encoder.writes.last().unwrap(), "close:cpoolrec");
    }

    #[test]
    fn smoke_test_primitive_record_encodes_value_element() {
        let mut record = ConstantPoolRecord {
            tag: PRIMITIVE,
            token: String::new(),
            value: 42,
            byte_data: None,
            data_type: Box::new(MockDataType { length: 8 }),
            is_constructor: true,
        };
        // A primitive record with no byte_data falls back to encoding an (empty) token element.
        record.token = String::from("ignored-for-primitive");

        let mut encoder = MockEncoder::default();
        let dtmanage = MockPcodeDataTypeManager;
        record.encode(&mut encoder, 99, &dtmanage).unwrap();

        assert!(encoder.writes.contains(&"str:tag=primitive".to_string()));
        assert!(encoder.writes.contains(&"bool:constructor=true".to_string()));
        assert!(encoder.writes.contains(&"open:value".to_string()));
        assert!(encoder.writes.contains(&"uint:XMLcontent=42".to_string()));
        assert!(encoder
            .writes
            .contains(&"str:XMLcontent=ignored-for-primitive".to_string()));
    }
}
