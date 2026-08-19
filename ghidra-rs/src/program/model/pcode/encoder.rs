use super::ids::{AttributeId, ElementId};
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::AddressSpace;
use std::io;

/// An interface for writing structured data to a stream.
///
/// The resulting encoded data is structured similarly to an XML document. The document contains
/// a nested set of *elements*, with labels corresponding to [`ElementId`]. A single element can
/// hold zero or more attributes and zero or more child elements. An attribute holds a primitive
/// data element (boolean, integer, string) and is labeled by an [`AttributeId`]. The document is
/// written using a sequence of `open_element`/`close_element` calls, intermixed with `write_*`
/// calls to encode the data primitives. All primitives written using a `write_*` call are
/// associated with the current open element, and all `write_*` calls for one element must come
/// before opening any child element.
///
/// Port of `ghidra.program.model.pcode.Encoder`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
pub trait Encoder {
    /// Begin a new element in the encoding. The element will have the given [`ElementId`]
    /// annotation and becomes the current element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn open_element(&mut self, elem_id: ElementId) -> io::Result<()>;

    /// End the current element in the encoding. The current element must match the given
    /// annotation or an exception is thrown.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn close_element(&mut self, elem_id: ElementId) -> io::Result<()>;

    /// Write an annotated boolean value into the encoding. The boolean data is associated with
    /// the given [`AttributeId`] annotation and the current open element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()>;

    /// Write an annotated signed integer value into the encoding. The integer is associated with
    /// the given [`AttributeId`] annotation and the current open element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()>;

    /// Write an annotated unsigned integer value into the encoding. The integer is associated
    /// with the given [`AttributeId`] annotation and the current open element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()>;

    /// Write an annotated string into the encoding. The string is associated with the given
    /// [`AttributeId`] annotation and the current open element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()>;

    /// Write an annotated string, using an indexed attribute, into the encoding. Multiple
    /// attributes with a shared name can be written to the same element by calling this method
    /// multiple times with a different index value. The encoding will use attribute ids up to the
    /// base id plus the maximum index passed in. Implementors must be careful to not use other
    /// attributes with ids bigger than the base id within the element taking the indexed
    /// attribute.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_string_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        val: &str,
    ) -> io::Result<()>;

    /// Write an address space reference into the encoding. The address space is associated with
    /// the given [`AttributeId`] annotation and the current open element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()>;

    /// Write an address space reference into the encoding. An address space identified by its
    /// name and unique index is associated with the given annotation and the current open
    /// element.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_space_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        name: &str,
    ) -> io::Result<()>;

    /// Write a p-code operation opcode into the encoding, associating it with the given
    /// annotation.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()>;

    /// Write a p-code operation opcode into the encoding, given the opcode ordinal.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::pcode::ids::{ATTRIB_CONTENT, ATTRIB_VAL, ELEM_DATA};

    #[derive(Default)]
    struct MockEncoder {
        depth: i32,
        writes: Vec<String>,
    }

    impl Encoder for MockEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.depth += 1;
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.depth -= 1;
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }

        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.writes.push(format!("bool:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.writes.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.writes.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.writes.push(format!("str:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            attrib_id: AttributeId,
            index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("str[{}]:{}={}", index, attrib_id.name, val));
            Ok(())
        }

        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.writes
                .push(format!("space:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            attrib_id: AttributeId,
            index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("space[{}]:{}={}", index, attrib_id.name, name));
            Ok(())
        }

        fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}={:?}", attrib_id.name, opcode));
            Ok(())
        }

        fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}=#{}", attrib_id.name, opcode));
            Ok(())
        }
    }

    #[test]
    fn smoke_test_mock_encoder_round_trip() {
        let mut encoder = MockEncoder::default();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);

        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_bool(ATTRIB_CONTENT, true).unwrap();
        encoder.write_unsigned_integer(ATTRIB_VAL, 42).unwrap();
        encoder.write_space(ATTRIB_VAL, &space).unwrap();
        encoder
            .write_opcode(ATTRIB_VAL, OpCode::CpuiCopy)
            .unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert_eq!(encoder.depth, 0);
        // open + bool + unsigned int + space + opcode + close = 6 recorded writes.
        assert_eq!(encoder.writes.len(), 6);
        assert_eq!(encoder.writes[0], "open:data");
        assert!(encoder.writes.contains(&"space:val=ram".to_string()));
    }
}
