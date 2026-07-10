use super::Encoder;
use std::io;

/// An Encoder that holds its bytes in memory (where they can possibly be edited) and
/// can then finally write them all to a writer via a call to writeTo().
///
/// Port of `ghidra.program.model.pcode.CachedEncoder`.
pub trait CachedEncoder: Encoder {
    /// Clear any state associated with the encoder.
    /// The encoder should be ready to write a new document after this call.
    fn clear(&mut self);

    /// The encoder is considered empty if the writeTo() method would output zero bytes.
    ///
    /// # Returns
    /// true if there are no bytes in the encoder
    fn is_empty(&self) -> bool;

    /// Dump all the accumulated bytes in this encoder to the writer.
    ///
    /// # Arguments
    /// * `writer` - the output writer
    ///
    /// # Errors
    /// Returns an error for problems during the write operation
    fn write_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::op_code::OpCode;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::pcode::ids::{ATTRIB_CONTENT, ATTRIB_VAL, ELEM_DATA};
    use std::io::Cursor;

    struct MockCachedEncoder {
        depth: i32,
        bytes: Vec<u8>,
    }

    impl MockCachedEncoder {
        fn new() -> Self {
            Self {
                depth: 0,
                bytes: Vec::new(),
            }
        }
    }

    impl Encoder for MockCachedEncoder {
        fn open_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> io::Result<()> {
            self.depth += 1;
            self.bytes.push(b'<');
            Ok(())
        }

        fn close_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> io::Result<()> {
            self.depth -= 1;
            self.bytes.push(b'>');
            Ok(())
        }

        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            self.bytes.push(b'B');
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: i64,
        ) -> io::Result<()> {
            self.bytes.push(b'I');
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            self.bytes.push(b'U');
            Ok(())
        }

        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            val: &str,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(val.as_bytes());
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(val.as_bytes());
            Ok(())
        }

        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(spc.name().as_bytes());
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(name.as_bytes());
            Ok(())
        }

        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: OpCode,
        ) -> io::Result<()> {
            self.bytes.push(b'O');
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            self.bytes.push(b'O');
            Ok(())
        }
    }

    impl CachedEncoder for MockCachedEncoder {
        fn clear(&mut self) {
            self.bytes.clear();
            self.depth = 0;
        }

        fn is_empty(&self) -> bool {
            self.bytes.is_empty()
        }

        fn write_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            writer.write_all(&self.bytes)
        }
    }

    #[test]
    fn test_cached_encoder_empty() {
        let encoder = MockCachedEncoder::new();
        assert!(encoder.is_empty());
    }

    #[test]
    fn test_cached_encoder_after_write() {
        let mut encoder = MockCachedEncoder::new();
        encoder
            .write_string(ATTRIB_VAL, "test")
            .expect("write_string failed");
        assert!(!encoder.is_empty());
    }

    #[test]
    fn test_cached_encoder_clear() {
        let mut encoder = MockCachedEncoder::new();
        encoder
            .write_string(ATTRIB_VAL, "test")
            .expect("write_string failed");
        assert!(!encoder.is_empty());

        encoder.clear();
        assert!(encoder.is_empty());
    }

    #[test]
    fn test_cached_encoder_write_to() {
        let mut encoder = MockCachedEncoder::new();
        encoder
            .write_string(ATTRIB_VAL, "hello")
            .expect("write_string failed");

        let mut output = Cursor::new(Vec::new());
        encoder
            .write_to(&mut output)
            .expect("write_to failed");

        let bytes = output.into_inner();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_cached_encoder_write_to_empty() {
        let encoder = MockCachedEncoder::new();
        let mut output = Cursor::new(Vec::new());
        encoder
            .write_to(&mut output)
            .expect("write_to failed");

        let bytes = output.into_inner();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_cached_encoder_multiple_operations() {
        let mut encoder = MockCachedEncoder::new();
        encoder
            .open_element(ELEM_DATA)
            .expect("open_element failed");
        encoder
            .write_bool(ATTRIB_CONTENT, true)
            .expect("write_bool failed");
        encoder
            .write_string(ATTRIB_VAL, "value")
            .expect("write_string failed");
        encoder
            .close_element(ELEM_DATA)
            .expect("close_element failed");

        assert!(!encoder.is_empty());

        let mut output = Cursor::new(Vec::new());
        encoder
            .write_to(&mut output)
            .expect("write_to failed");

        let bytes = output.into_inner();
        assert_eq!(bytes, b"<Bvalue>");
        assert_eq!(encoder.depth, 0);
    }
}
