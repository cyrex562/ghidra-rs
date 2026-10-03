use super::{AttributeId, CachedEncoder};
use std::io;

/// This is an encoder that produces encodings that can be retroactively patched.
/// The contained encoding is expected to be byte based. The user can record a position
/// in the encoding by calling the [`size`](PatchEncoder::size) method in the middle of
/// encoding, and then later use the returned offset to call
/// [`patch_integer_attribute`](PatchEncoder::patch_integer_attribute) and modify the encoding
/// at the recorded position.
///
/// Port of `ghidra.program.model.pcode.PatchEncoder`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
pub trait PatchEncoder: CachedEncoder {
    /// Write a given raw spaceid (as returned by `AddressSpace.getSpaceID()`) as an attribute.
    /// The effect is the same as if `write_space()` was called with the `AddressSpace` matching
    /// the spaceid, i.e. the decoder will read this as just a space attribute.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    fn write_space_id(&mut self, attrib_id: AttributeId, space_id: i64) -> io::Result<()>;

    /// The returned value can be used as a position for later modification.
    ///
    /// # Returns
    /// the number of bytes written to this stream so far
    fn size(&self) -> i32;

    /// Replace an integer attribute for the element at the given position.
    /// The position is assumed to be at an open directive for the element containing the
    /// attribute to be patched.
    ///
    /// # Returns
    /// true if the attribute is successfully patched
    fn patch_integer_attribute(&mut self, pos: i32, attrib_id: AttributeId, val: i64) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::op_code::OpCode;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::pcode::ids::{ATTRIB_SPACE, ATTRIB_VAL, ELEM_DATA};
    use crate::program::model::pcode::Encoder;
    use std::io::Cursor;

    /// A minimal byte-based patchable encoder: integers are written as a 1-byte marker followed
    /// by a fixed 8-byte big-endian value, so a previously recorded `size()` position can be
    /// revisited later to overwrite just the value bytes.
    #[derive(Default)]
    struct MockPatchEncoder {
        bytes: Vec<u8>,
    }

    impl MockPatchEncoder {
        fn new() -> Self {
            Self::default()
        }
    }

    impl crate::program::model::pcode::Encoder for MockPatchEncoder {
        fn open_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            self.bytes.push(b'<');
            Ok(())
        }

        fn close_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            self.bytes.push(b'>');
            Ok(())
        }

        fn write_bool(&mut self, _attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.bytes.push(b'B');
            self.bytes.push(val as u8);
            Ok(())
        }

        fn write_signed_integer(&mut self, _attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.bytes.push(b'I');
            self.bytes.extend_from_slice(&val.to_be_bytes());
            Ok(())
        }

        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.bytes.push(b'U');
            self.bytes.extend_from_slice(&(val as i64).to_be_bytes());
            Ok(())
        }

        fn write_string(&mut self, _attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.bytes.extend_from_slice(val.as_bytes());
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(val.as_bytes());
            Ok(())
        }

        fn write_space(&mut self, _attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.bytes.extend_from_slice(spc.name().as_bytes());
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.bytes.extend_from_slice(name.as_bytes());
            Ok(())
        }

        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: OpCode) -> io::Result<()> {
            self.bytes.push(b'O');
            Ok(())
        }

        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            self.bytes.push(b'O');
            Ok(())
        }
    }

    impl CachedEncoder for MockPatchEncoder {
        fn clear(&mut self) {
            self.bytes.clear();
        }

        fn is_empty(&self) -> bool {
            self.bytes.is_empty()
        }

        fn write_to(&self, writer: &mut dyn io::Write) -> io::Result<()> {
            writer.write_all(&self.bytes)
        }
    }

    impl PatchEncoder for MockPatchEncoder {
        fn write_space_id(&mut self, attrib_id: AttributeId, space_id: i64) -> io::Result<()> {
            self.write_signed_integer(attrib_id, space_id)
        }

        fn size(&self) -> i32 {
            self.bytes.len() as i32
        }

        fn patch_integer_attribute(&mut self, pos: i32, _attrib_id: AttributeId, val: i64) -> bool {
            let pos = pos as usize;
            let Some(&marker) = self.bytes.get(pos) else {
                return false;
            };
            if marker != b'I' && marker != b'U' {
                return false;
            }
            if pos + 9 > self.bytes.len() {
                return false;
            }
            self.bytes[pos + 1..pos + 9].copy_from_slice(&val.to_be_bytes());
            true
        }
    }

    fn read_i64_at(bytes: &[u8], pos: i32) -> i64 {
        let pos = pos as usize;
        i64::from_be_bytes(bytes[pos + 1..pos + 9].try_into().unwrap())
    }

    #[test]
    fn test_patch_integer_attribute_round_trip() {
        let mut encoder = MockPatchEncoder::new();
        encoder.open_element(ELEM_DATA).unwrap();
        let pos = encoder.size();
        encoder.write_signed_integer(ATTRIB_VAL, 111).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        let mut output = Cursor::new(Vec::new());
        encoder.write_to(&mut output).unwrap();
        assert_eq!(read_i64_at(&output.into_inner(), pos), 111);

        assert!(encoder.patch_integer_attribute(pos, ATTRIB_VAL, 999));

        let mut output = Cursor::new(Vec::new());
        encoder.write_to(&mut output).unwrap();
        assert_eq!(read_i64_at(&output.into_inner(), pos), 999);
    }

    #[test]
    fn test_patch_integer_attribute_rejects_bad_position() {
        let mut encoder = MockPatchEncoder::new();
        encoder.write_bool(ATTRIB_VAL, true).unwrap();
        // Position 0 holds a bool marker, not an integer one, so the patch must fail.
        assert!(!encoder.patch_integer_attribute(0, ATTRIB_VAL, 42));
        // Wildly out-of-range position must also fail rather than panic.
        assert!(!encoder.patch_integer_attribute(9999, ATTRIB_VAL, 42));
    }

    #[test]
    fn test_patch_encoder_is_object_safe() {
        let mut encoder: Box<dyn PatchEncoder> = Box::new(MockPatchEncoder::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_space_id(ATTRIB_SPACE, 5).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert!(!encoder.is_empty());
        assert!(encoder.size() > 0);
    }
}
