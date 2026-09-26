//! Models `ghidra.pcodeCPort.space.OtherSpace`.

use super::addr_space::AddrSpace;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_SPACE_OTHER;
use std::io;

/// A special address space for processor-specific storage locations.
///
/// Models `ghidra.pcodeCPort.space.OtherSpace`, which extends [`AddrSpace`] and overrides
/// `print_raw` and `encode`. The Java constructors set up the space's identity (translator,
/// type `IPTR_PROCESSOR`, name/index, flags for `heritaged` and `is_otherspace`) via the
/// `AddrSpace` superclass constructor; that construction-time behavior has no equivalent as
/// trait methods and is left to implementors.
pub trait OtherSpace: AddrSpace {
    /// Debug form for raw dumps: the offset formatted as unpadded hex, and the translator's
    /// expected default size.
    ///
    /// Overrides [`AddrSpace::print_raw`]: unlike a normal space, an "other" space's offset is
    /// printed unscaled and unpadded (no word-alignment remainder computation, no scaling).
    fn print_raw(&self, offset: i64) -> (String, i32) {
        let expect_size = self.get_trans().get_default_size();
        (format!("0x{:x}", offset as u64), expect_size)
    }

    /// Encodes this "other" space to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SPACE_OTHER)?;
        self.encode_basic_attributes(encoder)?;
        encoder.close_element(ELEM_SPACE_OTHER)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::space::SpaceType;
    use crate::decompiler::translate::Translate;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::decompiler::opcodes::op_code::OpCode;

    struct MockTranslate;
    impl crate::decompiler::translate::BasicSpaceProvider for MockTranslate {
        fn get_default_space(&self) -> &dyn AddrSpace {
            unimplemented!("overridden by get_default_size below")
        }

        fn get_constant_space(&self) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }
    }
    impl Translate for MockTranslate {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn alignment(&self) -> i32 {
            1
        }

        fn get_unique_base(&self) -> i64 {
            0
        }

        fn get_iop_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_fspec_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_stack_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_unique_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn num_spaces(&self) -> i32 {
            0
        }

        fn get_space(&self, _i: i32) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }

        fn no_high_ptr(&self) -> &dyn crate::decompiler::seam_stubs::RangeList {
            unimplemented!("not exercised by these tests")
        }

        fn instruction_length(&self, _baseaddr: &crate::program::model::address::Address) -> i32 {
            0
        }

        fn print_assembly(
            &self,
            _out: &mut dyn std::io::Write,
            _size: i32,
            _baseaddr: &crate::program::model::address::Address,
        ) -> std::io::Result<i32> {
            Ok(0)
        }

        fn get_default_size(&self) -> i32 {
            4
        }
    }

    struct MockOtherSpace;

    impl AddrSpace for MockOtherSpace {
        fn name(&self) -> &str {
            "other"
        }

        fn get_trans(&self) -> &dyn Translate {
            &MockTranslate
        }

        fn get_type(&self) -> SpaceType {
            SpaceType::IptrProcessor
        }

        fn get_delay(&self) -> i32 {
            0
        }

        fn get_index(&self) -> i32 {
            1
        }

        fn get_word_size(&self) -> i32 {
            1
        }

        fn get_scale(&self) -> i32 {
            0
        }

        fn get_addr_size(&self) -> i32 {
            8
        }

        fn get_mask(&self) -> i64 {
            -1
        }

        fn get_short_cut(&self) -> char {
            'O'
        }

        fn flags(&self) -> i32 {
            super::super::addr_space::IS_OTHERSPACE
        }
    }

    impl OtherSpace for MockOtherSpace {}

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }

        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }

        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            _attrib_id: AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: OpCode) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    fn mock() -> MockOtherSpace {
        MockOtherSpace
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let space = mock();
        let dyn_space: &dyn OtherSpace = &space;
        assert_eq!(dyn_space.name(), "other");
        assert!(dyn_space.is_other_space());
    }

    #[test]
    fn print_raw_formats_offset_unpadded_and_unscaled() {
        let space = mock();
        let (text, expect_size) = OtherSpace::print_raw(&space, 0x1234);
        assert_eq!(text, "0x1234");
        assert_eq!(expect_size, 4);
    }

    #[test]
    fn print_raw_matches_java_long_to_hex_string_for_negative_offsets() {
        let space = mock();
        let (text, _) = OtherSpace::print_raw(&space, -1);
        assert_eq!(text, "0xffffffffffffffff");
    }

    #[test]
    fn encode_uses_space_other_element() {
        let space = mock();
        let mut encoder = RecordingEncoder::default();
        OtherSpace::encode(&space, &mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["space_other"]);
        assert_eq!(encoder.closed, vec!["space_other"]);
    }
}
