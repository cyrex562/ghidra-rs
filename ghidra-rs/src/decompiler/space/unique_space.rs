//! Models `ghidra.pcodeCPort.space.UniqueSpace`.

use crate::decompiler::seam_stubs::AddrSpace;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_SPACE_UNIQUE;
use std::io;

/// The address space used as a pool for temporary registers.
///
/// Models `ghidra.pcodeCPort.space.UniqueSpace`, which extends [`AddrSpace`] (stubbed pending
/// its own port) and overrides only `encode`. The Java constructors set up the space's identity
/// (translator, index, `hasphysical` flag) via the `AddrSpace` superclass constructor; that
/// construction-time behavior has no equivalent as trait methods and is left to implementors.
pub trait UniqueSpace: AddrSpace {
    /// Encodes this unique space to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SPACE_UNIQUE)?;
        self.encode_basic_attributes(encoder)?;
        encoder.close_element(ELEM_SPACE_UNIQUE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::decompiler::opcodes::op_code::OpCode;

    struct MockUniqueSpace;

    impl AddrSpace for MockUniqueSpace {
        fn encode_basic_attributes(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
            encoder.write_bool(AttributeId::new("dummy", 0), true)
        }
    }

    impl UniqueSpace for MockUniqueSpace {}

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        bools: Vec<bool>,
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

        fn write_bool(&mut self, _attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.bools.push(val);
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

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let space = MockUniqueSpace;
        let dyn_space: &dyn UniqueSpace = &space;
        let mut encoder = RecordingEncoder::default();
        dyn_space.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["space_unique"]);
        assert_eq!(encoder.closed, vec!["space_unique"]);
        assert_eq!(encoder.bools, vec![true]);
    }
}
