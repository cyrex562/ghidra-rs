use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_ADDR};
use std::io;
use std::sync::Arc;

/// All the resolved pieces of data needed to build a Varnode.
///
/// Mirrors `ghidra.app.plugin.processors.sleigh.VarnodeData`.
#[derive(Clone, Debug)]
pub struct VarnodeData {
    pub space: Arc<AddressSpace>,
    pub offset: i64,
    pub size: i32,
}

impl VarnodeData {
    /// Constructs a new `VarnodeData` with the given address space, offset, and size.
    pub fn new(space: Arc<AddressSpace>, offset: i64, size: i32) -> Self {
        Self { space, offset, size }
    }

    /// Encodes this data to a stream as an `<addr>` element.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_ADDR)?;
        encoder.write_space(ATTRIB_SPACE, &self.space)?;
        encoder.write_unsigned_integer(ATTRIB_OFFSET, self.offset as u64)?;
        encoder.write_signed_integer(ATTRIB_SIZE, self.size as i64)?;
        encoder.close_element(ELEM_ADDR)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::pcode::ids::{ATTRIB_CONTENT, ATTRIB_VAL, ELEM_DATA};
    use std::io;

    #[derive(Default)]
    struct MockEncoder {
        writes: Vec<String>,
    }

    impl Encoder for MockEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
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
            self.writes.push(format!("str[{}]:{}={}", index, attrib_id.name, val));
            Ok(())
        }

        fn write_space(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            spc: &AddressSpace,
        ) -> io::Result<()> {
            self.writes.push(format!("space:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.writes.push(format!("space[{}]:{}={}", index, attrib_id.name, name));
            Ok(())
        }

        fn write_opcode(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            self.writes.push(format!("opcode:{}={:?}", attrib_id.name, opcode));
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            opcode: i32,
        ) -> io::Result<()> {
            self.writes.push(format!("opcode:{}=#{}", attrib_id.name, opcode));
            Ok(())
        }
    }

    #[test]
    fn new_constructs_varnode_data() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let vn = VarnodeData::new(space, 0x1000, 4);
        assert_eq!(vn.offset, 0x1000);
        assert_eq!(vn.size, 4);
    }

    #[test]
    fn encode_writes_addr_element() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let vn = VarnodeData::new(space, 0x2000, 8);

        let mut encoder = MockEncoder::default();
        vn.encode(&mut encoder).unwrap();

        assert_eq!(encoder.writes[0], "open:addr");
        assert_eq!(encoder.writes[1], "space:space=ram");
        assert_eq!(encoder.writes[2], "uint:offset=8192");
        assert_eq!(encoder.writes[3], "int:size=8");
        assert_eq!(encoder.writes[4], "close:addr");
    }

    #[test]
    fn encode_handles_zero_offset() {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let vn = VarnodeData::new(space, 0, 1);

        let mut encoder = MockEncoder::default();
        vn.encode(&mut encoder).unwrap();

        assert_eq!(encoder.writes.len(), 5);
        assert!(encoder.writes.iter().any(|w| w.contains("uint:offset=0")));
    }

    #[test]
    fn encode_handles_large_offset() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let vn = VarnodeData::new(space, 0x100000000i64, 16);

        let mut encoder = MockEncoder::default();
        vn.encode(&mut encoder).unwrap();

        assert!(encoder.writes.iter().any(|w| w.contains("uint:offset=4294967296")));
    }

    #[test]
    fn encode_preserves_all_fields() {
        let space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0);
        let vn = VarnodeData::new(space, 0x500, 2);

        let mut encoder = MockEncoder::default();
        vn.encode(&mut encoder).unwrap();

        assert!(encoder.writes.iter().any(|w| w.contains("space:space=stack")));
        assert!(encoder.writes.iter().any(|w| w.contains("uint:offset=1280")));
        assert!(encoder.writes.iter().any(|w| w.contains("int:size=2")));
    }
}
