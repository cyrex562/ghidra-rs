//! Real port of `ghidra.program.model.pcode.BlockCondition`.
//!
//! Java's `BlockCondition extends BlockGraph`: block representing an `&&`/`||` control-flow path
//! within a conditional expression -- possible multiple incoming edges, 2 outgoing edges (one for
//! true control flow, one for false), one "initial" condition block with 2 outgoing edges, and
//! one "secondary" condition block with 2 outgoing edges and exactly 1 incoming edge from
//! "initial".
//!
//! The private `opcode` field (`PcodeOp.BOOL_AND`/`PcodeOp.BOOL_OR`) is exposed as an abstract
//! accessor, matching this crate's established convention for the same issue (see `BlockGraph`'s/
//! `BlockCopy`'s module docs). Modeled as
//! [`OpCode`](crate::program::model::pcode::OpCode) rather than a raw `int`, matching
//! [`PcodeOpAST::get_opcode`](crate::program::model::pcode::pcode_op_ast::PcodeOpAST::get_opcode)'s
//! existing convention for the same field shape elsewhere in this crate.
//!
//! `encodeHeader`/`decodeHeader` are exposed under `block_condition_`-prefixed names instead of
//! `encode_header`/`decode_header`, matching this crate's convention for the usual
//! supertrait-name-collision issue (see `PcodeBlockBasic`'s `basic_encode_body`/
//! `basic_decode_body`). Unlike `BlockGraph` (which doesn't override `encodeHeader`/
//! `decodeHeader` at all), these call straight through to the inherited `PcodeBlock::encode_header`/
//! `decode_header`, matching Java's `super.encodeHeader(encoder)`/`super.decodeHeader(decoder)`
//! (which resolve directly to `PcodeBlock`, since `BlockGraph` has no override of its own).
//!
//! `decodeHeader`'s `catch (UnknownInstructionException e) { opcode = PcodeOp.BOOL_AND; }` is
//! reproduced via [`OpCode::from_mnemonic`](crate::program::model::pcode::OpCode::from_mnemonic)
//! returning `None` on an unrecognized mnemonic, falling back to `OpCode::BoolAnd` -- see that
//! method's doc for the one known (practically unreachable) divergence from Java's real
//! `opcodeTable`.

use crate::program::model::pcode::block_graph::BlockGraph;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ATTRIB_OPCODE;
use crate::program::model::pcode::OpCode;
use std::io;

/// Block representing an `&&` or `||` control flow path within a conditional expression: possible
/// multiple incoming edges, 2 outgoing edges (true/false), one "initial" condition block with 2
/// outgoing edges, and one "secondary" condition block with 2 outgoing edges and exactly 1
/// incoming edge from "initial".
///
/// Port of `ghidra.program.model.pcode.BlockCondition`. See this module's docs for what's real
/// vs. an abstract accessor.
pub trait BlockCondition: BlockGraph {
    /// Stands in for the private `opcode` field getter (`BlockCondition.getOpcode()`); the type
    /// of boolean operation (`BOOL_AND`/`BOOL_OR`).
    fn get_opcode(&self) -> OpCode;

    /// Stands in for the private `opcode` field setter, used by
    /// [`block_condition_decode_header`](BlockCondition::block_condition_decode_header) to
    /// restore the field from a stream.
    fn set_opcode(&self, opcode: OpCode);

    /// Port of the protected `BlockCondition.encodeHeader(Encoder)` override.
    fn block_condition_encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode_header(encoder)?;
        encoder.write_string(ATTRIB_OPCODE, self.get_opcode().mnemonic())
    }

    /// Port of the protected `BlockCondition.decodeHeader(Decoder)` override.
    fn block_condition_decode_header(&self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        self.decode_header(decoder)?;
        let opcodename = decoder
            .read_string_with_id(ATTRIB_OPCODE)
            .map_err(decode_err)?;
        let opcode = OpCode::from_mnemonic(&opcodename).unwrap_or(OpCode::BoolAnd);
        self.set_opcode(opcode);
        Ok(())
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockCondition", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_CONDITION};
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::sync::Arc;

    struct MockCondition {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        opcode: Cell<OpCode>,
    }

    impl MockCondition {
        fn new() -> Arc<MockCondition> {
            Arc::new(MockCondition {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
                opcode: Cell::new(OpCode::BoolAnd),
            })
        }
    }

    impl PcodeBlock for MockCondition {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_CONDITION
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
        fn decode(
            &self,
            _decoder: &dyn Decoder,
            _resolver: &dyn BlockMap,
        ) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    impl BlockGraph for MockCondition {
        fn get_size(&self) -> usize {
            self.blocks.borrow().len()
        }
        fn get_block(&self, i: usize) -> Arc<dyn PcodeBlock> {
            self.blocks.borrow()[i].clone()
        }
        fn push_block(&self, bl: Arc<dyn PcodeBlock>) {
            self.blocks.borrow_mut().push(bl);
        }
        fn get_max_index(&self) -> i32 {
            self.max_index.get()
        }
        fn set_max_index(&self, max_index: i32) {
            self.max_index.set(max_index);
        }
        fn decode_graph(&self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    impl BlockCondition for MockCondition {
        fn get_opcode(&self) -> OpCode {
            self.opcode.get()
        }
        fn set_opcode(&self, opcode: OpCode) {
            self.opcode.set(opcode);
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockCondition::new();
        let dyn_block: &dyn BlockCondition = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_CONDITION);
        // Constructor default in Java: opcode = PcodeOp.BOOL_AND.
        assert_eq!(dyn_block.get_opcode(), OpCode::BoolAnd);
    }

    #[test]
    fn structural_composition_holds_initial_and_secondary_blocks() {
        let block = MockCondition::new();
        let initial: Arc<dyn PcodeBlock> = MockCondition::new();
        let secondary: Arc<dyn PcodeBlock> = MockCondition::new();
        block.push_block(initial.clone());
        block.push_block(secondary.clone());
        assert_eq!(block.get_size(), 2);
        assert!(Arc::ptr_eq(&block.get_block(0), &initial));
        assert!(Arc::ptr_eq(&block.get_block(1), &secondary));
    }

    struct MockEncoder {
        writes: RefCell<Vec<String>>,
    }
    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_string(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: &str,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("str:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn block_condition_encode_header_writes_index_then_opcode_mnemonic() {
        let block = MockCondition::new();
        block.set_index(5);
        block.set_opcode(OpCode::BoolOr);

        let mut encoder = MockEncoder {
            writes: RefCell::new(Vec::new()),
        };
        block.block_condition_encode_header(&mut encoder).unwrap();

        assert_eq!(
            *encoder.writes.borrow(),
            vec!["int:index=5".to_string(), "str:opcode=BOOL_OR".to_string()]
        );
    }

    struct MockDecoder {
        index: i64,
        opcode_name: String,
    }
    impl Decoder for MockDecoder {
        fn get_address_factory(
            &self,
        ) -> Arc<dyn crate::program::model::address::factory::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(
            &self,
            _factory: Arc<dyn crate::program::model::address::factory::AddressFactory>,
        ) {
        }
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element_with_id(
            &self,
            _elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<i64, DecoderError> {
            Ok(self.index)
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<String, DecoderError> {
            Ok(self.opcode_name.clone())
        }
        fn read_space(
            &self,
        ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    #[test]
    fn block_condition_decode_header_resolves_known_mnemonic() {
        let block = MockCondition::new();
        let decoder = MockDecoder {
            index: 8,
            opcode_name: "BOOL_OR".to_string(),
        };
        block.block_condition_decode_header(&decoder).unwrap();
        assert_eq!(block.get_index(), 8);
        assert_eq!(block.get_opcode(), OpCode::BoolOr);
    }

    #[test]
    fn block_condition_decode_header_falls_back_to_bool_and_on_unknown_mnemonic() {
        let block = MockCondition::new();
        block.set_opcode(OpCode::BoolOr); // prove it actually gets overwritten
        let decoder = MockDecoder {
            index: 1,
            opcode_name: "NOT_A_REAL_MNEMONIC".to_string(),
        };
        block.block_condition_decode_header(&decoder).unwrap();
        // Matches Java's `catch (UnknownInstructionException e) { opcode = PcodeOp.BOOL_AND; }`.
        assert_eq!(block.get_opcode(), OpCode::BoolAnd);
    }
}
