//! Real port of `ghidra.program.model.pcode.BlockIfGoto`.
//!
//! Previously a placeholder trait lived at `crate::program::seam_stubs::BlockIfGoto`, exposing
//! only the setter
//! [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
//! needed before this class was ported for real. This file graduates that placeholder in place
//! (following the same precedent `PcodeBlock`/`BlockCopy`/`BlockGoto` used): `seam_stubs.rs`
//! re-exports [`BlockIfGoto`] under its old path.
//!
//! Java's `BlockIfGoto extends BlockGraph`: "block representing an if () goto control flow" --
//! possible multiple incoming edges, 1 output edge if the condition is false, 1 (implied) output
//! edge representing the unstructured control flow if the condition is true, and 1 interior block
//! evaluating the condition. Structurally almost identical to
//! [`BlockGoto`](crate::program::model::pcode::block_goto::BlockGoto) (same `gototarget`/
//! `gototype` fields, same abstract-accessor and `Option`-vs-bare-`Arc` `set_goto_target`
//! reasoning -- see that module's docs), but with two real behavioral differences preserved
//! faithfully from the Java source:
//!
//! 1. In `encodeBody`, `BlockGoto` opens the `<target>` element *before* computing
//!    `getFrontLeaf()`/`calcDepth()`, while `BlockIfGoto` computes them *first* and opens
//!    `<target>` afterward. Both orderings produce identical output (`getFrontLeaf`/`calcDepth`
//!    are pure, with no encoder side effects), but the statement order is preserved verbatim
//!    per this port's "faithfully reproduce real Java" policy.
//! 2. In `decodeBody`, `BlockIfGoto` additionally does `gototarget = null;` right after closing
//!    the `<target>` element and before calling `resolver.addGotoRef(...)` -- redundant on a
//!    freshly-constructed instance (the constructor already nulls it), but real Java source, and
//!    potentially observable if `decode` is ever called to re-decode into a reused instance.
//!    `BlockGoto.decodeBody` has no equivalent line. Reproduced here via an explicit
//!    `self_ifgoto.set_goto_target(None)` call in the same position.

use crate::program::model::pcode::block_graph::BlockGraph;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_DEPTH, ATTRIB_INDEX, ATTRIB_TYPE, ELEM_TARGET};
use crate::program::model::pcode::pcode_block::{get_front_leaf, PcodeBlock};
use std::io;
use std::sync::Arc;

/// Block representing an `if () goto` control flow: possible multiple incoming edges, 1 output
/// edge if the condition is false, 1 (implied) output edge representing the unstructured control
/// flow if the condition is true, and 1 interior block evaluating the condition.
///
/// Port of `ghidra.program.model.pcode.BlockIfGoto`. See this module's docs for what's real vs.
/// an abstract accessor, and for the two behavioral differences from `BlockGoto`.
pub trait BlockIfGoto: BlockGraph {
    /// Stands in for the private `gototarget` field getter (`BlockIfGoto.getGotoTarget()`).
    fn get_goto_target(&self) -> Option<Arc<dyn PcodeBlock>>;

    /// Stands in for the private `gototarget` field setter
    /// (`BlockIfGoto.setGotoTarget(PcodeBlock)`).
    fn set_goto_target(&self, target: Option<Arc<dyn PcodeBlock>>);

    /// Stands in for the private `gototype` field getter (`BlockIfGoto.getGotoType()`); 1=plaingoto,
    /// 2=break, 3=continue.
    fn get_goto_type(&self) -> i32;

    /// Stands in for the private `gototype` field setter, used by
    /// [`block_if_goto_decode_body`] to restore the field from a stream.
    fn set_goto_type(&self, goto_type: i32);

    /// Port of the protected `BlockIfGoto.encodeBody(Encoder)` override. See this module's docs
    /// for the element-open-vs-leaf/depth-computation ordering difference from `BlockGoto`.
    fn block_if_goto_encode_body(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.block_graph_encode_body(encoder)?;
        let target = self
            .get_goto_target()
            .expect("BlockIfGoto::block_if_goto_encode_body: gototarget not set");
        let leaf = get_front_leaf(target.clone());
        let depth = target.calc_depth(Some(leaf.clone()));
        encoder.open_element(ELEM_TARGET)?;
        encoder.write_signed_integer(ATTRIB_INDEX, leaf.get_index() as i64)?;
        encoder.write_signed_integer(ATTRIB_DEPTH, depth as i64)?;
        encoder.write_signed_integer(ATTRIB_TYPE, self.get_goto_type() as i64)?;
        encoder.close_element(ELEM_TARGET)
    }
}

/// Port of the protected `BlockIfGoto.decodeBody(Decoder, BlockMap)` override. Exposed as a free
/// function for the same self-`Arc` reason as
/// [`block_goto_decode_body`](crate::program::model::pcode::block_goto::block_goto_decode_body).
pub fn block_if_goto_decode_body(
    self_arc: &Arc<dyn PcodeBlock>,
    self_ifgoto: &dyn BlockIfGoto,
    decoder: &dyn Decoder,
    resolver: &dyn BlockMap,
) -> Result<(), DecoderException> {
    self_ifgoto.block_graph_decode_body(decoder, resolver)?;
    let el = decoder.open_element_with_id(ELEM_TARGET).map_err(decode_err)?;
    let target = decoder
        .read_signed_integer_with_id(ATTRIB_INDEX)
        .map_err(decode_err)? as i32;
    let depth = decoder
        .read_signed_integer_with_id(ATTRIB_DEPTH)
        .map_err(decode_err)? as i32;
    // Same signed-write/unsigned-read quirk as `BlockGoto.decodeBody`; reproduced faithfully.
    let goto_type = decoder
        .read_unsigned_integer_with_id(ATTRIB_TYPE)
        .map_err(decode_err)? as i32;
    self_ifgoto.set_goto_type(goto_type);
    decoder.close_element(el).map_err(decode_err)?;
    // Real Java line: `gototarget = null;`, redundant on a fresh instance but reproduced
    // faithfully. See this module's docs.
    self_ifgoto.set_goto_target(None);
    resolver.add_goto_ref(self_arc.clone(), target, depth);
    Ok(())
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockIfGoto", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::pcode_block::PCODE_BLOCK_IFGOTO;
    use std::cell::{Cell, RefCell};

    struct MockIfGoto {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        target: RefCell<Option<Arc<dyn PcodeBlock>>>,
        goto_type: Cell<i32>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl MockIfGoto {
        fn new() -> Arc<MockIfGoto> {
            let block = Arc::new(MockIfGoto {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
                target: RefCell::new(None),
                goto_type: Cell::new(1),
                self_ref: RefCell::new(None),
            });
            *block.self_ref.borrow_mut() = Some(block.clone() as Arc<dyn PcodeBlock>);
            block
        }
    }

    impl PcodeBlock for MockIfGoto {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_IFGOTO
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
        fn as_block_graph(&self) -> Option<&dyn BlockGraph> {
            Some(self)
        }
    }

    impl BlockGraph for MockIfGoto {
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

    impl BlockIfGoto for MockIfGoto {
        fn get_goto_target(&self) -> Option<Arc<dyn PcodeBlock>> {
            self.target.borrow().clone()
        }
        fn set_goto_target(&self, target: Option<Arc<dyn PcodeBlock>>) {
            *self.target.borrow_mut() = target;
        }
        fn get_goto_type(&self) -> i32 {
            self.goto_type.get()
        }
        fn set_goto_type(&self, goto_type: i32) {
            self.goto_type.set(goto_type);
        }
    }

    struct MockLeaf {
        index: Cell<i32>,
        parent: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }
    impl MockLeaf {
        fn new(index: i32) -> Arc<MockLeaf> {
            Arc::new(MockLeaf {
                index: Cell::new(index),
                parent: RefCell::new(None),
            })
        }
    }
    impl PcodeBlock for MockLeaf {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            crate::program::model::pcode::pcode_block::PCODE_BLOCK_BASIC
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
        fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
            self.parent.borrow().clone()
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockIfGoto::new();
        let dyn_block: &dyn BlockIfGoto = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_IFGOTO);
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
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
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
    fn block_if_goto_encode_body_writes_target_leaf_depth_and_type() {
        let block = MockIfGoto::new();
        block.set_goto_type(3);
        let leaf = MockLeaf::new(4);
        let target = MockIfGoto::new();
        target.push_block(leaf.clone() as Arc<dyn PcodeBlock>);
        *leaf.parent.borrow_mut() = Some(target.clone() as Arc<dyn PcodeBlock>);

        block.set_goto_target(Some(target.clone() as Arc<dyn PcodeBlock>));

        let mut encoder = MockEncoder {
            writes: RefCell::new(Vec::new()),
        };
        block.block_if_goto_encode_body(&mut encoder).unwrap();

        assert_eq!(
            *encoder.writes.borrow(),
            vec![
                "open:target".to_string(),
                "int:index=4".to_string(),
                "int:depth=1".to_string(),
                "int:type=3".to_string(),
                "close:target".to_string(),
            ]
        );
    }

    struct MockDecoder {
        end_index: i32,
        depth: i32,
        goto_type: u64,
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
            Ok(ELEM_TARGET.id)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_TARGET.id)
        }
        fn open_element_with_id(
            &self,
            _elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> Result<i32, DecoderError> {
            Ok(ELEM_TARGET.id)
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
            attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<i64, DecoderError> {
            if attrib_id.name == ATTRIB_INDEX.name {
                Ok(self.end_index as i64)
            } else {
                Ok(self.depth as i64)
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<u64, DecoderError> {
            Ok(self.goto_type)
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<String, DecoderError> {
            unimplemented!()
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

    struct MockResolver {
        goto_refs: RefCell<Vec<(Arc<dyn PcodeBlock>, i32, i32)>>,
    }
    impl BlockMap for MockResolver {
        fn get_address_factory(
            &self,
        ) -> Arc<dyn crate::program::model::address::factory::AddressFactory> {
            unimplemented!()
        }
        fn resolve_block(&self, _block_type: i32) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn new_child(&self) -> Box<dyn BlockMap> {
            // See the equivalent comment in `block_goto.rs`'s `MockResolver::new_child`: the
            // child resolver built by `block_graph_decode_body`'s "super" call is discarded
            // internally and never touched by these tests beyond construction.
            Box::new(MockResolver {
                goto_refs: RefCell::new(Vec::new()),
            })
        }
        fn level_list_len(&self) -> usize {
            0
        }
        fn level_list_get(&self, _i: usize) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn level_list_push(&self, _block: Arc<dyn PcodeBlock>) {}
        fn level_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {}
        fn leaf_list_len(&self) -> usize {
            0
        }
        fn leaf_list_get(&self, _i: usize) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn leaf_list_push(&self, _block: Arc<dyn PcodeBlock>) {}
        fn leaf_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {}
        fn goto_ref_len(&self) -> usize {
            0
        }
        fn goto_ref_get(&self, _i: usize) -> (Arc<dyn PcodeBlock>, i32, i32) {
            unimplemented!()
        }
        fn goto_ref_push(&self, gotoblock: Arc<dyn PcodeBlock>, root_index: i32, depth: i32) {
            self.goto_refs.borrow_mut().push((gotoblock, root_index, depth));
        }
    }

    #[test]
    fn block_if_goto_decode_body_nulls_target_and_adds_goto_ref() {
        let block = MockIfGoto::new();
        // Pre-seed a (stale) target to prove decodeBody's `gototarget = null;` line actually
        // clears it, matching the real Java source.
        block.set_goto_target(Some(MockLeaf::new(1) as Arc<dyn PcodeBlock>));
        let self_arc = block.self_ref.borrow().clone().unwrap();
        let decoder = MockDecoder {
            end_index: 6,
            depth: 2,
            goto_type: 3,
        };
        let resolver = MockResolver {
            goto_refs: RefCell::new(Vec::new()),
        };

        block_if_goto_decode_body(&self_arc, &*block, &decoder, &resolver).unwrap();

        assert_eq!(block.get_goto_type(), 3);
        assert!(block.get_goto_target().is_none());
        let refs = resolver.goto_refs.borrow();
        assert_eq!(refs.len(), 1);
        assert!(Arc::ptr_eq(&refs[0].0, &self_arc));
        assert_eq!(refs[0].1, 6);
        assert_eq!(refs[0].2, 2);
    }
}
