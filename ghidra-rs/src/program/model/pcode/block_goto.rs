//! Real port of `ghidra.program.model.pcode.BlockGoto`.
//!
//! Previously a placeholder trait lived at `crate::program::seam_stubs::BlockGoto`, exposing only
//! the setter
//! [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
//! needed before this class was ported for real. This file graduates that placeholder in place
//! (following the same precedent `PcodeBlock`/`BlockCopy` used): `seam_stubs.rs` re-exports
//! [`BlockGoto`] under its old path, so `BlockMap`'s existing call sites (and its test mocks) keep
//! compiling, modulo the `set_goto_target` signature change documented below.
//!
//! Java's `BlockGoto extends BlockGraph`: "a plain goto block" with possibly multiple incoming
//! edges, no real outgoing edges, and one implied outgoing edge representing the unstructured
//! goto. The private `gototarget`/`gototype` fields are exposed as abstract accessor methods a
//! concrete implementation supplies, matching this crate's established convention (see
//! `BlockGraph`'s/`BlockCopy`'s module docs).
//!
//! [`set_goto_target`](BlockGoto::set_goto_target) now takes `Option<Arc<dyn PcodeBlock>>` rather
//! than a bare `Arc<dyn PcodeBlock>` (the placeholder's original signature): the Java field is
//! nullable (`gototarget = null;` in the constructor), and
//! [`BlockIfGoto`](crate::program::model::pcode::block_if_goto::BlockIfGoto)'s real `decodeBody`
//! explicitly re-nulls it after resolving a goto reference, which needs a way to pass `None`
//! through the same setter. `BlockMap::resolve_goto_references`'s one call site is updated to
//! pass `Some(bl)` accordingly.
//!
//! `encodeBody`/`decodeBody` are exposed under `block_goto_`-prefixed names instead of
//! `encode_body`/`decode_body`, matching this crate's existing convention for the same
//! supertrait-collision issue (see `BlockGraph`'s `block_graph_encode_body`/
//! `block_graph_decode_body`). [`block_goto_decode_body`] additionally needs `this` as an owned
//! `Arc<dyn PcodeBlock>` (`resolver.addGotoRef(this, target, depth)` in Java), which a `&self`
//! method cannot produce generically -- the same limitation already documented on
//! [`PcodeBlock::add_in_edge`](crate::program::model::pcode::pcode_block::PcodeBlock::add_in_edge)
//! and `PcodeBlock`'s `decode_next_in_edge`/`decode_edges` free functions -- so it is exposed as a
//! free function taking the owning block's self-`Arc<dyn PcodeBlock>` explicitly, alongside a
//! `&dyn BlockGoto` reference for the block-specific setter it also needs.

use crate::program::model::pcode::block_graph::BlockGraph;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_DEPTH, ATTRIB_INDEX, ATTRIB_TYPE, ELEM_TARGET};
use crate::program::model::pcode::pcode_block::{get_front_leaf, PcodeBlock};
use std::io;
use std::sync::Arc;

/// A "plain" goto block: possible multiple incoming edges, no outgoing edges, 1 (implied)
/// outgoing edge representing the unstructured goto.
///
/// Port of `ghidra.program.model.pcode.BlockGoto`. See this module's docs for what's real vs. an
/// abstract accessor.
pub trait BlockGoto: BlockGraph {
    /// Stands in for the private `gototarget` field getter (`BlockGoto.getGotoTarget()`).
    fn get_goto_target(&self) -> Option<Arc<dyn PcodeBlock>>;

    /// Stands in for the private `gototarget` field setter (`BlockGoto.setGotoTarget(PcodeBlock)`).
    /// See this module's docs for why this takes `Option` rather than a bare `Arc`.
    fn set_goto_target(&self, target: Option<Arc<dyn PcodeBlock>>);

    /// Stands in for the private `gototype` field getter (`BlockGoto.getGotoType()`); 1=plaingoto,
    /// 2=break, 4=continue.
    fn get_goto_type(&self) -> i32;

    /// Stands in for the private `gototype` field setter, used by
    /// [`block_goto_decode_body`] to restore the field from a stream.
    fn set_goto_type(&self, goto_type: i32);

    /// Port of the protected `BlockGoto.encodeBody(Encoder)` override. See this module's docs for
    /// the naming.
    fn block_goto_encode_body(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.block_graph_encode_body(encoder)?;
        encoder.open_element(ELEM_TARGET)?;
        let target = self
            .get_goto_target()
            .expect("BlockGoto::block_goto_encode_body: gototarget not set");
        let leaf = get_front_leaf(target.clone());
        let depth = target.calc_depth(Some(leaf.clone()));
        encoder.write_signed_integer(ATTRIB_INDEX, leaf.get_index() as i64)?;
        encoder.write_signed_integer(ATTRIB_DEPTH, depth as i64)?;
        encoder.write_signed_integer(ATTRIB_TYPE, self.get_goto_type() as i64)?;
        encoder.close_element(ELEM_TARGET)
    }
}

/// Port of the protected `BlockGoto.decodeBody(Decoder, BlockMap)` override. Exposed as a free
/// function; see this module's docs for why.
pub fn block_goto_decode_body(
    self_arc: &Arc<dyn PcodeBlock>,
    self_goto: &dyn BlockGoto,
    decoder: &dyn Decoder,
    resolver: &dyn BlockMap,
) -> Result<(), DecoderException> {
    self_goto.block_graph_decode_body(decoder, resolver)?;
    let el = decoder.open_element_with_id(ELEM_TARGET).map_err(decode_err)?;
    let target = decoder
        .read_signed_integer_with_id(ATTRIB_INDEX)
        .map_err(decode_err)? as i32;
    let depth = decoder
        .read_signed_integer_with_id(ATTRIB_DEPTH)
        .map_err(decode_err)? as i32;
    // Real Java quirk: `gototype` is *written* via `writeSignedInteger` (see
    // `block_goto_encode_body` above) but *read* here via `readUnsignedInteger` -- a genuine
    // signed/unsigned mismatch in `BlockGoto.java` itself, reproduced faithfully.
    let goto_type = decoder
        .read_unsigned_integer_with_id(ATTRIB_TYPE)
        .map_err(decode_err)? as i32;
    self_goto.set_goto_type(goto_type);
    decoder.close_element(el).map_err(decode_err)?;
    resolver.add_goto_ref(self_arc.clone(), target, depth);
    Ok(())
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockGoto", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::pcode_block::PCODE_BLOCK_GOTO;
    use std::cell::{Cell, RefCell};

    struct MockGoto {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        target: RefCell<Option<Arc<dyn PcodeBlock>>>,
        goto_type: Cell<i32>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl MockGoto {
        fn new() -> Arc<MockGoto> {
            let block = Arc::new(MockGoto {
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

    impl PcodeBlock for MockGoto {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_GOTO
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

    impl BlockGraph for MockGoto {
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

    impl BlockGoto for MockGoto {
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
        let block = MockGoto::new();
        let dyn_block: &dyn BlockGoto = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_GOTO);
    }

    #[test]
    fn get_goto_target_round_trips_through_set() {
        let block = MockGoto::new();
        assert!(block.get_goto_target().is_none());
        let target = MockLeaf::new(5) as Arc<dyn PcodeBlock>;
        block.set_goto_target(Some(target.clone()));
        assert!(Arc::ptr_eq(&block.get_goto_target().unwrap(), &target));
        block.set_goto_target(None);
        assert!(block.get_goto_target().is_none());
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
    fn block_goto_encode_body_writes_target_leaf_depth_and_type() {
        let block = MockGoto::new();
        block.set_goto_type(2);
        // `target` is a BlockGraph directly wrapping `leaf`, with `leaf`'s parent pointer set to
        // `target` (our `BlockGraph::add_block`/`push_block` deliberately doesn't wire this back-
        // pointer automatically -- see block_graph.rs's module docs -- so the test wires it by
        // hand, matching what the real Java structuring pipeline would have set up beforehand).
        // getFrontLeaf(target) should descend one BlockGraph level to `leaf`; calcDepth(leaf),
        // called on `target`, should walk `leaf -> parent(target)` in exactly 1 hop.
        let leaf = MockLeaf::new(9);
        let target = MockGoto::new();
        target.push_block(leaf.clone() as Arc<dyn PcodeBlock>);
        *leaf.parent.borrow_mut() = Some(target.clone() as Arc<dyn PcodeBlock>);

        block.set_goto_target(Some(target.clone() as Arc<dyn PcodeBlock>));

        let mut encoder = MockEncoder {
            writes: RefCell::new(Vec::new()),
        };
        block.block_goto_encode_body(&mut encoder).unwrap();

        assert_eq!(
            *encoder.writes.borrow(),
            vec![
                "open:target".to_string(),
                "int:index=9".to_string(),
                "int:depth=1".to_string(),
                "int:type=2".to_string(),
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
            // `block_graph_decode_body` (called via `block_goto_decode_body` as the "super" call)
            // always builds a fresh child resolver first; these tests' decoders never actually
            // emit any `<bhead>` elements, so the child resolver's own state is never touched
            // beyond this construction. A standalone `MockResolver` is sufficient.
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
    fn block_goto_decode_body_reads_target_and_adds_goto_ref() {
        let block = MockGoto::new();
        let self_arc = block.self_ref.borrow().clone().unwrap();
        let decoder = MockDecoder {
            end_index: 11,
            depth: 3,
            goto_type: 4,
        };
        let resolver = MockResolver {
            goto_refs: RefCell::new(Vec::new()),
        };

        block_goto_decode_body(&self_arc, &*block, &decoder, &resolver).unwrap();

        assert_eq!(block.get_goto_type(), 4);
        let refs = resolver.goto_refs.borrow();
        assert_eq!(refs.len(), 1);
        assert!(Arc::ptr_eq(&refs[0].0, &self_arc));
        assert_eq!(refs[0].1, 11);
        assert_eq!(refs[0].2, 3);
    }
}
