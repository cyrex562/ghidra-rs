//! Real port of `ghidra.program.model.pcode.BlockMultiGoto`.
//!
//! Previously a placeholder trait lived at `crate::program::seam_stubs::BlockMultiGoto`, exposing
//! only the mutator
//! [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
//! needed before this class was ported for real. This file graduates that placeholder in place
//! (following the same precedent `PcodeBlock`/`BlockCopy`/`BlockGoto`/`BlockIfGoto` used):
//! `seam_stubs.rs` re-exports [`BlockMultiGoto`] under its old path.
//!
//! Java's `BlockMultiGoto extends BlockGraph`: "a block representing a 2-or-more control flow
//! branchpoint" -- possible multiple incoming edges, 1 or more outgoing edges (switch control
//! flow), 2 or more (implied) outgoing edges representing unstructured branch destinations (a
//! switch case with a goto statement), and 1 interior block representing the switch's decision
//! point. The private `targets` field (`ArrayList<PcodeBlock>`) is exposed as abstract
//! index-accessor methods, matching this crate's convention for container fields (see
//! `BlockGraph`'s own `list` field).
//!
//! Real Java quirk preserved faithfully: `encodeBody` never writes an `ATTRIB_TYPE` attribute for
//! any target -- the source has `encoder.writeSignedInteger(ATTRIB_TYPE, 2);` commented out with
//! `// Always a break` -- unlike `BlockGoto`/`BlockIfGoto`'s `encodeBody`, which both do write
//! `ATTRIB_TYPE`. Similarly, `decodeBody`'s per-target loop reads only `ATTRIB_INDEX`/
//! `ATTRIB_DEPTH`, with no `ATTRIB_TYPE` read at all.
//!
//! Also faithfully preserved: `decodeBody` never populates `targets` directly. Each decoded
//! `<target>` element instead calls `resolver.addGotoRef(this, target, depth)`, deferring actual
//! population of the `targets` list to
//! [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references),
//! which (once every leaf in the whole graph is known) resolves the reference and calls
//! `gotoblock.asBlockMultiGoto().addGotoTarget(bl)` -- already wired up in that method against the
//! [`add_goto_target`](BlockMultiGoto::add_goto_target) placeholder before this port existed.
//!
//! `encodeBody` is exposed under `block_multi_goto_encode_body` (not `encode_body`) for the usual
//! supertrait-name-collision reason (see `BlockGraph`'s module docs); `decodeBody` needs `this` as
//! an owned `Arc<dyn PcodeBlock>` for `resolver.addGotoRef`, so it's exposed as a free function
//! for the same reason as `BlockGoto`'s/`BlockIfGoto`'s decode-body free functions.

use crate::program::model::pcode::block_graph::BlockGraph;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_DEPTH, ATTRIB_INDEX, ELEM_TARGET};
use crate::program::model::pcode::pcode_block::{get_front_leaf, PcodeBlock};
use std::io;
use std::sync::Arc;

/// A block representing a 2-or-more control flow branchpoint: possible multiple incoming edges, 1
/// or more outgoing edges (as in switch control flow), 2 or more (implied) outgoing edges
/// representing unstructured branch destinations (a switch case with a goto statement), and 1
/// interior block representing the decision block of the switch.
///
/// Port of `ghidra.program.model.pcode.BlockMultiGoto`. See this module's docs for what's real
/// vs. an abstract accessor, and for the `ATTRIB_TYPE`/`targets`-population quirks.
pub trait BlockMultiGoto: BlockGraph {
    /// Number of pending goto targets (the private `targets` field's length).
    fn goto_target_count(&self) -> usize;

    /// Stands in for `targets.get(i)`.
    fn get_goto_target(&self, i: usize) -> Arc<dyn PcodeBlock>;

    /// Stands in for `targets.add(target)` (`BlockMultiGoto.addGotoTarget(PcodeBlock)`).
    fn add_goto_target(&self, target: Arc<dyn PcodeBlock>);

    /// Port of the protected `BlockMultiGoto.encodeBody(Encoder)` override. See this module's
    /// docs for the missing `ATTRIB_TYPE` write.
    fn block_multi_goto_encode_body(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.block_graph_encode_body(encoder)?;
        for i in 0..self.goto_target_count() {
            let target = self.get_goto_target(i);
            encoder.open_element(ELEM_TARGET)?;
            let leaf = get_front_leaf(target.clone());
            let depth = target.calc_depth(Some(leaf.clone()));
            encoder.write_signed_integer(ATTRIB_INDEX, leaf.get_index() as i64)?;
            encoder.write_signed_integer(ATTRIB_DEPTH, depth as i64)?;
            // encoder.write_signed_integer(ATTRIB_TYPE, 2)?; // Always a break -- real Java has
            // this line commented out, so it is never actually written; reproduced faithfully.
            encoder.close_element(ELEM_TARGET)?;
        }
        Ok(())
    }
}

/// Port of the protected `BlockMultiGoto.decodeBody(Decoder, BlockMap)` override. Exposed as a
/// free function for the same self-`Arc` reason as
/// [`block_goto_decode_body`](crate::program::model::pcode::block_goto::block_goto_decode_body).
/// See this module's docs for why `targets` is never populated here.
pub fn block_multi_goto_decode_body(
    self_arc: &Arc<dyn PcodeBlock>,
    self_multi: &dyn BlockMultiGoto,
    decoder: &dyn Decoder,
    resolver: &dyn BlockMap,
) -> Result<(), DecoderException> {
    self_multi.block_graph_decode_body(decoder, resolver)?;
    loop {
        let el = decoder.peek_element().map_err(decode_err)?;
        if el != ELEM_TARGET.id {
            break;
        }
        decoder.open_element().map_err(decode_err)?;
        let target = decoder
            .read_signed_integer_with_id(ATTRIB_INDEX)
            .map_err(decode_err)? as i32;
        let depth = decoder
            .read_signed_integer_with_id(ATTRIB_DEPTH)
            .map_err(decode_err)? as i32;
        decoder.close_element(el).map_err(decode_err)?;
        resolver.add_goto_ref(self_arc.clone(), target, depth);
    }
    Ok(())
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockMultiGoto", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::pcode_block::PCODE_BLOCK_MULTIGOTO;
    use std::cell::{Cell, RefCell};

    struct MockMultiGoto {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        targets: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl MockMultiGoto {
        fn new() -> Arc<MockMultiGoto> {
            let block = Arc::new(MockMultiGoto {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
                targets: RefCell::new(Vec::new()),
                self_ref: RefCell::new(None),
            });
            *block.self_ref.borrow_mut() = Some(block.clone() as Arc<dyn PcodeBlock>);
            block
        }
    }

    impl PcodeBlock for MockMultiGoto {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_MULTIGOTO
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

    impl BlockGraph for MockMultiGoto {
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

    impl BlockMultiGoto for MockMultiGoto {
        fn goto_target_count(&self) -> usize {
            self.targets.borrow().len()
        }
        fn get_goto_target(&self, i: usize) -> Arc<dyn PcodeBlock> {
            self.targets.borrow()[i].clone()
        }
        fn add_goto_target(&self, target: Arc<dyn PcodeBlock>) {
            self.targets.borrow_mut().push(target);
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
        let block = MockMultiGoto::new();
        let dyn_block: &dyn BlockMultiGoto = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_MULTIGOTO);
    }

    #[test]
    fn add_goto_target_accumulates_in_order() {
        let block = MockMultiGoto::new();
        let a = MockLeaf::new(1) as Arc<dyn PcodeBlock>;
        let b = MockLeaf::new(2) as Arc<dyn PcodeBlock>;
        block.add_goto_target(a.clone());
        block.add_goto_target(b.clone());
        assert_eq!(block.goto_target_count(), 2);
        assert!(Arc::ptr_eq(&block.get_goto_target(0), &a));
        assert!(Arc::ptr_eq(&block.get_goto_target(1), &b));
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
    fn block_multi_goto_encode_body_writes_one_target_per_entry_without_type() {
        let block = MockMultiGoto::new();
        let leaf1 = MockLeaf::new(2);
        let leaf2 = MockLeaf::new(5);
        block.add_goto_target(leaf1.clone() as Arc<dyn PcodeBlock>);
        block.add_goto_target(leaf2.clone() as Arc<dyn PcodeBlock>);

        let mut encoder = MockEncoder {
            writes: RefCell::new(Vec::new()),
        };
        block.block_multi_goto_encode_body(&mut encoder).unwrap();

        // Both leaves are their own front leaf (no BlockGraph wrapping) at depth 0 (calcDepth
        // called on the leaf itself, comparing against the same leaf, returns 0 immediately).
        assert_eq!(
            *encoder.writes.borrow(),
            vec![
                "open:target".to_string(),
                "int:index=2".to_string(),
                "int:depth=0".to_string(),
                "close:target".to_string(),
                "open:target".to_string(),
                "int:index=5".to_string(),
                "int:depth=0".to_string(),
                "close:target".to_string(),
            ]
        );
    }

    struct MockDecoder {
        entries: Vec<(i32, i32)>,
        pos: std::sync::atomic::AtomicUsize,
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
            if self.pos.load(std::sync::atomic::Ordering::SeqCst) < self.entries.len() {
                Ok(ELEM_TARGET.id)
            } else {
                Ok(0)
            }
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
            self.pos.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            let (index, depth) = self.entries[self.pos.load(std::sync::atomic::Ordering::SeqCst)];
            if attrib_id.name == ATTRIB_INDEX.name {
                Ok(index as i64)
            } else {
                Ok(depth as i64)
            }
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
    fn block_multi_goto_decode_body_adds_one_goto_ref_per_target_without_touching_targets_list() {
        let block = MockMultiGoto::new();
        let self_arc = block.self_ref.borrow().clone().unwrap();
        let decoder = MockDecoder {
            entries: vec![(3, 0), (7, 1)],
            pos: std::sync::atomic::AtomicUsize::new(0),
        };
        let resolver = MockResolver {
            goto_refs: RefCell::new(Vec::new()),
        };

        block_multi_goto_decode_body(&self_arc, &*block, &decoder, &resolver).unwrap();

        let refs = resolver.goto_refs.borrow();
        assert_eq!(refs.len(), 2);
        assert!(Arc::ptr_eq(&refs[0].0, &self_arc));
        assert_eq!((refs[0].1, refs[0].2), (3, 0));
        assert_eq!((refs[1].1, refs[1].2), (7, 1));
        // Real Java: decodeBody never touches `targets` directly -- that's left to
        // BlockMap.resolveGotoReferences calling addGotoTarget later.
        assert_eq!(block.goto_target_count(), 0);
    }
}
