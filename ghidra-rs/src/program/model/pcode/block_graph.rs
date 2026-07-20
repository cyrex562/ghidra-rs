use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_INDEX, ATTRIB_TYPE, ELEM_BHEAD};
use crate::program::seam_stubs::{pcode_block_type_to_name, BlockMap, PcodeBlock};
use std::io;
use std::sync::Arc;

/// A block (with in edges and out edges) that contains other blocks.
///
/// Port of `ghidra.program.model.pcode.BlockGraph`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends PcodeBlock`, which is not yet ported; see the
/// [`PcodeBlock`](crate::program::seam_stubs::PcodeBlock) placeholder (declared as this trait's
/// supertrait bound) for what is stubbed out and why. `BlockCopy` and `BlockMap`, referenced by
/// [`transfer_object_ref`](BlockGraph::transfer_object_ref) and
/// [`block_graph_decode_body`](BlockGraph::block_graph_decode_body) respectively, are likewise
/// stubbed in [`crate::program::seam_stubs`].
///
/// Container state (the block list and `maxindex`) is exposed as abstract accessor methods
/// (`get_size`/`get_block`/`push_block`/`get_max_index`/`set_max_index`) that a concrete
/// implementation supplies; `add_block`/`set_indices`/`add_edge`/`transfer_object_ref` are
/// default methods that reproduce the real Java algorithms in terms of those accessors and the
/// [`PcodeBlock`] supertrait's own `get_index`/`set_index`.
///
/// `transfer_object_ref` is restructured from Java's explicit BFS queue into direct recursion:
/// both visit every descendant exactly once and the final state is identical, but recursion
/// avoids needing an owned queue of trait-object handles.
///
/// Two methods that would collide by name with the [`PcodeBlock`] supertrait (which also has an
/// `encodeBody`/`decodeBody`-shaped pair and its own single-purpose `decode`) are exposed under
/// `block_graph_`-prefixed/`_graph`-suffixed names instead, matching this crate's existing
/// convention for the same issue (see
/// [`ShortDataType`](crate::program::model::data::short_data_type::ShortDataType)'s module docs):
/// Rust does not allow a subtrait to re-declare a supertrait method under the same name.
///
/// [`decode_graph`](BlockGraph::decode_graph) (port of `BlockGraph.decode(Decoder)`) is left as a
/// required method: the real implementation constructs a top-level `BlockMap` directly from the
/// decoder's `AddressFactory` (`new BlockMap(decoder.getAddressFactory())`), which needs a
/// concrete `BlockMap` constructor that the [`BlockMap`] placeholder does not provide (it only
/// models building a *child* resolver from an existing one, via `BlockMap::new_child`).
pub trait BlockGraph: PcodeBlock {
    /// Port of the private `list` field's size (`BlockGraph.getSize()`).
    fn get_size(&self) -> usize;

    /// Port of the private `list` field's indexed lookup (`BlockGraph.getBlock(int)`).
    fn get_block(&self, i: usize) -> Arc<dyn PcodeBlock>;

    /// Appends a block to the end of the private `list` field. Does not wire up a parent
    /// back-pointer; see this trait's module docs for why.
    fn push_block(&self, bl: Arc<dyn PcodeBlock>);

    /// Port of the private `maxindex` field getter.
    fn get_max_index(&self) -> i32;

    /// Port of the private `maxindex` field setter.
    fn set_max_index(&self, max_index: i32);

    /// Add a block to this container. There are (initially) no edges between it and any other
    /// block in the container.
    ///
    /// Port of `BlockGraph.addBlock(PcodeBlock)`.
    fn add_block(&self, bl: Arc<dyn PcodeBlock>) {
        let (min, max) = match bl.as_block_graph() {
            Some(gbl) => (gbl.get_index(), gbl.get_max_index()),
            None => {
                let idx = bl.get_index();
                (idx, idx)
            }
        };

        if self.get_size() == 0 {
            self.set_index(min);
            self.set_max_index(max);
        } else {
            if min < self.get_index() {
                self.set_index(min);
            }
            if max > self.get_max_index() {
                self.set_max_index(max);
            }
        }
        self.push_block(bl);
    }

    /// Assign a unique index to all blocks in this container. After this call, `get_block(i)`
    /// will return the block that satisfies `block.get_index() == i`.
    ///
    /// Port of `BlockGraph.setIndices()`.
    fn set_indices(&self) {
        for i in 0..self.get_size() {
            self.get_block(i).set_index(i as i32);
        }
        self.set_index(0);
        self.set_max_index(self.get_size() as i32 - 1);
    }

    /// Add a directed edge between two blocks in this container.
    ///
    /// Port of `BlockGraph.addEdge(PcodeBlock, PcodeBlock)`.
    fn add_edge(&self, begin: Arc<dyn PcodeBlock>, end: &dyn PcodeBlock) {
        end.add_in_edge(begin, 0);
    }

    /// Recursively run through this structured `BlockGraph` finding the `BlockCopy` leaves.
    /// Using the `BlockCopy` altindex, look up the original `BlockCopy` in `ingraph` and
    /// transfer the object ref and Address into the leaf.
    ///
    /// Port of `BlockGraph.transferObjectRef(BlockGraph)`. See this trait's module docs for the
    /// BFS-to-recursion restructuring.
    fn transfer_object_ref(&self, ingraph: &dyn BlockGraph) {
        for i in 0..self.get_size() {
            let block = self.get_block(i);
            if let Some(copyblock) = block.as_block_copy() {
                let altindex = copyblock.get_alt_index();
                if altindex >= 0 && (altindex as usize) < ingraph.get_size() {
                    let block2 = ingraph.get_block(altindex as usize);
                    if let Some(copyblock2) = block2.as_block_copy() {
                        // Transfer the object reference.
                        copyblock.set(copyblock2.get_ref(), copyblock2.get_start());
                    }
                }
            } else if let Some(subgraph) = block.as_block_graph() {
                subgraph.transfer_object_ref(ingraph);
            }
        }
    }

    /// Port of `BlockGraph.encodeBody(Encoder)`, which overrides the protected
    /// `PcodeBlock.encodeBody(Encoder)`. Exposed under a distinct name since [`PcodeBlock`]
    /// already declares `encode_body`; see this trait's module docs for why it can't be
    /// redeclared here.
    fn block_graph_encode_body(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode_body(encoder)?;
        for i in 0..self.get_size() {
            let bl = self.get_block(i);
            encoder.open_element(ELEM_BHEAD)?;
            encoder.write_signed_integer(ATTRIB_INDEX, bl.get_index() as i64)?;
            let name = pcode_block_type_to_name(bl.get_block_type()).unwrap_or("");
            encoder.write_string(ATTRIB_TYPE, name)?;
            encoder.close_element(ELEM_BHEAD)?;
        }
        for i in 0..self.get_size() {
            self.get_block(i).encode(encoder)?;
        }
        Ok(())
    }

    /// Port of `BlockGraph.decodeBody(Decoder, BlockMap)`, which overrides the protected
    /// `PcodeBlock.decodeBody(Decoder, BlockMap)`. Exposed under a distinct name since
    /// [`PcodeBlock`] already declares `decode_body`; see this trait's module docs for why it
    /// can't be redeclared here.
    fn block_graph_decode_body(
        &self,
        decoder: &dyn Decoder,
        resolver: &dyn BlockMap,
    ) -> Result<(), DecoderException> {
        let newresolver = resolver.new_child();
        self.decode_body(decoder, newresolver.as_ref())?;

        let mut tmplist: Vec<Arc<dyn PcodeBlock>> = Vec::new();
        loop {
            let el = decoder.peek_element().map_err(decode_err)?;
            if el != ELEM_BHEAD.id {
                break;
            }
            decoder.open_element().map_err(decode_err)?;
            let ind = decoder
                .read_signed_integer_with_id(ATTRIB_INDEX)
                .map_err(decode_err)? as i32;
            let name = decoder
                .read_string_with_id(ATTRIB_TYPE)
                .map_err(decode_err)?;
            let newbl = newresolver.create_block(&name, ind);
            tmplist.push(newbl);
            decoder.close_element(el).map_err(decode_err)?;
        }
        newresolver.sort_level_list();
        for bl in tmplist {
            bl.decode(decoder, newresolver.as_ref())?;
            self.add_block(bl);
        }
        Ok(())
    }

    /// Decode all blocks and edges in this container from a stream.
    ///
    /// Port of `BlockGraph.decode(Decoder)`. Left as a required method (no default); see this
    /// trait's module docs for why the top-level `BlockMap` construction can't be generalized
    /// here. A future implementation should mirror:
    /// `BlockMap resolver = new BlockMap(decoder.getAddressFactory()); decode(decoder, resolver);
    /// resolver.resolveGotoReferences();` (where the two-argument `decode` is the inherited
    /// `PcodeBlock::decode`).
    fn decode_graph(&self, decoder: &dyn Decoder) -> Result<(), DecoderException>;
}

fn decode_err(e: crate::program::model::pcode::decoder::DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockGraph", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::{BlockCopy, PCODE_BLOCK_BASIC, PCODE_BLOCK_GRAPH};
    use std::any::Any;
    use std::cell::{Cell, RefCell};

    struct MockLeaf {
        index: Cell<i32>,
        block_type: i32,
    }

    impl MockLeaf {
        fn new(index: i32, block_type: i32) -> Arc<dyn PcodeBlock> {
            Arc::new(MockLeaf {
                index: Cell::new(index),
                block_type,
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
            self.block_type
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

    struct MockCopyBlock {
        index: Cell<i32>,
        alt_index: i32,
        ref_val: RefCell<Option<Arc<dyn Any + Send + Sync>>>,
        start: RefCell<Address>,
    }

    impl MockCopyBlock {
        fn new(
            index: i32,
            alt_index: i32,
            ref_val: Option<Arc<dyn Any + Send + Sync>>,
            start: Address,
        ) -> Arc<MockCopyBlock> {
            Arc::new(MockCopyBlock {
                index: Cell::new(index),
                alt_index,
                ref_val: RefCell::new(ref_val),
                start: RefCell::new(start),
            })
        }
    }

    impl PcodeBlock for MockCopyBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            crate::program::seam_stubs::PCODE_BLOCK_COPY
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
        fn as_block_copy(&self) -> Option<&dyn BlockCopy> {
            Some(self)
        }
    }

    impl BlockCopy for MockCopyBlock {
        fn get_alt_index(&self) -> i32 {
            self.alt_index
        }
        fn get_ref(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            self.ref_val.borrow().clone()
        }
        fn get_start(&self) -> Address {
            self.start.borrow().clone()
        }
        fn set(&self, r: Option<Arc<dyn Any + Send + Sync>>, addr: Address) {
            *self.ref_val.borrow_mut() = r;
            *self.start.borrow_mut() = addr;
        }
    }

    struct MockBlockGraph {
        index: Cell<i32>,
        max_index: Cell<i32>,
        block_type: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockBlockGraph {
        fn new() -> Arc<MockBlockGraph> {
            Arc::new(MockBlockGraph {
                index: Cell::new(-1),
                max_index: Cell::new(-1),
                block_type: Cell::new(PCODE_BLOCK_GRAPH),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockBlockGraph {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            self.block_type.get()
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

    impl BlockGraph for MockBlockGraph {
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

    #[test]
    fn usable_as_trait_object() {
        let graph = MockBlockGraph::new();
        let dyn_graph: &dyn BlockGraph = &*graph;
        assert_eq!(dyn_graph.get_size(), 0);
    }

    #[test]
    fn add_block_tracks_min_max_index_like_java() {
        let graph = MockBlockGraph::new();
        // First (non-BlockGraph) child sets index/maxindex to its own index.
        graph.add_block(MockLeaf::new(5, PCODE_BLOCK_BASIC));
        assert_eq!(graph.get_index(), 5);
        assert_eq!(graph.get_max_index(), 5);

        // A lower-indexed child pulls the container's index down...
        graph.add_block(MockLeaf::new(2, PCODE_BLOCK_BASIC));
        assert_eq!(graph.get_index(), 2);
        assert_eq!(graph.get_max_index(), 5);

        // ...and a higher-indexed child pushes maxindex up.
        graph.add_block(MockLeaf::new(9, PCODE_BLOCK_BASIC));
        assert_eq!(graph.get_index(), 2);
        assert_eq!(graph.get_max_index(), 9);

        assert_eq!(graph.get_size(), 3);
    }

    #[test]
    fn add_block_uses_nested_graph_min_max() {
        let inner = MockBlockGraph::new();
        inner.add_block(MockLeaf::new(10, PCODE_BLOCK_BASIC));
        inner.add_block(MockLeaf::new(20, PCODE_BLOCK_BASIC));
        assert_eq!(inner.get_index(), 10);
        assert_eq!(inner.get_max_index(), 20);

        let outer = MockBlockGraph::new();
        outer.add_block(inner.clone() as Arc<dyn PcodeBlock>);
        // Outer container adopts the nested BlockGraph's [index, maxindex] range.
        assert_eq!(outer.get_index(), 10);
        assert_eq!(outer.get_max_index(), 20);
    }

    #[test]
    fn set_indices_reassigns_positions_and_own_bounds() {
        let graph = MockBlockGraph::new();
        graph.add_block(MockLeaf::new(100, PCODE_BLOCK_BASIC));
        graph.add_block(MockLeaf::new(200, PCODE_BLOCK_BASIC));
        graph.add_block(MockLeaf::new(300, PCODE_BLOCK_BASIC));

        graph.set_indices();

        assert_eq!(graph.get_block(0).get_index(), 0);
        assert_eq!(graph.get_block(1).get_index(), 1);
        assert_eq!(graph.get_block(2).get_index(), 2);
        assert_eq!(graph.get_index(), 0);
        assert_eq!(graph.get_max_index(), 2);
    }

    #[test]
    fn add_edge_delegates_to_end_add_in_edge() {
        struct RecordingBlock {
            index: Cell<i32>,
            edges: RefCell<Vec<i32>>,
        }
        impl PcodeBlock for RecordingBlock {
            fn get_index(&self) -> i32 {
                self.index.get()
            }
            fn set_index(&self, index: i32) {
                self.index.set(index);
            }
            fn get_block_type(&self) -> i32 {
                PCODE_BLOCK_BASIC
            }
            fn add_in_edge(&self, begin: Arc<dyn PcodeBlock>, label: i32) {
                self.edges.borrow_mut().push(begin.get_index());
                assert_eq!(label, 0);
            }
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

        let graph = MockBlockGraph::new();
        let begin = MockLeaf::new(7, PCODE_BLOCK_BASIC);
        let end = RecordingBlock {
            index: Cell::new(1),
            edges: RefCell::new(Vec::new()),
        };

        graph.add_edge(begin, &end);
        assert_eq!(*end.edges.borrow(), vec![7]);
    }

    #[test]
    fn transfer_object_ref_moves_ref_and_start_from_matching_alt_index() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let start_addr = Address::new(ram.clone(), 0x4000);

        #[derive(Debug, PartialEq)]
        struct BasicBlockHandle(u32);

        let original_ref: Arc<dyn Any + Send + Sync> = Arc::new(BasicBlockHandle(42));
        let ingraph = MockBlockGraph::new();
        ingraph.push_block(MockCopyBlock::new(0, 0, Some(original_ref.clone()), start_addr.clone()));

        let target = MockBlockGraph::new();
        let empty_addr = Address::new(ram.clone(), 0);
        let copy_leaf = MockCopyBlock::new(0, 0, None, empty_addr);
        target.push_block(copy_leaf.clone());

        target.transfer_object_ref(&*ingraph);

        let transferred_ref = copy_leaf.get_ref().expect("ref should have been transferred");
        assert_eq!(
            transferred_ref.downcast_ref::<BasicBlockHandle>(),
            Some(&BasicBlockHandle(42))
        );
        assert_eq!(copy_leaf.get_start(), start_addr);
    }

    #[test]
    fn transfer_object_ref_recurses_into_nested_graphs() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let start_addr = Address::new(ram.clone(), 0x8000);

        let original_ref: Arc<dyn Any + Send + Sync> = Arc::new(99u32);
        let ingraph = MockBlockGraph::new();
        ingraph.push_block(MockCopyBlock::new(0, 0, Some(original_ref), start_addr.clone()));

        let inner = MockBlockGraph::new();
        let empty_addr = Address::new(ram.clone(), 0);
        let nested_copy = MockCopyBlock::new(0, 0, None, empty_addr);
        inner.push_block(nested_copy.clone());

        let outer = MockBlockGraph::new();
        outer.push_block(inner.clone() as Arc<dyn PcodeBlock>);

        outer.transfer_object_ref(&*ingraph);

        assert!(nested_copy.get_ref().is_some());
        assert_eq!(nested_copy.get_start(), start_addr);
    }

    #[test]
    fn block_graph_encode_body_emits_bhead_per_block_then_encodes_each() {
        #[derive(Default)]
        struct MockEncoder {
            writes: Vec<String>,
        }
        impl Encoder for MockEncoder {
            fn open_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.writes.push(format!("open:{}", elem_id.name));
                Ok(())
            }
            fn close_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.writes.push(format!("close:{}", elem_id.name));
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
                self.writes.push(format!("int:{}={}", attrib_id.name, val));
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
                self.writes.push(format!("str:{}={}", attrib_id.name, val));
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

        let graph = MockBlockGraph::new();
        graph.push_block(MockLeaf::new(0, PCODE_BLOCK_GRAPH));
        graph.push_block(MockLeaf::new(1, PCODE_BLOCK_BASIC));

        let mut encoder = MockEncoder::default();
        graph.block_graph_encode_body(&mut encoder).unwrap();

        assert_eq!(
            encoder.writes,
            vec![
                "open:bhead".to_string(),
                "int:index=0".to_string(),
                "str:type=graph".to_string(),
                "close:bhead".to_string(),
                "open:bhead".to_string(),
                "int:index=1".to_string(),
                "str:type=basic".to_string(),
                "close:bhead".to_string(),
            ]
        );
    }
}
