//! Real port of `ghidra.program.model.pcode.BlockList`.
//!
//! Java's `BlockList extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.LIST;`. In this crate's trait-object
//! architecture, that type tag is already the concrete implementor's own
//! [`PcodeBlock::get_block_type`](crate::program::model::pcode::pcode_block::PcodeBlock::get_block_type)
//! returning
//! [`PCODE_BLOCK_LIST`](crate::program::model::pcode::pcode_block::PCODE_BLOCK_LIST) -- a
//! construction-time detail already fully covered by `PcodeBlock`'s own abstract accessor, the
//! same way every other `Block*` marker subclass's `blocktype` assignment is. There is therefore
//! nothing left for this class to add beyond a distinct marker trait a concrete implementation can
//! opt into to declare "this `BlockGraph` really is a `BlockList`" -- this is a complete,
//! faithful 1:1 port of the class's entire real content, not a stub standing in for missing
//! behavior.
//!
//! Deliberately **not** given a blanket `impl<T: BlockGraph> BlockList for T {}`: Java's
//! `instanceof BlockList` is only true for genuine `BlockList` instances, not every `BlockGraph`,
//! so a blanket impl would misrepresent that discrimination for any future consumer that needs to
//! tell block-graph subclasses apart (mirroring how `BlockCopy`/`BlockGoto`/etc. are likewise
//! explicit, non-blanket opt-in impls).

use crate::program::model::pcode::block_graph::BlockGraph;

/// Block representing a sequence of other blocks: possible multiple incoming edges, 1 outgoing
/// edge, and 1 or more interior blocks that are executed in sequence.
///
/// Port of `ghidra.program.model.pcode.BlockList`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockList: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_LIST};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockList {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockList {
        fn new() -> Arc<MockList> {
            Arc::new(MockList {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockList {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_LIST
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

    impl BlockGraph for MockList {
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

    impl BlockList for MockList {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockList::new();
        let dyn_block: &dyn BlockList = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_LIST);
    }

    #[test]
    fn structural_composition_holds_sequential_interior_blocks() {
        let block = MockList::new();
        let first: Arc<dyn PcodeBlock> = MockList::new();
        let second: Arc<dyn PcodeBlock> = MockList::new();
        block.push_block(first.clone());
        block.push_block(second.clone());
        assert_eq!(block.get_size(), 2);
        assert!(Arc::ptr_eq(&block.get_block(0), &first));
        assert!(Arc::ptr_eq(&block.get_block(1), &second));
    }
}
