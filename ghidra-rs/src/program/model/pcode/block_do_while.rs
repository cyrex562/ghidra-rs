//! Real port of `ghidra.program.model.pcode.BlockDoWhile`.
//!
//! Java's `BlockDoWhile extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.DOWHILE;`. See
//! [`crate::program::model::pcode::block_list`]'s module doc for why an empty marker trait is a
//! complete, faithful 1:1 port of a class shaped like this, and why it is deliberately not given
//! a blanket impl.

use crate::program::model::pcode::block_graph::BlockGraph;

/// Do-while block: possible multiple incoming edges, 1 (implied) edge outgoing back to itself,
/// 1 edge outgoing (the loop exit), and 1 block representing the body of the loop.
///
/// Port of `ghidra.program.model.pcode.BlockDoWhile`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockDoWhile: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_DOWHILE};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockDoWhile {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockDoWhile {
        fn new() -> Arc<MockDoWhile> {
            Arc::new(MockDoWhile {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockDoWhile {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_DOWHILE
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

    impl BlockGraph for MockDoWhile {
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

    impl BlockDoWhile for MockDoWhile {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockDoWhile::new();
        let dyn_block: &dyn BlockDoWhile = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_DOWHILE);
    }

    #[test]
    fn structural_composition_holds_body_block() {
        let block = MockDoWhile::new();
        let body: Arc<dyn PcodeBlock> = MockDoWhile::new();
        block.push_block(body.clone());
        assert_eq!(block.get_size(), 1);
        assert!(Arc::ptr_eq(&block.get_block(0), &body));
    }
}
