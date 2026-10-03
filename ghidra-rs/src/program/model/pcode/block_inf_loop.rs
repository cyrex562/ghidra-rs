//! Real port of `ghidra.program.model.pcode.BlockInfLoop`.
//!
//! Java's `BlockInfLoop extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.INFLOOP;`. See
//! [`crate::program::model::pcode::block_list`]'s module doc for why an empty marker trait is a
//! complete, faithful 1:1 port of a class shaped like this, and why it is deliberately not given
//! a blanket impl.

use crate::program::model::pcode::block_graph::BlockGraph;

/// Block representing an infinite loop: possible multiple incoming edges, no outgoing edges, 1
/// (implied) outgoing edge representing loop to the top control flow, and 1 interior block
/// representing the body of the loop.
///
/// Port of `ghidra.program.model.pcode.BlockInfLoop`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockInfLoop: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_INFLOOP};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockInfLoop {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockInfLoop {
        fn new() -> Arc<MockInfLoop> {
            Arc::new(MockInfLoop {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockInfLoop {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_INFLOOP
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

    impl BlockGraph for MockInfLoop {
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

    impl BlockInfLoop for MockInfLoop {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockInfLoop::new();
        let dyn_block: &dyn BlockInfLoop = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_INFLOOP);
    }

    #[test]
    fn structural_composition_holds_body_block() {
        let block = MockInfLoop::new();
        let body: Arc<dyn PcodeBlock> = MockInfLoop::new();
        block.push_block(body.clone());
        assert_eq!(block.get_size(), 1);
        assert!(Arc::ptr_eq(&block.get_block(0), &body));
    }
}
