//! Real port of `ghidra.program.model.pcode.BlockIfElse`.
//!
//! Java's `BlockIfElse extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.IFELSE;`. See
//! [`crate::program::model::pcode::block_list`]'s module doc for why an empty marker trait is a
//! complete, faithful 1:1 port of a class shaped like this, and why it is deliberately not given
//! a blanket impl.

use crate::program::model::pcode::block_graph::BlockGraph;

/// A standard if/else control flow block: possible multiple incoming edges, 1 outgoing edge going
/// to the common out block rejoining the 2 control flows, 1 "condition" block with exactly 2
/// outputs, 1 "true" block representing the control flow if the condition is true, and 1 "false"
/// block representing the control flow if the condition is false.
///
/// Port of `ghidra.program.model.pcode.BlockIfElse`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockIfElse: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_IFELSE};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockIfElse {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockIfElse {
        fn new() -> Arc<MockIfElse> {
            Arc::new(MockIfElse {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockIfElse {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_IFELSE
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

    impl BlockGraph for MockIfElse {
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

    impl BlockIfElse for MockIfElse {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockIfElse::new();
        let dyn_block: &dyn BlockIfElse = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_IFELSE);
    }

    #[test]
    fn structural_composition_holds_condition_true_and_false_blocks() {
        let block = MockIfElse::new();
        let condition: Arc<dyn PcodeBlock> = MockIfElse::new();
        let true_block: Arc<dyn PcodeBlock> = MockIfElse::new();
        let false_block: Arc<dyn PcodeBlock> = MockIfElse::new();
        block.push_block(condition.clone());
        block.push_block(true_block.clone());
        block.push_block(false_block.clone());
        assert_eq!(block.get_size(), 3);
        assert!(Arc::ptr_eq(&block.get_block(0), &condition));
        assert!(Arc::ptr_eq(&block.get_block(1), &true_block));
        assert!(Arc::ptr_eq(&block.get_block(2), &false_block));
    }
}
