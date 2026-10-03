//! Real port of `ghidra.program.model.pcode.BlockSwitch`.
//!
//! Java's `BlockSwitch extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.SWITCH;`. See
//! [`crate::program::model::pcode::block_list`]'s module doc for why an empty marker trait is a
//! complete, faithful 1:1 port of a class shaped like this, and why it is deliberately not given
//! a blanket impl.

use crate::program::model::pcode::block_graph::BlockGraph;

/// A block representing a switch construction: possible multiple incoming edges, 1 outgoing edge
/// representing all the interior control flow cases coming back together, 1 interior block
/// representing the decision point with outgoing edges to the different cases (or the exit
/// block), and multiple interior blocks for each "case" of the switch (each of which must have
/// exactly 1 outgoing edge to the common exit block, or none).
///
/// Port of `ghidra.program.model.pcode.BlockSwitch`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockSwitch: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_SWITCH};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockSwitch {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockSwitch {
        fn new() -> Arc<MockSwitch> {
            Arc::new(MockSwitch {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockSwitch {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_SWITCH
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

    impl BlockGraph for MockSwitch {
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

    impl BlockSwitch for MockSwitch {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockSwitch::new();
        let dyn_block: &dyn BlockSwitch = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_SWITCH);
    }

    #[test]
    fn structural_composition_holds_decision_and_case_blocks() {
        let block = MockSwitch::new();
        let decision: Arc<dyn PcodeBlock> = MockSwitch::new();
        let case1: Arc<dyn PcodeBlock> = MockSwitch::new();
        let case2: Arc<dyn PcodeBlock> = MockSwitch::new();
        block.push_block(decision.clone());
        block.push_block(case1.clone());
        block.push_block(case2.clone());
        assert_eq!(block.get_size(), 3);
        assert!(Arc::ptr_eq(&block.get_block(0), &decision));
        assert!(Arc::ptr_eq(&block.get_block(1), &case1));
        assert!(Arc::ptr_eq(&block.get_block(2), &case2));
    }
}
