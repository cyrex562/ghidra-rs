//! Real port of `ghidra.program.model.pcode.BlockProperIf`.
//!
//! Java's `BlockProperIf extends BlockGraph` has no fields, no overridden methods, and a
//! constructor whose entire body is `blocktype = PcodeBlock.PROPERIF;`. See
//! [`crate::program::model::pcode::block_list`]'s module doc for why an empty marker trait is a
//! complete, faithful 1:1 port of a class shaped like this, and why it is deliberately not given
//! a blanket impl.

use crate::program::model::pcode::block_graph::BlockGraph;

/// A block containing condition control flow: possible multiple incoming edges, 1 outgoing edge
/// representing rejoined control flow, and 2 interior blocks -- one "condition" block
/// representing the decision point on whether to take the conditional flow, and one "body" block
/// representing the conditional flow that may be followed or may be skipped.
///
/// Port of `ghidra.program.model.pcode.BlockProperIf`. See this module's docs for why this is an
/// empty marker trait.
pub trait BlockProperIf: BlockGraph {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::pcode_block::{PcodeBlock, PCODE_BLOCK_PROPERIF};
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::sync::Arc;

    struct MockProperIf {
        index: Cell<i32>,
        max_index: Cell<i32>,
        blocks: RefCell<Vec<Arc<dyn PcodeBlock>>>,
    }

    impl MockProperIf {
        fn new() -> Arc<MockProperIf> {
            Arc::new(MockProperIf {
                index: Cell::new(0),
                max_index: Cell::new(-1),
                blocks: RefCell::new(Vec::new()),
            })
        }
    }

    impl PcodeBlock for MockProperIf {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_PROPERIF
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

    impl BlockGraph for MockProperIf {
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

    impl BlockProperIf for MockProperIf {}

    #[test]
    fn usable_as_trait_object_and_reports_block_type() {
        let block = MockProperIf::new();
        let dyn_block: &dyn BlockProperIf = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_PROPERIF);
    }

    #[test]
    fn structural_composition_holds_condition_and_body_blocks() {
        let block = MockProperIf::new();
        let condition: Arc<dyn PcodeBlock> = MockProperIf::new();
        let body: Arc<dyn PcodeBlock> = MockProperIf::new();
        block.push_block(condition.clone());
        block.push_block(body.clone());
        assert_eq!(block.get_size(), 2);
        assert!(Arc::ptr_eq(&block.get_block(0), &condition));
        assert!(Arc::ptr_eq(&block.get_block(1), &body));
    }
}
