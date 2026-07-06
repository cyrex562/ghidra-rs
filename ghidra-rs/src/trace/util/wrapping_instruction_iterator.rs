use crate::program::model::listing::{Instruction, InstructionIterator};
use std::sync::Arc;

/// Wraps an iterator to implement the [`InstructionIterator`] interface.
///
/// Analogous to Java's `ghidra.trace.util.WrappingInstructionIterator`. This provides
/// a generic wrapper for any iterator over Instruction elements, allowing it to be used as an [`InstructionIterator`].
pub struct WrappingInstructionIterator<I: Iterator<Item = Arc<dyn Instruction>>> {
    iter: I,
}

impl<I: Iterator<Item = Arc<dyn Instruction>>> WrappingInstructionIterator<I> {
    /// Creates a new wrapping iterator.
    ///
    /// # Arguments
    /// * `iter` - The iterator to wrap
    pub fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I: Iterator<Item = Arc<dyn Instruction>>> Iterator for WrappingInstructionIterator<I> {
    type Item = Arc<dyn Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<I: Iterator<Item = Arc<dyn Instruction>>> InstructionIterator for WrappingInstructionIterator<I> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::{Any, TypeId};

    struct MockInstruction;

    impl crate::program::model::listing::CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "test".to_string()
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
            vec![]
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_min_address(&self) -> crate::program::model::address::Address {
            let space = crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                1,
            );
            crate::program::model::address::Address::new(space, 0)
        }

        fn get_max_address(&self) -> crate::program::model::address::Address {
            let space = crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                1,
            );
            crate::program::model::address::Address::new(space, 1)
        }

        fn get_mnemonic_string(&self) -> String {
            "test".to_string()
        }

        fn get_comment(&self, _comment_type: crate::program::seam_stubs::CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
        ) -> Vec<String> {
            vec![]
        }
    }

    impl crate::program::seam_stubs::ProcessorContext for MockInstruction {}

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn crate::program::seam_stubs::InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<crate::program::model::listing::OperandValue> {
            vec![]
        }

        fn get_input_objects(&self) -> Vec<crate::program::model::listing::OperandValue> {
            vec![]
        }

        fn get_operand_references(&self, _operand_index: i32) -> Vec<crate::program::model::address::Reference> {
            vec![]
        }

        fn get_mnemonic(&self) -> String {
            "test".to_string()
        }

        fn get_default_fall_through_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_length(&self) -> i32 {
            1
        }

        fn has_default_length_override(&self) -> bool {
            false
        }

        fn is_valid(&self) -> bool {
            true
        }

        fn get_flow_override(&self) -> crate::program::seam_stubs::FlowOverride {
            crate::program::seam_stubs::FlowOverride::None
        }

        fn get_operand_ref_type(&self, _operand_index: i32) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::Data
        }

        fn get_all_flow_addresses(&self) -> Vec<crate::program::model::address::Address> {
            vec![]
        }

        fn get_fallthrough(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_next_instruction_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_pcode_ops(&self, _op_type: Option<i32>) -> Vec<Arc<dyn crate::program::model::pcode::PcodeOp>> {
            vec![]
        }
    }

    #[test]
    fn wraps_iterator_delegates_to_inner() {
        let instrs: Vec<Arc<dyn Instruction>> = vec![
            Arc::new(MockInstruction) as Arc<dyn Instruction>,
            Arc::new(MockInstruction),
            Arc::new(MockInstruction),
        ];
        let mut it = WrappingInstructionIterator::new(instrs.into_iter());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_none());
    }

    #[test]
    fn wraps_empty_iterator() {
        let instrs: Vec<Arc<dyn Instruction>> = vec![];
        let mut it = WrappingInstructionIterator::new(instrs.into_iter());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_returns_none_after_exhaustion() {
        let instrs: Vec<Arc<dyn Instruction>> = vec![Arc::new(MockInstruction)];
        let mut it = WrappingInstructionIterator::new(instrs.into_iter());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_filtered_iterator() {
        let instrs: Vec<Arc<dyn Instruction>> = vec![
            Arc::new(MockInstruction) as Arc<dyn Instruction>,
            Arc::new(MockInstruction),
            Arc::new(MockInstruction),
        ];
        let filtered = instrs.into_iter().filter(|_| true);
        let mut it = WrappingInstructionIterator::new(filtered);
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_with_partial_filter() {
        let instrs: Vec<Arc<dyn Instruction>> = vec![
            Arc::new(MockInstruction) as Arc<dyn Instruction>,
            Arc::new(MockInstruction),
            Arc::new(MockInstruction),
        ];
        let filtered = instrs.into_iter().filter(|_| true).take(2);
        let mut it = WrappingInstructionIterator::new(filtered);
        assert!(it.next().is_some());
        assert!(it.next().is_some());
        assert_eq!(it.next(), None);
    }
}
