use crate::program::model::listing::Instruction;
use std::sync::Arc;

/// Iterator that returns instructions.
///
/// This trait mirrors Ghidra's `InstructionIterator`, which combines the behavior of both
/// Iterator and Iterable in Java. Implementations should provide efficient iteration
/// over Instruction elements.
pub trait InstructionIterator: Iterator<Item = Arc<dyn Instruction>> {}

/// Empty instruction iterator with no items.
#[derive(Debug, Clone, Copy)]
pub struct EmptyInstructionIterator;

impl Iterator for EmptyInstructionIterator {
    type Item = Arc<dyn Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl InstructionIterator for EmptyInstructionIterator {}

/// List-based instruction iterator.
///
/// Wraps a vector of Instruction items and iterates over them by consuming ownership.
pub struct ListInstructionIterator {
    iter: std::vec::IntoIter<Arc<dyn Instruction>>,
}

impl ListInstructionIterator {
    /// Creates a new iterator over the supplied instruction items.
    pub fn new(items: Vec<Arc<dyn Instruction>>) -> Self {
        Self {
            iter: items.into_iter(),
        }
    }
}

impl Iterator for ListInstructionIterator {
    type Item = Arc<dyn Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl InstructionIterator for ListInstructionIterator {}

/// Creates an empty instruction iterator.
pub fn empty() -> Box<dyn InstructionIterator> {
    Box::new(EmptyInstructionIterator)
}

/// Creates an instruction iterator from a vector of instruction items.
pub fn of(items: Vec<Arc<dyn Instruction>>) -> Box<dyn InstructionIterator> {
    Box::new(ListInstructionIterator::new(items))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    impl crate::program::model::lang::ProcessorContext for MockInstruction {}

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype> {
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
    fn empty_iterator_returns_none() {
        let mut iterator = EmptyInstructionIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_from_factory_returns_none() {
        let mut iterator = empty();
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_yields_items() {
        let items: Vec<Arc<dyn Instruction>> =
            vec![Arc::new(MockInstruction), Arc::new(MockInstruction)];
        let mut iterator = ListInstructionIterator::new(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_from_factory_yields_items() {
        let items: Vec<Arc<dyn Instruction>> =
            vec![Arc::new(MockInstruction), Arc::new(MockInstruction)];
        let mut iterator = of(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_empty_list() {
        let items: Vec<Arc<dyn Instruction>> = vec![];
        let mut iterator = ListInstructionIterator::new(items);

        assert!(iterator.next().is_none());
    }
}
