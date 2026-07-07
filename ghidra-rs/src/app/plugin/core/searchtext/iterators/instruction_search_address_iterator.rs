use crate::program::model::address::{Address, AddressIterator};
use crate::program::model::listing::InstructionIterator;
use std::cell::RefCell;
use std::sync::Arc;

/// Wrapper that converts an InstructionIterator to an AddressIterator.
///
/// Iterates through instructions and yields each instruction's starting address.
///
/// Port of `ghidra.app.plugin.core.searchtext.iterators.InstructionSearchAddressIterator`.
pub struct InstructionSearchAddressIterator {
    instruction_iterator: RefCell<Box<dyn InstructionIterator>>,
    cached_next: RefCell<Option<Option<Arc<dyn crate::program::model::listing::Instruction>>>>,
}

impl InstructionSearchAddressIterator {
    /// Creates a new iterator that wraps the given instruction iterator.
    pub fn new(instruction_iterator: Box<dyn InstructionIterator>) -> Self {
        Self {
            instruction_iterator: RefCell::new(instruction_iterator),
            cached_next: RefCell::new(None),
        }
    }

    fn ensure_cached(&self) {
        if self.cached_next.borrow().is_none() {
            let next = self.instruction_iterator.borrow_mut().next();
            *self.cached_next.borrow_mut() = Some(next);
        }
    }
}

impl AddressIterator for InstructionSearchAddressIterator {
    fn has_next(&self) -> bool {
        self.ensure_cached();
        self.cached_next
            .borrow()
            .as_ref()
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    fn next_address(&mut self) -> Option<Address> {
        self.ensure_cached();
        self.cached_next
            .borrow_mut()
            .take()
            .flatten()
            .map(|instruction| instruction.get_min_address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestInstructionIterator {
        instructions: Vec<Arc<dyn crate::program::model::listing::Instruction>>,
        index: usize,
    }

    impl TestInstructionIterator {
        fn new(instructions: Vec<Arc<dyn crate::program::model::listing::Instruction>>) -> Self {
            Self { instructions, index: 0 }
        }
    }

    impl Iterator for TestInstructionIterator {
        type Item = Arc<dyn crate::program::model::listing::Instruction>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.instructions.len() {
                let instr = self.instructions[self.index].clone();
                self.index += 1;
                Some(instr)
            } else {
                None
            }
        }
    }

    impl InstructionIterator for TestInstructionIterator {}

    fn test_address(offset: i64) -> Address {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        );
        Address::new(space, offset)
    }

    struct MockInstruction {
        address: Address,
    }

    impl crate::program::seam_stubs::MemBuffer for MockInstruction {}

    impl crate::program::seam_stubs::PropertySet for MockInstruction {}

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

        fn get_min_address(&self) -> Address {
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.clone()
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

    impl crate::program::model::listing::Instruction for MockInstruction {
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
    fn empty_iterator_has_no_next() {
        let inner = TestInstructionIterator::new(vec![]);
        let mut iter = InstructionSearchAddressIterator::new(Box::new(inner));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn iterator_delegates_to_inner_iterator() {
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x1008);
        let instr1 = Arc::new(MockInstruction {
            address: addr1.clone(),
        });
        let instr2 = Arc::new(MockInstruction {
            address: addr2.clone(),
        });
        let inner = TestInstructionIterator::new(vec![instr1, instr2]);
        let mut iter = InstructionSearchAddressIterator::new(Box::new(inner));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr1));
        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr2));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn multiple_next_calls_when_empty() {
        let inner = TestInstructionIterator::new(vec![]);
        let mut iter = InstructionSearchAddressIterator::new(Box::new(inner));
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
        assert!(iter.next_address().is_none());
    }

    #[test]
    fn single_instruction() {
        let addr = test_address(0x2000);
        let instr = Arc::new(MockInstruction {
            address: addr.clone(),
        });
        let inner = TestInstructionIterator::new(vec![instr]);
        let mut iter = InstructionSearchAddressIterator::new(Box::new(inner));

        assert!(iter.has_next());
        assert_eq!(iter.next_address(), Some(addr));
        assert!(!iter.has_next());
        assert!(iter.next_address().is_none());
    }
}
