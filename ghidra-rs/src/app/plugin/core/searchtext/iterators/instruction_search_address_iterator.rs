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

    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::{
        ContextChangeException, Instruction, OperandValue, MAX_LENGTH_OVERRIDE,
    };
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{
        CommentType, FlowOverride, InstructionContext, MemBuffer, RegisterValue,
    };
    use crate::program::util::CodeUnitInsertionException;

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl PropertySet for MockInstruction {}

    impl ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockInstruction {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "test".to_string()
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
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

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            1
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }

        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }

        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_input_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }

        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<OperandValue>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }

        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType {
            RefType::Data
        }

        fn get_default_fall_through_offset(&self) -> i32 {
            self.get_length()
        }

        fn get_default_fall_through(&self) -> Option<Address> {
            None
        }

        fn get_fall_through(&self) -> Option<Address> {
            None
        }

        fn get_fall_from(&self) -> Option<Address> {
            None
        }

        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_flow_type(&self) -> RefType {
            RefType::FallThrough
        }

        fn is_fallthrough(&self) -> bool {
            true
        }

        fn has_fallthrough(&self) -> bool {
            true
        }

        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }

        fn set_flow_override(&mut self, _flow_override: FlowOverride) {}

        fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
            let _ = MAX_LENGTH_OVERRIDE;
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            false
        }

        fn get_parsed_length(&self) -> i32 {
            1
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }

        fn get_pcode(&self) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_delay_slot_depth(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn set_fall_through(&mut self, _addr: Option<Address>) {}

        fn clear_fall_through_override(&mut self) {}

        fn is_fall_through_overridden(&self) -> bool {
            false
        }

        fn get_instruction_context(&self) -> Arc<dyn InstructionContext> {
            unimplemented!("not needed for this smoke test")
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
