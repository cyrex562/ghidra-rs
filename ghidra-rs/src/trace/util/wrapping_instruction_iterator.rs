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
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::{ContextChangeException, OperandValue};
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, FlowOverride, InstructionContext, MemBuffer, RegisterValue};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::util::CodeUnitInsertionException;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockInstruction;

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            mock_address(0)
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
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
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
            mock_address(0)
        }

        fn get_max_address(&self) -> Address {
            mock_address(1)
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
            0
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
            unimplemented!("not needed for this smoke test")
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
            1
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
