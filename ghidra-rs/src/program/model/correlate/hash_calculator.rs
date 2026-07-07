use crate::program::model::listing::Instruction;
use crate::program::model::mem::MemoryAccessException;

/// Interface for hashing across sequences of Instructions in different ways.
///
/// Port of `ghidra.program.model.correlate.HashCalculator`.
pub trait HashCalculator {
    /// Calculate a (partial) hash across a single instruction.
    ///
    /// # Arguments
    /// * `start_hash` - initial hash value
    /// * `inst` - the instruction to fold into the hash
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if memory access fails during hashing.
    fn calc_hash(&self, start_hash: i32, inst: &dyn Instruction) -> Result<i32, MemoryAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::symbol::RefType;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContext;
    use crate::program::seam_stubs::{FlowOverride, InstructionContext};
    use std::sync::Arc;

    struct MockInstruction;

    impl CodeUnit for MockInstruction {
        fn get_address(&self) -> Address {
            Address::default()
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn contains(&self, addr: Address) -> bool {
            false
        }

        fn get_max_address(&self) -> Address {
            Address::default()
        }

        fn get_mnemonic(&self) -> String {
            "NOP".to_string()
        }
    }

    impl ProcessorContext for MockInstruction {}

    impl InstructionContext for MockInstruction {}

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<crate::program::model::listing::OperandValue> {
            vec![]
        }

        fn get_input_objects(&self) -> Vec<crate::program::model::listing::OperandValue> {
            vec![]
        }

        fn get_result_objects(&self) -> Vec<crate::program::model::listing::OperandValue> {
            vec![]
        }

        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }

        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<crate::program::model::listing::OperandValue>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }

        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType {
            RefType::default()
        }

        fn get_default_fall_through_offset(&self) -> i32 {
            4
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

        fn get_flows_to(&self) -> Vec<Address> {
            vec![]
        }

        fn get_fall_through_flows_to(&self) -> Vec<Address> {
            vec![]
        }

        fn get_pcode(&self) -> Option<Vec<crate::program::model::pcode::PcodeOp>> {
            None
        }

        fn get_pcode_at(&self, _addr: Address) -> Option<Vec<crate::program::model::pcode::PcodeOp>> {
            None
        }

        fn set_length_override(&mut self, _len: i32) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }

        fn clear_length_override(&mut self) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_flow_override(&self) -> FlowOverride {
            FlowOverride::None
        }

        fn set_flow_override(&mut self, _override: FlowOverride) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }

        fn get_delay_slot_depth(&self) -> i32 {
            0
        }

        fn get_next_instruction(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_previous_instruction(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    struct TestHashCalculator;

    impl HashCalculator for TestHashCalculator {
        fn calc_hash(&self, start_hash: i32, _inst: &dyn Instruction) -> Result<i32, MemoryAccessException> {
            Ok(start_hash)
        }
    }

    #[test]
    fn hash_calculator_trait_can_be_implemented() {
        let calc = TestHashCalculator;
        let mock_inst = MockInstruction;
        let result = calc.calc_hash(42, &mock_inst);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn hash_calculator_can_return_error() {
        struct ErrorHashCalculator;

        impl HashCalculator for ErrorHashCalculator {
            fn calc_hash(
                &self,
                _start_hash: i32,
                _inst: &dyn Instruction,
            ) -> Result<i32, MemoryAccessException> {
                Err(MemoryAccessException::new("test error"))
            }
        }

        let calc = ErrorHashCalculator;
        let mock_inst = MockInstruction;
        let result = calc.calc_hash(42, &mock_inst);
        assert!(result.is_err());
    }
}
