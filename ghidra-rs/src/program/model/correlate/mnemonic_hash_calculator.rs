use crate::generic::hash::SimpleCRC32;
use crate::program::model::listing::Instruction;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::correlate::HashCalculator;

/// Hash function hashing only the mnemonic of an individual Instruction.
///
/// Port of `ghidra.program.model.correlate.MnemonicHashCalculator`.
pub struct MnemonicHashCalculator;

impl HashCalculator for MnemonicHashCalculator {
    fn calc_hash(&self, start_hash: i32, inst: &dyn Instruction) -> Result<i32, MemoryAccessException> {
        let mnemonic = inst.get_mnemonic_string();
        let mut hash = start_hash as u32;
        for ch in mnemonic.chars() {
            hash = SimpleCRC32::hash_one_byte(hash, ch as u32);
        }
        Ok(hash as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::symbol::RefType;
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, FlowOverride, InstructionContext, MemBuffer, RegisterValue};
    use crate::program::model::listing::{OperandValue, program::Program};
    use crate::program::model::symbol::{ExternalReference, Reference, ReferenceIterator, SourceType, Symbol};
    use crate::program::model::pcode::PcodeOp;
    use std::sync::Arc;

    struct TestInstruction {
        mnemonic: String,
    }

    impl MemBuffer for TestInstruction {}
    impl PropertySet for TestInstruction {}

    impl ProcessorContextView for TestInstruction {
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

    impl ProcessorContext for TestInstruction {
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

    impl CodeUnit for TestInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "0x1000".to_string()
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
            mock_address(0x1000)
        }

        fn get_max_address(&self) -> Address {
            mock_address(0x1000)
        }

        fn get_mnemonic_string(&self) -> String {
            self.mnemonic.clone()
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
            4
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            for b in buffer.iter_mut() {
                *b = 0x90;
            }
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr == &mock_address(0x1000)
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            (0x1000i64).cmp(&addr.offset()) as i32
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
            unimplemented!()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!()
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
            _reg: &crate::program::model::lang::register::Register,
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

        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl InstructionContext for TestInstruction {}

    impl Instruction for TestInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> {
            vec![]
        }

        fn get_input_objects(&self) -> Vec<OperandValue> {
            vec![]
        }

        fn get_result_objects(&self) -> Vec<OperandValue> {
            vec![]
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

        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_flow_type(&self) -> RefType {
            RefType::default()
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

        fn set_flow_override(&mut self, _override: FlowOverride) {}

        fn set_length_override(&mut self, _len: i32) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            false
        }

        fn get_parsed_length(&self) -> i32 {
            4
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; 4])
        }

        fn get_pcode(&self) -> Vec<PcodeOp> {
            vec![]
        }

        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> {
            vec![]
        }

        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> {
            vec![]
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
            unimplemented!()
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn hash_empty_mnemonic() {
        let calc = MnemonicHashCalculator;
        let inst = TestInstruction {
            mnemonic: "".to_string(),
        };
        let result = calc.calc_hash(0, &inst);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn hash_single_char_mnemonic() {
        let calc = MnemonicHashCalculator;
        let inst = TestInstruction {
            mnemonic: "A".to_string(),
        };
        let result = calc.calc_hash(0, &inst);
        assert!(result.is_ok());
        let hash = result.unwrap() as u32;
        let expected = SimpleCRC32::hash_one_byte(0u32, 'A' as u32);
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_multiple_char_mnemonic() {
        let calc = MnemonicHashCalculator;
        let inst = TestInstruction {
            mnemonic: "MOV".to_string(),
        };
        let result = calc.calc_hash(0, &inst);
        assert!(result.is_ok());
        let hash = result.unwrap() as u32;
        let mut expected = 0u32;
        expected = SimpleCRC32::hash_one_byte(expected, 'M' as u32);
        expected = SimpleCRC32::hash_one_byte(expected, 'O' as u32);
        expected = SimpleCRC32::hash_one_byte(expected, 'V' as u32);
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_with_initial_value() {
        let calc = MnemonicHashCalculator;
        let inst = TestInstruction {
            mnemonic: "NOP".to_string(),
        };
        let start = 0x12345678i32;
        let result = calc.calc_hash(start, &inst);
        assert!(result.is_ok());
        let hash = result.unwrap() as u32;
        let mut expected = start as u32;
        expected = SimpleCRC32::hash_one_byte(expected, 'N' as u32);
        expected = SimpleCRC32::hash_one_byte(expected, 'O' as u32);
        expected = SimpleCRC32::hash_one_byte(expected, 'P' as u32);
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_different_mnemonics_produce_different_hashes() {
        let calc = MnemonicHashCalculator;
        let inst1 = TestInstruction {
            mnemonic: "ADD".to_string(),
        };
        let inst2 = TestInstruction {
            mnemonic: "SUB".to_string(),
        };
        let hash1 = calc.calc_hash(0, &inst1).unwrap() as u32;
        let hash2 = calc.calc_hash(0, &inst2).unwrap() as u32;
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_incremental_consistency() {
        let calc = MnemonicHashCalculator;
        let mnemonic = "CALL";
        let inst = TestInstruction {
            mnemonic: mnemonic.to_string(),
        };
        let result = calc.calc_hash(0, &inst);
        assert!(result.is_ok());

        let mut expected = 0u32;
        for ch in mnemonic.chars() {
            expected = SimpleCRC32::hash_one_byte(expected, ch as u32);
        }
        assert_eq!(result.unwrap() as u32, expected);
    }
}
