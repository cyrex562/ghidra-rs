use crate::program::model::lang::{ParallelInstructionLanguageHelper, ProcessorContextView};
use crate::program::model::listing::Instruction;

/// Helper for identifying parallel instruction attributes in Hexagon processor.
///
/// Port of `ghidra.app.util.viewer.field.HexagonParallelInstructionHelper`.
///
/// Provides the ability to identify whether an instruction is part of a parallel
/// instruction group and whether it marks the end of such a group. Hexagon uses
/// packet-based execution where multiple instructions can execute in parallel.
#[derive(Debug, Clone, Copy)]
pub struct HexagonParallelInstructionHelper;

impl HexagonParallelInstructionHelper {
    /// Creates a new instance of the helper.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HexagonParallelInstructionHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelInstructionLanguageHelper for HexagonParallelInstructionHelper {
    fn get_mnemonic_prefix(&self, instr: &dyn Instruction) -> Option<String> {
        if self.is_parallel_instruction(instr) {
            Some("||".to_string())
        } else {
            None
        }
    }

    fn is_parallel_instruction(&self, instruction: &dyn Instruction) -> bool {
        let packet_offset_reg = match ProcessorContextView::get_register(instruction, "packetOffset") {
            Some(reg_ref) => reg_ref,
            None => return false,
        };

        let reg = packet_offset_reg.borrow();
        match ProcessorContextView::get_value(instruction, &reg, false) {
            Some(value) => value != 0,
            None => false,
        }
    }

    fn is_end_of_parallel_instruction_group(&self, instruction: &dyn Instruction) -> bool {
        match instruction.get_bytes() {
            Ok(bytes) => {
                if bytes.len() < 2 {
                    return true;
                }
                // Assume little endian
                // End of packet instruction will have PP='11' or EE='00'
                // PP/EE are in bits 7-6 of byte at index 1
                let bits = (bytes[1] & 0xC0) >> 6;
                bits == 0 || bits == 3
            }
            Err(_) => {
                // On error, treat as end of group to be safe
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::listing::OperandValue;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::symbol::{ExternalReference, Reference, ReferenceIterator, RefType, SourceType, Symbol};
    use crate::program::seam_stubs::{CommentType, FlowOverride, InstructionContext, MemBuffer, RegisterValue};
    use crate::program::util::CodeUnitInsertionException;
    use std::sync::Arc;

    struct MockInstruction {
        mnemonic: String,
        bytes: Vec<u8>,
        packet_offset_value: Option<i128>,
        has_packet_offset_register: bool,
    }

    impl MockInstruction {
        fn new() -> Self {
            Self {
                mnemonic: "add".to_string(),
                bytes: vec![0x00, 0x00],
                packet_offset_value: None,
                has_packet_offset_register: true,
            }
        }

        fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
            self.bytes = bytes;
            self
        }

        fn with_mnemonic(mut self, mnemonic: String) -> Self {
            self.mnemonic = mnemonic;
            self
        }

        fn with_packet_offset_value(mut self, value: Option<i128>) -> Self {
            self.packet_offset_value = value;
            self
        }

        fn without_packet_offset_register(mut self) -> Self {
            self.has_packet_offset_register = false;
            self
        }
    }

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            mock_address()
        }
    }
    impl crate::program::model::util::property_set::PropertySet for MockInstruction {}
    impl InstructionContext for MockInstruction {}

    impl ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            if name == "packetOffset" && self.has_packet_offset_register {
                let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
                Some(Register::new(
                    "packetOffset",
                    "Packet Offset",
                    Address::new(space, 0),
                    4,
                    false,
                    0,
                ))
            } else {
                None
            }
        }

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            self.packet_offset_value
        }

        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &Register) -> bool {
            self.packet_offset_value.is_some()
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

    fn mock_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x1000)
    }

    impl CodeUnit for MockInstruction {
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
            mock_address()
        }

        fn get_max_address(&self) -> Address {
            mock_address()
        }

        fn get_mnemonic_string(&self) -> String {
            if self.packet_offset_value.is_some() && self.packet_offset_value != Some(0) {
                format!("||{}", self.mnemonic)
            } else {
                self.mnemonic.clone()
            }
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
            Ok(self.bytes.clone())
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            for (i, b) in buffer.iter_mut().enumerate() {
                if i < self.bytes.len() {
                    *b = self.bytes[i];
                }
            }
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr == &mock_address()
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

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
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

        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
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

        fn set_length_override(&mut self, _len: i32) -> Result<(), CodeUnitInsertionException> {
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            false
        }

        fn get_parsed_length(&self) -> i32 {
            4
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(self.bytes.clone())
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

    #[test]
    fn test_new() {
        let helper = HexagonParallelInstructionHelper::new();
        assert_eq!(helper, HexagonParallelInstructionHelper);
    }

    #[test]
    fn test_default() {
        let helper = HexagonParallelInstructionHelper::default();
        assert_eq!(helper, HexagonParallelInstructionHelper);
    }

    #[test]
    fn test_is_parallel_instruction_with_zero_offset() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_packet_offset_value(Some(0));
        assert!(!helper.is_parallel_instruction(&instr));
    }

    #[test]
    fn test_is_parallel_instruction_with_nonzero_offset() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_packet_offset_value(Some(1));
        assert!(helper.is_parallel_instruction(&instr));
    }

    #[test]
    fn test_is_parallel_instruction_with_no_register() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().without_packet_offset_register();
        assert!(!helper.is_parallel_instruction(&instr));
    }

    #[test]
    fn test_is_parallel_instruction_with_no_value() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_packet_offset_value(None);
        assert!(!helper.is_parallel_instruction(&instr));
    }

    #[test]
    fn test_get_mnemonic_prefix_parallel() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_packet_offset_value(Some(1));
        assert_eq!(helper.get_mnemonic_prefix(&instr), Some("||".to_string()));
    }

    #[test]
    fn test_get_mnemonic_prefix_not_parallel() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_packet_offset_value(Some(0));
        assert_eq!(helper.get_mnemonic_prefix(&instr), None);
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_bits_zero() {
        let helper = HexagonParallelInstructionHelper::new();
        // bits[7:6] of byte[1] = 00, so it's end of group
        let instr = MockInstruction::new().with_bytes(vec![0xFF, 0x00]);
        assert!(helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_bits_three() {
        let helper = HexagonParallelInstructionHelper::new();
        // bits[7:6] of byte[1] = 11 (0xC0), so it's end of group
        let instr = MockInstruction::new().with_bytes(vec![0xFF, 0xC0]);
        assert!(helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_bits_one() {
        let helper = HexagonParallelInstructionHelper::new();
        // bits[7:6] of byte[1] = 01 (0x40), so it's not end of group
        let instr = MockInstruction::new().with_bytes(vec![0xFF, 0x40]);
        assert!(!helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_bits_two() {
        let helper = HexagonParallelInstructionHelper::new();
        // bits[7:6] of byte[1] = 10 (0x80), so it's not end of group
        let instr = MockInstruction::new().with_bytes(vec![0xFF, 0x80]);
        assert!(!helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_short_bytes() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_bytes(vec![0xFF]);
        assert!(helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_is_end_of_parallel_instruction_group_empty_bytes() {
        let helper = HexagonParallelInstructionHelper::new();
        let instr = MockInstruction::new().with_bytes(vec![]);
        assert!(helper.is_end_of_parallel_instruction_group(&instr));
    }

    #[test]
    fn test_various_byte_patterns() {
        let helper = HexagonParallelInstructionHelper::new();

        // Test mixed byte patterns with different bits
        let mut test_cases = vec![
            (vec![0x12, 0x34], false),  // bits = 11, end of group
            (vec![0x12, 0x3C], false),  // bits = 11, end of group
            (vec![0x12, 0x3F], true),   // bits = 11, end of group
            (vec![0x12, 0x05], true),   // bits = 00, end of group
            (vec![0x12, 0x45], false),  // bits = 01, not end of group
            (vec![0x12, 0x85], false),  // bits = 10, not end of group
        ];

        for (bytes, expected) in test_cases {
            let instr = MockInstruction::new().with_bytes(bytes.clone());
            assert_eq!(
                helper.is_end_of_parallel_instruction_group(&instr),
                expected,
                "Failed for bytes: {:?}",
                bytes
            );
        }
    }
}
