use std::sync::Arc;

use crate::program::model::lang::instruction_prototype::InstructionPrototype;

/// Language provider specific parser context which may be cached.
///
/// Port of `ghidra.program.model.lang.ParserContext`.
pub trait ParserContext {
    /// Returns the instruction prototype for this parser context.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;

    struct MockPrototype;

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn crate::program::model::lang::ProcessorContextView,
        ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, crate::program::model::mem::MemoryAccessException>
        {
            unimplemented!()
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &crate::program::model::address::Address,
            _buffer: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn crate::program::model::lang::ProcessorContextView,
        ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, crate::program::model::lang::instruction_prototype::GetPseudoParserContextError>
        {
            unimplemented!()
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> String {
            "TEST".to_string()
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn crate::program::seam_stubs::Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn crate::program::seam_stubs::Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> crate::program::model::symbol::RefType {
            unimplemented!()
        }

        fn get_delay_slot_depth(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn crate::program::seam_stubs::InstructionContext) -> i32 {
            0
        }

        fn get_fall_through(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_fall_through_offset(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> i32 {
            4
        }

        fn get_flows(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> Option<Vec<crate::program::model::address::Address>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
        ) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
        ) -> Option<crate::program::model::scalar::Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
            _override_: Option<&dyn crate::program::seam_stubs::PcodeOverride>,
        ) -> crate::program::model::symbol::RefType {
            unimplemented!()
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self, _context: &dyn crate::program::seam_stubs::InstructionContext) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
            _override_: Option<&dyn crate::program::seam_stubs::PcodeOverride>,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn crate::program::seam_stubs::PatchEncoder,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
            _override_: Option<&dyn crate::program::seam_stubs::PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn crate::program::seam_stubs::InstructionContext,
            _operand_index: i32,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!()
        }
    }

    struct MockContext;

    impl ParserContext for MockContext {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            Arc::new(MockPrototype)
        }
    }

    #[test]
    fn get_prototype_returns_arc() {
        let ctx = MockContext;
        let proto = ctx.get_prototype();
        assert_eq!(proto.get_length(), 4);
    }
}
