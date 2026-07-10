use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// A command to clear a fallthrough override from an instruction.
pub struct ClearFallThroughCmd {
    inst_addr: Address,
}

impl ClearFallThroughCmd {
    /// Creates a new command to remove a fallthrough override.
    ///
    /// # Arguments
    ///
    /// * `inst_addr` - the address of the instruction from which to remove the fallthrough override.
    pub fn new(inst_addr: Address) -> Self {
        ClearFallThroughCmd { inst_addr }
    }
}

impl Command<dyn Program + 'static> for ClearFallThroughCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        if let Some(listing) = program.get_listing() {
            if let Some(inst) = listing.get_instruction_at(&self.inst_addr) {
                let inst_ptr = inst.as_ref() as *const dyn crate::program::model::listing::Instruction
                    as *mut dyn crate::program::model::listing::Instruction;
                unsafe {
                    (*inst_ptr).clear_fall_through_override();
                }
                return true;
            }
        }
        false
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        "Clear Fall-through Override".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::util::TaskMonitor;
    use crate::program::model::listing::Instruction;
    use crate::framework::model::DomainObject;
    use crate::program::model::lang::ProcessorContextView;

    fn mk_addr(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockInstruction {
        addr: Address,
        fall_through_override_cleared: bool,
    }

    impl DomainObject for MockInstruction {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl crate::program::seam_stubs::MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
    }

    impl crate::program::model::util::PropertySet for MockInstruction {}

    impl crate::program::model::listing::code_unit::CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("0x{:x}", self.addr.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.addr.clone()
        }

        fn get_max_address(&self) -> Address {
            Address::new(self.addr.space().clone(), self.addr.offset() + 3)
        }

        fn contains(&self, _addr: &Address) -> bool {
            false
        }

        fn get_comment(&self, _comment_type: crate::program::seam_stubs::CommentType) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment_type: crate::program::seam_stubs::CommentType, _comment: Option<String>) {}

        fn get_mnemonic_string(&self) -> String {
            String::new()
        }

        fn get_comment_as_array(&self, _comment_type: crate::program::seam_stubs::CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment_as_array(&mut self, _comment_type: crate::program::seam_stubs::CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            4
        }

        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }

        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }

        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {}

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {}

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            unimplemented!("not needed for this test")
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not needed for this test")
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {}

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {}

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

    impl ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_value(&self, _register: &crate::program::model::lang::register::Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(
            &self,
            _register: &crate::program::model::lang::register::Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &crate::program::model::lang::register::Register) -> bool {
            false
        }
    }

    impl crate::program::model::lang::ProcessorContext for MockInstruction {
        fn set_value(
            &mut self,
            _register: &crate::program::model::lang::register::Register,
            _value: i128,
        ) -> Result<(), crate::program::model::listing::ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), crate::program::model::listing::ContextChangeException> {
            Ok(())
        }

        fn clear_register(
            &mut self,
            _register: &crate::program::model::lang::register::Register,
        ) -> Result<(), crate::program::model::listing::ContextChangeException> {
            Ok(())
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype> {
            unimplemented!()
        }

        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_op_objects(&self, _operand_index: i32) -> Vec<crate::program::model::listing::OperandValue> {
            Vec::new()
        }

        fn get_input_objects(&self) -> Vec<crate::program::model::listing::OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self) -> Vec<crate::program::model::listing::OperandValue> {
            Vec::new()
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

        fn get_operand_ref_type(&self, _operand_index: i32) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::FallThrough
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

        fn clear_fall_through_override(&mut self) {
            self.fall_through_override_cleared = true;
        }

        fn set_fall_through(&mut self, _addr: Option<Address>) {}

        fn is_fall_through_overridden(&self) -> bool {
            false
        }

        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }

        fn get_flow_type(&self) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::FallThrough
        }

        fn is_fallthrough(&self) -> bool {
            true
        }

        fn has_fallthrough(&self) -> bool {
            true
        }

        fn get_flow_override(&self) -> crate::program::seam_stubs::FlowOverride {
            crate::program::seam_stubs::FlowOverride::None
        }

        fn set_flow_override(&mut self, _flow_override: crate::program::seam_stubs::FlowOverride) {}

        fn set_length_override(&mut self, _length: i32) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }

        fn is_length_overridden(&self) -> bool {
            false
        }

        fn get_parsed_length(&self) -> i32 {
            4
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }

        fn get_pcode(&self) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_delay_slot_depth(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_instruction_context(&self) -> Arc<dyn crate::program::seam_stubs::InstructionContext> {
            unimplemented!()
        }

        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    struct MockListing {
        instruction: Option<Arc<dyn Instruction + Send + Sync>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_code_unit_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self, _comment_type: crate::program::seam_stubs::CommentType, _address: &crate::program::model::address::Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &crate::program::model::address::Address) -> Box<dyn crate::program::seam_stubs::CodeUnitComments> {
            struct MockComments;
            impl crate::program::seam_stubs::CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &crate::program::model::address::Address,
            _comment_type: crate::program::seam_stubs::CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_code_units(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instruction_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            self.instruction
                .clone()
                .map(|i| -> Arc<dyn crate::program::model::listing::instruction::Instruction> { i })
        }
        fn get_instruction_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instructions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_from(
            &self,
            _addr: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_from(&self, _addr: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_undefined_data_at(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn crate::program::model::address::AddressSetView>, crate::util::exception::CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_code_unit_after(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: crate::program::model::address::Address,
            _prototype: Arc<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            _mem_buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &dyn crate::program::model::lang::ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn crate::program::model::listing::instruction::Instruction>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn crate::program::seam_stubs::InstructionSet,
            _overwrite: bool,
        ) -> Result<Box<dyn crate::program::model::address::AddressSetView>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data_sized(
            &mut self,
            _addr: crate::program::model::address::Address,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _length: i32,
        ) -> Result<Arc<dyn crate::program::model::listing::data::Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data(
            &mut self,
            _addr: crate::program::model::address::Address,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Result<Arc<dyn crate::program::model::listing::data::Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_code_units(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _clear_context: bool,
        ) {
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &crate::program::model::address::Address, _end: &crate::program::model::address::Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &crate::program::model::address::Address, _end_addr: &crate::program::model::address::Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &crate::program::model::address::Address,
            _end_addr: &crate::program::model::address::Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<Arc<dyn crate::program::model::listing::program_module::ProgramModule>, crate::util::exception::DuplicateNameException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_root_module(&self, _tree_name: &str) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_root_module_by_id(&self, _tree_id: i64) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_default_root_module(&self) -> Arc<dyn crate::program::model::listing::program_module::ProgramModule> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tree_names(&self) -> Vec<String> {
            vec!["Program Tree".to_string()]
        }
        fn remove_tree(&mut self, _tree_name: &str) -> bool {
            false
        }
        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            0
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            0
        }
        fn get_data_type_manager(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            struct MockDataTypeManager;
            impl crate::program::model::data::data_type_manager::DataTypeManager for MockDataTypeManager {}
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: crate::program::model::address::Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::listing::function::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn crate::program::model::symbol::Namespace>,
            _entry_point: crate::program::model::address::Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Arc<dyn crate::program::model::listing::function::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_function(&mut self, _entry_point: &crate::program::model::address::Address) {}
        fn get_function_at(&self, _entry_point: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_function_containing(&self, _addr: &crate::program::model::address::Address) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(&self, _start: &crate::program::model::address::Address, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &crate::program::model::address::Address,
            _comment_type: crate::program::seam_stubs::CommentType,
        ) -> Vec<Box<dyn crate::program::seam_stubs::CommentHistory>> {
            Vec::new()
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    struct MockProgram {
        listing: MockListing,
    }

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            Some(&mut self.listing as &mut dyn crate::program::model::listing::Listing)
        }
    }

    #[test]
    fn command_name_is_correct() {
        let addr = mk_addr(0x1000);
        let cmd = ClearFallThroughCmd::new(addr);
        assert_eq!(cmd.name(), "Clear Fall-through Override");
    }

    #[test]
    fn command_status_msg_is_none() {
        let addr = mk_addr(0x1000);
        let cmd = ClearFallThroughCmd::new(addr);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_clears_fall_through_override() {
        let addr = mk_addr(0x1000);
        let mock_inst = Arc::new(MockInstruction {
            addr: addr.clone(),
            fall_through_override_cleared: false,
        });
        let mut cmd = ClearFallThroughCmd::new(addr);
        let mut program = MockProgram {
            listing: MockListing {
                instruction: Some(mock_inst.clone()),
            },
        };

        assert!(!mock_inst.fall_through_override_cleared);
        assert!(cmd.apply_to(&mut program));
        assert!(mock_inst.fall_through_override_cleared);
    }

    #[test]
    fn apply_to_returns_false_when_instruction_not_found() {
        let addr = mk_addr(0x1000);
        let mut cmd = ClearFallThroughCmd::new(addr);
        let mut program = MockProgram {
            listing: MockListing {
                instruction: None,
            },
        };

        assert!(!cmd.apply_to(&mut program));
    }

    #[test]
    fn apply_to_returns_false_when_listing_not_available() {
        struct ProgramWithoutListing;

        impl DomainObject for ProgramWithoutListing {
            fn is_changed(&self) -> bool {
                false
            }
        }

        impl Program for ProgramWithoutListing {
            fn get_name(&self) -> String {
                "mock".to_string()
            }

            fn get_language_id(&self) -> String {
                "mock:LE:32:default".to_string()
            }
        }

        let addr = mk_addr(0x1000);
        let mut cmd = ClearFallThroughCmd::new(addr);
        let mut program = ProgramWithoutListing;

        assert!(!cmd.apply_to(&mut program));
    }
}
