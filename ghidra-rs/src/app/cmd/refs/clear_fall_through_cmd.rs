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
    use crate::program::model::listing::Instruction;
    use crate::framework::model::DomainObject;
    use crate::program::model::lang::ProcessorContextView;

    struct MockInstruction {
        addr: Address,
        fall_through_override_cleared: bool,
    }

    impl DomainObject for MockInstruction {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl crate::program::seam_stubs::MemBuffer for MockInstruction {}

    impl crate::program::model::util::PropertySet for MockInstruction {
        fn get_property(&self, _property_name: &str) -> Option<Box<dyn std::any::Any>> {
            None
        }

        fn set_property(&mut self, _property_name: &str, _value: Option<Box<dyn std::any::Any>>) {}
    }

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
            self.addr
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

        fn get_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn add_reference(
            &mut self,
            _address: &Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {}

        fn remove_reference(&mut self, _address: &Address, _ref_type: crate::program::model::symbol::RefType) {}

        fn get_bookmarks(&self) -> Vec<Arc<dyn crate::program::model::listing::Bookmark>> {
            Vec::new()
        }

        fn set_bookmark(
            &mut self,
            _bookmark_type: &str,
            _category: &str,
            _comment: &str,
        ) {}

        fn remove_bookmark(&mut self, _bookmark_type: &str, _category: &str) {}
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
            crate::program::model::symbol::RefType::Fall
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
        instruction: Option<Arc<dyn Instruction>>,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_instruction_at(&self, _addr: &Address) -> Option<Arc<dyn Instruction>> {
            self.instruction.clone()
        }

        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn remove_function(&mut self, _entry_point: &Address) {}

        fn create_function(
            &mut self,
            _entry_point: &Address,
            _name: &str,
        ) -> Result<Arc<dyn crate::program::model::listing::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!()
        }

        fn create_function_in_namespace(
            &mut self,
            _entry_point: &Address,
            _name: &str,
            _namespace: Option<Arc<dyn crate::program::model::symbol::Namespace>>,
        ) -> Result<Arc<dyn crate::program::model::listing::Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!()
        }

        fn get_global_functions(&self, _name: &str) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_external_functions(&self) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn get_functions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!()
        }

        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }

        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn crate::program::model::listing::code_unit::CodeUnit>> {
            None
        }

        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
        }

        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!()
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
        let addr = Address::new(0x1000);
        let cmd = ClearFallThroughCmd::new(addr);
        assert_eq!(cmd.name(), "Clear Fall-through Override");
    }

    #[test]
    fn command_status_msg_is_none() {
        let addr = Address::new(0x1000);
        let cmd = ClearFallThroughCmd::new(addr);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_clears_fall_through_override() {
        let addr = Address::new(0x1000);
        let mock_inst = Arc::new(MockInstruction {
            addr,
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
        let addr = Address::new(0x1000);
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

        let addr = Address::new(0x1000);
        let mut cmd = ClearFallThroughCmd::new(addr);
        let mut program = ProgramWithoutListing;

        assert!(!cmd.apply_to(&mut program));
    }
}
