use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::lang::{InstructionPrototype, ProcessorContextView};
use crate::program::seam_stubs::InstructionSet;
use crate::program::util::code_unit_insertion_exception::CodeUnitInsertionException;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;
use crate::trace::model::listing::trace_instruction::TraceInstruction;
use crate::trace::seam_stubs::TracePlatform;

/// A view of instruction units.
///
/// Port of `ghidra.trace.model.listing.TraceInstructionsView`.
///
/// This view excludes all data units, defined or undefined.
///
/// The Java interface's overloaded `create(...)` and `addInstructionSet(...)` methods cannot be
/// represented as same-named Rust methods (Rust has no overloading), so each overload is given a
/// distinct, descriptive name below.
pub trait TraceInstructionsView: TraceBaseDefinedUnitsView {
    /// Create an instruction.
    ///
    /// Mirrors the Java overload `create(Lifespan, Address, TracePlatform,
    /// InstructionPrototype, ProcessorContextView, int)`.
    fn create(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        platform: &dyn TracePlatform,
        prototype: &dyn InstructionPrototype,
        context: &dyn ProcessorContextView,
        forced_length_override: i32,
    ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException>;

    /// Create an instruction for the host platform. Mirrors the Java default method
    /// `create(Lifespan, Address, InstructionPrototype, ProcessorContextView, int)`.
    fn create_on_host(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        prototype: &dyn InstructionPrototype,
        context: &dyn ProcessorContextView,
        forced_length_override: i32,
    ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.create(
            lifespan,
            address,
            platform.as_ref(),
            prototype,
            context,
            forced_length_override,
        )
    }

    /// Create several instructions.
    ///
    /// This does not fail on conflicts; conflicts are instead recorded in the
    /// `instruction_set`. Returns the (host) address set of instructions actually added.
    /// Mirrors the Java overload `addInstructionSet(Lifespan, TracePlatform, InstructionSet,
    /// boolean)`.
    fn add_instruction_set(
        &mut self,
        lifespan: &dyn Lifespan,
        platform: &dyn TracePlatform,
        instruction_set: &dyn InstructionSet,
        overwrite: bool,
    ) -> Box<dyn AddressSetView>;

    /// Create several instructions for the host platform. Mirrors the Java default method
    /// `addInstructionSet(Lifespan, InstructionSet, boolean)`.
    fn add_instruction_set_on_host(
        &mut self,
        lifespan: &dyn Lifespan,
        instruction_set: &dyn InstructionSet,
        overwrite: bool,
    ) -> Box<dyn AddressSetView> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.add_instruction_set(lifespan, platform.as_ref(), instruction_set, overwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::InstructionContext as LangInstructionContext;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::Language;
    use crate::program::model::lang::{ProcessorContext, ProcessorContextView as PCV};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::{Instruction, OperandValue};
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, FlowOverride, InstructionContext, MemBuffer, ParserContext};
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TracePlatformManager, TraceThread};
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    struct MockPlatformManager {
        host_platform_calls: Rc<Cell<u32>>,
    }
    impl TracePlatformManager for MockPlatformManager {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            self.host_platform_calls.set(self.host_platform_calls.get() + 1);
            Box::new(MockPlatform)
        }
    }

    struct MockTrace {
        host_platform_calls: Rc<Cell<u32>>,
    }
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::program::seam_stubs::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {}
        fn get_emulator_cache_version(&self) -> i64 {
            0
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            Box::new(MockPlatformManager { host_platform_calls: Rc::clone(&self.host_platform_calls) })
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockPrototype {
        length: i32,
    }
    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn PCV,
        ) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn PCV,
        ) -> Result<Box<dyn ParserContext>, crate::program::model::lang::instruction_prototype::GetPseudoParserContextError>
        {
            unimplemented!("not exercised by this smoke test")
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
        fn get_mnemonic(&self, _context: &dyn LangInstructionContext) -> String {
            "MOV".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_instruction_mask(&self) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }
        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }
        fn get_flow_type(&self, _context: &dyn LangInstructionContext) -> RefType {
            RefType::FallThrough
        }
        fn get_delay_slot_depth(&self, _context: &dyn LangInstructionContext) -> i32 {
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
        fn get_op_type(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> i32 {
            0
        }
        fn get_fall_through(&self, _context: &dyn LangInstructionContext) -> Option<Address> {
            None
        }
        fn get_fall_through_offset(&self, _context: &dyn LangInstructionContext) -> i32 {
            self.length
        }
        fn get_flows(&self, _context: &dyn LangInstructionContext) -> Option<Vec<Address>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Option<Vec<OperandValue>> {
            None
        }
        fn get_address(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> Option<Address> {
            None
        }
        fn get_register(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> Option<RegisterRef> {
            None
        }
        fn get_scalar(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> Option<Scalar> {
            None
        }
        fn get_op_objects(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }
        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }
        fn get_input_objects(&self, _context: &dyn LangInstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_result_objects(&self, _context: &dyn LangInstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_pcode(
            &self,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::PatchEncoder,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_pcode_for_operand(&self, _context: &dyn LangInstructionContext, _operand_index: i32) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockContext;
    impl PCV for MockContext {
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
        fn get_register_value(
            &self,
            _register: &Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    struct MockReferenceIterator;
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            None
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockInstructionContext;
    impl InstructionContext for MockInstructionContext {}

    #[derive(Clone)]
    struct MockInstruction {
        address: Address,
        length: i32,
    }

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }
    impl PropertySet for MockInstruction {}

    impl PCV for MockInstruction {
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
        fn get_register_value(
            &self,
            _register: &Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
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
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
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
            self.address.add_wrap(self.length as i64 - 1)
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
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
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }
        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
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
            Box::new(MockReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
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
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Instruction for MockInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not exercised by this smoke test")
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
        fn get_default_operand_representation_list(&self, _operand_index: i32) -> Option<Vec<OperandValue>> {
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
            self.length
        }
        fn get_default_fall_through(&self) -> Option<Address> {
            Some(self.address.add_wrap(self.length as i64))
        }
        fn get_fall_through(&self) -> Option<Address> {
            Some(self.address.add_wrap(self.length as i64))
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
            self.length
        }
        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
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
            Arc::new(MockInstructionContext)
        }
    }

    impl TraceCodeUnit for MockInstruction {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), self.address.add_wrap(self.length as i64 - 1))
        }
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            0
        }
        fn set_end_snap(&mut self, _end_snap: i64) {}
        fn get_end_snap(&self) -> i64 {
            0
        }
        fn delete(&mut self) {}
    }

    impl TraceInstruction for MockInstruction {
        fn get_guest_default_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_guest_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
    }

    struct MockInstructionSet;
    impl InstructionSet for MockInstructionSet {}

    /// A minimal in-memory view backing store, only realistic enough to prove that `create`
    /// inserts instructions at the requested address, that conflicts are rejected, and that the
    /// host-platform defaults (`create_on_host`, `add_instruction_set_on_host`) delegate through
    /// `Trace::get_platform_manager().get_host_platform()`.
    struct MockView {
        units: Vec<(Address, i32)>,
        host_platform_calls: Rc<Cell<u32>>,
    }

    impl TraceBaseCodeUnitsView for MockView {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace { host_platform_calls: Rc::clone(&self.host_platform_calls) })
        }
        fn size(&self) -> i32 {
            self.units.len() as i32
        }
        fn get_before(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_at(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_after(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_between(
            &self,
            _snap: i64,
            _min: &Address,
            _max: &Address,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_in_set(&self, _snap: i64, _set: &dyn AddressSetView, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_in_range(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_from(&self, _snap: i64, _start: &Address, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_all(&self, _snap: i64, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_address_set_view_within(&self, _snap: i64, _within: &AddressRange) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn contains_address(&self, _snap: i64, address: &Address) -> bool {
            self.units.iter().any(|(a, _)| a == address)
        }
        fn covers_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
            false
        }
        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }
        fn intersects_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
            false
        }
        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }
        fn get_for_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }
        fn get_by_platform_register(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
    }

    impl TraceBaseDefinedUnitsView for MockView {
        fn clear(
            &mut self,
            _span: &dyn Lifespan,
            _range: &AddressRange,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_register(
            &mut self,
            _span: &dyn Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            _span: &dyn Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    impl TraceInstructionsView for MockView {
        fn create(
            &mut self,
            _lifespan: &dyn Lifespan,
            address: &Address,
            _platform: &dyn TracePlatform,
            prototype: &dyn InstructionPrototype,
            _context: &dyn ProcessorContextView,
            _forced_length_override: i32,
        ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException> {
            if self.units.iter().any(|(a, _)| a == address) {
                return Err(CodeUnitInsertionException::new("conflict"));
            }
            let length = prototype.get_length();
            self.units.push((address.clone(), length));
            Ok(Box::new(MockInstruction { address: address.clone(), length }))
        }

        fn add_instruction_set(
            &mut self,
            lifespan: &dyn Lifespan,
            platform: &dyn TracePlatform,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            // The `InstructionSet` stub carries no enumerable instructions yet, so this mock
            // simulates "installing" a single fixed instruction to prove the plumbing.
            let address = addr(0x800);
            let _ = self.create(lifespan, &address, platform, &MockPrototype { length: 2 }, &MockContext, 0);
            let mut set = AddressSet::new();
            set.add_range(&address, &address.add_wrap(1));
            Box::new(set)
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct DummyLifespan;
    impl Lifespan for DummyLifespan {
        fn lmin(&self) -> i64 {
            0
        }
        fn lmax(&self) -> i64 {
            10
        }
        fn contains(&self, n: i64) -> bool {
            (0..=10).contains(&n)
        }
        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(DummyLifespan)
        }
        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(DummyLifespan)
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(0..=10)
        }
    }

    fn make_view() -> MockView {
        MockView { units: Vec::new(), host_platform_calls: Rc::new(Cell::new(0)) }
    }

    #[test]
    fn create_inserts_and_rejects_conflicts() {
        let mut view: Box<dyn TraceInstructionsView> = Box::new(make_view());

        let created = view
            .create(&DummyLifespan, &addr(0x400), &MockPlatform, &MockPrototype { length: 4 }, &MockContext, 0)
            .expect("create should succeed for a fresh address");
        assert_eq!(created.get_min_address(), addr(0x400));
        assert_eq!(created.get_length(), 4);
        assert_eq!(view.size(), 1);

        let conflict =
            view.create(&DummyLifespan, &addr(0x400), &MockPlatform, &MockPrototype { length: 4 }, &MockContext, 0);
        assert!(conflict.is_err(), "creating at an already-occupied address must fail");
    }

    #[test]
    fn create_on_host_delegates_to_host_platform() {
        let mut view = make_view();
        assert_eq!(view.host_platform_calls.get(), 0);

        let created = view
            .create_on_host(&DummyLifespan, &addr(0x400), &MockPrototype { length: 4 }, &MockContext, 0)
            .expect("create_on_host should succeed");
        assert_eq!(created.get_min_address(), addr(0x400));
        assert_eq!(view.host_platform_calls.get(), 1, "create_on_host must resolve the host platform exactly once");
    }

    #[test]
    fn add_instruction_set_on_host_delegates_to_host_platform() {
        let mut view = make_view();
        assert_eq!(view.host_platform_calls.get(), 0);

        let added = view.add_instruction_set_on_host(&DummyLifespan, &MockInstructionSet, false);
        assert!(added.contains(&addr(0x800)));
        assert_eq!(
            view.host_platform_calls.get(),
            1,
            "add_instruction_set_on_host must resolve the host platform exactly once"
        );
        assert_eq!(view.size(), 1);
    }
}
