//! Port of `ghidra.program.model.listing.InstructionPcodeOverride`.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::inject_payload::CALLFIXUP_TYPE;
use crate::program::model::lang::InjectPayload;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::PcodeOverride;
use crate::program::model::symbol::{RefType, Reference};
use crate::program::seam_stubs::FlowOverride;
use crate::util::Msg;

/// Port of `ghidra.program.model.listing.InstructionPcodeOverride`.
///
/// Ported as a trait (rather than only a concrete struct) because this type was selected as a
/// dependency-cycle cut-point: `Instruction` implementors (`InstructionDB`, `PseudoInstruction`)
/// each construct `new InstructionPcodeOverride(this)` to obtain a `PcodeOverride` for their own
/// p-code queries, while `InstructionPcodeOverride` itself is defined in terms of `Instruction`.
/// The Java class implements `PcodeOverride` with no public members beyond its constructor, so
/// this trait is a marker supertrait: callers can depend on `dyn InstructionPcodeOverride`
/// instead of the concrete class, and any `PcodeOverride` sourced from an instruction may
/// implement it. [`InstructionPcodeOverrideImpl`] provides the concrete caching algorithm from
/// the Java source and implements this trait.
pub trait InstructionPcodeOverride: PcodeOverride {}

/// Direct port of the Java `InstructionPcodeOverride` class: caches the primary and overriding
/// "from" references of an instruction and answers [`PcodeOverride`] queries from that cache.
///
/// The cache is populated lazily (on first query) and never refreshed, mirroring the Java
/// class's assumption that instances are short-lived (the duration of a single `PcodeEmit`
/// pass). All mutator methods take `&self`, per [`PcodeOverride`]'s contract; the applied flags
/// and reference cache are carried via interior mutability instead of the Java fields.
pub struct InstructionPcodeOverrideImpl {
    instr: Arc<dyn Instruction>,
    call_override_applied: Cell<bool>,
    jump_override_applied: Cell<bool>,
    call_other_call_override_applied: Cell<bool>,
    call_other_jump_override_applied: Cell<bool>,
    primary_call_address: RefCell<Option<Address>>,
    primary_overriding_references: RefCell<Option<Vec<Arc<dyn Reference>>>>,
}

impl InstructionPcodeOverrideImpl {
    /// This constructor caches nothing eagerly; the primary and overriding "from" references of
    /// `instr` are computed and cached lazily on first query. Mirrors the Java constructor
    /// `InstructionPcodeOverride(Instruction instr)`.
    pub fn new(instr: Arc<dyn Instruction>) -> Self {
        InstructionPcodeOverrideImpl {
            instr,
            call_override_applied: Cell::new(false),
            jump_override_applied: Cell::new(false),
            call_other_call_override_applied: Cell::new(false),
            call_other_jump_override_applied: Cell::new(false),
            primary_call_address: RefCell::new(None),
            primary_overriding_references: RefCell::new(None),
        }
    }

    /// Initialize the cache of any references on the instruction that would cause an override.
    /// Port of the private `getPrimaryOverridingReferences()`.
    fn primary_overriding_references(&self) -> Vec<Arc<dyn Reference>> {
        if let Some(refs) = self.primary_overriding_references.borrow().as_ref() {
            return refs.clone();
        }

        let mut overriding = Vec::new();
        for reference in self.instr.get_references_from() {
            if !reference.is_primary() || !reference.to_address().is_memory_address() {
                continue;
            }
            let ref_type = reference.reference_type();
            if ref_type.is_override() {
                overriding.push(reference);
            } else if ref_type.is_call() && self.primary_call_address.borrow().is_none() {
                *self.primary_call_address.borrow_mut() = Some(reference.to_address());
            }
        }

        *self.primary_overriding_references.borrow_mut() = Some(overriding.clone());
        overriding
    }

    /// Looks up the function at `addr`, if any.
    ///
    /// Requires unique ownership of the underlying program in order to obtain its function
    /// manager; returns `None` if the program is currently shared elsewhere. Stands in for
    /// `instr.getProgram().getFunctionManager().getFunctionAt(addr)`.
    fn function_at(&self, addr: &Address) -> Option<Arc<dyn Function>> {
        let mut program = self.instr.get_program();
        Arc::get_mut(&mut program)?
            .get_function_manager()?
            .get_function_at(addr)
    }
}

impl PcodeOverride for InstructionPcodeOverrideImpl {
    fn get_instruction_start(&self) -> Address {
        self.instr.get_min_address()
    }

    fn get_flow_override(&self) -> FlowOverride {
        self.instr.get_flow_override()
    }

    fn get_overriding_reference(&self, ref_type: RefType) -> Option<Address> {
        if !ref_type.is_override() {
            return None;
        }

        let overriding_refs = self.primary_overriding_references();
        let mut override_address = None;
        for reference in &overriding_refs {
            if reference.reference_type() == ref_type {
                if override_address.is_none() {
                    override_address = Some(reference.to_address());
                } else {
                    return None; // only allow one primary reference of each type
                }
            }
        }
        override_address
    }

    fn get_fall_through_override(&self) -> Option<Address> {
        let default_fall_addr = self.instr.get_default_fall_through();
        let fall_addr = self.instr.get_fall_through();
        if let Some(fall) = &fall_addr {
            if self.instr.is_length_overridden() || Some(fall) != default_fall_addr.as_ref() {
                return fall_addr;
            }
        }
        None
    }

    fn has_call_fixup(&self, call_dest_addr: Address) -> bool {
        match self.function_at(&call_dest_addr) {
            Some(func) => func.get_call_fixup().is_some(),
            None => false,
        }
    }

    fn get_call_fixup(&self, call_dest_addr: Address) -> Option<Box<dyn InjectPayload>> {
        let func = self.function_at(&call_dest_addr)?;
        let fixup_name = func.get_call_fixup()?;
        let program = self.instr.get_program();
        let fixup = program
            .get_compiler_spec()?
            .get_pcode_inject_library()
            .get_payload(CALLFIXUP_TYPE, &fixup_name);
        if fixup.is_none() {
            Msg::warn(
                "InstructionPcodeOverride",
                &format!("Undefined call-fixup at {call_dest_addr}: {fixup_name}"),
            );
        }
        fixup
    }

    fn set_call_override_ref_applied(&self) {
        self.call_override_applied.set(true);
    }

    fn is_call_override_ref_applied(&self) -> bool {
        self.call_override_applied.get()
    }

    fn set_jump_override_ref_applied(&self) {
        self.jump_override_applied.set(true);
    }

    fn is_jump_override_ref_applied(&self) -> bool {
        self.jump_override_applied.get()
    }

    fn set_call_other_call_override_ref_applied(&self) {
        self.call_other_call_override_applied.set(true);
    }

    fn is_call_other_call_override_ref_applied(&self) -> bool {
        self.call_other_call_override_applied.get()
    }

    fn set_call_other_jump_override_ref_applied(&self) {
        self.call_other_jump_override_applied.set(true);
    }

    fn is_call_other_jump_override_applied(&self) -> bool {
        self.call_other_jump_override_applied.get()
    }

    fn has_potential_override(&self) -> bool {
        !self.primary_overriding_references().is_empty()
    }

    #[allow(deprecated)]
    fn get_primary_call_reference(&self) -> Option<Address> {
        self.primary_overriding_references();
        self.primary_call_address.borrow().clone()
    }
}

impl InstructionPcodeOverride for InstructionPcodeOverrideImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContext;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::OperandValue;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::SourceType;
    use crate::program::seam_stubs::{InjectContext, InstructionContext};
use crate::program::model::mem::MemBuffer;

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A minimal `Reference` recording just what `InstructionPcodeOverrideImpl` inspects.
    struct MockReference {
        to: Address,
        primary: bool,
        ref_type: RefType,
    }

    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            self.to.clone()
        }
        fn to_address(&self) -> Address {
            self.to.clone()
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            self.ref_type
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A minimal `Instruction` proving [`InstructionPcodeOverrideImpl`] can drive its cache
    /// purely off the `Instruction`/`MemBuffer`/`ProcessorContext` contract, with no database
    /// backing.
    struct MockInstruction {
        min_addr: Address,
        default_fall: Option<Address>,
        fall: Option<Address>,
        length_overridden: bool,
        refs_from: Vec<Arc<dyn Reference>>,
    }

    impl MemBuffer for MockInstruction {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_addr.clone()
        }
    }

    impl ProcessorContext for MockInstruction {
        fn set_value(&mut self, _register: &crate::program::model::lang::register::Register, _value: i128) -> Result<(), crate::program::model::listing::ContextChangeException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_register_value(&mut self, _value: Box<dyn crate::program::seam_stubs::RegisterValue>) -> Result<(), crate::program::model::listing::ContextChangeException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_register(&mut self, _register: &crate::program::model::lang::register::Register) -> Result<(), crate::program::model::listing::ContextChangeException> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::program::model::util::PropertySet for MockInstruction {}

    impl crate::program::model::lang::processor_context_view::ProcessorContextView for MockInstruction {
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
        fn get_register_value(&self, _register: &crate::program::model::lang::register::Register) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &crate::program::model::lang::register::Register) -> bool {
            false
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
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
            self.min_addr.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_addr.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "mock".to_string()
        }
        fn get_comment(&self, _comment_type: crate::program::model::listing::CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: crate::program::model::listing::CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(&self, _buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
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
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            self.refs_from.clone()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by this smoke test: has_call_fixup/get_call_fixup are covered separately")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _stack_offset: i32, _source_type: SourceType, _ref_type: RefType) {}
        fn set_register_reference(&mut self, _op_index: i32, _register: &crate::program::model::lang::register::Register, _source_type: SourceType, _ref_type: RefType) {}
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
        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
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
            self.get_length()
        }
        fn get_default_fall_through(&self) -> Option<Address> {
            self.default_fall.clone()
        }
        fn get_fall_through(&self) -> Option<Address> {
            self.fall.clone()
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
            RefType::Invalid
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
        fn set_length_override(&mut self, _length: i32) -> Result<(), crate::program::util::CodeUnitInsertionException> {
            Ok(())
        }
        fn is_length_overridden(&self) -> bool {
            self.length_overridden
        }
        fn get_parsed_length(&self) -> i32 {
            self.get_length()
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
            struct MockContext;
            impl InstructionContext for MockContext {}
            Arc::new(MockContext)
        }
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let instr: Arc<dyn Instruction> = Arc::new(MockInstruction {
            min_addr: addr(&space, 0x1000),
            default_fall: Some(addr(&space, 0x1001)),
            fall: Some(addr(&space, 0x1001)),
            length_overridden: false,
            refs_from: Vec::new(),
        });
        let over = InstructionPcodeOverrideImpl::new(instr);
        let dyn_over: &dyn InstructionPcodeOverride = &over;
        assert_eq!(dyn_over.get_instruction_start(), addr(&space, 0x1000));
    }

    #[test]
    fn caches_overriding_reference_and_primary_call_address() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let override_target = addr(&space, 0x2000);
        let call_target = addr(&space, 0x3000);

        let refs: Vec<Arc<dyn Reference>> = vec![
            Arc::new(MockReference {
                to: override_target.clone(),
                primary: true,
                ref_type: RefType::CallOverrideUnconditional,
            }),
            Arc::new(MockReference {
                to: call_target.clone(),
                primary: true,
                ref_type: RefType::UnconditionalCall,
            }),
            // Non-primary reference: must be ignored.
            Arc::new(MockReference {
                to: addr(&space, 0x4000),
                primary: false,
                ref_type: RefType::CallOverrideUnconditional,
            }),
        ];

        let instr: Arc<dyn Instruction> = Arc::new(MockInstruction {
            min_addr: addr(&space, 0x1000),
            default_fall: Some(addr(&space, 0x1001)),
            fall: Some(addr(&space, 0x1005)),
            length_overridden: false,
            refs_from: refs,
        });
        let over = InstructionPcodeOverrideImpl::new(instr);

        assert!(over.has_potential_override());
        assert_eq!(
            over.get_overriding_reference(RefType::CallOverrideUnconditional),
            Some(override_target)
        );
        assert_eq!(over.get_overriding_reference(RefType::JumpOverrideUnconditional), None);
        #[allow(deprecated)]
        {
            assert_eq!(over.get_primary_call_reference(), Some(call_target));
        }

        // fall-through differs from the default -> reported as an override.
        assert_eq!(over.get_fall_through_override(), Some(addr(&space, 0x1005)));

        assert!(!over.is_call_override_ref_applied());
        over.set_call_override_ref_applied();
        assert!(over.is_call_override_ref_applied());
        assert!(!over.is_jump_override_ref_applied());
    }

    #[test]
    fn get_overriding_reference_rejects_non_override_type() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let instr: Arc<dyn Instruction> = Arc::new(MockInstruction {
            min_addr: addr(&space, 0x1000),
            default_fall: Some(addr(&space, 0x1001)),
            fall: Some(addr(&space, 0x1001)),
            length_overridden: false,
            refs_from: Vec::new(),
        });
        let over = InstructionPcodeOverrideImpl::new(instr);

        // RefType::UnconditionalCall is not an override type, so this must return None even
        // though it is never in the reference set.
        assert_eq!(over.get_overriding_reference(RefType::UnconditionalCall), None);
        assert!(!over.has_potential_override());
    }
}
