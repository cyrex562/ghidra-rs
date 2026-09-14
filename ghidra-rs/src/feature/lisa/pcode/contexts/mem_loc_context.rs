//! Port of `ghidra.lisa.pcode.contexts.MemLocContext`.

use std::sync::Arc;

use crate::feature::lisa::pcode::contexts::statement_context::StatementContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::Varnode;

/// A [`VarnodeContext`] for a `LOAD`/`STORE`-style p-code operation's memory location operand,
/// additionally tracking which [`AddressSpace`] that location's address space input identifies.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.MemLocContext` in the Java source, which `extends
/// VarnodeContext`. Following this crate's composition-over-inheritance convention, this wraps a
/// `VarnodeContext` by composition instead.
#[derive(Clone, Debug)]
pub struct MemLocContext {
    base: VarnodeContext,
    /// Mirrors the Java class's private `space` field. `None` mirrors a Java `null` there
    /// (reached when neither the op's input-0-derived space ID nor the address factory's default
    /// address space resolves to anything) -- ordinary, not an error condition by itself; only
    /// dereferencing it (in [`MemLocContext::get_text`]) would throw a `NullPointerException` in
    /// Java, reproduced here by [`MemLocContext::get_text`] panicking only at that point.
    space: Option<Arc<AddressSpace>>,
}

impl MemLocContext {
    /// Java: `MemLocContext(StatementContext ctx)`.
    ///
    /// # Panics
    ///
    /// If `ctx`'s op has no input at index 1 (the memory location varnode itself: Java's
    /// `super(ctx.getOp().getInput(1))` would instead wrap a `null` varnode, deferred-panicking
    /// the same way [`PcodeContext::basic_expr`](crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext::basic_expr)'s
    /// docs describe), if `ctx`'s op has no input at index 0 (the address space ID operand), or
    /// if [`StatementContext::get_address_factory`] itself panics (`ctx`'s `inst` is absent --
    /// see that method's own docs).
    pub fn new(ctx: &StatementContext) -> Self {
        let vn = ctx
            .get_op()
            .get_input(1)
            .cloned()
            .expect("MemLocContext::new: op has no input at index 1");
        let base = VarnodeContext::new(vn);

        let address_factory = ctx
            .get_address_factory()
            .expect("MemLocContext::new: address factory is None (Java NullPointerException)");
        let space_input = ctx
            .get_op()
            .get_input(0)
            .cloned()
            .expect("MemLocContext::new: op has no input at index 0");
        // Java: `(int) ctx.getOp().getInput(0).getOffset()` -- a narrowing `long` -> `int` cast,
        // truncating to the low 32 bits (matched here by Rust's own truncating `as i32`).
        let space_id = space_input.get_offset() as i32;
        let space = address_factory
            .get_address_space_by_id(space_id)
            .or_else(|| address_factory.get_default_address_space());

        Self { base, space }
    }

    /// Java: the overridden `getText()`.
    ///
    /// # Panics
    ///
    /// If [`MemLocContext::space`] is `None` -- the `NullPointerException` a real caller
    /// dereferencing Java's `null` `space` field would hit here, deferred from construction. See
    /// the struct docs.
    pub fn get_text(&self) -> String {
        let space = self
            .space
            .as_ref()
            .expect("MemLocContext::get_text: space is None (Java NullPointerException)");
        format!("{}@{}", space.name(), self.base.varnode().get_address())
    }

    /// Java: the inherited `isConstant()`.
    pub fn is_constant(&self) -> bool {
        self.base.is_constant()
    }

    /// Java: the inherited `getSize()`.
    pub fn get_size(&self) -> i32 {
        self.base.get_size()
    }

    /// Java: the inherited `getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.base.get_offset()
    }

    /// The wrapped varnode, standing in for direct access to `VarnodeContext`'s protected `vn`
    /// field.
    pub fn varnode(&self) -> &Varnode {
        self.base.varnode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn factory_with(space: Arc<AddressSpace>) -> Arc<dyn AddressFactory> {
        Arc::new(DefaultAddressFactory::with_default_space(vec![space.clone()], Some(space)))
    }

    // --- A minimal `Instruction` mock exposing a program whose `AddressFactory` we control,
    // enough to exercise `MemLocContext::new`. Every supertrait method not exercised by these
    // tests panics if called, mirroring the established pattern used throughout this crate (e.g.
    // `statement_context.rs`'s own `MockInstruction`).

    struct MockInstruction {
        address_factory: Option<Arc<dyn AddressFactory>>,
    }

    impl MemBuffer for MockInstruction {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            Address::new(ram_space(), 0)
        }
    }
    impl PropertySet for MockInstruction {}

    impl crate::program::model::lang::ProcessorContextView for MockInstruction {
        fn get_base_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
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

    use crate::program::model::lang::register::Register;

    impl crate::program::model::lang::ProcessorContext for MockInstruction {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
            Ok(())
        }
        fn clear_register(
            &mut self,
            _register: &Register,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
            Ok(())
        }
    }

    struct MockProgram {
        address_factory: Option<Arc<dyn AddressFactory>>,
    }
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.address_factory.clone()
        }
    }

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
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
            Address::new(ram_space(), 0)
        }
        fn get_max_address(&self) -> Address {
            Address::new(ram_space(), 0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
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
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram { address_factory: self.address_factory.clone() })
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
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
        fn get_prototype(&self) -> Arc<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_op_objects(
            &self,
            _operand_index: i32,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_input_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_result_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }
        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }
        fn get_operand_ref_type(&self, _operand_index: i32) -> SymRefType {
            SymRefType::Data
        }
        fn get_default_fall_through_offset(&self) -> i32 {
            0
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
        fn get_flow_type(&self) -> SymRefType {
            SymRefType::FallThrough
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
        fn set_length_override(
            &mut self,
            _length: i32,
        ) -> Result<(), crate::program::util::CodeUnitInsertionException> {
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
        fn get_instruction_context(&self) -> Arc<dyn crate::program::seam_stubs::InstructionContext> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn stmt_ctx_with_factory(
        space_id_offset: i64,
        address_factory: Option<Arc<dyn AddressFactory>>,
    ) -> StatementContext {
        let space = ram_space();
        let space_id = varnode(&space, space_id_offset, 4);
        let mem_addr = varnode(&space, 0x2000, 4);
        let op = PcodeOp::new(
            OpCode::Load,
            SequenceNumber::new(Address::new(space, 0x1000), 0),
            vec![space_id, mem_addr],
            None,
        );
        let inst: Arc<dyn Instruction> = Arc::new(MockInstruction { address_factory });
        StatementContext::new(inst, op)
    }

    #[test]
    fn new_resolves_the_space_by_id_from_input_0s_offset() {
        let ram = ram_space();
        let factory = factory_with(ram.clone());
        let ctx = stmt_ctx_with_factory(ram.space_id().into(), Some(factory));

        let mem_loc = MemLocContext::new(&ctx);

        assert_eq!(mem_loc.get_text(), format!("{}@{}", ram.name(), Address::new(ram_space(), 0x2000)));
    }

    #[test]
    fn new_falls_back_to_the_default_address_space_when_the_id_is_unknown() {
        let ram = ram_space();
        let factory = factory_with(ram.clone());
        // A space ID that doesn't resolve to any space in `factory` falls back to the factory's
        // default address space (still `ram` here, since that's the only space registered).
        let ctx = stmt_ctx_with_factory(0xDEAD, Some(factory));

        let mem_loc = MemLocContext::new(&ctx);

        assert_eq!(mem_loc.get_text(), format!("{}@{}", ram.name(), Address::new(ram_space(), 0x2000)));
    }

    #[test]
    #[should_panic(expected = "address factory is None")]
    fn new_panics_when_the_program_has_no_address_factory() {
        let ctx = stmt_ctx_with_factory(0, None);
        let _ = MemLocContext::new(&ctx);
    }

    #[test]
    fn is_constant_size_and_offset_delegate_to_the_wrapped_varnode() {
        let ram = ram_space();
        let factory = factory_with(ram.clone());
        let ctx = stmt_ctx_with_factory(ram.space_id().into(), Some(factory));

        let mem_loc = MemLocContext::new(&ctx);

        assert!(!mem_loc.is_constant());
        assert_eq!(mem_loc.get_size(), 4);
        assert_eq!(mem_loc.get_offset(), 0x2000);
    }
}
