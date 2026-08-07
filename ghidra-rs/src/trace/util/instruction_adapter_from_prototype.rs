//! Port of `ghidra.trace.util.InstructionAdapterFromPrototype`.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::operand_type::OperandType;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::InstructionContext;
use crate::program::model::listing::instruction::{Instruction, OperandValue};
use crate::program::model::listing::instruction_pcode_override::InstructionPcodeOverrideImpl;
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::RefType;
use crate::trace::model::listing::trace_instruction::TraceInstruction;

/// Default [`Instruction`] behavior computed from a [`TraceInstruction`]'s
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype),
/// remapping guest-language addresses into the trace's host address
/// space along the way.
///
/// Port of `ghidra.trace.util.InstructionAdapterFromPrototype`.
///
/// ## Rust adaptation notes
///
/// Nearly every default method here overrides one inherited (abstract) from `Instruction` or its
/// `CodeUnit` supertrait -- e.g. `getMnemonicString()`, `getNumOperands()`, `getAddress(int)`.
/// Rust has no notion of a trait default method overriding an inherited abstract method of the
/// same name from an unrelated trait (the same issue documented on
/// [`TraceInstruction`](crate::trace::model::listing::trace_instruction::TraceInstruction) and
/// [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit)): defining a
/// method here with the same name as an inherited one merely adds an unrelated, identically-named
/// method, reachable only via explicit trait-qualified syntax
/// (`<T as InstructionAdapterFromPrototype>::method(&t)`) rather than automatic override dispatch.
/// Implementors that want this trait's behavior for `Instruction`'s abstract methods must
/// reproduce it by delegating from their `impl Instruction` block, e.g.:
///
/// ```ignore
/// impl Instruction for MyTraceInstruction {
///     fn get_mnemonic_string(&self) -> String {
///         <Self as InstructionAdapterFromPrototype>::get_mnemonic_string(self)
///     }
///     // ...
/// }
/// ```
///
/// Because these shadow methods call each other by name (matching the Java code's internal calls
/// through `this`), and each requires `Self: Sized` (a consequence of the name collision -- only
/// methods that don't collide, and don't call a colliding one, keep dynamic dispatch available),
/// this trait is only object-safe for its two Rust-only plumbing methods below; the rest must be
/// invoked on a concrete, sized type (directly, or via the delegation shown above).
///
/// This trait also needs two things Java's `this`-based dispatch gets for free that Rust's
/// `&self`-only default methods cannot derive from the inherited supertraits alone:
///
/// - [`Self::get_prototype_context`]: the [`InstructionContext`] to feed into
///   `InstructionPrototype` queries. Java's inherited `getInstructionContext()` already returns
///   exactly this, but this crate's `Instruction::get_instruction_context` currently returns the
///   unrelated placeholder marker
///   [`program::seam_stubs::InstructionContext`](crate::program::seam_stubs::InstructionContext)
///   rather than the real, already-ported
///   [`program::model::lang::InstructionContext`](crate::program::model::lang::instruction_context::InstructionContext)
///   that [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
///   actually consumes. Until those two are reconciled, implementors
///   must supply the real context here directly.
/// - [`Self::as_instruction_arc`]: a shared-ownership handle to `self` as `Arc<dyn Instruction>`,
///   needed to construct an [`InstructionPcodeOverrideImpl`] (which requires ownership, not just
///   `&self`) for [`Self::get_operand_ref_type`] and [`Self::get_pcode_with_overrides`]. Mirrors
///   Java's `new InstructionPcodeOverride(this)`.
pub trait InstructionAdapterFromPrototype: TraceInstruction {
    /// The [`InstructionContext`] to pass to
    /// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
    /// queries. See the trait docs
    /// for why this can't simply be `Instruction::get_instruction_context`.
    fn get_prototype_context(&self) -> Box<dyn InstructionContext>;

    /// `self`, shared via `Arc<dyn Instruction>`. See the trait docs for why this is needed.
    fn as_instruction_arc(&self) -> Arc<dyn Instruction>;

    /// The full textual representation of this instruction: mnemonic followed by its operands
    /// (using their default representations) and separators.
    fn get_full_string(&self) -> String
    where
        Self: Sized,
    {
        let mut sb = String::new();
        sb.push_str(&<Self as InstructionAdapterFromPrototype>::get_mnemonic_string(self));

        let n = <Self as InstructionAdapterFromPrototype>::get_num_operands(self);
        let mut sep = <Self as InstructionAdapterFromPrototype>::get_separator(self, 0);
        if sep.is_some() || n != 0 {
            sb.push(' ');
        }
        if let Some(s) = &sep {
            sb.push_str(s);
        }

        for i in 0..n {
            sb.push_str(&<Self as InstructionAdapterFromPrototype>::get_default_operand_representation(self, i));
            sep = <Self as InstructionAdapterFromPrototype>::get_separator(self, i + 1);
            if let Some(s) = &sep {
                sb.push_str(s);
            }
        }
        sb
    }

    /// Shadow of `CodeUnit::get_mnemonic_string`.
    fn get_mnemonic_string(&self) -> String
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_mnemonic(self.get_prototype_context().as_ref())
    }

    /// Shadow of `CodeUnit::get_num_operands`.
    fn get_num_operands(&self) -> i32
    where
        Self: Sized,
    {
        self.get_prototype().get_num_operands()
    }

    /// Shadow of `CodeUnit::get_address`, mapping address-valued operands from the instruction's
    /// (possibly guest) platform into the trace's host address space.
    fn get_address(&self, op_index: i32) -> Option<Address>
    where
        Self: Sized,
    {
        if op_index < 0 {
            return None;
        }
        let prototype = self.get_prototype();
        let context = self.get_prototype_context();
        let op_type = prototype.get_op_type(op_index, context.as_ref());
        if !OperandType::is_address(op_type as u32) {
            return None;
        }
        prototype
            .get_address(op_index, context.as_ref())
            .and_then(|addr| self.get_platform().map_guest_to_host(addr))
    }

    /// Shadow of `CodeUnit::get_scalar`.
    fn get_scalar(&self, op_index: i32) -> Option<Scalar>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_scalar(op_index, self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_register`.
    fn get_register(&self, op_index: i32) -> Option<RegisterRef>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_register(op_index, self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_op_objects`.
    fn get_op_objects(&self, op_index: i32) -> Vec<OperandValue>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_op_objects(op_index, self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_input_objects`.
    fn get_input_objects(&self) -> Vec<OperandValue>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_input_objects(self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_result_objects`.
    fn get_result_objects(&self) -> Vec<OperandValue>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_result_objects(self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_default_operand_representation`.
    fn get_default_operand_representation(&self, op_index: i32) -> String
    where
        Self: Sized,
    {
        let op_list = match <Self as InstructionAdapterFromPrototype>::get_default_operand_representation_list(self, op_index) {
            Some(list) => list,
            None => return "<UNSUPPORTED>".to_string(),
        };
        let mut sb = String::new();
        for elem in op_list {
            match elem {
                OperandValue::Address(addr) => {
                    sb.push_str("0x");
                    sb.push_str(&addr.format(false, 8));
                }
                OperandValue::Register(r) => sb.push_str(&r.borrow().to_string()),
                OperandValue::Scalar(s) => sb.push_str(&s.to_string()),
                OperandValue::Character(c) => sb.push(c),
                OperandValue::Text(s) => sb.push_str(&s),
            }
        }
        sb
    }

    /// Shadow of `Instruction::get_default_operand_representation_list`, remapping any
    /// address-valued piece from the instruction's (possibly guest) platform into the trace's
    /// host address space -- or, if unmappable, into a `"guest:..."` text placeholder.
    fn get_default_operand_representation_list(&self, op_index: i32) -> Option<Vec<OperandValue>>
    where
        Self: Sized,
    {
        let list = self
            .get_prototype()
            .get_op_representation_list(op_index, self.get_prototype_context().as_ref())?;
        let platform = self.get_platform();
        if platform.is_host() {
            return Some(list);
        }
        Some(
            list.into_iter()
                .map(|value| match value {
                    OperandValue::Address(addr) => match platform.map_guest_to_host(addr.clone()) {
                        Some(host_addr) => OperandValue::Address(host_addr),
                        None => OperandValue::Text(format!("guest:{}", addr.format(true, 8))),
                    },
                    other => other,
                })
                .collect(),
        )
    }

    /// Shadow of `Instruction::get_separator`.
    fn get_separator(&self, op_index: i32) -> Option<String>
    where
        Self: Sized,
    {
        self.get_prototype().get_separator(op_index)
    }

    /// Shadow of `Instruction::get_operand_type`.
    fn get_operand_type(&self, op_index: i32) -> i32
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_op_type(op_index, self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_operand_ref_type`.
    fn get_operand_ref_type(&self, op_index: i32) -> RefType
    where
        Self: Sized,
    {
        let prototype = self.get_prototype();
        let context = self.get_prototype_context();
        let override_ = InstructionPcodeOverrideImpl::new(self.as_instruction_arc());
        prototype.get_operand_ref_type(op_index, context.as_ref(), Some(&override_))
    }

    /// Shadow of `Instruction::get_default_fall_through_offset`.
    fn get_default_fall_through_offset(&self) -> i32
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_fall_through_offset(self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::get_pcode` (no flow overrides).
    fn get_pcode(&self) -> Vec<PcodeOp>
    where
        Self: Sized,
    {
        <Self as InstructionAdapterFromPrototype>::get_pcode_with_overrides(self, false)
    }

    /// Shadow of `Instruction::get_pcode_with_overrides`.
    fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp>
    where
        Self: Sized,
    {
        let prototype = self.get_prototype();
        let context = self.get_prototype_context();
        if !include_overrides {
            return prototype.get_pcode(context.as_ref(), None);
        }
        let override_ = InstructionPcodeOverrideImpl::new(self.as_instruction_arc());
        prototype.get_pcode(context.as_ref(), Some(&override_))
    }

    /// Shadow of `Instruction::get_pcode_for_operand`.
    ///
    /// NOTE: This assumes operand p-code is not affected by flow override.
    fn get_pcode_for_operand(&self, op_index: i32) -> Vec<PcodeOp>
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_pcode_for_operand(self.get_prototype_context().as_ref(), op_index)
    }

    /// Shadow of `Instruction::get_delay_slot_depth`.
    fn get_delay_slot_depth(&self) -> i32
    where
        Self: Sized,
    {
        self.get_prototype()
            .get_delay_slot_depth(self.get_prototype_context().as_ref())
    }

    /// Shadow of `Instruction::is_in_delay_slot`.
    fn is_in_delay_slot(&self) -> bool
    where
        Self: Sized,
    {
        self.get_prototype().is_in_delay_slot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io;
    use std::sync::Arc;

    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::{
        GetPseudoParserContextError, InstructionPrototype,
    };
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::mask::Mask;
    use crate::program::model::lang::parser_context::ParserContext as RealParserContext;
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::{ProcessorContext, UnknownContextException};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::ContextChangeException;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::{PatchEncoder, PcodeOverride};
    use crate::program::model::symbol::{
        ExternalReference, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{
        CommentType, FlowOverride, MemBuffer, ParserContext, RegisterValue,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TracePlatform, TraceThread};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Records whether it was ever queried with a [`PcodeOverride`] whose instruction-start
    /// address matches `expected_start` -- proof that [`InstructionAdapterFromPrototype::
    /// get_operand_ref_type`] built its override from the *same* instruction (via
    /// `as_instruction_arc`), not a disconnected copy.
    struct MockPrototype {
        mnemonic: String,
        num_operands: i32,
        op_type: i32,
        op_address: Option<Address>,
        op_representation: Option<Vec<OperandValue>>,
        fall_through_offset: i32,
        expected_start: Address,
        override_seen_correct_start: Cell<bool>,
    }

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn ParserContext>, GetPseudoParserContextError> {
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

        fn get_mnemonic(&self, _context: &dyn InstructionContext) -> String {
            self.mnemonic.clone()
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
            RefType::FallThrough
        }

        fn get_delay_slot_depth(&self, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            self.num_operands
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
            self.op_type
        }

        fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }

        fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
            self.fall_through_offset
        }

        fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Vec<OperandValue>> {
            self.op_representation.clone()
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Address> {
            self.op_address.clone()
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
            override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            if let Some(o) = override_ {
                if o.get_instruction_start() == self.expected_start {
                    self.override_seen_correct_start.set(true);
                }
            }
            RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn InstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockContext;
    impl InstructionContext for MockContext {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_processor_context(&self) -> &dyn ProcessorContextView {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_mem_buffer(&self) -> &dyn crate::program::seam_stubs::MemBuffer {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parser_context(&self) -> Result<Box<dyn RealParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parser_context_at(
            &self,
            _instruction_address: Address,
        ) -> Result<Box<dyn RealParserContext>, crate::program::model::lang::instruction_context::InstructionContextError>
        {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// Not the trace's host platform: maps `guest_addr` to `host_addr` and everything else to
    /// `None`.
    struct MockPlatform {
        guest_addr: Address,
        host_addr: Address,
    }

    impl TracePlatform for MockPlatform {
        fn is_host(&self) -> bool {
            false
        }

        fn map_guest_to_host(&self, address: Address) -> Option<Address> {
            if address == self.guest_addr {
                Some(self.host_addr.clone())
            } else {
                None
            }
        }
    }

    struct MarkerInstructionContext;
    impl crate::program::seam_stubs::InstructionContext for MarkerInstructionContext {}

    #[derive(Clone)]
    struct MockAdapterInstruction {
        min_address: Address,
        length: i32,
        prototype: Arc<MockPrototype>,
        guest_addr: Address,
        host_addr: Address,
    }

    impl MemBuffer for MockAdapterInstruction {
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockAdapterInstruction {}

    impl ProcessorContextView for MockAdapterInstruction {
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

    impl ProcessorContext for MockAdapterInstruction {
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

    impl CodeUnit for MockAdapterInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
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
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            addr(self.min_address.offset() + self.length as i64 - 1)
        }

        fn get_mnemonic_string(&self) -> String {
            <Self as InstructionAdapterFromPrototype>::get_mnemonic_string(self)
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
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
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
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
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
            <Self as InstructionAdapterFromPrototype>::get_num_operands(self)
        }

        fn get_address(&self, op_index: i32) -> Option<Address> {
            <Self as InstructionAdapterFromPrototype>::get_address(self, op_index)
        }

        fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
            <Self as InstructionAdapterFromPrototype>::get_scalar(self, op_index)
        }
    }

    impl Instruction for MockAdapterInstruction {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            self.prototype.clone() as Arc<dyn InstructionPrototype>
        }

        fn get_register(&self, op_index: i32) -> Option<RegisterRef> {
            <Self as InstructionAdapterFromPrototype>::get_register(self, op_index)
        }

        fn get_op_objects(&self, op_index: i32) -> Vec<OperandValue> {
            <Self as InstructionAdapterFromPrototype>::get_op_objects(self, op_index)
        }

        fn get_input_objects(&self) -> Vec<OperandValue> {
            <Self as InstructionAdapterFromPrototype>::get_input_objects(self)
        }

        fn get_result_objects(&self) -> Vec<OperandValue> {
            <Self as InstructionAdapterFromPrototype>::get_result_objects(self)
        }

        fn get_default_operand_representation(&self, op_index: i32) -> String {
            <Self as InstructionAdapterFromPrototype>::get_default_operand_representation(
                self, op_index,
            )
        }

        fn get_default_operand_representation_list(
            &self,
            op_index: i32,
        ) -> Option<Vec<OperandValue>> {
            <Self as InstructionAdapterFromPrototype>::get_default_operand_representation_list(
                self, op_index,
            )
        }

        fn get_separator(&self, op_index: i32) -> Option<String> {
            <Self as InstructionAdapterFromPrototype>::get_separator(self, op_index)
        }

        fn get_operand_type(&self, op_index: i32) -> i32 {
            <Self as InstructionAdapterFromPrototype>::get_operand_type(self, op_index)
        }

        fn get_operand_ref_type(&self, op_index: i32) -> RefType {
            <Self as InstructionAdapterFromPrototype>::get_operand_ref_type(self, op_index)
        }

        fn get_default_fall_through_offset(&self) -> i32 {
            <Self as InstructionAdapterFromPrototype>::get_default_fall_through_offset(self)
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
            self.length
        }

        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_pcode(&self) -> Vec<PcodeOp> {
            <Self as InstructionAdapterFromPrototype>::get_pcode(self)
        }

        fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp> {
            <Self as InstructionAdapterFromPrototype>::get_pcode_with_overrides(
                self,
                include_overrides,
            )
        }

        fn get_pcode_for_operand(&self, op_index: i32) -> Vec<PcodeOp> {
            <Self as InstructionAdapterFromPrototype>::get_pcode_for_operand(self, op_index)
        }

        fn get_delay_slot_depth(&self) -> i32 {
            <Self as InstructionAdapterFromPrototype>::get_delay_slot_depth(self)
        }

        fn is_in_delay_slot(&self) -> bool {
            <Self as InstructionAdapterFromPrototype>::is_in_delay_slot(self)
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
            Arc::new(MarkerInstructionContext)
        }
    }

    impl TraceCodeUnit for MockAdapterInstruction {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            Box::new(MockPlatform {
                guest_addr: self.guest_addr.clone(),
                host_addr: self.host_addr.clone(),
            })
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
            AddressRange::new(
                self.min_address.clone(),
                addr(self.min_address.offset() + self.length as i64 - 1),
            )
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn set_end_snap(&mut self, _end_snap: i64) {}

        fn get_end_snap(&self) -> i64 {
            10
        }

        fn delete(&mut self) {}
    }

    impl TraceInstruction for MockAdapterInstruction {
        fn get_guest_default_fall_through(&self) -> Option<Address> {
            None
        }

        fn get_guest_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
    }

    impl InstructionAdapterFromPrototype for MockAdapterInstruction {
        fn get_prototype_context(&self) -> Box<dyn InstructionContext> {
            Box::new(MockContext)
        }

        fn as_instruction_arc(&self) -> Arc<dyn Instruction> {
            Arc::new(self.clone())
        }
    }

    fn make_instruction() -> MockAdapterInstruction {
        let guest_addr = addr(0x2000);
        let host_addr = addr(0x1000);
        let min_address = addr(0x400);
        MockAdapterInstruction {
            min_address: min_address.clone(),
            length: 4,
            prototype: Arc::new(MockPrototype {
                mnemonic: "MOV".to_string(),
                num_operands: 1,
                op_type: OperandType::ADDRESS as i32,
                op_address: Some(guest_addr.clone()),
                op_representation: Some(vec![OperandValue::Address(guest_addr.clone())]),
                fall_through_offset: 4,
                expected_start: min_address,
                override_seen_correct_start: Cell::new(false),
            }),
            guest_addr,
            host_addr,
        }
    }

    #[test]
    fn get_address_maps_guest_operand_to_host() {
        let instr = make_instruction();
        let host_addr = instr.host_addr.clone();

        assert_eq!(
            <MockAdapterInstruction as InstructionAdapterFromPrototype>::get_address(&instr, 0),
            Some(host_addr)
        );
        // Negative operand indices are rejected without consulting the prototype at all.
        assert_eq!(
            <MockAdapterInstruction as InstructionAdapterFromPrototype>::get_address(&instr, -1),
            None
        );
    }

    #[test]
    fn get_default_operand_representation_list_maps_guest_address() {
        let instr = make_instruction();
        let host_addr = instr.host_addr.clone();

        let list =
            <MockAdapterInstruction as InstructionAdapterFromPrototype>::get_default_operand_representation_list(
                &instr, 0,
            );
        // `OperandValue` doesn't implement `PartialEq`, so match on its shape instead of
        // asserting equality directly.
        match list.as_deref() {
            Some([OperandValue::Address(mapped)]) => assert_eq!(*mapped, host_addr),
            other => panic!("expected a single mapped Address operand, got {other:?}"),
        }
    }

    #[test]
    fn get_full_string_combines_mnemonic_and_mapped_operand() {
        let instr = make_instruction();
        let host_addr = instr.host_addr.clone();

        let full = <MockAdapterInstruction as InstructionAdapterFromPrototype>::get_full_string(
            &instr,
        );
        assert_eq!(full, format!("MOV 0x{}", host_addr.format(false, 8)));
    }

    #[test]
    fn get_operand_ref_type_builds_override_from_same_instruction() {
        let instr = make_instruction();

        let ref_type =
            <MockAdapterInstruction as InstructionAdapterFromPrototype>::get_operand_ref_type(
                &instr, 0,
            );
        assert_eq!(ref_type, RefType::Data);
        assert!(
            instr.prototype.override_seen_correct_start.get(),
            "override built by get_operand_ref_type must report this instruction's own start address"
        );
    }

    #[test]
    fn delegating_instruction_impl_matches_adapter_defaults() {
        let instr = make_instruction();

        // The concrete `impl Instruction` delegates to this trait's shadow defaults, so calling
        // through the `Instruction`/`CodeUnit` supertraits reaches the same behavior.
        assert_eq!(CodeUnit::get_mnemonic_string(&instr), "MOV".to_string());
        assert_eq!(CodeUnit::get_num_operands(&instr), 1);
        assert_eq!(
            CodeUnit::get_address(&instr, 0),
            Some(instr.host_addr.clone())
        );
    }

    #[test]
    fn usable_as_trait_object_via_supertraits() {
        let instr: Box<dyn InstructionAdapterFromPrototype> = Box::new(make_instruction());

        // TraceCodeUnit (supertrait) methods remain reachable through the trait object.
        assert_eq!(instr.get_start_snap(), 0);
        assert_eq!(instr.get_end_snap(), 10);

        // Instruction (supertrait) methods remain reachable through the trait object.
        assert!(instr.is_fallthrough());
        assert_eq!(instr.get_min_address(), addr(0x400));
    }
}
