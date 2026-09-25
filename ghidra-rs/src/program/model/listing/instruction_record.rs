//! The backing-independent state of a decoded instruction, and the borrowed view that answers
//! instruction queries from it.
//!
//! See `OWNERSHIP_MIGRATION.md`, "Instruction/CodeUnit arena (2026-09-25)". Ghidra has three
//! backings for one concept: `InstructionDB` (program listing), `DBTraceInstruction` (trace), and
//! `PseudoInstruction` (emulator / pseudo-disassembly). They differ only in *where* an
//! instruction's bytes and context come from and in the program-level queries (references,
//! symbols, neighbours) that are keyed by address. Everything else each Java class computes the
//! same way: hand the prototype an `InstructionContext` and post-process with the overrides.
//!
//! - [`InstructionRecord`] is that shared state: address, prototype, overrides.
//! - [`InstructionSnapshot`] is what a backing supplies to resolve a record: the bytes and the
//!   processor context at the instruction, and how to reach *another* instruction's parser context
//!   (cross-builds, delay slots) — the one genuinely backing-specific lookup.
//! - [`InstructionView`] borrows one of each. It implements the prototype-facing
//!   [`InstructionContext`] and carries the query logic common to every backing, so a backing's
//!   `Instruction` impl builds a view and delegates.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::instruction_context::{InstructionContext, InstructionContextError};
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::operand_type::OperandType;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};
use crate::program::model::pcode::{PcodeOp, PcodeOverride};
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::FlowOverride;

/// The prototype an [`InstructionRecord`] is decoded by, shared between every instruction of the
/// same constructor tree.
///
/// A trait object rather than the concrete `SleighInstructionPrototype` because the invalid
/// prototypes are real alternatives here, not only a null object (Java's `DecodeErrorInstruction`
/// uses an `InvalidPrototype` subclass that emits a decode-error p-code op). `Send + Sync` so that
/// an instruction holding one can cross threads.
pub type SharedPrototype = Arc<dyn InstructionPrototype + Send + Sync>;

/// A fall-through override on an instruction.
///
/// Java stores `null` for "no override", `Address.NO_ADDRESS` for "fall-through removed", and an
/// address otherwise; the absent case is `Option::None` around this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallThroughOverride {
    /// The fall-through was removed: the instruction does not fall through at all.
    Removed,
    /// The fall-through was redirected to this address.
    Target(Address),
}

/// Port of `FlowOverride.getModifiedFlowType(FlowType, FlowOverride)`, over the crate's single
/// [`RefType`] enum (Java's `FlowType` is its flow-carrying subset).
///
/// Shared by every instruction backing; formerly private to `InstructionDB`.
pub fn modified_flow_type(original_flow_type: RefType, flow_override: FlowOverride) -> RefType {
    let flow_type = original_flow_type;
    if flow_override == FlowOverride::None
        || (!flow_type.is_jump() && !flow_type.is_terminal() && !flow_type.is_call())
    {
        return flow_type;
    }
    // NOTE: The following flow-type overrides assume that a return will always be the last flow
    // pcode-op - since it is the first primary flow pcode-op that will get replaced.
    match flow_override {
        FlowOverride::Branch => {
            if flow_type.is_jump() {
                return flow_type;
            }
            if flow_type.is_conditional() {
                // assume that we will never start with a complex flow with terminator
                // i.e., CONDITIONAL-JUMP-TERMINATOR
                if flow_type.is_terminal() {
                    // assume return replaced
                    return RefType::ConditionalComputedJump;
                }
                return RefType::ConditionalJump;
            }
            if flow_type.is_computed() {
                return RefType::ComputedJump;
            }
            if flow_type.is_terminal() {
                // assume return replaced
                return RefType::ComputedJump;
            }
            RefType::UnconditionalJump
        }
        FlowOverride::Call => {
            if flow_type.is_call() {
                return flow_type;
            }
            if flow_type.is_conditional() {
                if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                    // assume original return was preserved
                    return RefType::ConditionalCallTerminator;
                }
                if flow_type.is_terminal() {
                    // assume return was replaced
                    return RefType::ConditionalComputedCall;
                }
                return RefType::ConditionalCall;
            }
            if flow_type.is_computed() {
                if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                    // assume original return was preserved
                    return RefType::ComputedCallTerminator;
                }
                return RefType::ComputedCall;
            }
            if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                // assume original return was preserved
                return RefType::CallTerminator;
            }
            if flow_type.is_terminal() {
                // assume return was replaced
                return RefType::ComputedCall;
            }
            RefType::UnconditionalCall
        }
        FlowOverride::CallReturn => {
            if flow_type.is_conditional() {
                if flow_type.is_computed() {
                    return RefType::ConditionalComputedCall;
                }
                if flow_type.is_terminal() {
                    // assume return was replaced
                    return RefType::ComputedCallTerminator;
                }
                return flow_type; // don't replace
            }
            if flow_type.is_computed() {
                return RefType::ComputedCallTerminator;
            }
            if flow_type.is_terminal() {
                // assume return was replaced
                return RefType::ComputedCallTerminator;
            }
            RefType::CallTerminator
        }
        FlowOverride::Return => {
            if flow_type.is_conditional() {
                return RefType::ConditionalTerminator;
            }
            RefType::Terminator
        }
        FlowOverride::None => flow_type,
    }
}

/// The backing-independent state of one decoded instruction: where it is, how it decodes, and
/// the overrides applied to it.
///
/// Holds no bytes and no context; those are the [`InstructionSnapshot`] a backing resolves the
/// record against. Setters only record the value: side effects Java performs through the
/// program (e.g. `InstructionDB.setFlowOverride` retyping references) stay with the backing.
#[derive(Clone)]
pub struct InstructionRecord {
    address: Address,
    prototype: SharedPrototype,
    flow_override: FlowOverride,
    fall_through_override: Option<FallThroughOverride>,
    /// `0` for "no override", matching Java's `lengthOverride` field.
    length_override: i32,
}

impl std::fmt::Debug for InstructionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstructionRecord")
            .field("address", &self.address)
            .field("length", &self.prototype.get_length())
            .field("flow_override", &self.flow_override)
            .field("fall_through_override", &self.fall_through_override)
            .field("length_override", &self.length_override)
            .finish()
    }
}

impl InstructionRecord {
    /// A record for an instruction at `address` decoded by `prototype`, with no overrides.
    pub fn new(address: Address, prototype: SharedPrototype) -> Self {
        Self {
            address,
            prototype,
            flow_override: FlowOverride::None,
            fall_through_override: None,
            length_override: 0,
        }
    }

    /// The instruction's (minimum) address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The prototype the instruction was decoded by.
    pub fn prototype(&self) -> &SharedPrototype {
        &self.prototype
    }

    /// The instruction length: the length override if one is set, else the prototype's length.
    pub fn length(&self) -> i32 {
        if self.length_override != 0 {
            self.length_override
        } else {
            self.prototype.get_length()
        }
    }

    /// The number of bytes the prototype actually parsed, ignoring any length override.
    pub fn parsed_length(&self) -> i32 {
        self.prototype.get_length()
    }

    /// The length override, or `0` if none is set.
    pub fn length_override(&self) -> i32 {
        self.length_override
    }

    /// Records a length override; `0` clears it. Validation (range, alignment, conflicts with the
    /// following code unit) is the backing's job, as it is in Java's `InstructionDB`.
    pub fn set_length_override(&mut self, length: i32) {
        self.length_override = length;
    }

    /// The flow override applied to this instruction.
    pub fn flow_override(&self) -> FlowOverride {
        self.flow_override
    }

    /// Records the flow override.
    pub fn set_flow_override(&mut self, flow_override: FlowOverride) {
        self.flow_override = flow_override;
    }

    /// The fall-through override, or `None` if the default fall-through applies.
    pub fn fall_through_override(&self) -> Option<&FallThroughOverride> {
        self.fall_through_override.as_ref()
    }

    /// Records a fall-through override directly.
    pub fn set_fall_through_override(&mut self, fall_through: Option<FallThroughOverride>) {
        self.fall_through_override = fall_through;
    }

    /// Port of the override bookkeeping in `PseudoInstruction.setFallThrough(Address)`: an
    /// address equal to `default_fall_through` clears the override, `None` removes the
    /// fall-through, and any other address redirects it.
    pub fn set_fall_through(&mut self, addr: Option<Address>, default_fall_through: Option<&Address>) {
        self.fall_through_override = if addr.as_ref() == default_fall_through {
            None
        } else {
            match addr {
                None => Some(FallThroughOverride::Removed),
                Some(a) => Some(FallThroughOverride::Target(a)),
            }
        };
    }
}

/// What a backing supplies so an [`InstructionRecord`] can be resolved: the instruction's bytes,
/// the processor context at it, and parser contexts for other instructions.
///
/// Implemented by each backing over the data it owns or reads (an owned byte cache for a pseudo
/// instruction; program or trace memory at a version for the database backings). A snapshot
/// never goes stale — see `OWNERSHIP_MIGRATION.md` convention 3.
pub trait InstructionSnapshot {
    /// The bytes at (and after) the instruction, positioned at the instruction's address.
    fn mem_buffer(&self) -> &dyn MemBuffer;

    /// The processor context (context register state) at the instruction.
    fn processor_context(&self) -> &dyn ProcessorContextView;

    /// The parser context of the instruction at `address`, which is *not* `record`'s own address
    /// (Java's `InstructionContext.getParserContext(Address)` for a cross-build or delay-slot
    /// instruction).
    ///
    /// # Errors
    /// [`InstructionContextError::UnknownContext`] if no compatible instruction can be found or
    /// parsed there.
    fn parser_context_at(
        &self,
        record: &InstructionRecord,
        address: &Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError>;
}

/// Adapts the prototype's parser context (`program::seam_stubs::ParserContext`) to the one an
/// [`InstructionContext`] hands out, forwarding `as_any` so the prototype's cast back to its own
/// context type still works. Needed while the crate carries both same-named `ParserContext`
/// traits; see `InstructionDB`'s identical bridge.
pub struct ParserContextBridge(pub Box<dyn crate::program::seam_stubs::ParserContext>);

impl ParserContext for ParserContextBridge {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        self.0.get_prototype()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.0.as_any()
    }
}

/// A record resolved against a snapshot: the queries every instruction backing answers the same
/// way.
///
/// Borrowed and cheap to build (two references); a backing constructs one per query. It is also
/// the [`InstructionContext`] the prototype is queried with.
pub struct InstructionView<'a, S: ?Sized> {
    record: &'a InstructionRecord,
    snapshot: &'a S,
}

impl<S: ?Sized> Clone for InstructionView<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: ?Sized> Copy for InstructionView<'_, S> {}

impl<'a, S: InstructionSnapshot + ?Sized> InstructionView<'a, S> {
    /// A view of `record` resolved against `snapshot`.
    pub fn new(record: &'a InstructionRecord, snapshot: &'a S) -> Self {
        Self { record, snapshot }
    }

    /// The record being viewed.
    pub fn record(&self) -> &'a InstructionRecord {
        self.record
    }

    fn proto(&self) -> &'a SharedPrototype {
        &self.record.prototype
    }

    /// Port of `getMnemonicString()`: `prototype.getMnemonic(this)`.
    pub fn mnemonic(&self) -> String {
        self.proto().get_mnemonic(self)
    }

    /// Port of `getNumOperands()`.
    pub fn num_operands(&self) -> i32 {
        self.proto().get_num_operands()
    }

    /// Port of `getAddress(int)`: the operand's address, if the operand is typed as one.
    pub fn operand_address(&self, op_index: i32) -> Option<Address> {
        if op_index < 0 {
            return None;
        }
        let op_type = self.proto().get_op_type(op_index, self);
        if OperandType::is_address(op_type as u32) {
            return self.proto().get_address(op_index, self);
        }
        None
    }

    /// Port of `getScalar(int)`.
    pub fn scalar(&self, op_index: i32) -> Option<Scalar> {
        if op_index < 0 {
            return None;
        }
        self.proto().get_scalar(op_index, self)
    }

    /// Port of `getRegister(int)`.
    pub fn register(&self, op_index: i32) -> Option<RegisterRef> {
        if op_index < 0 {
            return None;
        }
        self.proto().get_register(op_index, self)
    }

    /// Port of `getOpObjects(int)`.
    pub fn op_objects(&self, op_index: i32) -> Vec<OperandValue> {
        if op_index < 0 {
            return Vec::new();
        }
        self.proto().get_op_objects(op_index, self)
    }

    /// Port of `getInputObjects()`.
    pub fn input_objects(&self) -> Vec<OperandValue> {
        self.proto().get_input_objects(self)
    }

    /// Port of `getResultObjects()`.
    pub fn result_objects(&self) -> Vec<OperandValue> {
        self.proto().get_result_objects(self)
    }

    /// Port of `getDefaultOperandRepresentationList(int)`.
    pub fn default_operand_representation_list(&self, op_index: i32) -> Option<Vec<OperandValue>> {
        self.proto().get_op_representation_list(op_index, self)
    }

    /// Port of `getDefaultOperandRepresentation(int)`: the pieces concatenated, addresses as
    /// `0x` + the unpadded offset, `"<UNSUPPORTED>"` if the language cannot represent it.
    pub fn default_operand_representation(&self, op_index: i32) -> String {
        let Some(op_list) = self.default_operand_representation_list(op_index) else {
            return "<UNSUPPORTED>".to_string();
        };
        let mut buffer = String::new();
        for op_elem in op_list {
            match op_elem {
                OperandValue::Address(op_addr) => {
                    buffer.push_str("0x");
                    buffer.push_str(&op_addr.format(false, 1));
                }
                OperandValue::Register(register) => buffer.push_str(register.name()),
                OperandValue::Scalar(scalar) => buffer.push_str(&scalar.to_string()),
                OperandValue::Character(c) => buffer.push(c),
                OperandValue::Text(text) => buffer.push_str(&text),
            }
        }
        buffer
    }

    /// Port of `getOperandType(int)`.
    pub fn operand_type(&self, op_index: i32) -> i32 {
        self.proto().get_op_type(op_index, self)
    }

    /// Port of `getSeparator(int)`.
    pub fn separator(&self, op_index: i32) -> Option<String> {
        self.proto().get_separator(op_index)
    }

    /// Port of `getFlowType()`: the prototype's flow type with the flow override applied.
    pub fn flow_type(&self) -> RefType {
        modified_flow_type(self.proto().get_flow_type(self), self.record.flow_override)
    }

    /// Port of `getDefaultFallThroughOffset()`.
    pub fn default_fall_through_offset(&self) -> i32 {
        self.proto().get_fall_through_offset(self)
    }

    /// Port of `getDefaultFallThrough()`: the address after the instruction (and its delay
    /// slots), if the overridden flow type falls through. Overflowing the space yields `None`, as
    /// Java swallows the `AddressOverflowException`.
    pub fn default_fall_through(&self) -> Option<Address> {
        if self.flow_type().has_fallthrough() {
            return self
                .record
                .address
                .add_no_wrap(i64::from(self.default_fall_through_offset()))
                .ok();
        }
        None
    }

    /// Port of `getFallThrough()` for a backing that stores the override in the record.
    pub fn fall_through(&self) -> Option<Address> {
        match &self.record.fall_through_override {
            None => self.default_fall_through(),
            Some(FallThroughOverride::Target(addr)) => Some(addr.clone()),
            Some(FallThroughOverride::Removed) => None,
        }
    }

    /// Port of `isFallThroughOverridden()`.
    pub fn is_fall_through_overridden(&self) -> bool {
        self.record.fall_through_override.is_some()
    }

    /// Port of `hasFallthrough()`.
    pub fn has_fallthrough(&self) -> bool {
        if self.is_fall_through_overridden() {
            return self.fall_through().is_some();
        }
        self.flow_type().has_fallthrough()
    }

    /// Port of `isFallthrough()`.
    pub fn is_fallthrough(&self) -> bool {
        if !self.flow_type().is_fallthrough() {
            return false;
        }
        self.has_fallthrough()
    }

    /// Port of `getDefaultFlows()`: the prototype's flows, suppressed when a `RETURN` override
    /// replaces a single flow. `None` stands for Java's empty array.
    pub fn default_flows(&self) -> Option<Vec<Address>> {
        let flows = self.proto().get_flows(self).unwrap_or_default();
        if self.record.flow_override == FlowOverride::Return && flows.len() == 1 {
            return None;
        }
        if flows.is_empty() {
            None
        } else {
            Some(flows)
        }
    }

    /// Port of `getDelaySlotDepth()`.
    pub fn delay_slot_depth(&self) -> i32 {
        self.proto().get_delay_slot_depth(self)
    }

    /// Port of `isInDelaySlot()`.
    pub fn is_in_delay_slot(&self) -> bool {
        self.proto().is_in_delay_slot()
    }

    /// Port of `getPcode()` / `getPcode(boolean)`: the prototype's p-code, steered by `override_`
    /// when the backing supplies one.
    pub fn pcode(&self, override_: Option<&dyn PcodeOverride>) -> Vec<PcodeOp> {
        self.proto().get_pcode(self, override_)
    }

    /// Port of `getPcode(int)`: the p-code computing one operand's value.
    pub fn pcode_for_operand(&self, op_index: i32) -> Vec<PcodeOp> {
        self.proto().get_pcode_for_operand(self, op_index)
    }

    /// Port of `toString()` shared by `PseudoInstruction` and `InstructionDB`: the mnemonic,
    /// a space if anything follows, then each operand with its separators.
    pub fn display_string(&self) -> String {
        let mut buffer = self.mnemonic();
        let n = self.num_operands();
        let mut sep = self.separator(0);
        if sep.is_some() || n != 0 {
            buffer.push(' ');
        }
        if let Some(s) = &sep {
            buffer.push_str(s);
        }
        for i in 0..n {
            buffer.push_str(&self.default_operand_representation(i));
            sep = self.separator(i + 1);
            if let Some(s) = &sep {
                buffer.push_str(s);
            }
        }
        buffer
    }
}

impl<S: InstructionSnapshot + ?Sized> InstructionContext for InstructionView<'_, S> {
    fn get_address(&self) -> Address {
        self.record.address.clone()
    }

    fn get_processor_context(&self) -> &dyn ProcessorContextView {
        self.snapshot.processor_context()
    }

    fn get_mem_buffer(&self) -> &dyn MemBuffer {
        self.snapshot.mem_buffer()
    }

    /// The prototype's parser context over this view's bytes and context.
    fn get_parser_context(&self) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
        let context = self
            .record
            .prototype
            .get_parser_context(self.snapshot.mem_buffer(), self.snapshot.processor_context())?;
        Ok(Box::new(ParserContextBridge(context)))
    }

    /// This instruction's own parser context at its address; any other address is the
    /// snapshot's [`InstructionSnapshot::parser_context_at`].
    fn get_parser_context_at(
        &self,
        instruction_address: Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
        if instruction_address == self.record.address {
            return Ok(self.get_parser_context()?);
        }
        self.snapshot.parser_context_at(self.record, &instruction_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
    use crate::program::model::lang::unknown_context_exception::UnknownContextException;
    use crate::program::model::mem::ByteMemBufferImpl;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::sleigh::SleighLanguage;

    /// A snapshot over a byte buffer and a fresh context; no other instruction is reachable.
    struct Bytes {
        mem: ByteMemBufferImpl,
        context: ProcessorContextImpl,
    }

    impl InstructionSnapshot for Bytes {
        fn mem_buffer(&self) -> &dyn MemBuffer {
            &self.mem
        }
        fn processor_context(&self) -> &dyn ProcessorContextView {
            &self.context
        }
        fn parser_context_at(
            &self,
            _record: &InstructionRecord,
            _address: &Address,
        ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
            Err(UnknownContextException::with_message("no other instruction").into())
        }
    }

    fn decode(lang: &Arc<SleighLanguage>, offset: i64, bytes: &[u8]) -> (InstructionRecord, Bytes) {
        let addr = Address::new(lang.get_default_space(), offset);
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true);
        let proto = lang
            .parse_prototype(
                Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true)),
                Vec::new(),
                false,
            )
            .unwrap();
        let context = ProcessorContextImpl::new(lang.clone());
        (InstructionRecord::new(addr, Arc::new(proto)), Bytes { mem, context })
    }

    #[test]
    fn a_view_answers_the_shared_queries_from_record_and_snapshot() {
        let lang = decode_tests::language();
        // jmp +5 from 0x1000: an unconditional jump to 0x1007
        let (record, snapshot) = decode(&lang, 0x1000, &[0x20, 0x05]);
        let view = InstructionView::new(&record, &snapshot);
        assert_eq!(view.mnemonic(), "jmp");
        assert_eq!(view.num_operands(), 1);
        assert_eq!(view.operand_address(0).unwrap().offset(), 0x1007);
        assert_eq!(view.operand_address(-1), None);
        assert_eq!(view.default_operand_representation(0), "0x1007");
        assert_eq!(view.display_string(), "jmp 0x1007");
        assert_eq!(view.flow_type(), RefType::UnconditionalJump);
        assert_eq!(view.default_flows().unwrap()[0].offset(), 0x1007);
        assert_eq!(view.default_fall_through(), None);
        assert!(!view.has_fallthrough());
        assert_eq!(view.get_address().offset(), 0x1000);
        assert!(view
            .get_parser_context_at(Address::new(lang.get_default_space(), 0x1002))
            .is_err());
        assert!(view.get_parser_context_at(view.get_address()).is_ok());
    }

    #[test]
    fn overrides_in_the_record_change_what_the_view_reports() {
        let lang = decode_tests::language();
        let (mut record, snapshot) = decode(&lang, 0x1000, &[0x20, 0x05]);
        record.set_flow_override(FlowOverride::Call);
        let view = InstructionView::new(&record, &snapshot);
        assert_eq!(view.flow_type(), RefType::UnconditionalCall);
        // a call falls through
        assert_eq!(view.default_fall_through().unwrap().offset(), 0x1002);

        record.set_flow_override(FlowOverride::Return);
        let view = InstructionView::new(&record, &snapshot);
        assert_eq!(view.flow_type(), RefType::Terminator);
        // RETURN suppresses the single flow
        assert_eq!(view.default_flows(), None);

        // mov r1,#0x2a: falls through to 0x1002 by default
        let (mut record, snapshot) = decode(&lang, 0x1000, &[0x11, 0x2a]);
        let default = InstructionView::new(&record, &snapshot).default_fall_through();
        assert_eq!(default.as_ref().unwrap().offset(), 0x1002);
        let target = Address::new(lang.get_default_space(), 0x3000);
        record.set_fall_through(Some(target.clone()), default.as_ref());
        assert_eq!(record.fall_through_override(), Some(&FallThroughOverride::Target(target.clone())));
        assert_eq!(InstructionView::new(&record, &snapshot).fall_through(), Some(target));
        record.set_fall_through(None, default.as_ref());
        let view = InstructionView::new(&record, &snapshot);
        assert_eq!(view.fall_through(), None);
        assert!(!view.has_fallthrough());
        assert!(!view.is_fallthrough());
        // setting the default back clears the override
        record.set_fall_through(default.clone(), default.as_ref());
        assert_eq!(record.fall_through_override(), None);
        assert!(InstructionView::new(&record, &snapshot).is_fallthrough());
    }

    #[test]
    fn length_override_replaces_but_does_not_hide_the_parsed_length() {
        let lang = decode_tests::language();
        let (mut record, _) = decode(&lang, 0x1000, &[0x11, 0x2a]);
        assert_eq!((record.length(), record.parsed_length()), (2, 2));
        record.set_length_override(1);
        assert_eq!((record.length(), record.parsed_length()), (1, 2));
        record.set_length_override(0);
        assert_eq!(record.length(), 2);
    }

    #[test]
    fn modified_flow_type_follows_the_java_table() {
        assert_eq!(modified_flow_type(RefType::FallThrough, FlowOverride::Branch), RefType::FallThrough);
        assert_eq!(
            modified_flow_type(RefType::UnconditionalCall, FlowOverride::Branch),
            RefType::UnconditionalJump
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalJump, FlowOverride::Call),
            RefType::ConditionalCall
        );
        assert_eq!(
            modified_flow_type(RefType::UnconditionalJump, FlowOverride::CallReturn),
            RefType::CallTerminator
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalJump, FlowOverride::Return),
            RefType::ConditionalTerminator
        );
    }
}
