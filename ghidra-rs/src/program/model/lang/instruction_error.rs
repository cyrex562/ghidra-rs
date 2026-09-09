//! Port of `ghidra.program.model.lang.InstructionError`.
//!
//! Describes an error or conflict detected while adding disassembled instructions to a program:
//! duplicate/conflicting code units, a failed parse, a memory error while parsing, or an
//! unaligned flow. Constructed (and owned) by whichever [`InstructionBlock`] it was raised
//! against.
//!
//! `InstructionBlock` -- the block that owns/raises these errors -- was already ported (before
//! this file) as a trait rather than a concrete struct, specifically because Java's
//! `InstructionBlock` constructs `InstructionError`s that reference it back
//! (`new InstructionError(this, type, ...)`), and `InstructionError` didn't exist yet. That
//! trait's methods reference this crate's [`seam_stubs::InstructionError`] marker trait (via
//! `Box<dyn InstructionError>`) rather than this concrete type, so no change to that already-done
//! file is needed: this concrete [`InstructionError`] implements that marker trait (see its impl
//! below) and is otherwise a full, real port of the Java class.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::instruction_block::InstructionBlock;
use crate::program::model::listing::Instruction;
use crate::program::seam_stubs::{InstructionError as InstructionErrorSeam, RegisterValue};
use crate::program::util::instruction_utils::InstructionUtils;
use crate::util::Msg;

/// The kind of [`InstructionError`].
///
/// Port of the nested enum `InstructionError.InstructionErrorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionErrorType {
    /// Duplicate instruction detected while instructions were being added to program. This
    /// should not be marked but should prevent additional instructions from being added
    /// unnecessarily.
    Duplicate,
    /// Conflict with existing instruction detected while instructions were being added to
    /// program. Conflict address corresponds to existing code unit. The first instruction within
    /// the block whose range overlaps the conflict code-unit should terminate the block prior to
    /// being added.
    InstructionConflict,
    /// Conflict with existing data detected while instructions were being added to program.
    /// Conflict address corresponds to existing code unit. The first instruction within the
    /// block whose range overlaps the conflict code-unit should terminate the block prior to
    /// being added.
    DataConflict,
    /// Offcut conflict with existing instruction detected while instructions were being added to
    /// program. Conflict address corresponds to existing code unit. The first instruction within
    /// the block whose range overlaps the conflict code-unit should terminate the block prior to
    /// being added.
    OffcutInstruction,
    /// Instruction parsing failed at the conflict address. This conflict should only have a
    /// conflict address which immediately follows the last instruction within the block or
    /// matches the block-start if the block is empty.
    Parse,
    /// Instruction parsing failed at the conflict address due to a memory error. This conflict
    /// should only have a conflict address which immediately follows the last instruction within
    /// the block or matches the block-start if the block is empty.
    Memory,
    /// Instruction contains an unaligned flow which is indicative of a language problem. The
    /// conflict address corresponds to the instruction containing the flow. While the instruction
    /// at the conflict address may be added it should be the last.
    FlowAlignment,
}

impl InstructionErrorType {
    /// Instruction error associated with a conflict with an existing code unit (instruction or
    /// data). Port of the `isConflict` instance field.
    pub fn is_conflict(self) -> bool {
        matches!(
            self,
            InstructionErrorType::Duplicate
                | InstructionErrorType::InstructionConflict
                | InstructionErrorType::DataConflict
                | InstructionErrorType::OffcutInstruction
        )
    }
}

/// An error or conflict detected while disassembling/adding instructions to a program.
///
/// Port of `ghidra.program.model.lang.InstructionError`.
pub struct InstructionError {
    block: Arc<dyn InstructionBlock>,
    error_type: InstructionErrorType,
    /// Address of another code unit which conflicts with the new instruction (only applies to
    /// CODE_UNIT or DUPLICATE conflict errors).
    conflict_address: Option<Address>,
    /// Address of the intended instruction which failed to be created.
    instruction_address: Address,
    /// Disassembly context at `instruction_address` (applies to PARSE error only).
    parse_context: Option<Box<dyn RegisterValue>>,
    /// Flow-from address (`None` if unknown).
    flow_from_address: Option<Address>,
    message: String,
}

impl InstructionError {
    /// Construct an instruction error/conflict.
    ///
    /// Port of the package-private general constructor
    /// `InstructionError(InstructionBlock, InstructionErrorType, Address, Address, Address,
    /// String)`.
    ///
    /// # Arguments
    /// * `block` - instruction block which corresponds to this error
    /// * `error_type` - type of instruction error/conflict
    /// * `instruction_address` - address of new intended instruction which failed to be created
    /// * `conflict_address` - address of another code unit which conflicts with new intended
    ///   instruction
    /// * `flow_from_address` - flow from address
    /// * `message` - a message describing the conflict
    pub(crate) fn new(
        block: Arc<dyn InstructionBlock>,
        error_type: InstructionErrorType,
        instruction_address: Address,
        conflict_address: Option<Address>,
        flow_from_address: Option<Address>,
        message: String,
    ) -> Self {
        InstructionError {
            block,
            error_type,
            conflict_address,
            instruction_address,
            parse_context: None,
            flow_from_address,
            message,
        }
    }

    /// Construct a PARSE error.
    ///
    /// Port of the package-private PARSE constructor `InstructionError(InstructionBlock,
    /// RegisterValue, Address, Address, String)`.
    ///
    /// # Arguments
    /// * `block` - instruction block which corresponds to this error
    /// * `context_value` - disassembler context used during instruction parse
    /// * `instruction_address` - address of new intended instruction which failed to be created
    /// * `flow_from_address` - flow from address
    /// * `message` - a message describing the conflict
    pub(crate) fn new_parse_error(
        block: Arc<dyn InstructionBlock>,
        context_value: Box<dyn RegisterValue>,
        instruction_address: Address,
        flow_from_address: Option<Address>,
        message: String,
    ) -> Self {
        InstructionError {
            block,
            error_type: InstructionErrorType::Parse,
            conflict_address: None,
            instruction_address,
            parse_context: Some(context_value),
            flow_from_address,
            message,
        }
    }

    /// Instruction block which corresponds to this error.
    pub fn get_instruction_block(&self) -> Arc<dyn InstructionBlock> {
        self.block.clone()
    }

    /// Type of instruction error.
    pub fn get_instruction_error_type(&self) -> InstructionErrorType {
        self.error_type
    }

    pub fn is_instruction_conflict(&self) -> bool {
        matches!(
            self.error_type,
            InstructionErrorType::OffcutInstruction | InstructionErrorType::InstructionConflict
        )
    }

    pub fn is_offcut_error(&self) -> bool {
        self.error_type == InstructionErrorType::OffcutInstruction
    }

    /// Address of new intended instruction which failed to be created (never null in the Java
    /// source).
    pub fn get_instruction_address(&self) -> Address {
        self.instruction_address.clone()
    }

    /// Address of another code unit which conflicts with intended instruction (required for
    /// CODE_UNIT and DUPLICATE errors, `None` for others).
    pub fn get_conflict_address(&self) -> Option<Address> {
        self.conflict_address.clone()
    }

    /// Disassembler context at intended instruction address (required for PARSE error, `None`
    /// for others).
    pub fn get_parse_context_value(&self) -> Option<&dyn RegisterValue> {
        self.parse_context.as_deref()
    }

    /// Flow-from address if known, else `None`.
    pub fn get_flow_from_address(&self) -> Option<Address> {
        self.flow_from_address.clone()
    }

    /// Instruction error message.
    pub fn get_conflict_message(&self) -> &str {
        &self.message
    }

    /// Port of the static `InstructionError.dumpInstructionDifference(Instruction, Instruction)`.
    ///
    /// Logs a debug message describing the differences between a newly disassembled instruction
    /// and the pre-existing instruction it conflicts with.
    pub fn dump_instruction_difference(new_inst: &dyn Instruction, existing_instr: &dyn Instruction) {
        use crate::program::model::mem::MemBuffer;
        let mut buf = format!(
            "Instruction conflict details at {}",
            MemBuffer::get_address(new_inst)
        );
        buf.push_str("\n  New Instruction: ");
        buf.push_str(&get_instruction_details(new_inst));
        buf.push_str("\n  Existing Instruction: ");
        buf.push_str(&get_instruction_details(existing_instr));
        Msg::debug("InstructionError", &buf);
    }
}

impl InstructionErrorSeam for InstructionError {
    fn get_instruction_address(&self) -> Address {
        self.instruction_address.clone()
    }
}

/// Port of the private static `InstructionError.getInstructionDetails(Instruction)`.
fn get_instruction_details(instr: &dyn Instruction) -> String {
    let mut buf = String::new();
    buf.push_str(&instruction_to_string(instr));
    buf.push('\n');
    buf.push_str(&instr.get_formatted_context_register_value_breakout("     "));
    buf
}

/// Reproduces `InstructionDB.toString()` (mnemonic followed by its operands joined by whatever
/// separators the instruction reports), since this crate's `Instruction`/`CodeUnit` traits don't
/// yet expose a `Display`/`to_string()` port equivalent to Java's `Instruction.toString()`. Built
/// from the same public accessors (`get_mnemonic_string`, `get_num_operands`, `get_separator`,
/// `get_default_operand_representation`) that `InstructionDB.toString()` itself uses, so this is
/// a faithful (if inlined) port of that algorithm rather than an approximation.
fn instruction_to_string(instr: &dyn Instruction) -> String {
    use crate::program::model::listing::code_unit::CodeUnit;

    let mut buf = String::new();
    buf.push_str(&instr.get_mnemonic_string());

    let n = instr.get_num_operands();
    let mut sep = instr.get_separator(0);
    if sep.is_some() || n != 0 {
        buf.push(' ');
    }
    if let Some(s) = &sep {
        buf.push_str(s);
    }

    for i in 0..n {
        buf.push_str(&instr.get_default_operand_representation(i));
        sep = instr.get_separator(i + 1);
        if let Some(s) = &sep {
            buf.push_str(s);
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::register_value::RegisterValue as RealRegisterValue;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use std::sync::Arc;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn test_register() -> RegisterRef {
        Register::new("r0", "", Address::new(register_space(), 0), 4, false, 0)
    }

    /// Minimal `InstructionBlock` stand-in used only to give constructed `InstructionError`s
    /// something to reference and return via `get_instruction_block()`.
    struct StubBlock {
        start: Address,
    }

    impl InstructionBlock for StubBlock {
        fn set_start_of_flow(&mut self, _is_start: bool) {}
        fn is_flow_start(&self) -> bool {
            false
        }
        fn get_start_address(&self) -> Address {
            self.start.clone()
        }
        fn get_max_address(&self) -> Address {
            self.start.clone()
        }
        fn get_instruction_at(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn find_first_intersecting_instruction(
            &self,
            _min: &Address,
            _max: &Address,
        ) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn add_instruction(&mut self, _instruction: Arc<dyn Instruction>) {}
        fn add_block_flow(
            &mut self,
            _block_flow: Box<dyn crate::program::seam_stubs::InstructionBlockFlow>,
        ) {
        }
        fn add_branch_flow(&mut self, _destination_address: Address) {}
        fn set_fall_through(&mut self, _fallthrough_address: Option<Address>) {}
        fn get_branch_flows(&self) -> Vec<Address> {
            Vec::new()
        }
        fn get_block_flows(
            &self,
        ) -> Option<Vec<Box<dyn crate::program::seam_stubs::InstructionBlockFlow>>> {
            None
        }
        fn get_fall_through(&self) -> Option<Address> {
            None
        }
        fn set_instruction_error(
            &mut self,
            _error_type: crate::program::seam_stubs::InstructionErrorType,
            _intended_instruction_address: Address,
            _conflict_address: Address,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
        }
        fn set_parse_conflict(
            &mut self,
            _conflict_address: Address,
            _context_value: Box<dyn RegisterValue>,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
        }
        fn clear_conflict(&mut self) {}
        fn get_instruction_conflict(&self) -> Option<Box<dyn InstructionErrorSeam>> {
            None
        }
        fn iter_instructions(&self) -> Box<dyn Iterator<Item = Arc<dyn Instruction>> + '_> {
            Box::new(std::iter::empty())
        }
        fn get_last_instruction_address(&self) -> Option<Address> {
            None
        }
        fn is_empty(&self) -> bool {
            true
        }
        fn get_instruction_count(&self) -> usize {
            0
        }
        fn get_instructions_added_count(&self) -> i32 {
            0
        }
        fn set_instructions_added_count(&mut self, _count: i32) {}
        fn get_flow_from_address(&self) -> Option<Address> {
            None
        }
        fn set_flow_from_address(&mut self, _flow_from: Option<Address>) {}
        fn has_instruction_error(&self) -> bool {
            false
        }
    }

    fn stub_block() -> Arc<dyn InstructionBlock> {
        Arc::new(StubBlock { start: ram_addr(0x1000) })
    }

    #[test]
    fn general_constructor_populates_all_fields_except_parse_context() {
        let block = stub_block();
        let err = InstructionError::new(
            block.clone(),
            InstructionErrorType::InstructionConflict,
            ram_addr(0x2000),
            Some(ram_addr(0x2000)),
            Some(ram_addr(0x1ffc)),
            "conflict!".to_string(),
        );

        assert!(Arc::ptr_eq(&err.get_instruction_block(), &block));
        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::InstructionConflict);
        assert_eq!(err.get_instruction_address(), ram_addr(0x2000));
        assert_eq!(err.get_conflict_address(), Some(ram_addr(0x2000)));
        assert_eq!(err.get_flow_from_address(), Some(ram_addr(0x1ffc)));
        assert_eq!(err.get_conflict_message(), "conflict!");
        assert!(err.get_parse_context_value().is_none());
    }

    #[test]
    fn parse_constructor_forces_parse_type_and_no_conflict_address() {
        let block = stub_block();
        let context = RealRegisterValue::with_value(test_register(), 0x42);
        let err = InstructionError::new_parse_error(
            block,
            Box::new(context),
            ram_addr(0x3000),
            None,
            "parse failed".to_string(),
        );

        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(err.get_conflict_address(), None);
        assert_eq!(err.get_flow_from_address(), None);
        assert!(err.get_parse_context_value().is_some());
        assert_eq!(
            err.get_parse_context_value().unwrap().get_unsigned_value_ignore_mask(),
            0x42
        );
    }

    #[test]
    fn is_instruction_conflict_true_only_for_instruction_conflict_and_offcut() {
        let block = stub_block();
        for (error_type, expected) in [
            (InstructionErrorType::Duplicate, false),
            (InstructionErrorType::InstructionConflict, true),
            (InstructionErrorType::DataConflict, false),
            (InstructionErrorType::OffcutInstruction, true),
            (InstructionErrorType::Parse, false),
            (InstructionErrorType::Memory, false),
            (InstructionErrorType::FlowAlignment, false),
        ] {
            let err = InstructionError::new(
                block.clone(),
                error_type,
                ram_addr(0x1000),
                None,
                None,
                String::new(),
            );
            assert_eq!(err.is_instruction_conflict(), expected, "{error_type:?}");
        }
    }

    #[test]
    fn is_offcut_error_true_only_for_offcut_instruction() {
        let block = stub_block();
        let offcut = InstructionError::new(
            block.clone(),
            InstructionErrorType::OffcutInstruction,
            ram_addr(0x1000),
            None,
            None,
            String::new(),
        );
        let not_offcut = InstructionError::new(
            block,
            InstructionErrorType::InstructionConflict,
            ram_addr(0x1000),
            None,
            None,
            String::new(),
        );
        assert!(offcut.is_offcut_error());
        assert!(!not_offcut.is_offcut_error());
    }

    #[test]
    fn is_conflict_matches_java_error_type_grouping() {
        assert!(InstructionErrorType::Duplicate.is_conflict());
        assert!(InstructionErrorType::InstructionConflict.is_conflict());
        assert!(InstructionErrorType::DataConflict.is_conflict());
        assert!(InstructionErrorType::OffcutInstruction.is_conflict());
        assert!(!InstructionErrorType::Parse.is_conflict());
        assert!(!InstructionErrorType::Memory.is_conflict());
        assert!(!InstructionErrorType::FlowAlignment.is_conflict());
    }

    #[test]
    fn seam_trait_get_instruction_address_matches_inherent_getter() {
        let block = stub_block();
        let err = InstructionError::new(
            block,
            InstructionErrorType::Memory,
            ram_addr(0x4000),
            None,
            None,
            String::new(),
        );
        let as_seam: &dyn InstructionErrorSeam = &err;
        assert_eq!(as_seam.get_instruction_address(), ram_addr(0x4000));
        assert_eq!(as_seam.get_instruction_address(), err.get_instruction_address());
    }

    #[test]
    fn instruction_to_string_matches_instructiondb_algorithm() {
        // `mock_instruction` reports mnemonic "MOV", 2 operands each rendering as "1", and
        // `get_separator(0) == Some(", ")` with no separator elsewhere -- reproducing
        // `InstructionDB.toString()`'s algorithm against those fixed values by hand: mnemonic,
        // then (since a separator exists before operand 0) a space then that separator, then each
        // operand's representation with its own following separator appended if present.
        let instr = mock_instruction(ram_addr(0x1000), ram_addr(0x1003));
        assert_eq!(instruction_to_string(&*instr), "MOV , 11");
    }

    #[test]
    fn dump_instruction_difference_does_not_panic() {
        // No assertion on Msg output (it just logs); this proves the whole formatting/breakout
        // pipeline runs end-to-end without panicking for a realistic mock instruction pair.
        let new_inst = mock_instruction(ram_addr(0x1000), ram_addr(0x1003));
        let existing_instr = mock_instruction(ram_addr(0x1000), ram_addr(0x1003));
        InstructionError::dump_instruction_difference(&*new_inst, &*existing_instr);
    }

    #[test]
    fn get_instruction_details_includes_mnemonic_and_context_breakout() {
        let instr = mock_instruction(ram_addr(0x1000), ram_addr(0x1003));
        let details = get_instruction_details(&*instr);
        assert!(details.contains("MOV"));
        // `mock_instruction`'s `get_base_context_register()` returns `None`, so the breakout
        // falls back to this fixed message (see `InstructionUtils::get_formatted_context_register_value_breakout`).
        assert!(details.contains("[Instruction context not defined]"));
    }
}
