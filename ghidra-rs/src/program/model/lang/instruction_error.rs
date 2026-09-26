//! Port of `ghidra.program.model.lang.InstructionError`.
//!
//! Describes an error or conflict detected while adding disassembled instructions to a program:
//! duplicate/conflicting code units, a failed parse, a memory error while parsing, or an
//! unaligned flow. Raised against (and owned by) an
//! [`InstructionBlock`](crate::program::model::lang::instruction_block::InstructionBlock).
//!
//! Java's constructors take the owning block (`new InstructionError(this, type, ...)`) and
//! expose it again through `getInstructionBlock()`. The block owns its error, so that
//! back-reference is dropped here (decision 2026-09-24: back-references become IDs or call-time
//! arguments): whoever holds an error reached it through its block. No Java caller outside
//! `InstructionError` itself reads `getInstructionBlock()`.

use crate::program::model::address::Address;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::Instruction;
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
    error_type: InstructionErrorType,
    /// Address of another code unit which conflicts with the new instruction (only applies to
    /// CODE_UNIT or DUPLICATE conflict errors).
    conflict_address: Option<Address>,
    /// Address of the intended instruction which failed to be created.
    instruction_address: Address,
    /// Disassembly context at `instruction_address` (applies to PARSE error only; `None` for a
    /// language without a context register).
    parse_context: Option<RegisterValue>,
    /// Flow-from address (`None` if unknown).
    flow_from_address: Option<Address>,
    message: String,
}

impl InstructionError {
    /// Construct an instruction error/conflict.
    ///
    /// Port of the package-private general constructor
    /// `InstructionError(InstructionBlock, InstructionErrorType, Address, Address, Address,
    /// String)`, less the owning block (see the module docs).
    ///
    /// # Arguments
    /// * `error_type` - type of instruction error/conflict
    /// * `instruction_address` - address of new intended instruction which failed to be created
    /// * `conflict_address` - address of another code unit which conflicts with new intended
    ///   instruction
    /// * `flow_from_address` - flow from address
    /// * `message` - a message describing the conflict
    pub(crate) fn new(
        error_type: InstructionErrorType,
        instruction_address: Address,
        conflict_address: Option<Address>,
        flow_from_address: Option<Address>,
        message: String,
    ) -> Self {
        InstructionError {
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
    /// RegisterValue, Address, Address, String)`, less the owning block (see the module docs).
    ///
    /// # Arguments
    /// * `context_value` - disassembler context used during instruction parse (`None`, Java's
    ///   `null`, for a language without a context register)
    /// * `instruction_address` - address of new intended instruction which failed to be created
    /// * `flow_from_address` - flow from address
    /// * `message` - a message describing the conflict
    pub(crate) fn new_parse_error(
        context_value: Option<RegisterValue>,
        instruction_address: Address,
        flow_from_address: Option<Address>,
        message: String,
    ) -> Self {
        InstructionError {
            error_type: InstructionErrorType::Parse,
            conflict_address: None,
            instruction_address,
            parse_context: context_value,
            flow_from_address,
            message,
        }
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
    pub fn get_parse_context_value(&self) -> Option<&RegisterValue> {
        self.parse_context.as_ref()
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

    #[test]
    fn general_constructor_populates_all_fields_except_parse_context() {
        let err = InstructionError::new(
            InstructionErrorType::InstructionConflict,
            ram_addr(0x2000),
            Some(ram_addr(0x2000)),
            Some(ram_addr(0x1ffc)),
            "conflict!".to_string(),
        );

        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::InstructionConflict);
        assert_eq!(err.get_instruction_address(), ram_addr(0x2000));
        assert_eq!(err.get_conflict_address(), Some(ram_addr(0x2000)));
        assert_eq!(err.get_flow_from_address(), Some(ram_addr(0x1ffc)));
        assert_eq!(err.get_conflict_message(), "conflict!");
        assert!(err.get_parse_context_value().is_none());
    }

    #[test]
    fn parse_constructor_forces_parse_type_and_no_conflict_address() {
        let context = RealRegisterValue::with_value(test_register(), 0x42);
        let err = InstructionError::new_parse_error(
            Some(context),
            ram_addr(0x3000),
            None,
            "parse failed".to_string(),
        );

        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(err.get_conflict_address(), None);
        assert_eq!(err.get_flow_from_address(), None);
        assert!(err.get_parse_context_value().is_some());
        assert_eq!(
            err.get_parse_context_value().unwrap().unsigned_value_ignore_mask(),
            0x42
        );
    }

    #[test]
    fn is_instruction_conflict_true_only_for_instruction_conflict_and_offcut() {
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
        let offcut = InstructionError::new(
            InstructionErrorType::OffcutInstruction,
            ram_addr(0x1000),
            None,
            None,
            String::new(),
        );
        let not_offcut = InstructionError::new(
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
