use std::fmt;

/// Instruction type from GNU binutils `include/dis-asm.h`.
///
/// Java equivalent: `ghidra.app.util.disassemble.GnuDisassembledInstruction.DIS_INSN_TYPE`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisInsnType {
    /// Not a valid instruction.
    NonInsn,
    /// Not a branch instruction.
    NonBranch,
    /// Unconditional branch.
    Branch,
    /// Conditional branch.
    CondBranch,
    /// Jump to subroutine.
    Jsr,
    /// Conditional jump to subroutine.
    CondJsr,
    /// Data reference instruction.
    DRef,
    /// Two data references in instruction.
    DRef2,
}

impl DisInsnType {
    /// Converts the ordinal from the C `dis_insn_type` enum in GNU binutils `dis-asm.h`.
    ///
    /// Panics if `ordinal` is out of range (matches Java's `ArrayIndexOutOfBoundsException`).
    pub fn from_ordinal(ordinal: i32) -> Self {
        match ordinal {
            0 => Self::NonInsn,
            1 => Self::NonBranch,
            2 => Self::Branch,
            3 => Self::CondBranch,
            4 => Self::Jsr,
            5 => Self::CondJsr,
            6 => Self::DRef,
            7 => Self::DRef2,
            _ => panic!("invalid DIS_INSN_TYPE ordinal: {ordinal}"),
        }
    }
}

/// Holds the disassembled string of an instruction and the extra information
/// (type, number of bytes disassembled to produce instruction, etc.) of bytes
/// disassembled by the GNU disassembler.
///
/// Java equivalent: `ghidra.app.util.disassemble.GnuDisassembledInstruction`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuDisassembledInstruction {
    instruction: String,
    bytes_in_instruction: i32,
    branch_delay_instructions: i32,
    data_size: i32,
    instruction_type: DisInsnType,
    is_valid: bool,
}

impl GnuDisassembledInstruction {
    pub fn new(
        instruction_line: &str,
        bytes_in_instruction: i32,
        is_valid: bool,
        branch_delay_instructions: i32,
        data_size: i32,
        dis_insn_type_ordinal: i32,
    ) -> Self {
        Self {
            instruction: instruction_line.trim().to_string(),
            bytes_in_instruction,
            is_valid,
            branch_delay_instructions,
            data_size,
            instruction_type: DisInsnType::from_ordinal(dis_insn_type_ordinal),
        }
    }

    pub fn get_number_of_bytes_in_instruction(&self) -> i32 {
        self.bytes_in_instruction
    }

    /// Returns `None` when the instruction is invalid (mirrors Java returning `null`).
    pub fn get_instruction_type(&self) -> Option<DisInsnType> {
        self.is_valid.then_some(self.instruction_type)
    }

    /// Returns `None` when the instruction is invalid (mirrors Java returning `null`).
    pub fn get_branch_delay_instructions(&self) -> Option<i32> {
        self.is_valid.then_some(self.branch_delay_instructions)
    }

    /// Returns `None` when the instruction is invalid (mirrors Java returning `null`).
    pub fn get_data_size(&self) -> Option<i32> {
        self.is_valid.then_some(self.data_size)
    }

    pub fn get_instruction(&self) -> &str {
        &self.instruction
    }
}

impl fmt::Display for GnuDisassembledInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.instruction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid(insn: &str) -> GnuDisassembledInstruction {
        GnuDisassembledInstruction::new(insn, 4, true, 1, 2, 2 /* Branch */)
    }

    fn make_invalid(insn: &str) -> GnuDisassembledInstruction {
        GnuDisassembledInstruction::new(insn, 4, false, 1, 2, 0 /* NonInsn */)
    }

    #[test]
    fn test_constructor_trims_whitespace() {
        let i = make_valid("  nop  ");
        assert_eq!(i.get_instruction(), "nop");
    }

    #[test]
    fn test_display_returns_instruction() {
        let i = make_valid("jmp 0x1000");
        assert_eq!(i.to_string(), "jmp 0x1000");
    }

    #[test]
    fn test_bytes_in_instruction_always_returned() {
        let i = GnuDisassembledInstruction::new("bad", 6, false, 0, 0, 0);
        assert_eq!(i.get_number_of_bytes_in_instruction(), 6);
    }

    #[test]
    fn test_valid_getters_return_some() {
        let i = GnuDisassembledInstruction::new("beq", 4, true, 3, 8, 3 /* CondBranch */);
        assert_eq!(i.get_instruction_type(), Some(DisInsnType::CondBranch));
        assert_eq!(i.get_branch_delay_instructions(), Some(3));
        assert_eq!(i.get_data_size(), Some(8));
    }

    #[test]
    fn test_invalid_getters_return_none() {
        let i = make_invalid("???");
        assert_eq!(i.get_instruction_type(), None);
        assert_eq!(i.get_branch_delay_instructions(), None);
        assert_eq!(i.get_data_size(), None);
    }

    #[test]
    fn test_dis_insn_type_all_ordinals() {
        let cases = [
            (0, DisInsnType::NonInsn),
            (1, DisInsnType::NonBranch),
            (2, DisInsnType::Branch),
            (3, DisInsnType::CondBranch),
            (4, DisInsnType::Jsr),
            (5, DisInsnType::CondJsr),
            (6, DisInsnType::DRef),
            (7, DisInsnType::DRef2),
        ];
        for (ord, expected) in cases {
            assert_eq!(DisInsnType::from_ordinal(ord), expected, "ordinal {ord}");
        }
    }

    #[test]
    #[should_panic(expected = "invalid DIS_INSN_TYPE ordinal: 8")]
    fn test_dis_insn_type_invalid_ordinal_panics() {
        DisInsnType::from_ordinal(8);
    }

    #[test]
    fn test_empty_instruction_trimmed() {
        let i = GnuDisassembledInstruction::new("   ", 0, true, 0, 0, 1);
        assert_eq!(i.get_instruction(), "");
        assert_eq!(i.to_string(), "");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = make_valid("mov eax, 1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_debug_format() {
        let i = make_valid("nop");
        let s = format!("{i:?}");
        assert!(s.contains("nop"));
    }
}
