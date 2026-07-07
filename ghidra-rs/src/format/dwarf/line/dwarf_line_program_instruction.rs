use super::dwarf_line_program_state::DWARFLineProgramState;

/// Represents a single instruction from a DWARF line-number program.
///
/// This struct captures an instruction read from the line-number program, along with its
/// offset in the program, instruction name, operands, and the resulting state after
/// execution (if applicable).
///
/// Mirrors Ghidra's `DWARFLineProgramInstruction`.
#[derive(Debug, Clone)]
pub struct DWARFLineProgramInstruction {
    /// Offset of this instruction within the line-number program.
    pub offset: u64,
    /// Name of the instruction (e.g., "DW_LN_special_42").
    pub instr: String,
    /// Operands for this instruction.
    pub operands: Vec<i64>,
    /// The resulting machine state after executing this instruction,
    /// or `None` if the instruction does not produce a state change.
    pub row: Option<Box<DWARFLineProgramState>>,
}

impl DWARFLineProgramInstruction {
    /// Creates a new instruction.
    pub fn new(
        offset: u64,
        instr: String,
        operands: Vec<i64>,
        row: Option<DWARFLineProgramState>,
    ) -> Self {
        Self {
            offset,
            instr,
            operands,
            row: row.map(Box::new),
        }
    }

    /// Returns a formatted description of this instruction.
    ///
    /// If a state is present, includes the state information; otherwise returns
    /// a simpler description.
    pub fn get_desc(&self) -> String {
        match &self.row {
            Some(row) => {
                let mut flags = String::new();
                if row.is_basic_block {
                    flags.push_str(" basic block ");
                }
                if row.is_end_sequence {
                    flags.push_str(" end-of-seq ");
                }
                if row.is_statement {
                    flags.push_str(" statement ");
                }
                if row.prologue_end {
                    flags.push_str(" prologue-end ");
                }

                let operands_str = self
                    .operands
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                format!(
                    "[{:04x}] {} [{}] - 0x{:x}, file: {}, line: {}{}",
                    self.offset,
                    self.instr,
                    operands_str,
                    row.address,
                    row.file,
                    row.line,
                    if flags.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", flags)
                    }
                )
            }
            None => {
                let operands_str = self
                    .operands
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("[{:04x}] {} [{}]", self.offset, self.instr, operands_str)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_no_state() {
        let instr = DWARFLineProgramInstruction::new(
            0x1000,
            "DW_LN_special_42".to_string(),
            vec![5, 2],
            None,
        );

        assert_eq!(instr.offset, 0x1000);
        assert_eq!(instr.instr, "DW_LN_special_42");
        assert_eq!(instr.operands, vec![5, 2]);
        assert!(instr.row.is_none());
    }

    #[test]
    fn new_with_state() {
        let mut state = DWARFLineProgramState::new(true);
        state.address = 0x2000;
        state.file = 1;
        state.line = 42;

        let instr = DWARFLineProgramInstruction::new(
            0x1000,
            "DW_LN_advance_pc".to_string(),
            vec![256],
            Some(state),
        );

        assert_eq!(instr.offset, 0x1000);
        assert_eq!(instr.instr, "DW_LN_advance_pc");
        assert_eq!(instr.operands, vec![256]);
        assert!(instr.row.is_some());
        let row = instr.row.as_ref().unwrap();
        assert_eq!(row.address, 0x2000);
        assert_eq!(row.file, 1);
        assert_eq!(row.line, 42);
    }

    #[test]
    fn get_desc_without_state() {
        let instr = DWARFLineProgramInstruction::new(
            0x1234,
            "DW_LN_set_file".to_string(),
            vec![3],
            None,
        );

        let desc = instr.get_desc();
        assert!(desc.contains("[1234]"));
        assert!(desc.contains("DW_LN_set_file"));
        assert!(desc.contains("[3]"));
        assert!(!desc.contains("0x"));
    }

    #[test]
    fn get_desc_with_state_no_flags() {
        let mut state = DWARFLineProgramState::new(false);
        state.address = 0x1000;
        state.file = 1;
        state.line = 10;

        let instr = DWARFLineProgramInstruction::new(
            0x0100,
            "DW_LN_copy".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("[0100]"));
        assert!(desc.contains("DW_LN_copy"));
        assert!(desc.contains("0x1000"));
        assert!(desc.contains("file: 1"));
        assert!(desc.contains("line: 10"));
    }

    #[test]
    fn get_desc_with_state_statement_flag() {
        let mut state = DWARFLineProgramState::new(true);
        state.address = 0x2000;
        state.file = 2;
        state.line = 50;
        state.is_statement = true;

        let instr = DWARFLineProgramInstruction::new(
            0x0200,
            "test".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("statement"));
        assert!(desc.contains("0x2000"));
        assert!(desc.contains("file: 2"));
        assert!(desc.contains("line: 50"));
    }

    #[test]
    fn get_desc_with_state_basic_block_flag() {
        let mut state = DWARFLineProgramState::new(false);
        state.address = 0x3000;
        state.file = 3;
        state.line = 75;
        state.is_basic_block = true;

        let instr = DWARFLineProgramInstruction::new(
            0x0300,
            "test".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("basic block"));
    }

    #[test]
    fn get_desc_with_state_end_sequence_flag() {
        let mut state = DWARFLineProgramState::new(false);
        state.address = 0x4000;
        state.file = 1;
        state.line = 100;
        state.is_end_sequence = true;

        let instr = DWARFLineProgramInstruction::new(
            0x0400,
            "test".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("end-of-seq"));
    }

    #[test]
    fn get_desc_with_state_prologue_end_flag() {
        let mut state = DWARFLineProgramState::new(false);
        state.address = 0x5000;
        state.file = 1;
        state.line = 1;
        state.prologue_end = true;

        let instr = DWARFLineProgramInstruction::new(
            0x0500,
            "test".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("prologue-end"));
    }

    #[test]
    fn get_desc_with_multiple_operands() {
        let instr = DWARFLineProgramInstruction::new(
            0x0600,
            "DW_LN_special_99".to_string(),
            vec![10, 5, 20],
            None,
        );

        let desc = instr.get_desc();
        assert!(desc.contains("[10, 5, 20]"));
    }

    #[test]
    fn get_desc_with_empty_operands() {
        let instr = DWARFLineProgramInstruction::new(
            0x0700,
            "DW_LN_copy".to_string(),
            vec![],
            None,
        );

        let desc = instr.get_desc();
        assert!(desc.contains("[]"));
    }

    #[test]
    fn get_desc_with_all_flags() {
        let mut state = DWARFLineProgramState::new(true);
        state.address = 0xdeadbeef;
        state.file = 5;
        state.line = 123;
        state.is_statement = true;
        state.is_basic_block = true;
        state.is_end_sequence = true;
        state.prologue_end = true;

        let instr = DWARFLineProgramInstruction::new(
            0xabcd,
            "test".to_string(),
            vec![1, 2, 3],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("basic block"));
        assert!(desc.contains("end-of-seq"));
        assert!(desc.contains("statement"));
        assert!(desc.contains("prologue-end"));
        assert!(desc.contains("[1, 2, 3]"));
    }

    #[test]
    fn clone_is_independent() {
        let mut state = DWARFLineProgramState::new(true);
        state.address = 0x1000;

        let instr1 = DWARFLineProgramInstruction::new(
            0x100,
            "test1".to_string(),
            vec![5],
            Some(state),
        );

        let instr2 = instr1.clone();

        assert_eq!(instr1.offset, instr2.offset);
        assert_eq!(instr1.instr, instr2.instr);
        assert_eq!(instr1.operands, instr2.operands);
        assert_eq!(
            instr1.row.as_ref().unwrap().address,
            instr2.row.as_ref().unwrap().address
        );
    }

    #[test]
    fn offset_formatting_zero_pads() {
        let instr = DWARFLineProgramInstruction::new(
            0x42,
            "test".to_string(),
            vec![],
            None,
        );

        let desc = instr.get_desc();
        assert!(desc.starts_with("[0042]"));
    }

    #[test]
    fn address_formatting_hex() {
        let mut state = DWARFLineProgramState::new(true);
        state.address = 0xabcd;

        let instr = DWARFLineProgramInstruction::new(
            0x0,
            "test".to_string(),
            vec![],
            Some(state),
        );

        let desc = instr.get_desc();
        assert!(desc.contains("0xabcd"));
    }
}
