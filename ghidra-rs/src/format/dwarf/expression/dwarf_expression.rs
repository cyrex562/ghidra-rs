//! Port of `ghidra.app.util.bin.format.dwarf.expression.DWARFExpression`.
//!
//! An immutable list of [`DWARFExpressionInstruction`] operations, plus factory methods to read an
//! expression from its binary representation. Use a
//! [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator)
//! to execute a `DWARFExpression`.

use crate::format::seam_stubs::{
    DWARFCompilationUnit, DWARFExpressionException, DWARFExpressionInstruction,
    DWARFExpressionOpCode,
};

/// An immutable list of [`DWARFExpressionInstruction`] operations.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct DWARFExpression {
    instructions: Vec<DWARFExpressionInstruction>,
}

impl DWARFExpression {
    /// Mirrors `DWARFExpression.MAX_SANE_EXPR`.
    pub const MAX_SANE_EXPR: i32 = 512;

    /// Stands in for the private `DWARFExpression(List<DWARFExpressionInstruction>)` constructor
    /// that the Java `read` factories call. Exposed publicly since Rust has no equivalent of a
    /// same-file-only-visible constructor and callers (the evaluator's tests, and future callers
    /// that already have parsed instructions) need a way to build an expression directly.
    pub fn of(instructions: Vec<DWARFExpressionInstruction>) -> Self {
        DWARFExpression { instructions }
    }

    /// Deserializes a [`DWARFExpression`] from its raw bytes.
    ///
    /// Mirrors `DWARFExpression.read(byte[], DWARFCompilationUnit)`, which builds a
    /// `ByteArrayProvider`/`BinaryReader` over `expr_bytes` and loops
    /// `DWARFExpressionInstruction.read(reader, cu.getPointerSize(), cu.getIntSize())` until the
    /// reader is exhausted, wrapping any I/O error (including an unknown opcode, which Java
    /// reports by throwing `IOException`) in a [`DWARFExpressionException`] that carries the
    /// partially-read expression.
    ///
    /// Blocked on forward dependencies that have not been ported yet: a concrete production
    /// `BinaryReader` implementation and `DWARFExpressionInstruction::read` (both still
    /// placeholders in [`crate::format::seam_stubs`]). Until those land this always fails; build
    /// expressions from already-parsed instructions with [`Self::of`] instead.
    pub fn read(
        _expr_bytes: &[u8],
        _cu: &dyn DWARFCompilationUnit,
    ) -> Result<DWARFExpression, DWARFExpressionException> {
        Err(DWARFExpressionException::new(
            "DWARFExpression.read is not yet implemented (DWARFExpressionInstruction::read and a \
             concrete BinaryReader have not been ported)",
        ))
    }

    /// Converts this expression into a generic form, lacking any operand values.
    ///
    /// Mirrors `DWARFExpression.toGenericForm()`. Useful for aggregating statistics about
    /// unsupported/problematic expressions encountered in a binary.
    pub fn to_generic_form(&self) -> DWARFExpression {
        let generic_instrs =
            self.instructions.iter().map(DWARFExpressionInstruction::to_generic_form).collect();
        DWARFExpression::of(generic_instrs)
    }

    /// Mirrors `DWARFExpression.getInstruction(int)`, which throws `IndexOutOfBoundsException` for
    /// an out of range index.
    pub fn get_instruction(&self, i: i32) -> Option<&DWARFExpressionInstruction> {
        usize::try_from(i).ok().and_then(|i| self.instructions.get(i))
    }

    /// Mirrors `DWARFExpression.getInstructionCount()`.
    pub fn get_instruction_count(&self) -> i32 {
        self.instructions.len() as i32
    }

    /// Mirrors `DWARFExpression.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Finds the index of an instruction by its offset from the beginning of the expression.
    ///
    /// Mirrors `DWARFExpression.findInstructionByOffset(long)`: the index of the instruction that
    /// starts at `offset`, or -1 if there is none.
    pub fn find_instruction_by_offset(&self, offset: i64) -> i32 {
        self.instructions
            .iter()
            .position(|instr| instr.get_offset() as i64 == offset)
            .map_or(-1, |i| i as i32)
    }

    /// Mirrors `DWARFExpression.toString(DWARFCompilationUnit)`.
    pub fn to_string_with_cu(&self, cu: &dyn DWARFCompilationUnit) -> String {
        let reg_mapping = cu.get_program().and_then(|p| p.get_register_mappings());
        self.to_string_formatted(-1, false, false, reg_mapping.as_deref())
    }

    /// Returns a formatted string representing this expression.
    ///
    /// Mirrors `DWARFExpression.toString(int, boolean, boolean, DWARFRegisterMappings)`.
    ///
    /// # Parameters
    /// - `caret_position`: index of which instruction to highlight as being the current
    ///   instruction, or -1 to not highlight any instruction.
    /// - `newlines`: if true, each instruction is on its own line.
    /// - `offsets`: if true, the byte offset in the expression is listed next to each instruction.
    /// - `reg_mapping`: mapping of dwarf to ghidra registers.
    pub fn to_string_formatted(
        &self,
        caret_position: i32,
        newlines: bool,
        offsets: bool,
        reg_mapping: Option<&crate::format::dwarf::dwarf_register_mappings::DWARFRegisterMappings>,
    ) -> String {
        use std::fmt::Write;

        let mut sb = String::new();
        for (instr_index, instr) in self.instructions.iter().enumerate() {
            if instr_index != 0 {
                sb.push_str(if newlines { "\n" } else { "; " });
            }
            if offsets {
                let _ = write!(sb, "{instr_index:3} [{:03x}]: ", instr.get_offset());
            }
            if caret_position == instr_index as i32 {
                sb.push_str(" ==> [");
            }
            sb.push_str(&instr.opcode.to_string_with_reg_mapping(reg_mapping));
            for operand_index in 0..instr.get_operand_count() {
                if operand_index == 0 {
                    sb.push(':');
                }
                let _ = write!(sb, " {}", instr.get_operand_value(operand_index));
            }
            if caret_position == instr_index as i32 {
                sb.push_str(" ] <==");
            }
            if matches!(
                instr.opcode,
                DWARFExpressionOpCode::DW_OP_bra | DWARFExpressionOpCode::DW_OP_skip
            ) {
                let mut dest_offset = instr.get_offset() as i64;
                if instr.get_operand_count() > 0 {
                    dest_offset += instr.get_operand_value(0);
                }
                let dest_index = self.find_instruction_by_offset(dest_offset);
                let _ = write!(
                    sb,
                    " /* dest index: {dest_index}, offset: {:03x} */",
                    dest_offset as i32
                );
            }
        }
        sb
    }
}

impl std::fmt::Display for DWARFExpression {
    /// Mirrors `DWARFExpression.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_formatted(-1, false, false, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instr(op: DWARFExpressionOpCode, operands: Vec<i64>, offset: i32) -> DWARFExpressionInstruction {
        DWARFExpressionInstruction::new(op, operands, offset)
    }

    #[test]
    fn empty_expression_is_empty() {
        let expr = DWARFExpression::of(vec![]);
        assert!(expr.is_empty());
        assert_eq!(expr.get_instruction_count(), 0);
        assert_eq!(expr.get_instruction(0), None);
    }

    #[test]
    fn instruction_lookup_by_index_and_offset() {
        use DWARFExpressionOpCode::*;
        let expr = DWARFExpression::of(vec![
            instr(DW_OP_lit1, vec![], 0),
            instr(DW_OP_lit2, vec![], 1),
            instr(DW_OP_plus, vec![], 2),
        ]);
        assert!(!expr.is_empty());
        assert_eq!(expr.get_instruction_count(), 3);
        assert_eq!(expr.get_instruction(1).unwrap().opcode, DW_OP_lit2);
        assert_eq!(expr.find_instruction_by_offset(2), 2);
        assert_eq!(expr.find_instruction_by_offset(99), -1);
    }

    #[test]
    fn to_generic_form_strips_operands_and_resets_offset() {
        use DWARFExpressionOpCode::*;
        let expr = DWARFExpression::of(vec![
            instr(DW_OP_const1u, vec![10], 5),
            instr(DW_OP_lit2, vec![], 6),
        ]);
        let generic = expr.to_generic_form();
        assert_eq!(generic.get_instruction_count(), 2);
        let first = generic.get_instruction(0).unwrap();
        assert_eq!(first.opcode, DW_OP_const1u);
        assert_eq!(first.get_operand_count(), 0);
        assert_eq!(first.get_offset(), 0);
    }

    #[test]
    fn display_matches_java_tostring_format() {
        use DWARFExpressionOpCode::*;
        // DW_OP_const1u 10, DW_OP_lit2, DW_OP_plus  -- matches the readelf-influenced Java format:
        // "opcode: operand; opcode; opcode"
        let expr = DWARFExpression::of(vec![
            instr(DW_OP_const1u, vec![10], 0),
            instr(DW_OP_lit2, vec![], 2),
            instr(DW_OP_plus, vec![], 3),
        ]);
        assert_eq!(expr.to_string(), "DW_OP_const1u: 10; DW_OP_lit2; DW_OP_plus");
    }

    #[test]
    fn display_with_offsets_and_caret() {
        use DWARFExpressionOpCode::*;
        let expr = DWARFExpression::of(vec![instr(DW_OP_nop, vec![], 0)]);
        let s = expr.to_string_formatted(0, false, true, None);
        assert_eq!(s, "  0 [000]:  ==> [DW_OP_nop ] <==");
    }

    #[test]
    fn skip_instruction_annotates_destination_index() {
        use DWARFExpressionOpCode::*;
        // @0 lit1, @1 skip(+4 -> offset 5), @4 lit7, @5 lit9
        let expr = DWARFExpression::of(vec![
            instr(DW_OP_lit1, vec![], 0),
            instr(DW_OP_skip, vec![4], 1),
            instr(DW_OP_lit7, vec![], 4),
            instr(DW_OP_lit9, vec![], 5),
        ]);
        let s = expr.to_string();
        assert!(s.contains("dest index: 3, offset: 005"), "{s}");
    }

    #[test]
    fn equality_and_hash_are_structural() {
        use DWARFExpressionOpCode::*;
        let a = DWARFExpression::of(vec![instr(DW_OP_lit1, vec![], 0)]);
        let b = DWARFExpression::of(vec![instr(DW_OP_lit1, vec![], 0)]);
        let c = DWARFExpression::of(vec![instr(DW_OP_lit2, vec![], 0)]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn read_reports_not_yet_implemented() {
        struct MockCu;
        impl DWARFCompilationUnit for MockCu {
            fn get_dwarf_version(&self) -> i16 {
                5
            }
        }
        let err = DWARFExpression::read(&[0x30], &MockCu).unwrap_err();
        assert!(err.to_string().contains("not yet implemented"), "{err}");
    }
}
