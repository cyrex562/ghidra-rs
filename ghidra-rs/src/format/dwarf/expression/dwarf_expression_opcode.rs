//! Port of `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode`.
//!
//! DWARF expression opcodes, and their expected operands.

use crate::format::dwarf::dwarf_register_mappings::DWARFRegisterMappings;
use crate::format::dwarf::expression::dwarf_expression_operand_type::DWARFExpressionOperandType;

/// DWARF expression opcodes, and their expected operands.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode`. Variants are
/// spelled exactly as the Java enum constants (rather than this crate's usual Rust `CamelCase`
/// convention) so that [`std::fmt::Display`] renders what Java's `toString()` does, matching the
/// convention already established for the many other verbatim-named `DW_*` opcode tables in this
/// crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum DWARFExpressionOpCode {
    /// Special value, not a real DWARF opcode.
    DW_OP_unknown_opcode = 0,
    DW_OP_addr = 0x3,
    DW_OP_deref = 0x6,
    DW_OP_const1u = 0x8,
    DW_OP_const1s = 0x9,
    DW_OP_const2u = 0xa,
    DW_OP_const2s = 0xb,
    DW_OP_const4u = 0xc,
    DW_OP_const4s = 0xd,
    DW_OP_const8u = 0xe,
    DW_OP_const8s = 0xf,
    DW_OP_constu = 0x10,
    DW_OP_consts = 0x11,
    DW_OP_dup = 0x12,
    DW_OP_drop = 0x13,
    DW_OP_over = 0x14,
    DW_OP_pick = 0x15,
    DW_OP_swap = 0x16,
    DW_OP_rot = 0x17,
    DW_OP_xderef = 0x18,
    DW_OP_abs = 0x19,
    DW_OP_and = 0x1a,
    DW_OP_div = 0x1b,
    DW_OP_minus = 0x1c,
    DW_OP_mod = 0x1d,
    DW_OP_mul = 0x1e,
    DW_OP_neg = 0x1f,
    DW_OP_not = 0x20,
    DW_OP_or = 0x21,
    DW_OP_plus = 0x22,
    DW_OP_plus_uconst = 0x23,
    DW_OP_shl = 0x24,
    DW_OP_shr = 0x25,
    DW_OP_shra = 0x26,
    DW_OP_xor = 0x27,
    DW_OP_bra = 0x28,
    DW_OP_eq = 0x29,
    DW_OP_ge = 0x2a,
    DW_OP_gt = 0x2b,
    DW_OP_le = 0x2c,
    DW_OP_lt = 0x2d,
    DW_OP_ne = 0x2e,
    DW_OP_skip = 0x2f,
    DW_OP_lit0 = 0x30,
    DW_OP_lit1 = 0x31,
    DW_OP_lit2 = 0x32,
    DW_OP_lit3 = 0x33,
    DW_OP_lit4 = 0x34,
    DW_OP_lit5 = 0x35,
    DW_OP_lit6 = 0x36,
    DW_OP_lit7 = 0x37,
    DW_OP_lit8 = 0x38,
    DW_OP_lit9 = 0x39,
    DW_OP_lit10 = 0x3a,
    DW_OP_lit11 = 0x3b,
    DW_OP_lit12 = 0x3c,
    DW_OP_lit13 = 0x3d,
    DW_OP_lit14 = 0x3e,
    DW_OP_lit15 = 0x3f,
    DW_OP_lit16 = 0x40,
    DW_OP_lit17 = 0x41,
    DW_OP_lit18 = 0x42,
    DW_OP_lit19 = 0x43,
    DW_OP_lit20 = 0x44,
    DW_OP_lit21 = 0x45,
    DW_OP_lit22 = 0x46,
    DW_OP_lit23 = 0x47,
    DW_OP_lit24 = 0x48,
    DW_OP_lit25 = 0x49,
    DW_OP_lit26 = 0x4a,
    DW_OP_lit27 = 0x4b,
    DW_OP_lit28 = 0x4c,
    DW_OP_lit29 = 0x4d,
    DW_OP_lit30 = 0x4e,
    DW_OP_lit31 = 0x4f,
    DW_OP_reg0 = 0x50,
    DW_OP_reg1 = 0x51,
    DW_OP_reg2 = 0x52,
    DW_OP_reg3 = 0x53,
    DW_OP_reg4 = 0x54,
    DW_OP_reg5 = 0x55,
    DW_OP_reg6 = 0x56,
    DW_OP_reg7 = 0x57,
    DW_OP_reg8 = 0x58,
    DW_OP_reg9 = 0x59,
    DW_OP_reg10 = 0x5a,
    DW_OP_reg11 = 0x5b,
    DW_OP_reg12 = 0x5c,
    DW_OP_reg13 = 0x5d,
    DW_OP_reg14 = 0x5e,
    DW_OP_reg15 = 0x5f,
    DW_OP_reg16 = 0x60,
    DW_OP_reg17 = 0x61,
    DW_OP_reg18 = 0x62,
    DW_OP_reg19 = 0x63,
    DW_OP_reg20 = 0x64,
    DW_OP_reg21 = 0x65,
    DW_OP_reg22 = 0x66,
    DW_OP_reg23 = 0x67,
    DW_OP_reg24 = 0x68,
    DW_OP_reg25 = 0x69,
    DW_OP_reg26 = 0x6a,
    DW_OP_reg27 = 0x6b,
    DW_OP_reg28 = 0x6c,
    DW_OP_reg29 = 0x6d,
    DW_OP_reg30 = 0x6e,
    DW_OP_reg31 = 0x6f,
    DW_OP_breg0 = 0x70,
    DW_OP_breg1 = 0x71,
    DW_OP_breg2 = 0x72,
    DW_OP_breg3 = 0x73,
    DW_OP_breg4 = 0x74,
    DW_OP_breg5 = 0x75,
    DW_OP_breg6 = 0x76,
    DW_OP_breg7 = 0x77,
    DW_OP_breg8 = 0x78,
    DW_OP_breg9 = 0x79,
    DW_OP_breg10 = 0x7a,
    DW_OP_breg11 = 0x7b,
    DW_OP_breg12 = 0x7c,
    DW_OP_breg13 = 0x7d,
    DW_OP_breg14 = 0x7e,
    DW_OP_breg15 = 0x7f,
    DW_OP_breg16 = 0x80,
    DW_OP_breg17 = 0x81,
    DW_OP_breg18 = 0x82,
    DW_OP_breg19 = 0x83,
    DW_OP_breg20 = 0x84,
    DW_OP_breg21 = 0x85,
    DW_OP_breg22 = 0x86,
    DW_OP_breg23 = 0x87,
    DW_OP_breg24 = 0x88,
    DW_OP_breg25 = 0x89,
    DW_OP_breg26 = 0x8a,
    DW_OP_breg27 = 0x8b,
    DW_OP_breg28 = 0x8c,
    DW_OP_breg29 = 0x8d,
    DW_OP_breg30 = 0x8e,
    DW_OP_breg31 = 0x8f,
    DW_OP_regx = 0x90,
    DW_OP_fbreg = 0x91,
    DW_OP_bregx = 0x92,
    DW_OP_piece = 0x93,
    DW_OP_deref_size = 0x94,
    DW_OP_xderef_size = 0x95,
    DW_OP_nop = 0x96,
    DW_OP_push_object_address = 0x97,
    DW_OP_call2 = 0x98,
    DW_OP_call4 = 0x99,
    DW_OP_call_ref = 0x9a,
    DW_OP_form_tls_address = 0x9b,
    DW_OP_call_frame_cfa = 0x9c,
    DW_OP_bit_piece = 0x9d,
    DW_OP_implicit_value = 0x9e,
    DW_OP_stack_value = 0x9f,

    // DWARF5
    DW_OP_implicit_pointer = 0xa0,
    DW_OP_addrx = 0xa1,
    DW_OP_constx = 0xa2,
    DW_OP_entry_value = 0xa3,
    DW_OP_const_type = 0xa4,
    DW_OP_regval_type = 0xa5,
    DW_OP_deref_type = 0xa6,
    DW_OP_xderef_type = 0xa7,
    DW_OP_convert = 0xa8,
    DW_OP_reinterpret = 0xa9,
}

/// All variants, in Java enum declaration order (which is also ascending raw-opcode order); used
/// by [`DWARFExpressionOpCode::parse`], mirroring the Java `values()` array captured once into
/// `lookupvals`/`opcodes`.
const VALUES: [DWARFExpressionOpCode; 165] = {
    use DWARFExpressionOpCode::*;
    [
        DW_OP_unknown_opcode,
        DW_OP_addr,
        DW_OP_deref,
        DW_OP_const1u,
        DW_OP_const1s,
        DW_OP_const2u,
        DW_OP_const2s,
        DW_OP_const4u,
        DW_OP_const4s,
        DW_OP_const8u,
        DW_OP_const8s,
        DW_OP_constu,
        DW_OP_consts,
        DW_OP_dup,
        DW_OP_drop,
        DW_OP_over,
        DW_OP_pick,
        DW_OP_swap,
        DW_OP_rot,
        DW_OP_xderef,
        DW_OP_abs,
        DW_OP_and,
        DW_OP_div,
        DW_OP_minus,
        DW_OP_mod,
        DW_OP_mul,
        DW_OP_neg,
        DW_OP_not,
        DW_OP_or,
        DW_OP_plus,
        DW_OP_plus_uconst,
        DW_OP_shl,
        DW_OP_shr,
        DW_OP_shra,
        DW_OP_xor,
        DW_OP_bra,
        DW_OP_eq,
        DW_OP_ge,
        DW_OP_gt,
        DW_OP_le,
        DW_OP_lt,
        DW_OP_ne,
        DW_OP_skip,
        DW_OP_lit0,
        DW_OP_lit1,
        DW_OP_lit2,
        DW_OP_lit3,
        DW_OP_lit4,
        DW_OP_lit5,
        DW_OP_lit6,
        DW_OP_lit7,
        DW_OP_lit8,
        DW_OP_lit9,
        DW_OP_lit10,
        DW_OP_lit11,
        DW_OP_lit12,
        DW_OP_lit13,
        DW_OP_lit14,
        DW_OP_lit15,
        DW_OP_lit16,
        DW_OP_lit17,
        DW_OP_lit18,
        DW_OP_lit19,
        DW_OP_lit20,
        DW_OP_lit21,
        DW_OP_lit22,
        DW_OP_lit23,
        DW_OP_lit24,
        DW_OP_lit25,
        DW_OP_lit26,
        DW_OP_lit27,
        DW_OP_lit28,
        DW_OP_lit29,
        DW_OP_lit30,
        DW_OP_lit31,
        DW_OP_reg0,
        DW_OP_reg1,
        DW_OP_reg2,
        DW_OP_reg3,
        DW_OP_reg4,
        DW_OP_reg5,
        DW_OP_reg6,
        DW_OP_reg7,
        DW_OP_reg8,
        DW_OP_reg9,
        DW_OP_reg10,
        DW_OP_reg11,
        DW_OP_reg12,
        DW_OP_reg13,
        DW_OP_reg14,
        DW_OP_reg15,
        DW_OP_reg16,
        DW_OP_reg17,
        DW_OP_reg18,
        DW_OP_reg19,
        DW_OP_reg20,
        DW_OP_reg21,
        DW_OP_reg22,
        DW_OP_reg23,
        DW_OP_reg24,
        DW_OP_reg25,
        DW_OP_reg26,
        DW_OP_reg27,
        DW_OP_reg28,
        DW_OP_reg29,
        DW_OP_reg30,
        DW_OP_reg31,
        DW_OP_breg0,
        DW_OP_breg1,
        DW_OP_breg2,
        DW_OP_breg3,
        DW_OP_breg4,
        DW_OP_breg5,
        DW_OP_breg6,
        DW_OP_breg7,
        DW_OP_breg8,
        DW_OP_breg9,
        DW_OP_breg10,
        DW_OP_breg11,
        DW_OP_breg12,
        DW_OP_breg13,
        DW_OP_breg14,
        DW_OP_breg15,
        DW_OP_breg16,
        DW_OP_breg17,
        DW_OP_breg18,
        DW_OP_breg19,
        DW_OP_breg20,
        DW_OP_breg21,
        DW_OP_breg22,
        DW_OP_breg23,
        DW_OP_breg24,
        DW_OP_breg25,
        DW_OP_breg26,
        DW_OP_breg27,
        DW_OP_breg28,
        DW_OP_breg29,
        DW_OP_breg30,
        DW_OP_breg31,
        DW_OP_regx,
        DW_OP_fbreg,
        DW_OP_bregx,
        DW_OP_piece,
        DW_OP_deref_size,
        DW_OP_xderef_size,
        DW_OP_nop,
        DW_OP_push_object_address,
        DW_OP_call2,
        DW_OP_call4,
        DW_OP_call_ref,
        DW_OP_form_tls_address,
        DW_OP_call_frame_cfa,
        DW_OP_bit_piece,
        DW_OP_implicit_value,
        DW_OP_stack_value,
        DW_OP_implicit_pointer,
        DW_OP_addrx,
        DW_OP_constx,
        DW_OP_entry_value,
        DW_OP_const_type,
        DW_OP_regval_type,
        DW_OP_deref_type,
        DW_OP_xderef_type,
        DW_OP_convert,
        DW_OP_reinterpret,
    ]
};

impl DWARFExpressionOpCode {
    /// Mirrors `DWARFExpressionOpCode.getOpCodeValue()`.
    pub fn get_op_code_value(self) -> u8 {
        self as u8
    }

    /// Mirrors `DWARFExpressionOpCode.getOperandTypes()`: the expected operand types that an
    /// instruction would have for this opcode.
    pub fn get_operand_types(self) -> &'static [DWARFExpressionOperandType] {
        use DWARFExpressionOpCode::*;
        use DWARFExpressionOperandType::*;
        match self {
            DW_OP_addr => &[Addr],
            DW_OP_const1u => &[UByte],
            DW_OP_const1s => &[SByte],
            DW_OP_const2u => &[UShort],
            DW_OP_const2s => &[SShort],
            DW_OP_const4u => &[UInt],
            DW_OP_const4s => &[SInt],
            DW_OP_const8u => &[ULong],
            DW_OP_const8s => &[SLong],
            DW_OP_constu => &[ULeb128],
            DW_OP_consts => &[SLeb128],
            DW_OP_pick => &[UByte],
            DW_OP_plus_uconst => &[ULeb128],
            DW_OP_bra => &[SShort],
            DW_OP_skip => &[SShort],
            DW_OP_breg0 | DW_OP_breg1 | DW_OP_breg2 | DW_OP_breg3 | DW_OP_breg4 | DW_OP_breg5
            | DW_OP_breg6 | DW_OP_breg7 | DW_OP_breg8 | DW_OP_breg9 | DW_OP_breg10
            | DW_OP_breg11 | DW_OP_breg12 | DW_OP_breg13 | DW_OP_breg14 | DW_OP_breg15
            | DW_OP_breg16 | DW_OP_breg17 | DW_OP_breg18 | DW_OP_breg19 | DW_OP_breg20
            | DW_OP_breg21 | DW_OP_breg22 | DW_OP_breg23 | DW_OP_breg24 | DW_OP_breg25
            | DW_OP_breg26 | DW_OP_breg27 | DW_OP_breg28 | DW_OP_breg29 | DW_OP_breg30
            | DW_OP_breg31 => &[SLeb128],
            DW_OP_regx => &[ULeb128],
            DW_OP_fbreg => &[SLeb128],
            DW_OP_bregx => &[ULeb128, SLeb128],
            DW_OP_piece => &[ULeb128],
            DW_OP_deref_size => &[UByte],
            DW_OP_xderef_size => &[UByte],
            DW_OP_call2 => &[UShort],
            DW_OP_call4 => &[UInt],
            DW_OP_call_ref => &[DwarfInt],
            DW_OP_bit_piece => &[ULeb128, ULeb128],
            DW_OP_implicit_value => &[ULeb128, SizedBlob],
            DW_OP_implicit_pointer => &[DwarfInt, SLeb128],
            DW_OP_addrx => &[ULeb128],
            DW_OP_constx => &[ULeb128],
            DW_OP_entry_value => &[ULeb128, SizedBlob],
            DW_OP_const_type => &[ULeb128, UByte, SizedBlob],
            DW_OP_regval_type => &[ULeb128, ULeb128],
            DW_OP_deref_type => &[UByte, ULeb128],
            DW_OP_xderef_type => &[UByte, ULeb128],
            DW_OP_convert => &[ULeb128],
            DW_OP_reinterpret => &[ULeb128],
            // Every other opcode (deref, dup/drop/over/swap/rot, the arithmetic/logic/comparison
            // ops, xderef, all `lit*`/`reg*`, nop, push_object_address, form_tls_address,
            // call_frame_cfa, stack_value, and the special DW_OP_unknown_opcode) takes no
            // operands, mirroring the Java constructor overload with no varargs.
            _ => &[],
        }
    }

    /// Mirrors `DWARFExpressionOpCode.isInRange(op, lo, hi)`: true if `op`'s raw value is within
    /// the inclusive `lo..hi` range.
    pub fn is_in_range(op: Self, lo: Self, hi: Self) -> bool {
        lo as u8 <= op as u8 && op as u8 <= hi as u8
    }

    /// Mirrors `DWARFExpressionOpCode.getRelativeOpCodeOffset(baseOp)`: e.g. `DW_OP_reg12`
    /// relative to `DW_OP_reg0` is 12.
    pub fn get_relative_op_code_offset(self, base_op: Self) -> i32 {
        self as i32 - base_op as i32
    }

    /// Mirrors `DWARFExpressionOpCode.toString(DWARFRegisterMappings)`, which appends the mapped
    /// Ghidra register name to the `reg`/`breg` opcodes.
    pub fn to_string_with_reg_mapping(self, reg_mapping: Option<&DWARFRegisterMappings>) -> String {
        use DWARFExpressionOpCode::*;
        let reg_idx = if Self::is_in_range(self, DW_OP_reg0, DW_OP_reg31) {
            self.get_relative_op_code_offset(DW_OP_reg0)
        } else if Self::is_in_range(self, DW_OP_breg0, DW_OP_breg31) {
            self.get_relative_op_code_offset(DW_OP_breg0)
        } else {
            -1
        };
        let reg = if reg_idx >= 0 { reg_mapping.and_then(|rm| rm.ghidra_reg(reg_idx)) } else { None };
        match reg {
            Some(reg) => format!("{self}({})", reg.name()),
            None => self.to_string(),
        }
    }

    /// Mirrors `DWARFExpressionOpCode.parse(int)`: returns the matching enum member, or `None`
    /// (Java `null`) for an unknown opcode.
    ///
    /// `opcode` is the raw numeric value of the opcode (currently defined by DWARF as `uint8`).
    pub fn parse(opcode: i32) -> Option<Self> {
        if !(0..=u8::MAX as i32).contains(&opcode) {
            return None;
        }
        let opcode = opcode as u8;
        // `VALUES` is declared in ascending raw-opcode order (mirroring the Java source's own
        // required ordering, documented on `parse` there), so a binary search matches Java's
        // `Arrays.binarySearch(opcodes, opcode)`.
        VALUES.binary_search_by_key(&opcode, |v| v.get_op_code_value()).ok().map(|i| VALUES[i])
    }
}

impl std::fmt::Display for DWARFExpressionOpCode {
    /// The variant names are spelled exactly as Java's enum constants, so `{:?}` is Java's
    /// `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DWARFExpressionOpCode::*;
    use DWARFExpressionOperandType::*;

    #[test]
    fn get_op_code_value_matches_dwarf_spec_values() {
        assert_eq!(DW_OP_unknown_opcode.get_op_code_value(), 0);
        assert_eq!(DW_OP_addr.get_op_code_value(), 0x3);
        assert_eq!(DW_OP_reg0.get_op_code_value(), 0x50);
        assert_eq!(DW_OP_breg0.get_op_code_value(), 0x70);
        assert_eq!(DW_OP_reinterpret.get_op_code_value(), 0xa9);
    }

    #[test]
    fn values_are_in_ascending_declaration_order() {
        for pair in VALUES.windows(2) {
            assert!(
                pair[0].get_op_code_value() < pair[1].get_op_code_value(),
                "{:?} ({:#x}) must sort before {:?} ({:#x}) for parse()'s binary search to work",
                pair[0],
                pair[0].get_op_code_value(),
                pair[1],
                pair[1].get_op_code_value()
            );
        }
    }

    #[test]
    fn get_operand_types_matches_java_source_tables() {
        assert_eq!(DW_OP_addr.get_operand_types(), &[Addr]);
        assert_eq!(DW_OP_deref.get_operand_types(), &[] as &[DWARFExpressionOperandType]);
        assert_eq!(DW_OP_const1u.get_operand_types(), &[UByte]);
        assert_eq!(DW_OP_const1s.get_operand_types(), &[SByte]);
        assert_eq!(DW_OP_const2u.get_operand_types(), &[UShort]);
        assert_eq!(DW_OP_const2s.get_operand_types(), &[SShort]);
        assert_eq!(DW_OP_const4u.get_operand_types(), &[UInt]);
        assert_eq!(DW_OP_const4s.get_operand_types(), &[SInt]);
        assert_eq!(DW_OP_const8u.get_operand_types(), &[ULong]);
        assert_eq!(DW_OP_const8s.get_operand_types(), &[SLong]);
        assert_eq!(DW_OP_constu.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_consts.get_operand_types(), &[SLeb128]);
        assert_eq!(DW_OP_pick.get_operand_types(), &[UByte]);
        assert_eq!(DW_OP_plus_uconst.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_bra.get_operand_types(), &[SShort]);
        assert_eq!(DW_OP_skip.get_operand_types(), &[SShort]);
        assert_eq!(DW_OP_breg0.get_operand_types(), &[SLeb128]);
        assert_eq!(DW_OP_breg31.get_operand_types(), &[SLeb128]);
        assert_eq!(DW_OP_regx.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_fbreg.get_operand_types(), &[SLeb128]);
        assert_eq!(DW_OP_bregx.get_operand_types(), &[ULeb128, SLeb128]);
        assert_eq!(DW_OP_piece.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_deref_size.get_operand_types(), &[UByte]);
        assert_eq!(DW_OP_xderef_size.get_operand_types(), &[UByte]);
        assert_eq!(DW_OP_call2.get_operand_types(), &[UShort]);
        assert_eq!(DW_OP_call4.get_operand_types(), &[UInt]);
        assert_eq!(DW_OP_call_ref.get_operand_types(), &[DwarfInt]);
        assert_eq!(DW_OP_bit_piece.get_operand_types(), &[ULeb128, ULeb128]);
        assert_eq!(DW_OP_implicit_value.get_operand_types(), &[ULeb128, SizedBlob]);
        assert_eq!(DW_OP_implicit_pointer.get_operand_types(), &[DwarfInt, SLeb128]);
        assert_eq!(DW_OP_addrx.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_constx.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_entry_value.get_operand_types(), &[ULeb128, SizedBlob]);
        assert_eq!(DW_OP_const_type.get_operand_types(), &[ULeb128, UByte, SizedBlob]);
        assert_eq!(DW_OP_regval_type.get_operand_types(), &[ULeb128, ULeb128]);
        assert_eq!(DW_OP_deref_type.get_operand_types(), &[UByte, ULeb128]);
        assert_eq!(DW_OP_xderef_type.get_operand_types(), &[UByte, ULeb128]);
        assert_eq!(DW_OP_convert.get_operand_types(), &[ULeb128]);
        assert_eq!(DW_OP_reinterpret.get_operand_types(), &[ULeb128]);
    }

    #[test]
    fn get_operand_types_is_empty_for_no_operand_opcodes() {
        for op in [
            DW_OP_dup, DW_OP_drop, DW_OP_over, DW_OP_swap, DW_OP_rot, DW_OP_xderef, DW_OP_abs,
            DW_OP_and, DW_OP_div, DW_OP_minus, DW_OP_mod, DW_OP_mul, DW_OP_neg, DW_OP_not,
            DW_OP_or, DW_OP_plus, DW_OP_shl, DW_OP_shr, DW_OP_shra, DW_OP_xor, DW_OP_eq,
            DW_OP_ge, DW_OP_gt, DW_OP_le, DW_OP_lt, DW_OP_ne, DW_OP_lit0, DW_OP_lit31,
            DW_OP_reg0, DW_OP_reg31, DW_OP_nop, DW_OP_push_object_address,
            DW_OP_form_tls_address, DW_OP_call_frame_cfa, DW_OP_stack_value,
            DW_OP_unknown_opcode,
        ] {
            assert!(op.get_operand_types().is_empty(), "{op:?} should have no operand types");
        }
    }

    #[test]
    fn is_in_range_checks_inclusive_bounds() {
        assert!(DWARFExpressionOpCode::is_in_range(DW_OP_reg12, DW_OP_reg0, DW_OP_reg31));
        assert!(DWARFExpressionOpCode::is_in_range(DW_OP_reg0, DW_OP_reg0, DW_OP_reg31));
        assert!(DWARFExpressionOpCode::is_in_range(DW_OP_reg31, DW_OP_reg0, DW_OP_reg31));
        assert!(!DWARFExpressionOpCode::is_in_range(DW_OP_breg0, DW_OP_reg0, DW_OP_reg31));
    }

    #[test]
    fn get_relative_op_code_offset_computes_distance_from_base() {
        assert_eq!(DW_OP_reg12.get_relative_op_code_offset(DW_OP_reg0), 12);
        assert_eq!(DW_OP_breg5.get_relative_op_code_offset(DW_OP_breg0), 5);
        assert_eq!(DW_OP_reg0.get_relative_op_code_offset(DW_OP_reg0), 0);
    }

    #[test]
    fn to_string_with_reg_mapping_falls_back_to_display_without_mapping() {
        assert_eq!(DW_OP_reg3.to_string_with_reg_mapping(None), "DW_OP_reg3");
        assert_eq!(DW_OP_deref.to_string_with_reg_mapping(None), "DW_OP_deref");
    }

    #[test]
    fn display_renders_java_style_constant_name() {
        assert_eq!(DW_OP_addr.to_string(), "DW_OP_addr");
        assert_eq!(format!("{DW_OP_call_frame_cfa}"), "DW_OP_call_frame_cfa");
    }

    #[test]
    fn parse_finds_variant_by_raw_opcode() {
        assert_eq!(DWARFExpressionOpCode::parse(0x3), Some(DW_OP_addr));
        assert_eq!(DWARFExpressionOpCode::parse(0x50), Some(DW_OP_reg0));
        assert_eq!(DWARFExpressionOpCode::parse(0xa9), Some(DW_OP_reinterpret));
        assert_eq!(DWARFExpressionOpCode::parse(0), Some(DW_OP_unknown_opcode));
    }

    #[test]
    fn parse_returns_none_for_unknown_or_out_of_range_opcode() {
        // 0x00 through 0x02 (and 0x04..0x05, and 0xaa..0xff) have no DW_OP_* mapping.
        assert_eq!(DWARFExpressionOpCode::parse(0x4), None);
        assert_eq!(DWARFExpressionOpCode::parse(0xaa), None);
        assert_eq!(DWARFExpressionOpCode::parse(0xff), None);
        assert_eq!(DWARFExpressionOpCode::parse(-1), None);
        assert_eq!(DWARFExpressionOpCode::parse(0x100), None);
    }
}
