/// pcode opcodes associated with their opcode number.
///
/// Some names are replaced with placeholder ops for the sleigh compiler and interpreter:
/// `CpuiMultiequal` = BUILD, `CpuiIndirect` = DELAY_SLOT, `CpuiPtradd` = LABEL,
/// `CpuiPtrsub` = CROSSBUILD.
///
/// Corresponds to `ghidra.pcodeCPort.opcodes.OpCode`.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    DoNotUseMeIAmEnumElementZero = 0,
    CpuiCopy,
    CpuiLoad,
    CpuiStore,
    CpuiBranch,
    CpuiCbranch,
    CpuiBranchind,
    CpuiCall,
    CpuiCallind,
    CpuiCallother,
    CpuiReturn,
    CpuiIntEqual,
    CpuiIntNotequal,
    CpuiIntSless,
    CpuiIntSlessequal,
    CpuiIntLess,
    CpuiIntLessequal,
    CpuiIntZext,
    CpuiIntSext,
    CpuiIntAdd,
    CpuiIntSub,
    CpuiIntCarry,
    CpuiIntScarry,
    CpuiIntSborrow,
    CpuiInt2comp,
    CpuiIntNegate,
    CpuiIntXor,
    CpuiIntAnd,
    CpuiIntOr,
    CpuiIntLeft,
    CpuiIntRight,
    CpuiIntSright,
    CpuiIntMult,
    CpuiIntDiv,
    CpuiIntSdiv,
    CpuiIntRem,
    CpuiIntSrem,
    CpuiBoolNegate,
    CpuiBoolXor,
    CpuiBoolAnd,
    CpuiBoolOr,
    CpuiFloatEqual,
    CpuiFloatNotequal,
    CpuiFloatLess,
    CpuiFloatLessequal,
    CpuiUnused1,
    CpuiFloatNan,
    CpuiFloatAdd,
    CpuiFloatDiv,
    CpuiFloatMult,
    CpuiFloatSub,
    CpuiFloatNeg,
    CpuiFloatAbs,
    CpuiFloatSqrt,
    CpuiFloatInt2float,
    CpuiFloatFloat2float,
    CpuiFloatTrunc,
    CpuiFloatCeil,
    CpuiFloatFloor,
    CpuiFloatRound,
    CpuiMultiequal,
    CpuiIndirect,
    CpuiPiece,
    CpuiSubpiece,
    CpuiCast,
    CpuiPtradd,
    CpuiPtrsub,
    CpuiSegmentop,
    CpuiCpoolref,
    CpuiNew,
    CpuiInsert,
    CpuiZpull,
    CpuiPopcount,
    CpuiLzcount,
    CpuiSpull,
    CpuiMax,
}

const ALL_OPCODES: &[OpCode] = &[
    OpCode::DoNotUseMeIAmEnumElementZero,
    OpCode::CpuiCopy,
    OpCode::CpuiLoad,
    OpCode::CpuiStore,
    OpCode::CpuiBranch,
    OpCode::CpuiCbranch,
    OpCode::CpuiBranchind,
    OpCode::CpuiCall,
    OpCode::CpuiCallind,
    OpCode::CpuiCallother,
    OpCode::CpuiReturn,
    OpCode::CpuiIntEqual,
    OpCode::CpuiIntNotequal,
    OpCode::CpuiIntSless,
    OpCode::CpuiIntSlessequal,
    OpCode::CpuiIntLess,
    OpCode::CpuiIntLessequal,
    OpCode::CpuiIntZext,
    OpCode::CpuiIntSext,
    OpCode::CpuiIntAdd,
    OpCode::CpuiIntSub,
    OpCode::CpuiIntCarry,
    OpCode::CpuiIntScarry,
    OpCode::CpuiIntSborrow,
    OpCode::CpuiInt2comp,
    OpCode::CpuiIntNegate,
    OpCode::CpuiIntXor,
    OpCode::CpuiIntAnd,
    OpCode::CpuiIntOr,
    OpCode::CpuiIntLeft,
    OpCode::CpuiIntRight,
    OpCode::CpuiIntSright,
    OpCode::CpuiIntMult,
    OpCode::CpuiIntDiv,
    OpCode::CpuiIntSdiv,
    OpCode::CpuiIntRem,
    OpCode::CpuiIntSrem,
    OpCode::CpuiBoolNegate,
    OpCode::CpuiBoolXor,
    OpCode::CpuiBoolAnd,
    OpCode::CpuiBoolOr,
    OpCode::CpuiFloatEqual,
    OpCode::CpuiFloatNotequal,
    OpCode::CpuiFloatLess,
    OpCode::CpuiFloatLessequal,
    OpCode::CpuiUnused1,
    OpCode::CpuiFloatNan,
    OpCode::CpuiFloatAdd,
    OpCode::CpuiFloatDiv,
    OpCode::CpuiFloatMult,
    OpCode::CpuiFloatSub,
    OpCode::CpuiFloatNeg,
    OpCode::CpuiFloatAbs,
    OpCode::CpuiFloatSqrt,
    OpCode::CpuiFloatInt2float,
    OpCode::CpuiFloatFloat2float,
    OpCode::CpuiFloatTrunc,
    OpCode::CpuiFloatCeil,
    OpCode::CpuiFloatFloor,
    OpCode::CpuiFloatRound,
    OpCode::CpuiMultiequal,
    OpCode::CpuiIndirect,
    OpCode::CpuiPiece,
    OpCode::CpuiSubpiece,
    OpCode::CpuiCast,
    OpCode::CpuiPtradd,
    OpCode::CpuiPtrsub,
    OpCode::CpuiSegmentop,
    OpCode::CpuiCpoolref,
    OpCode::CpuiNew,
    OpCode::CpuiInsert,
    OpCode::CpuiZpull,
    OpCode::CpuiPopcount,
    OpCode::CpuiLzcount,
    OpCode::CpuiSpull,
    OpCode::CpuiMax,
];

impl OpCode {
    /// Returns the name string associated with this opcode, or `None` for `CpuiMax`.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Self::DoNotUseMeIAmEnumElementZero => Some("BLANK"),
            Self::CpuiCopy => Some("COPY"),
            Self::CpuiLoad => Some("LOAD"),
            Self::CpuiStore => Some("STORE"),
            Self::CpuiBranch => Some("BRANCH"),
            Self::CpuiCbranch => Some("CBRANCH"),
            Self::CpuiBranchind => Some("BRANCHIND"),
            Self::CpuiCall => Some("CALL"),
            Self::CpuiCallind => Some("CALLIND"),
            Self::CpuiCallother => Some("CALLOTHER"),
            Self::CpuiReturn => Some("RETURN"),
            Self::CpuiIntEqual => Some("INT_EQUAL"),
            Self::CpuiIntNotequal => Some("INT_NOTEQUAL"),
            Self::CpuiIntSless => Some("INT_SLESS"),
            Self::CpuiIntSlessequal => Some("INT_SLESSEQUAL"),
            Self::CpuiIntLess => Some("INT_LESS"),
            Self::CpuiIntLessequal => Some("INT_LESSEQUAL"),
            Self::CpuiIntZext => Some("INT_ZEXT"),
            Self::CpuiIntSext => Some("INT_SEXT"),
            Self::CpuiIntAdd => Some("INT_ADD"),
            Self::CpuiIntSub => Some("INT_SUB"),
            Self::CpuiIntCarry => Some("INT_CARRY"),
            Self::CpuiIntScarry => Some("INT_SCARRY"),
            Self::CpuiIntSborrow => Some("INT_SBORROW"),
            Self::CpuiInt2comp => Some("INT_2COMP"),
            Self::CpuiIntNegate => Some("INT_NEGATE"),
            Self::CpuiIntXor => Some("INT_XOR"),
            Self::CpuiIntAnd => Some("INT_AND"),
            Self::CpuiIntOr => Some("INT_OR"),
            Self::CpuiIntLeft => Some("INT_LEFT"),
            Self::CpuiIntRight => Some("INT_RIGHT"),
            Self::CpuiIntSright => Some("INT_SRIGHT"),
            Self::CpuiIntMult => Some("INT_MULT"),
            Self::CpuiIntDiv => Some("INT_DIV"),
            Self::CpuiIntSdiv => Some("INT_SDIV"),
            Self::CpuiIntRem => Some("INT_REM"),
            Self::CpuiIntSrem => Some("INT_SREM"),
            Self::CpuiBoolNegate => Some("BOOL_NEGATE"),
            Self::CpuiBoolXor => Some("BOOL_XOR"),
            Self::CpuiBoolAnd => Some("BOOL_AND"),
            Self::CpuiBoolOr => Some("BOOL_OR"),
            Self::CpuiFloatEqual => Some("FLOAT_EQUAL"),
            Self::CpuiFloatNotequal => Some("FLOAT_NOTEQUAL"),
            Self::CpuiFloatLess => Some("FLOAT_LESS"),
            Self::CpuiFloatLessequal => Some("FLOAT_LESSEQUAL"),
            Self::CpuiUnused1 => Some("UNUSED1"),
            Self::CpuiFloatNan => Some("FLOAT_NAN"),
            Self::CpuiFloatAdd => Some("FLOAT_ADD"),
            Self::CpuiFloatDiv => Some("FLOAT_DIV"),
            Self::CpuiFloatMult => Some("FLOAT_MULT"),
            Self::CpuiFloatSub => Some("FLOAT_SUB"),
            Self::CpuiFloatNeg => Some("FLOAT_NEG"),
            Self::CpuiFloatAbs => Some("FLOAT_ABS"),
            Self::CpuiFloatSqrt => Some("FLOAT_SQRT"),
            Self::CpuiFloatInt2float => Some("INT2FLOAT"),
            Self::CpuiFloatFloat2float => Some("FLOAT2FLOAT"),
            Self::CpuiFloatTrunc => Some("TRUNC"),
            Self::CpuiFloatCeil => Some("CEIL"),
            Self::CpuiFloatFloor => Some("FLOOR"),
            Self::CpuiFloatRound => Some("ROUND"),
            Self::CpuiMultiequal => Some("BUILD"),
            Self::CpuiIndirect => Some("DELAY_SLOT"),
            Self::CpuiPiece => Some("PIECE"),
            Self::CpuiSubpiece => Some("SUBPIECE"),
            Self::CpuiCast => Some("CAST"),
            Self::CpuiPtradd => Some("LABEL"),
            Self::CpuiPtrsub => Some("CROSSBUILD"),
            Self::CpuiSegmentop => Some("SEGMENTOP"),
            Self::CpuiCpoolref => Some("CPOOLREF"),
            Self::CpuiNew => Some("NEW"),
            Self::CpuiInsert => Some("INSERT"),
            Self::CpuiZpull => Some("ZPULL"),
            Self::CpuiPopcount => Some("POPCOUNT"),
            Self::CpuiLzcount => Some("LZCOUNT"),
            Self::CpuiSpull => Some("SPULL"),
            Self::CpuiMax => None,
        }
    }

    /// Returns the declaration-order index (0-based) of this opcode.
    pub fn ordinal(&self) -> usize {
        *self as usize
    }

    /// Returns the complementary opcode for comparison operations, or `CpuiMax` if not applicable.
    ///
    /// Corresponds to `OpCode.getOpCodeFlip()`.
    pub fn op_code_flip(&self) -> OpCode {
        match self {
            Self::CpuiIntEqual => Self::CpuiIntNotequal,
            Self::CpuiIntNotequal => Self::CpuiIntEqual,
            Self::CpuiIntSless => Self::CpuiIntSlessequal,
            Self::CpuiIntSlessequal => Self::CpuiIntSless,
            Self::CpuiIntLess => Self::CpuiIntLessequal,
            Self::CpuiIntLessequal => Self::CpuiIntLess,
            Self::CpuiBoolNegate => Self::CpuiCopy,
            Self::CpuiFloatEqual => Self::CpuiFloatNotequal,
            Self::CpuiFloatNotequal => Self::CpuiFloatEqual,
            Self::CpuiFloatLess => Self::CpuiFloatLessequal,
            Self::CpuiFloatLessequal => Self::CpuiFloatLess,
            _ => Self::CpuiMax,
        }
    }

    /// Returns `true` if the complementary operation would reorder the input parameters.
    ///
    /// Corresponds to `OpCode.getBooleanFlip()`.
    pub fn get_boolean_flip(&self) -> bool {
        match self {
            Self::CpuiIntSless
            | Self::CpuiIntSlessequal
            | Self::CpuiIntLess
            | Self::CpuiIntLessequal
            | Self::CpuiFloatLess
            | Self::CpuiFloatLessequal => true,
            _ => false,
        }
    }

    /// Returns the opcode at the given ordinal, or `None` if out of range.
    ///
    /// Corresponds to `OpCode.getOpcode(int)`.
    pub fn from_ordinal(ordinal: usize) -> Option<Self> {
        ALL_OPCODES.get(ordinal).copied()
    }

    /// Returns the opcode with the given name, or `None` if not found.
    ///
    /// "BLANK" (ordinal 0) and `CpuiMax` (no name) are excluded, matching the Java map.
    /// Corresponds to `OpCode.getOpcode(String)`.
    pub fn from_name(nm: &str) -> Option<Self> {
        match nm {
            "COPY" => Some(Self::CpuiCopy),
            "LOAD" => Some(Self::CpuiLoad),
            "STORE" => Some(Self::CpuiStore),
            "BRANCH" => Some(Self::CpuiBranch),
            "CBRANCH" => Some(Self::CpuiCbranch),
            "BRANCHIND" => Some(Self::CpuiBranchind),
            "CALL" => Some(Self::CpuiCall),
            "CALLIND" => Some(Self::CpuiCallind),
            "CALLOTHER" => Some(Self::CpuiCallother),
            "RETURN" => Some(Self::CpuiReturn),
            "INT_EQUAL" => Some(Self::CpuiIntEqual),
            "INT_NOTEQUAL" => Some(Self::CpuiIntNotequal),
            "INT_SLESS" => Some(Self::CpuiIntSless),
            "INT_SLESSEQUAL" => Some(Self::CpuiIntSlessequal),
            "INT_LESS" => Some(Self::CpuiIntLess),
            "INT_LESSEQUAL" => Some(Self::CpuiIntLessequal),
            "INT_ZEXT" => Some(Self::CpuiIntZext),
            "INT_SEXT" => Some(Self::CpuiIntSext),
            "INT_ADD" => Some(Self::CpuiIntAdd),
            "INT_SUB" => Some(Self::CpuiIntSub),
            "INT_CARRY" => Some(Self::CpuiIntCarry),
            "INT_SCARRY" => Some(Self::CpuiIntScarry),
            "INT_SBORROW" => Some(Self::CpuiIntSborrow),
            "INT_2COMP" => Some(Self::CpuiInt2comp),
            "INT_NEGATE" => Some(Self::CpuiIntNegate),
            "INT_XOR" => Some(Self::CpuiIntXor),
            "INT_AND" => Some(Self::CpuiIntAnd),
            "INT_OR" => Some(Self::CpuiIntOr),
            "INT_LEFT" => Some(Self::CpuiIntLeft),
            "INT_RIGHT" => Some(Self::CpuiIntRight),
            "INT_SRIGHT" => Some(Self::CpuiIntSright),
            "INT_MULT" => Some(Self::CpuiIntMult),
            "INT_DIV" => Some(Self::CpuiIntDiv),
            "INT_SDIV" => Some(Self::CpuiIntSdiv),
            "INT_REM" => Some(Self::CpuiIntRem),
            "INT_SREM" => Some(Self::CpuiIntSrem),
            "BOOL_NEGATE" => Some(Self::CpuiBoolNegate),
            "BOOL_XOR" => Some(Self::CpuiBoolXor),
            "BOOL_AND" => Some(Self::CpuiBoolAnd),
            "BOOL_OR" => Some(Self::CpuiBoolOr),
            "FLOAT_EQUAL" => Some(Self::CpuiFloatEqual),
            "FLOAT_NOTEQUAL" => Some(Self::CpuiFloatNotequal),
            "FLOAT_LESS" => Some(Self::CpuiFloatLess),
            "FLOAT_LESSEQUAL" => Some(Self::CpuiFloatLessequal),
            "UNUSED1" => Some(Self::CpuiUnused1),
            "FLOAT_NAN" => Some(Self::CpuiFloatNan),
            "FLOAT_ADD" => Some(Self::CpuiFloatAdd),
            "FLOAT_DIV" => Some(Self::CpuiFloatDiv),
            "FLOAT_MULT" => Some(Self::CpuiFloatMult),
            "FLOAT_SUB" => Some(Self::CpuiFloatSub),
            "FLOAT_NEG" => Some(Self::CpuiFloatNeg),
            "FLOAT_ABS" => Some(Self::CpuiFloatAbs),
            "FLOAT_SQRT" => Some(Self::CpuiFloatSqrt),
            "INT2FLOAT" => Some(Self::CpuiFloatInt2float),
            "FLOAT2FLOAT" => Some(Self::CpuiFloatFloat2float),
            "TRUNC" => Some(Self::CpuiFloatTrunc),
            "CEIL" => Some(Self::CpuiFloatCeil),
            "FLOOR" => Some(Self::CpuiFloatFloor),
            "ROUND" => Some(Self::CpuiFloatRound),
            "BUILD" => Some(Self::CpuiMultiequal),
            "DELAY_SLOT" => Some(Self::CpuiIndirect),
            "PIECE" => Some(Self::CpuiPiece),
            "SUBPIECE" => Some(Self::CpuiSubpiece),
            "CAST" => Some(Self::CpuiCast),
            "LABEL" => Some(Self::CpuiPtradd),
            "CROSSBUILD" => Some(Self::CpuiPtrsub),
            "SEGMENTOP" => Some(Self::CpuiSegmentop),
            "CPOOLREF" => Some(Self::CpuiCpoolref),
            "NEW" => Some(Self::CpuiNew),
            "INSERT" => Some(Self::CpuiInsert),
            "ZPULL" => Some(Self::CpuiZpull),
            "POPCOUNT" => Some(Self::CpuiPopcount),
            "LZCOUNT" => Some(Self::CpuiLzcount),
            "SPULL" => Some(Self::CpuiSpull),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_zero_is_do_not_use() {
        assert_eq!(OpCode::DoNotUseMeIAmEnumElementZero.ordinal(), 0);
    }

    #[test]
    fn ordinal_copy_is_one() {
        assert_eq!(OpCode::CpuiCopy.ordinal(), 1);
    }

    #[test]
    fn ordinal_max_is_last() {
        assert_eq!(OpCode::CpuiMax.ordinal(), 75);
    }

    #[test]
    fn from_ordinal_zero() {
        assert_eq!(
            OpCode::from_ordinal(0),
            Some(OpCode::DoNotUseMeIAmEnumElementZero)
        );
    }

    #[test]
    fn from_ordinal_one() {
        assert_eq!(OpCode::from_ordinal(1), Some(OpCode::CpuiCopy));
    }

    #[test]
    fn from_ordinal_max() {
        assert_eq!(OpCode::from_ordinal(75), Some(OpCode::CpuiMax));
    }

    #[test]
    fn from_ordinal_out_of_range() {
        assert_eq!(OpCode::from_ordinal(76), None);
    }

    #[test]
    fn from_ordinal_roundtrip_all() {
        for (i, &op) in ALL_OPCODES.iter().enumerate() {
            assert_eq!(OpCode::from_ordinal(i), Some(op));
            assert_eq!(op.ordinal(), i);
        }
    }

    #[test]
    fn name_copy() {
        assert_eq!(OpCode::CpuiCopy.name(), Some("COPY"));
    }

    #[test]
    fn name_do_not_use_is_blank() {
        assert_eq!(
            OpCode::DoNotUseMeIAmEnumElementZero.name(),
            Some("BLANK")
        );
    }

    #[test]
    fn name_max_is_none() {
        assert_eq!(OpCode::CpuiMax.name(), None);
    }

    #[test]
    fn name_multiequal_is_build() {
        assert_eq!(OpCode::CpuiMultiequal.name(), Some("BUILD"));
    }

    #[test]
    fn name_indirect_is_delay_slot() {
        assert_eq!(OpCode::CpuiIndirect.name(), Some("DELAY_SLOT"));
    }

    #[test]
    fn name_ptradd_is_label() {
        assert_eq!(OpCode::CpuiPtradd.name(), Some("LABEL"));
    }

    #[test]
    fn name_ptrsub_is_crossbuild() {
        assert_eq!(OpCode::CpuiPtrsub.name(), Some("CROSSBUILD"));
    }

    #[test]
    fn from_name_copy() {
        assert_eq!(OpCode::from_name("COPY"), Some(OpCode::CpuiCopy));
    }

    #[test]
    fn from_name_blank_is_excluded() {
        assert_eq!(OpCode::from_name("BLANK"), None);
    }

    #[test]
    fn from_name_unknown() {
        assert_eq!(OpCode::from_name("BOGUS"), None);
    }

    #[test]
    fn from_name_build_maps_to_multiequal() {
        assert_eq!(OpCode::from_name("BUILD"), Some(OpCode::CpuiMultiequal));
    }

    #[test]
    fn from_name_roundtrip_all_named() {
        for &op in ALL_OPCODES {
            if op == OpCode::DoNotUseMeIAmEnumElementZero || op == OpCode::CpuiMax {
                continue;
            }
            let nm = op.name().expect("named op must have a name");
            assert_eq!(OpCode::from_name(nm), Some(op), "roundtrip failed for {nm}");
        }
    }

    #[test]
    fn op_code_flip_equal_notequal() {
        assert_eq!(
            OpCode::CpuiIntEqual.op_code_flip(),
            OpCode::CpuiIntNotequal
        );
        assert_eq!(
            OpCode::CpuiIntNotequal.op_code_flip(),
            OpCode::CpuiIntEqual
        );
    }

    #[test]
    fn op_code_flip_sless_slessequal() {
        assert_eq!(
            OpCode::CpuiIntSless.op_code_flip(),
            OpCode::CpuiIntSlessequal
        );
        assert_eq!(
            OpCode::CpuiIntSlessequal.op_code_flip(),
            OpCode::CpuiIntSless
        );
    }

    #[test]
    fn op_code_flip_bool_negate_is_copy() {
        assert_eq!(OpCode::CpuiBoolNegate.op_code_flip(), OpCode::CpuiCopy);
    }

    #[test]
    fn op_code_flip_float_less_lessequal() {
        assert_eq!(
            OpCode::CpuiFloatLess.op_code_flip(),
            OpCode::CpuiFloatLessequal
        );
        assert_eq!(
            OpCode::CpuiFloatLessequal.op_code_flip(),
            OpCode::CpuiFloatLess
        );
    }

    #[test]
    fn op_code_flip_default_is_max() {
        assert_eq!(OpCode::CpuiCopy.op_code_flip(), OpCode::CpuiMax);
        assert_eq!(OpCode::CpuiIntAdd.op_code_flip(), OpCode::CpuiMax);
    }

    #[test]
    fn get_boolean_flip_false_for_equal() {
        assert!(!OpCode::CpuiIntEqual.get_boolean_flip());
        assert!(!OpCode::CpuiIntNotequal.get_boolean_flip());
        assert!(!OpCode::CpuiFloatEqual.get_boolean_flip());
        assert!(!OpCode::CpuiFloatNotequal.get_boolean_flip());
        assert!(!OpCode::CpuiBoolNegate.get_boolean_flip());
    }

    #[test]
    fn get_boolean_flip_true_for_less() {
        assert!(OpCode::CpuiIntSless.get_boolean_flip());
        assert!(OpCode::CpuiIntSlessequal.get_boolean_flip());
        assert!(OpCode::CpuiIntLess.get_boolean_flip());
        assert!(OpCode::CpuiIntLessequal.get_boolean_flip());
        assert!(OpCode::CpuiFloatLess.get_boolean_flip());
        assert!(OpCode::CpuiFloatLessequal.get_boolean_flip());
    }

    #[test]
    fn get_boolean_flip_false_for_non_boolean() {
        assert!(!OpCode::CpuiIntAdd.get_boolean_flip());
        assert!(!OpCode::CpuiMax.get_boolean_flip());
    }
}
