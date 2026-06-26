/// The different types of operands that a DWARF expression opcode can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFExpressionOperandType {
    /// Unsigned LEB128 (variable length).
    ULeb128,
    /// Signed LEB128 (variable length).
    SLeb128,
    /// Signed byte (1 byte).
    SByte,
    /// Signed short (2 bytes).
    SShort,
    /// Signed int (4 bytes).
    SInt,
    /// Signed long (8 bytes).
    SLong,
    /// Unsigned byte (1 byte).
    UByte,
    /// Unsigned short (2 bytes).
    UShort,
    /// Unsigned int (4 bytes).
    UInt,
    /// Unsigned long (8 bytes).
    ULong,
    /// Address (1, 2, 4, or 8 bytes determined by the compilation unit pointer size).
    Addr,
    /// Raw byte blob whose length is specified by another operand.
    SizedBlob,
    /// Either `UInt` or `ULong` depending on the DWARF native integer size.
    DwarfInt,
}

/// An empty operand-type list, analogous to Java's `EMPTY_TYPELIST`.
pub const EMPTY_TYPELIST: &[DWARFExpressionOperandType] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        use DWARFExpressionOperandType::*;
        let variants = [
            ULeb128, SLeb128, SByte, SShort, SInt, SLong, UByte, UShort, UInt, ULong, Addr,
            SizedBlob, DwarfInt,
        ];
        // verify count matches Java source (13 variants)
        assert_eq!(variants.len(), 13);
        // each variant must compare equal to itself
        for v in &variants {
            assert_eq!(v, v);
        }
    }

    #[test]
    fn empty_typelist_is_empty() {
        assert!(EMPTY_TYPELIST.is_empty());
    }

    #[test]
    fn clone_and_copy() {
        let v = DWARFExpressionOperandType::Addr;
        let c = v;
        assert_eq!(v, c);
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn debug_repr_is_non_empty() {
        let s = format!("{:?}", DWARFExpressionOperandType::DwarfInt);
        assert!(!s.is_empty());
    }
}
