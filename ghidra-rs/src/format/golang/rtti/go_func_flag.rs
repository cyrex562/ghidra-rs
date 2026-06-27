/// Bitmask flags for the `flags` field of a Go runtime `_func` (`GoFuncData`).
///
/// Mirrors Ghidra's `GoFuncFlag` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoFuncFlag {
    /// Function is a top-level frame (TOPFRAME, bit 0).
    TopFrame,
    /// Function writes to SP and cannot be unwound by the runtime (SPWRITE, bit 1).
    SpWrite,
    /// Function is written in assembly (ASM, bit 2).
    Asm,
}

impl GoFuncFlag {
    /// Returns the bitmask value for this flag.
    pub fn value(self) -> u32 {
        match self {
            Self::TopFrame => 1 << 0,
            Self::SpWrite  => 1 << 1,
            Self::Asm      => 1 << 2,
        }
    }

    /// Returns `true` if this flag's bit is set in `bits`.
    pub fn is_set(self, bits: u32) -> bool {
        (bits & self.value()) != 0
    }

    /// Returns all flags whose bits are set in `bits`, in declaration order.
    pub fn parse_flags(bits: u32) -> Vec<Self> {
        [Self::TopFrame, Self::SpWrite, Self::Asm]
            .into_iter()
            .filter(|f| f.is_set(bits))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::GoFuncFlag;

    #[test]
    fn values_match_java() {
        assert_eq!(GoFuncFlag::TopFrame.value(), 1);
        assert_eq!(GoFuncFlag::SpWrite.value(), 2);
        assert_eq!(GoFuncFlag::Asm.value(), 4);
    }

    #[test]
    fn is_set_true_when_bit_present() {
        assert!(GoFuncFlag::TopFrame.is_set(0b111));
        assert!(GoFuncFlag::SpWrite.is_set(0b110));
        assert!(GoFuncFlag::Asm.is_set(0b100));
    }

    #[test]
    fn is_set_false_when_bit_absent() {
        assert!(!GoFuncFlag::TopFrame.is_set(0b110));
        assert!(!GoFuncFlag::SpWrite.is_set(0b101));
        assert!(!GoFuncFlag::Asm.is_set(0b011));
    }

    #[test]
    fn parse_flags_zero_returns_empty() {
        assert!(GoFuncFlag::parse_flags(0).is_empty());
    }

    #[test]
    fn parse_flags_all_bits_returns_all_variants() {
        let flags = GoFuncFlag::parse_flags(0b111);
        assert_eq!(flags.len(), 3);
        assert!(flags.contains(&GoFuncFlag::TopFrame));
        assert!(flags.contains(&GoFuncFlag::SpWrite));
        assert!(flags.contains(&GoFuncFlag::Asm));
    }

    #[test]
    fn parse_flags_single_bit() {
        let flags = GoFuncFlag::parse_flags(0b010);
        assert_eq!(flags, vec![GoFuncFlag::SpWrite]);
    }

    #[test]
    fn parse_flags_ignores_unknown_bits() {
        // Bit 3 and above are unknown; only known flags should be returned.
        let flags = GoFuncFlag::parse_flags(0b1111_1000);
        assert!(flags.is_empty());
    }

    #[test]
    fn parse_flags_declaration_order() {
        let flags = GoFuncFlag::parse_flags(0b111);
        assert_eq!(flags[0], GoFuncFlag::TopFrame);
        assert_eq!(flags[1], GoFuncFlag::SpWrite);
        assert_eq!(flags[2], GoFuncFlag::Asm);
    }
}
