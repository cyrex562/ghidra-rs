/// CHPE range types, mirroring `ghidra.app.util.bin.format.pe.chpe.ChpeRangeType`.
///
/// The `UNKNOWN` variant (value `0x100`) is synthetic — it captures any value
/// that does not correspond to a known type, exactly as the Java source does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChpeRangeType {
    Arm64,
    Arm64Ec,
    X86_64,
    Unknown,
}

impl ChpeRangeType {
    /// Returns the numeric value associated with this range type.
    pub fn value(self) -> u32 {
        match self {
            ChpeRangeType::Arm64 => 0x0,
            ChpeRangeType::Arm64Ec => 0x1,
            ChpeRangeType::X86_64 => 0x2,
            ChpeRangeType::Unknown => 0x100,
        }
    }

    /// Returns the [`ChpeRangeType`] for the given numeric value.
    ///
    /// Returns [`ChpeRangeType::Unknown`] when the value does not correspond to
    /// a known type, mirroring the Java `type(int)` fallback behaviour.
    pub fn from_value(value: u32) -> ChpeRangeType {
        match value {
            0x0 => ChpeRangeType::Arm64,
            0x1 => ChpeRangeType::Arm64Ec,
            0x2 => ChpeRangeType::X86_64,
            _ => ChpeRangeType::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_round_trip() {
        for &rt in &[
            ChpeRangeType::Arm64,
            ChpeRangeType::Arm64Ec,
            ChpeRangeType::X86_64,
        ] {
            assert_eq!(ChpeRangeType::from_value(rt.value()), rt);
        }
    }

    #[test]
    fn unknown_value_constant() {
        assert_eq!(ChpeRangeType::Unknown.value(), 0x100);
    }

    #[test]
    fn unknown_returned_for_unrecognised_value() {
        assert_eq!(ChpeRangeType::from_value(0x3), ChpeRangeType::Unknown);
        assert_eq!(ChpeRangeType::from_value(0xFF), ChpeRangeType::Unknown);
        assert_eq!(ChpeRangeType::from_value(0x100), ChpeRangeType::Unknown);
    }

    #[test]
    fn spot_check_values() {
        assert_eq!(ChpeRangeType::Arm64.value(), 0x0);
        assert_eq!(ChpeRangeType::Arm64Ec.value(), 0x1);
        assert_eq!(ChpeRangeType::X86_64.value(), 0x2);
    }
}
