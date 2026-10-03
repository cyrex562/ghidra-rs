use std::fmt;

use crate::format::golang::go_ver::GoVer;
use crate::format::golang::go_ver_range::GoVerRange;

/// Enum defining the various bitflags held in a `GoType`'s `tflag`.
///
/// Port of Java `ghidra.app.util.bin.format.golang.rtti.types.GoTypeFlag`. Each flag is only
/// meaningful for the range of Go versions that define it; the same bit (`1 << 4`) means
/// `UnrolledBitmap` in Go 1.22-1.23 and `GCMaskOnDemand` from Go 1.24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoTypeFlag {
    Uncommon,
    ExtraStar,
    Named,
    RegularMemory,
    UnrolledBitmap,
    GCMaskOnDemand,
    DirectIFace,
}

impl GoTypeFlag {
    /// Java `values()`, in declaration order.
    pub const ALL: [GoTypeFlag; 7] = [
        GoTypeFlag::Uncommon,
        GoTypeFlag::ExtraStar,
        GoTypeFlag::Named,
        GoTypeFlag::RegularMemory,
        GoTypeFlag::UnrolledBitmap,
        GoTypeFlag::GCMaskOnDemand,
        GoTypeFlag::DirectIFace,
    ];

    /// Mirrors `GoTypeFlag.getValue()`.
    pub fn value(self) -> i32 {
        match self {
            GoTypeFlag::Uncommon => 1 << 0,
            GoTypeFlag::ExtraStar => 1 << 1,
            GoTypeFlag::Named => 1 << 2,
            GoTypeFlag::RegularMemory => 1 << 3,
            GoTypeFlag::UnrolledBitmap => 1 << 4,
            GoTypeFlag::GCMaskOnDemand => 1 << 4,
            GoTypeFlag::DirectIFace => 1 << 5,
        }
    }

    fn valid_versions(self) -> GoVerRange {
        match self {
            GoTypeFlag::Uncommon
            | GoTypeFlag::ExtraStar
            | GoTypeFlag::Named
            | GoTypeFlag::RegularMemory => GoVerRange::ALL,
            GoTypeFlag::UnrolledBitmap => GoVerRange::parse("1.22-1.23"),
            GoTypeFlag::GCMaskOnDemand | GoTypeFlag::DirectIFace => GoVerRange::parse("1.24-"),
        }
    }

    /// Mirrors `GoTypeFlag.isSet(int, GoVer)`.
    pub fn is_set(self, i: i32, ver: GoVer) -> bool {
        self.valid_versions().contains(ver) && (i & self.value()) != 0
    }

    /// Mirrors `GoTypeFlag.isValid(int, GoVer)`.
    pub fn is_valid(b: i32, ver: GoVer) -> bool {
        let mut remaining = b;
        for flag in Self::ALL {
            if flag.valid_versions().contains(ver) {
                remaining &= !flag.value();
            }
        }
        remaining == 0
    }

    /// Mirrors `GoTypeFlag.parseFlags(int, GoVer)`.
    pub fn parse_flags(b: i32, ver: GoVer) -> Vec<GoTypeFlag> {
        Self::ALL.into_iter().filter(|flag| flag.is_set(b, ver)).collect()
    }
}

/// Java `Enum.toString()`: the constant's name.
impl fmt::Display for GoTypeFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ver(minor: i32) -> GoVer {
        GoVer::new(1, minor, 0)
    }

    #[test]
    fn values_match_java() {
        let values: Vec<i32> = GoTypeFlag::ALL.iter().map(|f| f.value()).collect();
        assert_eq!(values, [1, 2, 4, 8, 16, 16, 32]);
        assert_eq!(GoTypeFlag::GCMaskOnDemand.to_string(), "GCMaskOnDemand");
    }

    #[test]
    fn is_set_requires_the_bit_and_a_valid_version() {
        assert!(GoTypeFlag::Uncommon.is_set(0b1, ver(10)));
        assert!(!GoTypeFlag::Uncommon.is_set(0b10, ver(10)));
        // bit 4 is UnrolledBitmap only in 1.22-1.23, GCMaskOnDemand from 1.24
        assert!(!GoTypeFlag::UnrolledBitmap.is_set(16, ver(21)));
        assert!(GoTypeFlag::UnrolledBitmap.is_set(16, ver(22)));
        assert!(GoTypeFlag::UnrolledBitmap.is_set(16, ver(23)));
        assert!(!GoTypeFlag::UnrolledBitmap.is_set(16, ver(24)));
        assert!(!GoTypeFlag::GCMaskOnDemand.is_set(16, ver(23)));
        assert!(GoTypeFlag::GCMaskOnDemand.is_set(16, ver(24)));
        assert!(GoTypeFlag::DirectIFace.is_set(32, ver(25)));
    }

    #[test]
    fn is_valid_rejects_bits_undefined_for_the_version() {
        assert!(GoTypeFlag::is_valid(0b1111, ver(18)));
        assert!(!GoTypeFlag::is_valid(16, ver(18)));
        assert!(GoTypeFlag::is_valid(16, ver(22)));
        assert!(!GoTypeFlag::is_valid(32, ver(23)));
        assert!(GoTypeFlag::is_valid(63, ver(24)));
        assert!(!GoTypeFlag::is_valid(64, ver(24)));
    }

    #[test]
    fn parse_flags_lists_set_flags_in_declaration_order() {
        assert_eq!(GoTypeFlag::parse_flags(0b101, ver(21)), [GoTypeFlag::Uncommon, GoTypeFlag::Named]);
        assert_eq!(
            GoTypeFlag::parse_flags(16 | 32 | 2, ver(24)),
            [GoTypeFlag::ExtraStar, GoTypeFlag::GCMaskOnDemand, GoTypeFlag::DirectIFace]
        );
        assert!(GoTypeFlag::parse_flags(0, ver(24)).is_empty());
    }
}
