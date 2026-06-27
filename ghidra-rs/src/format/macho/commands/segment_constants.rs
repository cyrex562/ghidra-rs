/// Read protection flag.
pub const PROTECTION_R: u32 = 0x1;
/// Write protection flag.
pub const PROTECTION_W: u32 = 0x2;
/// Execute protection flag.
pub const PROTECTION_X: u32 = 0x4;

/// If this flag bit is set, the segment contains Apple protection.
pub const FLAG_APPLE_PROTECTED: u32 = 0x8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_flags_are_distinct_bits() {
        assert_eq!(PROTECTION_R & PROTECTION_W, 0);
        assert_eq!(PROTECTION_R & PROTECTION_X, 0);
        assert_eq!(PROTECTION_W & PROTECTION_X, 0);
    }

    #[test]
    fn flag_apple_protected_does_not_overlap_protection_bits() {
        assert_eq!(FLAG_APPLE_PROTECTED & PROTECTION_R, 0);
        assert_eq!(FLAG_APPLE_PROTECTED & PROTECTION_W, 0);
        assert_eq!(FLAG_APPLE_PROTECTED & PROTECTION_X, 0);
    }

    #[test]
    fn protection_flag_values() {
        assert_eq!(PROTECTION_R, 0x1);
        assert_eq!(PROTECTION_W, 0x2);
        assert_eq!(PROTECTION_X, 0x4);
        assert_eq!(FLAG_APPLE_PROTECTED, 0x8);
    }
}
