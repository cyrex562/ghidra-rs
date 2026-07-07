/// PowerPC 32-bit Mach-O magic number (big-endian).
pub const MH_MAGIC: u32 = 0xfeed_face;

/// PowerPC 64-bit Mach-O magic number (big-endian).
pub const MH_MAGIC_64: u32 = 0xfeed_facf;

/// Intel x86 32-bit Mach-O magic number (little-endian byte-swapped).
pub const MH_CIGAM: u32 = 0xcefa_edfe;

/// Intel x86 64-bit Mach-O magic number (little-endian byte-swapped).
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

/// Returns `true` if `magic` is any of the four recognized Mach-O magic numbers.
pub fn is_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

/// Maximum byte length of a Mach-O section or segment name.
pub const NAME_LENGTH: usize = 16;

/// Data-type category path used when registering Mach-O types.
pub const DATA_TYPE_CATEGORY: &str = "/MachO";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_constants_values() {
        assert_eq!(MH_MAGIC, 0xfeed_face);
        assert_eq!(MH_MAGIC_64, 0xfeed_facf);
        assert_eq!(MH_CIGAM, 0xcefa_edfe);
        assert_eq!(MH_CIGAM_64, 0xcffa_edfe);
    }

    #[test]
    fn is_magic_accepts_all_four() {
        assert!(is_magic(MH_MAGIC));
        assert!(is_magic(MH_MAGIC_64));
        assert!(is_magic(MH_CIGAM));
        assert!(is_magic(MH_CIGAM_64));
    }

    #[test]
    fn is_magic_rejects_others() {
        assert!(!is_magic(0x0000_0000));
        assert!(!is_magic(0xffff_ffff));
        assert!(!is_magic(0xdead_beef));
    }

    #[test]
    fn name_length_is_16() {
        assert_eq!(NAME_LENGTH, 16);
    }

    #[test]
    fn data_type_category_value() {
        assert_eq!(DATA_TYPE_CATEGORY, "/MachO");
    }
}
