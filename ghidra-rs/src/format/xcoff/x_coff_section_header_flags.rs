/// Pad section.
pub const STYP_PAD: u16 = 0x0008;
/// Text (code) section.
pub const STYP_TEXT: u16 = 0x0020;
/// Data section.
pub const STYP_DATA: u16 = 0x0040;
/// BSS (uninitialized data) section.
pub const STYP_BSS: u16 = 0x0080;
/// Exception section (shares the same flag value as `STYP_BSS`).
pub const STYP_EXCEPT: u16 = 0x0080;
/// Comment/info section.
pub const STYP_INFO: u16 = 0x0200;
/// Loader section.
pub const STYP_LOADER: u16 = 0x1000;
/// Debug section.
pub const STYP_DEBUG: u16 = 0x2000;
/// Type-check section.
pub const STYP_TYPCHK: u16 = 0x4000;
/// Overflow section.
pub const STYP_OVRFLO: u16 = 0x8000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(STYP_PAD, 0x0008);
        assert_eq!(STYP_TEXT, 0x0020);
        assert_eq!(STYP_DATA, 0x0040);
        assert_eq!(STYP_BSS, 0x0080);
        assert_eq!(STYP_EXCEPT, 0x0080);
        assert_eq!(STYP_INFO, 0x0200);
        assert_eq!(STYP_LOADER, 0x1000);
        assert_eq!(STYP_DEBUG, 0x2000);
        assert_eq!(STYP_TYPCHK, 0x4000);
        assert_eq!(STYP_OVRFLO, 0x8000);
    }

    #[test]
    fn bss_and_except_share_value() {
        assert_eq!(STYP_BSS, STYP_EXCEPT);
    }

    #[test]
    fn distinct_flags_do_not_overlap() {
        let distinct = [
            STYP_PAD, STYP_TEXT, STYP_DATA, STYP_BSS, STYP_INFO,
            STYP_LOADER, STYP_DEBUG, STYP_TYPCHK, STYP_OVRFLO,
        ];
        for (i, &a) in distinct.iter().enumerate() {
            for (j, &b) in distinct.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "flags {i} and {j} must not overlap");
                }
            }
        }
    }

    #[test]
    fn flag_detection_with_bitmask() {
        let flags = STYP_TEXT | STYP_DATA | STYP_LOADER;
        assert_ne!(flags & STYP_TEXT, 0);
        assert_ne!(flags & STYP_DATA, 0);
        assert_ne!(flags & STYP_LOADER, 0);
        assert_eq!(flags & STYP_BSS, 0);
        assert_eq!(flags & STYP_DEBUG, 0);
    }
}
