/// XCOFF32 magic number.
pub const MAGIC_XCOFF32: u16 = 0x01df;
/// XCOFF64 magic number (discontinued AIX variant).
pub const MAGIC_XCOFF64_OLD: u16 = 0x01ef;
/// XCOFF64 magic number.
pub const MAGIC_XCOFF64: u16 = 0x01f7;

/// Returns `true` if `magic` is a recognised XCOFF magic value.
///
/// Mirrors `XCoffFileHeaderMagic.isMatch(short)`.
pub fn is_match(magic: u16) -> bool {
    magic == MAGIC_XCOFF32 || magic == MAGIC_XCOFF64_OLD || magic == MAGIC_XCOFF64
}

/// Returns `true` if the magic value indicates a 32-bit XCOFF file.
///
/// Mirrors `XCoffFileHeaderMagic.is32bit(XCoffFileHeader)`, accepting the raw
/// magic value from the header rather than the full header struct (which is not
/// yet ported).
pub fn is_32bit(magic: u16) -> bool {
    magic == MAGIC_XCOFF32
}

/// Returns `true` if the magic value indicates a 64-bit XCOFF file.
///
/// Mirrors `XCoffFileHeaderMagic.is64bit(XCoffFileHeader)`, accepting the raw
/// magic value from the header rather than the full header struct (which is not
/// yet ported).
pub fn is_64bit(magic: u16) -> bool {
    magic == MAGIC_XCOFF64_OLD || magic == MAGIC_XCOFF64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(MAGIC_XCOFF32, 0x01df);
        assert_eq!(MAGIC_XCOFF64_OLD, 0x01ef);
        assert_eq!(MAGIC_XCOFF64, 0x01f7);
    }

    #[test]
    fn is_match_accepts_all_known_magic_values() {
        assert!(is_match(MAGIC_XCOFF32));
        assert!(is_match(MAGIC_XCOFF64_OLD));
        assert!(is_match(MAGIC_XCOFF64));
    }

    #[test]
    fn is_match_rejects_unknown_values() {
        assert!(!is_match(0x0000));
        assert!(!is_match(0x01de));
        assert!(!is_match(0x01f8));
        assert!(!is_match(0xffff));
    }

    #[test]
    fn is_32bit_only_for_xcoff32() {
        assert!(is_32bit(MAGIC_XCOFF32));
        assert!(!is_32bit(MAGIC_XCOFF64_OLD));
        assert!(!is_32bit(MAGIC_XCOFF64));
        assert!(!is_32bit(0x0000));
    }

    #[test]
    fn is_64bit_for_both_xcoff64_variants() {
        assert!(is_64bit(MAGIC_XCOFF64_OLD));
        assert!(is_64bit(MAGIC_XCOFF64));
        assert!(!is_64bit(MAGIC_XCOFF32));
        assert!(!is_64bit(0x0000));
    }

    #[test]
    fn is_32bit_and_is_64bit_are_mutually_exclusive_for_known_magics() {
        for magic in [MAGIC_XCOFF32, MAGIC_XCOFF64_OLD, MAGIC_XCOFF64] {
            assert!(
                !(is_32bit(magic) && is_64bit(magic)),
                "magic {magic:#06x} must not be both 32-bit and 64-bit"
            );
        }
    }

    #[test]
    fn every_match_is_either_32bit_or_64bit() {
        for magic in [MAGIC_XCOFF32, MAGIC_XCOFF64_OLD, MAGIC_XCOFF64] {
            assert!(
                is_32bit(magic) || is_64bit(magic),
                "matched magic {magic:#06x} must resolve to 32- or 64-bit"
            );
        }
    }
}
