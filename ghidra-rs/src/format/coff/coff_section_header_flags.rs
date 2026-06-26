/// Regular segment.
pub const STYP_REG: u32 = 0x0000;

/// Dummy section.
pub const STYP_DSECT: u32 = 0x0001;

/// No-load segment.
pub const STYP_NOLOAD: u32 = 0x0002;

/// Group segment.
pub const STYP_GROUP: u32 = 0x0004;

/// Pad segment.
pub const STYP_PAD: u32 = 0x0008;

/// Copy segment.
pub const STYP_COPY: u32 = 0x0010;

/// The section contains only executable code.
pub const STYP_TEXT: u32 = 0x0020;

/// The section contains only initialized data.
pub const STYP_DATA: u32 = 0x0040;

/// The section defines uninitialized data.
pub const STYP_BSS: u32 = 0x0080;

/// Exception section.
pub const STYP_EXCEPT: u32 = 0x0100;

/// Comment section.
pub const STYP_INFO: u32 = 0x0200;

/// Overlay section (defines a piece of another named section which has no bytes).
pub const STYP_OVER: u32 = 0x0400;

/// Library section.
pub const STYP_LIB: u32 = 0x0800;

/// Loader section.
pub const STYP_LOADER: u32 = 0x1000;

/// Debug section.
pub const STYP_DEBUG: u32 = 0x2000;

/// Type check section.
pub const STYP_TYPECHK: u32 = 0x4000;

/// RLD and line number overflow sec hdr section.
pub const STYP_OVRFLO: u32 = 0x8000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values() {
        assert_eq!(STYP_REG,     0x0000);
        assert_eq!(STYP_DSECT,   0x0001);
        assert_eq!(STYP_NOLOAD,  0x0002);
        assert_eq!(STYP_GROUP,   0x0004);
        assert_eq!(STYP_PAD,     0x0008);
        assert_eq!(STYP_COPY,    0x0010);
        assert_eq!(STYP_TEXT,    0x0020);
        assert_eq!(STYP_DATA,    0x0040);
        assert_eq!(STYP_BSS,     0x0080);
        assert_eq!(STYP_EXCEPT,  0x0100);
        assert_eq!(STYP_INFO,    0x0200);
        assert_eq!(STYP_OVER,    0x0400);
        assert_eq!(STYP_LIB,     0x0800);
        assert_eq!(STYP_LOADER,  0x1000);
        assert_eq!(STYP_DEBUG,   0x2000);
        assert_eq!(STYP_TYPECHK, 0x4000);
        assert_eq!(STYP_OVRFLO,  0x8000);
    }

    #[test]
    fn nonzero_flags_are_single_bit() {
        for (name, val) in [
            ("STYP_DSECT",   STYP_DSECT),
            ("STYP_NOLOAD",  STYP_NOLOAD),
            ("STYP_GROUP",   STYP_GROUP),
            ("STYP_PAD",     STYP_PAD),
            ("STYP_COPY",    STYP_COPY),
            ("STYP_TEXT",    STYP_TEXT),
            ("STYP_DATA",    STYP_DATA),
            ("STYP_BSS",     STYP_BSS),
            ("STYP_EXCEPT",  STYP_EXCEPT),
            ("STYP_INFO",    STYP_INFO),
            ("STYP_OVER",    STYP_OVER),
            ("STYP_LIB",     STYP_LIB),
            ("STYP_LOADER",  STYP_LOADER),
            ("STYP_DEBUG",   STYP_DEBUG),
            ("STYP_TYPECHK", STYP_TYPECHK),
            ("STYP_OVRFLO",  STYP_OVRFLO),
        ] {
            assert!(val.is_power_of_two(), "{name} should be a power of two, got {val:#06x}");
        }
    }

    #[test]
    fn flags_do_not_overlap() {
        let flags = [
            STYP_DSECT, STYP_NOLOAD, STYP_GROUP, STYP_PAD, STYP_COPY,
            STYP_TEXT, STYP_DATA, STYP_BSS, STYP_EXCEPT, STYP_INFO,
            STYP_OVER, STYP_LIB, STYP_LOADER, STYP_DEBUG, STYP_TYPECHK,
            STYP_OVRFLO,
        ];
        let mut seen = 0u32;
        for f in flags {
            assert_eq!(seen & f, 0, "flag {f:#06x} overlaps with a previously seen flag");
            seen |= f;
        }
    }
}
