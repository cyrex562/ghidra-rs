/// No relocation information present; usually clear for objects, set for executables.
pub const F_RELFLG: u16 = 0x0001;

/// All unresolved symbols have been resolved; file may be considered executable.
pub const F_EXEC: u16 = 0x0002;

/// All line number information has been removed from the file (or was never added).
pub const F_LNNO: u16 = 0x0004;

/// All local symbols have been removed from the file (or were never added).
pub const F_LSYMS: u16 = 0x0008;

/// File is a minimal object file (".m").
pub const F_MINMAL: u16 = 0x0010;

/// File is a fully bound update file.
pub const F_UPDATE: u16 = 0x0020;

/// File has had its bytes swabbed (in names).
pub const F_SWABD: u16 = 0x0040;

pub const F_AR16WR: u16 = 0x0080;

/// File is 32-bit little endian.
pub const F_AR32WR: u16 = 0x0100;

pub const F_AR32W: u16 = 0x0200;

pub const F_PATCH: u16 = 0x0400;

pub const F_NODF: u16 = 0x0400;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values() {
        assert_eq!(F_RELFLG, 0x0001);
        assert_eq!(F_EXEC,   0x0002);
        assert_eq!(F_LNNO,   0x0004);
        assert_eq!(F_LSYMS,  0x0008);
        assert_eq!(F_MINMAL, 0x0010);
        assert_eq!(F_UPDATE, 0x0020);
        assert_eq!(F_SWABD,  0x0040);
        assert_eq!(F_AR16WR, 0x0080);
        assert_eq!(F_AR32WR, 0x0100);
        assert_eq!(F_AR32W,  0x0200);
        assert_eq!(F_PATCH,  0x0400);
        assert_eq!(F_NODF,   0x0400);
    }

    #[test]
    fn patch_and_nodf_share_value() {
        assert_eq!(F_PATCH, F_NODF);
    }

    #[test]
    fn flags_are_single_bit_except_aliases() {
        for (name, val) in [
            ("F_RELFLG", F_RELFLG),
            ("F_EXEC",   F_EXEC),
            ("F_LNNO",   F_LNNO),
            ("F_LSYMS",  F_LSYMS),
            ("F_MINMAL", F_MINMAL),
            ("F_UPDATE", F_UPDATE),
            ("F_SWABD",  F_SWABD),
            ("F_AR16WR", F_AR16WR),
            ("F_AR32WR", F_AR32WR),
            ("F_AR32W",  F_AR32W),
            ("F_PATCH",  F_PATCH),
        ] {
            assert!(val.is_power_of_two(), "{name} should be a power of two, got {val:#06x}");
        }
    }
}
