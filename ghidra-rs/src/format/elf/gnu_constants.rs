//! GNU ELF constants.
//!
//! Ported from `ghidra.app.util.bin.format.elf.GnuConstants`.

// Versym symbol index values

/// Symbol is local.
pub const VER_NDX_LOCAL: u16 = 0;
/// Symbol is global.
pub const VER_NDX_GLOBAL: u16 = 1;
/// Beginning of reserved entries.
pub const VER_NDX_LORESERVE: u16 = 0xff00;
/// Symbol is to be eliminated.
pub const VER_NDX_ELIMINATE: u16 = 0xff01;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ver_ndx_values() {
        assert_eq!(VER_NDX_LOCAL, 0);
        assert_eq!(VER_NDX_GLOBAL, 1);
        assert_eq!(VER_NDX_LORESERVE, 0xff00);
        assert_eq!(VER_NDX_ELIMINATE, 0xff01);
    }

    #[test]
    fn eliminate_follows_loreserve() {
        assert_eq!(VER_NDX_ELIMINATE, VER_NDX_LORESERVE + 1);
    }
}
