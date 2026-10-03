//! Port of `ghidra.app.util.bin.format.macho.relocation.PowerPC_MachoRelocationConstants`.
//!
//! `PowerPC_MachoRelocationHandler` constants.
//!
//! See <https://opensource.apple.com/source/xnu/xnu-1504.9.37/EXTERNAL_HEADERS/mach-o/ppc/reloc.h.auto.html>

/// Generic relocation as described above.
pub const PPC_RELOC_VANILLA: i32 = 0;

/// The second relocation entry of a pair.
pub const PPC_RELOC_PAIR: i32 = 1;

/// 14 bit branch displacement (to a word address).
pub const PPC_RELOC_BR14: i32 = 2;

/// 24 bit branch displacement (to a word address).
pub const PPC_RELOC_BR24: i32 = 3;

/// A [`PPC_RELOC_PAIR`] follows with the low half.
pub const PPC_RELOC_HI16: i32 = 4;

/// A [`PPC_RELOC_PAIR`] follows with the high half.
pub const PPC_RELOC_LO16: i32 = 5;

/// Same as the [`PPC_RELOC_HI16`] except the low 16 bits and the high 16 bits are added
/// together with the low 16 bits sign-extended first. This means if bit 15 of the low 16 bits
/// is set the high 16 bits stored in the instruction will be adjusted.
pub const PPC_RELOC_HA16: i32 = 6;

/// Same as the [`PPC_RELOC_LO16`] except that the low 2 bits are not stored in the
/// instruction and are always zero. This is used in double word load/store instructions.
pub const PPC_RELOC_LO14: i32 = 7;

/// A [`PPC_RELOC_PAIR`] follows with subtract symbol value.
pub const PPC_RELOC_SECTDIFF: i32 = 8;

/// Pre-bound lazy pointer.
pub const PPC_RELOC_PB_LA_PTR: i32 = 9;

/// A section difference forms of above.
/// A [`PPC_RELOC_PAIR`] follows these with subtract symbol value.
pub const PPC_RELOC_HI16_SECTDIFF: i32 = 10;
pub const PPC_RELOC_LO16_SECTDIFF: i32 = 11;
pub const PPC_RELOC_HA16_SECTDIFF: i32 = 12;
pub const PPC_RELOC_JBSR: i32 = 13;
pub const PPC_RELOC_LO14_SECTDIFF: i32 = 14;

/// Like [`PPC_RELOC_SECTDIFF`], but the symbol referenced was local.
pub const PPC_RELOC_LOCAL_SECTDIFF: i32 = 15;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(PPC_RELOC_VANILLA, 0);
        assert_eq!(PPC_RELOC_PAIR, 1);
        assert_eq!(PPC_RELOC_BR14, 2);
        assert_eq!(PPC_RELOC_BR24, 3);
        assert_eq!(PPC_RELOC_HI16, 4);
        assert_eq!(PPC_RELOC_LO16, 5);
        assert_eq!(PPC_RELOC_HA16, 6);
        assert_eq!(PPC_RELOC_LO14, 7);
        assert_eq!(PPC_RELOC_SECTDIFF, 8);
        assert_eq!(PPC_RELOC_PB_LA_PTR, 9);
        assert_eq!(PPC_RELOC_HI16_SECTDIFF, 10);
        assert_eq!(PPC_RELOC_LO16_SECTDIFF, 11);
        assert_eq!(PPC_RELOC_HA16_SECTDIFF, 12);
        assert_eq!(PPC_RELOC_JBSR, 13);
        assert_eq!(PPC_RELOC_LO14_SECTDIFF, 14);
        assert_eq!(PPC_RELOC_LOCAL_SECTDIFF, 15);
    }
}
