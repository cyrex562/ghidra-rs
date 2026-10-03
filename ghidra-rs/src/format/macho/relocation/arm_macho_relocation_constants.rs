//! Port of `ghidra.app.util.bin.format.macho.relocation.ARM_MachoRelocationConstants`.
//!
//! `ARM_MachoRelocationHandler` constants.
//!
//! See <https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm/reloc.h.auto.html>

/// Generic relocation as described above.
pub const ARM_RELOC_VANILLA: i32 = 0;

/// The second relocation entry of a pair.
pub const ARM_RELOC_PAIR: i32 = 1;

/// A PAIR follows with subtract symbol value.
pub const ARM_RELOC_SECTDIFF: i32 = 2;

/// Like [`ARM_RELOC_SECTDIFF`], but the symbol referenced was local.
pub const ARM_RELOC_LOCAL_SECTDIFF: i32 = 3;

/// Pre-bound lazy pointer.
pub const ARM_RELOC_PB_LA_PTR: i32 = 4;

/// 24 bit branch displacement (to a word address).
pub const ARM_RELOC_BR24: i32 = 5;

/// 22 bit branch displacement (to a half-word address).
pub const ARM_THUMB_RELOC_BR22: i32 = 6;

/// Obsolete - a thumb 32-bit branch instruction possibly needing page-spanning branch workaround.
pub const ARM_THUMB_32BIT_BRANCH: i32 = 7;

/// For these two r_type relocations they always have a pair following them and the r_length bits
/// are used differently. The encoding of the r_length is as follows:
///
/// low bit of r_length:
///    0 - :lower16: for movw instructions
///    1 - :upper16: for movt instructions
///
/// high bit of r_length:
///    0 - arm instructions
///    1 - thumb instructions
///
/// The other half of the relocated expression is in the following pair relocation entry in the
/// low 16 bits of r_address field.
pub const ARM_RELOC_HALF: i32 = 8;

/// See [`ARM_RELOC_HALF`].
pub const ARM_RELOC_HALF_SECTDIFF: i32 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(ARM_RELOC_VANILLA, 0);
        assert_eq!(ARM_RELOC_PAIR, 1);
        assert_eq!(ARM_RELOC_SECTDIFF, 2);
        assert_eq!(ARM_RELOC_LOCAL_SECTDIFF, 3);
        assert_eq!(ARM_RELOC_PB_LA_PTR, 4);
        assert_eq!(ARM_RELOC_BR24, 5);
        assert_eq!(ARM_THUMB_RELOC_BR22, 6);
        assert_eq!(ARM_THUMB_32BIT_BRANCH, 7);
        assert_eq!(ARM_RELOC_HALF, 8);
        assert_eq!(ARM_RELOC_HALF_SECTDIFF, 9);
    }
}
