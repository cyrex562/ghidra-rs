//! Port of `ghidra.app.util.bin.format.macho.relocation.AARCH64_MachoRelocationConstants`.
//!
//! `AARCH64_MachoRelocationHandler` constants.
//!
//! See <https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm64/reloc.h.auto.html>

/// For pointers.
pub const ARM64_RELOC_UNSIGNED: i32 = 0;

/// Must be followed by a [`ARM64_RELOC_UNSIGNED`].
pub const ARM64_RELOC_SUBTRACTOR: i32 = 1;

/// A B/BL instruction with 26-bit displacement.
pub const ARM64_RELOC_BRANCH26: i32 = 2;

/// PC-rel distance to page of target.
pub const ARM64_RELOC_PAGE21: i32 = 3;

/// Offset within page, scaled by r_length.
pub const ARM64_RELOC_PAGEOFF12: i32 = 4;

/// PC-rel distance to page of GOT slot.
pub const ARM64_RELOC_GOT_LOAD_PAGE21: i32 = 5;

/// Offset within page of GOT slot, scaled by r_length.
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: i32 = 6;

/// For pointers to GOT slots.
pub const ARM64_RELOC_POINTER_TO_GOT: i32 = 7;

/// PC-rel distance to page of TLVP slot.
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: i32 = 8;

/// Offset within page of TLVP slot, scaled by r_length.
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: i32 = 9;

/// Must be followed by [`ARM64_RELOC_PAGE21`] or [`ARM64_RELOC_PAGEOFF12`].
pub const ARM64_RELOC_ADDEND: i32 = 10;

/// Like [`ARM64_RELOC_UNSIGNED`], but addend in lower 32-bits.
pub const ARM64_RELOC_AUTHENTICATED_POINTER: i32 = 11;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(ARM64_RELOC_UNSIGNED, 0);
        assert_eq!(ARM64_RELOC_SUBTRACTOR, 1);
        assert_eq!(ARM64_RELOC_BRANCH26, 2);
        assert_eq!(ARM64_RELOC_PAGE21, 3);
        assert_eq!(ARM64_RELOC_PAGEOFF12, 4);
        assert_eq!(ARM64_RELOC_GOT_LOAD_PAGE21, 5);
        assert_eq!(ARM64_RELOC_GOT_LOAD_PAGEOFF12, 6);
        assert_eq!(ARM64_RELOC_POINTER_TO_GOT, 7);
        assert_eq!(ARM64_RELOC_TLVP_LOAD_PAGE21, 8);
        assert_eq!(ARM64_RELOC_TLVP_LOAD_PAGEOFF12, 9);
        assert_eq!(ARM64_RELOC_ADDEND, 10);
        assert_eq!(ARM64_RELOC_AUTHENTICATED_POINTER, 11);
    }
}
