//! Port of `ghidra.app.util.bin.format.macho.relocation.X86_32_MachoRelocationConstants`.
//!
//! `X86_32_MachoRelocationHandler` constants.
//!
//! See <https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html>

/// Generic relocation
pub const GENERIC_RELOC_VANILLA: i32 = 0;

/// Only follows a GENERIC_RELOC_SECTDIFF
pub const GENERIC_RELOC_PAIR: i32 = 1;

/// The difference of two symbols defined in two different sections
pub const GENERIC_RELOC_SECTDIFF: i32 = 2;

/// Pre-bound lazy pointer
pub const GENERIC_RELOC_PB_LA_PTR: i32 = 3;

/// The difference of two symbols defined in two different sections
pub const GENERIC_RELOC_LOCAL_SECTDIFF: i32 = 4;

/// Thread local variables
pub const GENERIC_RELOC_TLV: i32 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(GENERIC_RELOC_VANILLA, 0);
        assert_eq!(GENERIC_RELOC_PAIR, 1);
        assert_eq!(GENERIC_RELOC_SECTDIFF, 2);
        assert_eq!(GENERIC_RELOC_PB_LA_PTR, 3);
        assert_eq!(GENERIC_RELOC_LOCAL_SECTDIFF, 4);
        assert_eq!(GENERIC_RELOC_TLV, 5);
    }
}
