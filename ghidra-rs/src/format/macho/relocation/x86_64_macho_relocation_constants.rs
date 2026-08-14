//! Port of `ghidra.app.util.bin.format.macho.relocation.X86_64_MachoRelocationConstants`.
//!
//! `X86_64_MachoRelocationHandler` constants.
//!
//! See <https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/x86_64/reloc.h.auto.html>

/// For absolute addresses
pub const X86_64_RELOC_UNSIGNED: i32 = 0;

/// For signed 32-bit displacement
pub const X86_64_RELOC_SIGNED: i32 = 1;

/// A CALL/JMP instruction with 32-bit displacement
pub const X86_64_RELOC_BRANCH: i32 = 2;

/// A MOVQ load of a GOT entry
pub const X86_64_RELOC_GOT_LOAD: i32 = 3;

/// Other GOT references
pub const X86_64_RELOC_GOT: i32 = 4;

/// Must be followed by a X86_64_RELOC_UNSIGNED
pub const X86_64_RELOC_SUBTRACTOR: i32 = 5;

/// For signed 32-bit displacement with a -1 addend
pub const X86_64_RELOC_SIGNED_1: i32 = 6;

/// For signed 32-bit displacement with a -2 addend
pub const X86_64_RELOC_SIGNED_2: i32 = 7;

/// For signed 32-bit displacement with a -4 addend
pub const X86_64_RELOC_SIGNED_4: i32 = 8;

/// For thread local variables
pub const X86_64_RELOC_TLV: i32 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(X86_64_RELOC_UNSIGNED, 0);
        assert_eq!(X86_64_RELOC_SIGNED, 1);
        assert_eq!(X86_64_RELOC_BRANCH, 2);
        assert_eq!(X86_64_RELOC_GOT_LOAD, 3);
        assert_eq!(X86_64_RELOC_GOT, 4);
        assert_eq!(X86_64_RELOC_SUBTRACTOR, 5);
        assert_eq!(X86_64_RELOC_SIGNED_1, 6);
        assert_eq!(X86_64_RELOC_SIGNED_2, 7);
        assert_eq!(X86_64_RELOC_SIGNED_4, 8);
        assert_eq!(X86_64_RELOC_TLV, 9);
    }
}
