//! Hexagon-specific ELF program header constants.
//!
//! Ported from `ghidra.app.util.bin.format.elf.extend.Hexagon_ElfProgramHeaderConstants`.

/// Hexagon V4 processor version.
pub const EF_HEXAGON_MACH_V4: u32 = 0x3;
/// Hexagon V5 processor version.
pub const EF_HEXAGON_MACH_V5: u32 = 0x4;
/// Hexagon V55 processor version.
pub const EF_HEXAGON_MACH_V55: u32 = 0x5;
/// Hexagon V60 processor version.
pub const EF_HEXAGON_MACH_V60: u32 = 0x60;
/// Hexagon V61 processor version.
pub const EF_HEXAGON_MACH_V61: u32 = 0x61;
/// Hexagon V62 processor version.
pub const EF_HEXAGON_MACH_V62: u32 = 0x62;
/// Hexagon V65 processor version.
pub const EF_HEXAGON_MACH_V65: u32 = 0x65;
/// Hexagon V66 processor version.
pub const EF_HEXAGON_MACH_V66: u32 = 0x66;
/// Hexagon V67 processor version.
pub const EF_HEXAGON_MACH_V67: u32 = 0x67;
/// Hexagon V67 Small Core (V67t) processor version.
pub const EF_HEXAGON_MACH_V67T: u32 = 0x8067;
/// Hexagon V68 processor version.
pub const EF_HEXAGON_MACH_V68: u32 = 0x68;
/// Hexagon V69 processor version.
pub const EF_HEXAGON_MACH_V69: u32 = 0x69;
/// Hexagon V71 processor version.
pub const EF_HEXAGON_MACH_V71: u32 = 0x71;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mach_versions() {
        assert_eq!(EF_HEXAGON_MACH_V4, 0x3);
        assert_eq!(EF_HEXAGON_MACH_V5, 0x4);
        assert_eq!(EF_HEXAGON_MACH_V55, 0x5);
        assert_eq!(EF_HEXAGON_MACH_V60, 0x60);
        assert_eq!(EF_HEXAGON_MACH_V61, 0x61);
        assert_eq!(EF_HEXAGON_MACH_V62, 0x62);
        assert_eq!(EF_HEXAGON_MACH_V65, 0x65);
        assert_eq!(EF_HEXAGON_MACH_V66, 0x66);
        assert_eq!(EF_HEXAGON_MACH_V67, 0x67);
        assert_eq!(EF_HEXAGON_MACH_V67T, 0x8067);
        assert_eq!(EF_HEXAGON_MACH_V68, 0x68);
        assert_eq!(EF_HEXAGON_MACH_V69, 0x69);
        assert_eq!(EF_HEXAGON_MACH_V71, 0x71);
    }
}
