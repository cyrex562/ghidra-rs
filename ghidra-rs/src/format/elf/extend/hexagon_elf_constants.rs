//! Hexagon-specific ELF constants.
//!
//! Ported from `ghidra.app.util.bin.format.elf.Hexagon_ElfConstants`.

/// Hexagon V2 processor version.
pub const EF_HEXAGON_MACH_V2: u32 = 0x00000001;
/// Hexagon V3 processor version.
pub const EF_HEXAGON_MACH_V3: u32 = 0x00000002;
/// Hexagon V4 processor version.
pub const EF_HEXAGON_MACH_V4: u32 = 0x00000003;
/// Hexagon V5 processor version.
pub const EF_HEXAGON_MACH_V5: u32 = 0x00000004;
/// Hexagon V55 processor version.
pub const EF_HEXAGON_MACH_V55: u32 = 0x00000005;
/// Hexagon V60 processor version.
pub const EF_HEXAGON_MACH_V60: u32 = 0x00000060;
/// Hexagon V62 processor version.
pub const EF_HEXAGON_MACH_V62: u32 = 0x00000062;
/// Hexagon V65 processor version.
pub const EF_HEXAGON_MACH_V65: u32 = 0x00000065;
/// Hexagon V66 processor version.
pub const EF_HEXAGON_MACH_V66: u32 = 0x00000066;
/// Hexagon V67 processor version.
pub const EF_HEXAGON_MACH_V67: u32 = 0x00000067;
/// Hexagon V67T processor version.
pub const EF_HEXAGON_MACH_V67T: u32 = 0x00008067;
/// Hexagon V68 processor version.
pub const EF_HEXAGON_MACH_V68: u32 = 0x00000068;
/// Hexagon V69 processor version.
pub const EF_HEXAGON_MACH_V69: u32 = 0x00000069;
/// Hexagon V71 processor version.
pub const EF_HEXAGON_MACH_V71: u32 = 0x00000071;
/// Hexagon V71T processor version.
pub const EF_HEXAGON_MACH_V71T: u32 = 0x00008071;
/// Hexagon V73 processor version.
pub const EF_HEXAGON_MACH_V73: u32 = 0x00000073;
/// Processor version mask (bits[11:0] of e_flags).
pub const EF_HEXAGON_MACH: u32 = 0x000003ff;

/// Highest ISA version - same as specified in bits[11:0] of e_flags.
pub const EF_HEXAGON_ISA_MACH: u32 = 0x00000000;
/// Hexagon V2 ISA.
pub const EF_HEXAGON_ISA_V2: u32 = 0x00000010;
/// Hexagon V3 ISA.
pub const EF_HEXAGON_ISA_V3: u32 = 0x00000020;
/// Hexagon V4 ISA.
pub const EF_HEXAGON_ISA_V4: u32 = 0x00000030;
/// Hexagon V5 ISA.
pub const EF_HEXAGON_ISA_V5: u32 = 0x00000040;
/// Hexagon V55 ISA.
pub const EF_HEXAGON_ISA_V55: u32 = 0x00000050;
/// Hexagon V60 ISA.
pub const EF_HEXAGON_ISA_V60: u32 = 0x00000060;
/// Hexagon V62 ISA.
pub const EF_HEXAGON_ISA_V62: u32 = 0x00000062;
/// Hexagon V65 ISA.
pub const EF_HEXAGON_ISA_V65: u32 = 0x00000065;
/// Hexagon V66 ISA.
pub const EF_HEXAGON_ISA_V66: u32 = 0x00000066;
/// Hexagon V67 ISA.
pub const EF_HEXAGON_ISA_V67: u32 = 0x00000067;
/// Hexagon V68 ISA.
pub const EF_HEXAGON_ISA_V68: u32 = 0x00000068;
/// Hexagon V69 ISA.
pub const EF_HEXAGON_ISA_V69: u32 = 0x00000069;
/// Hexagon V71 ISA.
pub const EF_HEXAGON_ISA_V71: u32 = 0x00000071;
/// Hexagon V73 ISA.
pub const EF_HEXAGON_ISA_V73: u32 = 0x00000073;
/// Hexagon V75 ISA.
pub const EF_HEXAGON_ISA_V75: u32 = 0x00000075;
/// Highest ISA version mask.
pub const EF_HEXAGON_ISA: u32 = 0x000003ff;

/// Hexagon-specific section index for other access sizes.
pub const SHN_HEXAGON_SCOMMON: u32 = 0xff00;
/// Hexagon-specific section index for byte-sized access.
pub const SHN_HEXAGON_SCOMMON_1: u32 = 0xff01;
/// Hexagon-specific section index for half-word-sized access.
pub const SHN_HEXAGON_SCOMMON_2: u32 = 0xff02;
/// Hexagon-specific section index for word-sized access.
pub const SHN_HEXAGON_SCOMMON_4: u32 = 0xff03;
/// Hexagon-specific section index for double-word-sized access.
pub const SHN_HEXAGON_SCOMMON_8: u32 = 0xff04;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mach_versions() {
        assert_eq!(EF_HEXAGON_MACH_V2, 0x00000001);
        assert_eq!(EF_HEXAGON_MACH_V3, 0x00000002);
        assert_eq!(EF_HEXAGON_MACH_V4, 0x00000003);
        assert_eq!(EF_HEXAGON_MACH_V5, 0x00000004);
        assert_eq!(EF_HEXAGON_MACH_V55, 0x00000005);
        assert_eq!(EF_HEXAGON_MACH_V60, 0x00000060);
        assert_eq!(EF_HEXAGON_MACH_V62, 0x00000062);
        assert_eq!(EF_HEXAGON_MACH_V65, 0x00000065);
        assert_eq!(EF_HEXAGON_MACH_V66, 0x00000066);
        assert_eq!(EF_HEXAGON_MACH_V67, 0x00000067);
        assert_eq!(EF_HEXAGON_MACH_V67T, 0x00008067);
        assert_eq!(EF_HEXAGON_MACH_V68, 0x00000068);
        assert_eq!(EF_HEXAGON_MACH_V69, 0x00000069);
        assert_eq!(EF_HEXAGON_MACH_V71, 0x00000071);
        assert_eq!(EF_HEXAGON_MACH_V71T, 0x00008071);
        assert_eq!(EF_HEXAGON_MACH_V73, 0x00000073);
        assert_eq!(EF_HEXAGON_MACH, 0x000003ff);
    }

    #[test]
    fn isa_versions() {
        assert_eq!(EF_HEXAGON_ISA_MACH, 0x00000000);
        assert_eq!(EF_HEXAGON_ISA_V2, 0x00000010);
        assert_eq!(EF_HEXAGON_ISA_V3, 0x00000020);
        assert_eq!(EF_HEXAGON_ISA_V4, 0x00000030);
        assert_eq!(EF_HEXAGON_ISA_V5, 0x00000040);
        assert_eq!(EF_HEXAGON_ISA_V55, 0x00000050);
        assert_eq!(EF_HEXAGON_ISA_V60, 0x00000060);
        assert_eq!(EF_HEXAGON_ISA_V62, 0x00000062);
        assert_eq!(EF_HEXAGON_ISA_V65, 0x00000065);
        assert_eq!(EF_HEXAGON_ISA_V66, 0x00000066);
        assert_eq!(EF_HEXAGON_ISA_V67, 0x00000067);
        assert_eq!(EF_HEXAGON_ISA_V68, 0x00000068);
        assert_eq!(EF_HEXAGON_ISA_V69, 0x00000069);
        assert_eq!(EF_HEXAGON_ISA_V71, 0x00000071);
        assert_eq!(EF_HEXAGON_ISA_V73, 0x00000073);
        assert_eq!(EF_HEXAGON_ISA_V75, 0x00000075);
        assert_eq!(EF_HEXAGON_ISA, 0x000003ff);
    }

    #[test]
    fn scommon_sections() {
        assert_eq!(SHN_HEXAGON_SCOMMON, 0xff00);
        assert_eq!(SHN_HEXAGON_SCOMMON_1, 0xff01);
        assert_eq!(SHN_HEXAGON_SCOMMON_2, 0xff02);
        assert_eq!(SHN_HEXAGON_SCOMMON_4, 0xff03);
        assert_eq!(SHN_HEXAGON_SCOMMON_8, 0xff04);
    }
}
