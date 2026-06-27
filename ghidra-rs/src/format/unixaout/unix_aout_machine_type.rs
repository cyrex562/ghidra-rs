/// Unix a.out machine type identifiers.
///
/// Mirrors `ghidra.app.util.bin.format.unixaout.UnixAoutMachineType`.
///
/// Values drawn from NetBSD's `aout_mids.h` and the GNU BFD library's `libaout.h`.

pub const M_UNKNOWN: u16 = 0x00;
pub const M_68010: u16 = 0x01;
pub const M_68020: u16 = 0x02;
pub const M_SPARC: u16 = 0x03;
pub const M_R3000: u16 = 0x04;
pub const M_NS32032: u16 = 0x40;
pub const M_NS32532: u16 = 0x45;
pub const M_386: u16 = 0x64;
/// AMD 29000
pub const M_29K: u16 = 0x65;
/// i386-based Sequent machine running DYNIX
pub const M_386_DYNIX: u16 = 0x66;
pub const M_ARM: u16 = 0x67;
/// Sparclet = M_SPARC + 128
pub const M_SPARCLET: u16 = 0x83;
/// NetBSD/i386
pub const M_386_NETBSD: u16 = 0x86;
/// NetBSD/m68k, 8K pages
pub const M_M68K_NETBSD: u16 = 0x87;
/// NetBSD/m68k, 4K pages
pub const M_M68K4K_NETBSD: u16 = 0x88;
/// NetBSD/ns32k
pub const M_532_NETBSD: u16 = 0x89;
/// NetBSD/sparc
pub const M_SPARC_NETBSD: u16 = 0x8a;
/// NetBSD/pmax (MIPS little-endian)
pub const M_PMAX_NETBSD: u16 = 0x8b;
/// NetBSD/VAX (1K pages?)
pub const M_VAX_NETBSD: u16 = 0x8c;
/// NetBSD/Alpha
pub const M_ALPHA_NETBSD: u16 = 0x8d;
/// big-endian MIPS
pub const M_MIPS: u16 = 0x8e;
/// NetBSD/arm32
pub const M_ARM6_NETBSD: u16 = 0x8f;
pub const M_SH3: u16 = 0x91;
/// PowerPC 64
pub const M_POWERPC64: u16 = 0x94;
/// NetBSD/PowerPC (big-endian)
pub const M_POWERPC_NETBSD: u16 = 0x95;
/// NetBSD/VAX (4K pages)
pub const M_VAX4K_NETBSD: u16 = 0x96;
/// MIPS R2000/R3000
pub const M_MIPS1: u16 = 0x97;
/// MIPS R4000/R6000
pub const M_MIPS2: u16 = 0x98;
/// OpenBSD/m88k
pub const M_88K_OPENBSD: u16 = 0x99;
/// OpenBSD/hppa (PA-RISC)
pub const M_HPPA_OPENBSD: u16 = 0x9a;
/// SuperH 64-bit
pub const M_SH5_64: u16 = 0x9b;
/// NetBSD/sparc64
pub const M_SPARC64_NETBSD: u16 = 0x9c;
/// NetBSD/amd64
pub const M_X86_64_NETBSD: u16 = 0x9d;
/// SuperH 32-bit (ILP 32)
pub const M_SH5_32: u16 = 0x9e;
/// Itanium
pub const M_IA64: u16 = 0x9f;
/// ARM AARCH64
pub const M_AARCH64: u16 = 0xb7;
/// OpenRISC 1000
pub const M_OR1K: u16 = 0xb8;
/// RISC-V
pub const M_RISCV: u16 = 0xb9;
/// Axis ETRAX CRIS
pub const M_CRIS: u16 = 0xff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_machine_ids() {
        assert_eq!(M_UNKNOWN, 0x00);
        assert_eq!(M_68010, 0x01);
        assert_eq!(M_68020, 0x02);
        assert_eq!(M_SPARC, 0x03);
        assert_eq!(M_R3000, 0x04);
    }

    #[test]
    fn ns32_ids() {
        assert_eq!(M_NS32032, 0x40);
        assert_eq!(M_NS32532, 0x45);
    }

    #[test]
    fn x86_and_arm_ids() {
        assert_eq!(M_386, 0x64);
        assert_eq!(M_29K, 0x65);
        assert_eq!(M_386_DYNIX, 0x66);
        assert_eq!(M_ARM, 0x67);
    }

    #[test]
    fn netbsd_ids() {
        assert_eq!(M_386_NETBSD, 0x86);
        assert_eq!(M_M68K_NETBSD, 0x87);
        assert_eq!(M_M68K4K_NETBSD, 0x88);
        assert_eq!(M_532_NETBSD, 0x89);
        assert_eq!(M_SPARC_NETBSD, 0x8a);
        assert_eq!(M_PMAX_NETBSD, 0x8b);
        assert_eq!(M_VAX_NETBSD, 0x8c);
        assert_eq!(M_ALPHA_NETBSD, 0x8d);
        assert_eq!(M_MIPS, 0x8e);
        assert_eq!(M_ARM6_NETBSD, 0x8f);
        assert_eq!(M_SH3, 0x91);
        assert_eq!(M_POWERPC64, 0x94);
        assert_eq!(M_POWERPC_NETBSD, 0x95);
        assert_eq!(M_VAX4K_NETBSD, 0x96);
        assert_eq!(M_MIPS1, 0x97);
        assert_eq!(M_MIPS2, 0x98);
        assert_eq!(M_SPARC64_NETBSD, 0x9c);
        assert_eq!(M_X86_64_NETBSD, 0x9d);
    }

    #[test]
    fn openbsd_ids() {
        assert_eq!(M_88K_OPENBSD, 0x99);
        assert_eq!(M_HPPA_OPENBSD, 0x9a);
    }

    #[test]
    fn superh_and_modern_ids() {
        assert_eq!(M_SH5_64, 0x9b);
        assert_eq!(M_SH5_32, 0x9e);
        assert_eq!(M_IA64, 0x9f);
        assert_eq!(M_AARCH64, 0xb7);
        assert_eq!(M_OR1K, 0xb8);
        assert_eq!(M_RISCV, 0xb9);
        assert_eq!(M_CRIS, 0xff);
    }

    #[test]
    fn sparclet_is_sparc_plus_128() {
        assert_eq!(M_SPARCLET, M_SPARC + 128);
    }

    #[test]
    fn all_values_fit_in_u16() {
        let all: &[u16] = &[
            M_UNKNOWN, M_68010, M_68020, M_SPARC, M_R3000, M_NS32032, M_NS32532,
            M_386, M_29K, M_386_DYNIX, M_ARM, M_SPARCLET, M_386_NETBSD,
            M_M68K_NETBSD, M_M68K4K_NETBSD, M_532_NETBSD, M_SPARC_NETBSD,
            M_PMAX_NETBSD, M_VAX_NETBSD, M_ALPHA_NETBSD, M_MIPS, M_ARM6_NETBSD,
            M_SH3, M_POWERPC64, M_POWERPC_NETBSD, M_VAX4K_NETBSD, M_MIPS1,
            M_MIPS2, M_88K_OPENBSD, M_HPPA_OPENBSD, M_SH5_64, M_SPARC64_NETBSD,
            M_X86_64_NETBSD, M_SH5_32, M_IA64, M_AARCH64, M_OR1K, M_RISCV, M_CRIS,
        ];
        assert_eq!(all.len(), 39);
    }
}
