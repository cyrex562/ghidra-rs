/// Returns the encoded Intel CPU subtype value from family and model.
const fn cpu_subtype_intel(f: i32, m: i32) -> i32 {
    f + (m << 4)
}

// PowerPC subtypes
pub const CPU_SUBTYPE_POWERPC_ALL: i32 = 0;
pub const CPU_SUBTYPE_POWERPC_601: i32 = 1;
pub const CPU_SUBTYPE_POWERPC_602: i32 = 2;
pub const CPU_SUBTYPE_POWERPC_603: i32 = 3;
pub const CPU_SUBTYPE_POWERPC_603E: i32 = 4;
pub const CPU_SUBTYPE_POWERPC_603EV: i32 = 5;
pub const CPU_SUBTYPE_POWERPC_604: i32 = 6;
pub const CPU_SUBTYPE_POWERPC_604E: i32 = 7;
pub const CPU_SUBTYPE_POWERPC_620: i32 = 8;
pub const CPU_SUBTYPE_POWERPC_750: i32 = 9;
pub const CPU_SUBTYPE_POWERPC_7400: i32 = 10;
pub const CPU_SUBTYPE_POWERPC_7450: i32 = 11;
pub const CPU_SUBTYPE_POWERPC_MAX: i32 = 10;
pub const CPU_SUBTYPE_POWERPC_SCVGER: i32 = 11;
pub const CPU_SUBTYPE_POWERPC_970: i32 = 100;

// I386 subtypes (computed via cpu_subtype_intel family, model)
pub const CPU_SUBTYPE_I386_ALL: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_386: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_486: i32 = cpu_subtype_intel(4, 0);
pub const CPU_SUBTYPE_486SX: i32 = cpu_subtype_intel(4, 8);
pub const CPU_SUBTYPE_586: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENT: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENTPRO: i32 = cpu_subtype_intel(6, 1);
pub const CPU_SUBTYPE_PENTII_M3: i32 = cpu_subtype_intel(6, 3);
pub const CPU_SUBTYPE_PENTII_M5: i32 = cpu_subtype_intel(6, 5);
pub const CPU_SUBTYPE_CELERON: i32 = cpu_subtype_intel(7, 6);
pub const CPU_SUBTYPE_CELERON_MOBILE: i32 = cpu_subtype_intel(7, 7);
pub const CPU_SUBTYPE_PENTIUM_3: i32 = cpu_subtype_intel(8, 0);
pub const CPU_SUBTYPE_PENTIUM_3_M: i32 = cpu_subtype_intel(8, 1);
pub const CPU_SUBTYPE_PENTIUM_3_XEON: i32 = cpu_subtype_intel(8, 2);
pub const CPU_SUBTYPE_PENTIUM_M: i32 = cpu_subtype_intel(9, 0);
pub const CPU_SUBTYPE_PENTIUM_4: i32 = cpu_subtype_intel(10, 0);
pub const CPU_SUBTYPE_PENTIUM_4_M: i32 = cpu_subtype_intel(10, 1);
pub const CPU_SUBTYPE_ITANIUM: i32 = cpu_subtype_intel(11, 0);
pub const CPU_SUBTYPE_ITANIUM_2: i32 = cpu_subtype_intel(11, 1);
pub const CPU_SUBTYPE_XEON: i32 = cpu_subtype_intel(12, 0);
pub const CPU_SUBTYPE_XEON_MP: i32 = cpu_subtype_intel(12, 1);

// X86 subtypes
pub const CPU_SUBTYPE_X86_ALL: i32 = 3;
pub const CPU_SUBTYPE_X86_ARCH1: i32 = 4;
pub const CPU_THREADTYPE_INTEL_HTT: i32 = 1;

// MIPS subtypes
pub const CPU_SUBTYPE_MIPS_ALL: i32 = 0;
pub const CPU_SUBTYPE_MIPS_R2300: i32 = 1;
pub const CPU_SUBTYPE_MIPS_R2600: i32 = 2;
pub const CPU_SUBTYPE_MIPS_R2800: i32 = 3;
pub const CPU_SUBTYPE_MIPS_R2000A: i32 = 4;
pub const CPU_SUBTYPE_MIPS_R2000: i32 = 5;
pub const CPU_SUBTYPE_MIPS_R3000A: i32 = 6;
pub const CPU_SUBTYPE_MIPS_R3000: i32 = 7;

// MC98000 (PowerPC) subtypes
pub const CPU_SUBTYPE_MC98000_ALL: i32 = 0;
pub const CPU_SUBTYPE_MC98601: i32 = 1;

// HPPA subtypes
pub const CPU_SUBTYPE_HPPA_ALL: i32 = 0;
pub const CPU_SUBTYPE_HPPA_7100: i32 = 0;
pub const CPU_SUBTYPE_HPPA_7100LC: i32 = 1;

// MC88000 subtypes
pub const CPU_SUBTYPE_MC88000_ALL: i32 = 0;
pub const CPU_SUBTYPE_MC88100: i32 = 1;
pub const CPU_SUBTYPE_MC88110: i32 = 2;

// SPARC subtypes
pub const CPU_SUBTYPE_SPARC_ALL: i32 = 0;

// I860 subtypes
pub const CPU_SUBTYPE_I860_ALL: i32 = 0;
pub const CPU_SUBTYPE_I860_860: i32 = 1;

// VAX subtypes
pub const CPU_SUBTYPE_VAX_ALL: i32 = 0;
pub const CPU_SUBTYPE_VAX780: i32 = 1;
pub const CPU_SUBTYPE_VAX785: i32 = 2;
pub const CPU_SUBTYPE_VAX750: i32 = 3;
pub const CPU_SUBTYPE_VAX730: i32 = 4;
pub const CPU_SUBTYPE_UVAXI: i32 = 5;
pub const CPU_SUBTYPE_UVAXII: i32 = 6;
pub const CPU_SUBTYPE_VAX8200: i32 = 7;
pub const CPU_SUBTYPE_VAX8500: i32 = 8;
pub const CPU_SUBTYPE_VAX8600: i32 = 9;
pub const CPU_SUBTYPE_VAX8650: i32 = 10;
pub const CPU_SUBTYPE_VAX8800: i32 = 11;
pub const CPU_SUBTYPE_UVAXIII: i32 = 12;

// 680x0 subtypes
pub const CPU_SUBTYPE_MC680X0_ALL: i32 = 1;
pub const CPU_SUBTYPE_MC68030: i32 = 1;
pub const CPU_SUBTYPE_MC68040: i32 = 2;
pub const CPU_SUBTYPE_MC68030_ONLY: i32 = 3;

// ARM subtypes
pub const CPU_SUBTYPE_ARM_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM_V4T: i32 = 5;
pub const CPU_SUBTYPE_ARM_V6: i32 = 6;
pub const CPU_SUBTYPE_ARM_V5: i32 = 7;
pub const CPU_SUBTYPE_ARM_V5TEJ: i32 = 7;
pub const CPU_SUBTYPE_ARM_XSCALE: i32 = 8;
pub const CPU_SUBTYPE_ARM_V7: i32 = 9;
pub const CPU_SUBTYPE_ARM_V7F: i32 = 10;
pub const CPU_SUBTYPE_ARM_V7S: i32 = 11;
pub const CPU_SUBTYPE_ARM_V7K: i32 = 12;
pub const CPU_SUBTYPE_ARM_V6M: i32 = 14;
pub const CPU_SUBTYPE_ARM_V7M: i32 = 15;
pub const CPU_SUBTYPE_ARM_V7EM: i32 = 16;

// General subtypes
pub const CPU_SUBTYPE_MULTIPLE: i32 = -1;
pub const CPU_SUBTYPE_LITTLE_ENDIAN: i32 = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: i32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powerpc_subtypes() {
        assert_eq!(CPU_SUBTYPE_POWERPC_ALL, 0);
        assert_eq!(CPU_SUBTYPE_POWERPC_601, 1);
        assert_eq!(CPU_SUBTYPE_POWERPC_970, 100);
        assert_eq!(CPU_SUBTYPE_POWERPC_MAX, 10);
        assert_eq!(CPU_SUBTYPE_POWERPC_SCVGER, 11);
    }

    #[test]
    fn intel_subtype_formula() {
        // cpu_subtype_intel(f, m) = f + (m << 4)
        assert_eq!(cpu_subtype_intel(3, 0), 3);
        assert_eq!(cpu_subtype_intel(4, 8), 132); // 4 + (8 << 4) = 4 + 128
        assert_eq!(cpu_subtype_intel(6, 1), 22);  // 6 + 16
        assert_eq!(cpu_subtype_intel(12, 1), 28); // 12 + 16
    }

    #[test]
    fn i386_subtypes() {
        assert_eq!(CPU_SUBTYPE_I386_ALL, 3);
        assert_eq!(CPU_SUBTYPE_386, 3);
        assert_eq!(CPU_SUBTYPE_486, 4);
        assert_eq!(CPU_SUBTYPE_486SX, 132);
        assert_eq!(CPU_SUBTYPE_586, 5);
        assert_eq!(CPU_SUBTYPE_PENT, 5);
        assert_eq!(CPU_SUBTYPE_PENTPRO, 22);
        assert_eq!(CPU_SUBTYPE_PENTII_M3, 54);
        assert_eq!(CPU_SUBTYPE_PENTII_M5, 86);
        assert_eq!(CPU_SUBTYPE_CELERON, 103);
        assert_eq!(CPU_SUBTYPE_CELERON_MOBILE, 119);
        assert_eq!(CPU_SUBTYPE_PENTIUM_3, 8);
        assert_eq!(CPU_SUBTYPE_PENTIUM_3_M, 24);
        assert_eq!(CPU_SUBTYPE_PENTIUM_3_XEON, 40);
        assert_eq!(CPU_SUBTYPE_PENTIUM_M, 9);
        assert_eq!(CPU_SUBTYPE_PENTIUM_4, 10);
        assert_eq!(CPU_SUBTYPE_PENTIUM_4_M, 26);
        assert_eq!(CPU_SUBTYPE_ITANIUM, 11);
        assert_eq!(CPU_SUBTYPE_ITANIUM_2, 27);
        assert_eq!(CPU_SUBTYPE_XEON, 12);
        assert_eq!(CPU_SUBTYPE_XEON_MP, 28);
    }

    #[test]
    fn x86_subtypes() {
        assert_eq!(CPU_SUBTYPE_X86_ALL, 3);
        assert_eq!(CPU_SUBTYPE_X86_ARCH1, 4);
        assert_eq!(CPU_THREADTYPE_INTEL_HTT, 1);
    }

    #[test]
    fn mips_subtypes() {
        assert_eq!(CPU_SUBTYPE_MIPS_ALL, 0);
        assert_eq!(CPU_SUBTYPE_MIPS_R2300, 1);
        assert_eq!(CPU_SUBTYPE_MIPS_R2000A, 4);
        assert_eq!(CPU_SUBTYPE_MIPS_R3000A, 6);
        assert_eq!(CPU_SUBTYPE_MIPS_R3000, 7);
    }

    #[test]
    fn vax_subtypes() {
        assert_eq!(CPU_SUBTYPE_VAX_ALL, 0);
        assert_eq!(CPU_SUBTYPE_VAX780, 1);
        assert_eq!(CPU_SUBTYPE_UVAXIII, 12);
    }

    #[test]
    fn arm_subtypes() {
        assert_eq!(CPU_SUBTYPE_ARM_ALL, 0);
        assert_eq!(CPU_SUBTYPE_ARM_V4T, 5);
        assert_eq!(CPU_SUBTYPE_ARM_V5, 7);
        assert_eq!(CPU_SUBTYPE_ARM_V5TEJ, 7);
        assert_eq!(CPU_SUBTYPE_ARM_V7, 9);
        assert_eq!(CPU_SUBTYPE_ARM_V7EM, 16);
    }

    #[test]
    fn general_subtypes() {
        assert_eq!(CPU_SUBTYPE_MULTIPLE, -1);
        assert_eq!(CPU_SUBTYPE_LITTLE_ENDIAN, 0);
        assert_eq!(CPU_SUBTYPE_BIG_ENDIAN, 1);
    }

    #[test]
    fn mc680x0_subtypes() {
        assert_eq!(CPU_SUBTYPE_MC680X0_ALL, 1);
        assert_eq!(CPU_SUBTYPE_MC68030, 1);
        assert_eq!(CPU_SUBTYPE_MC68040, 2);
        assert_eq!(CPU_SUBTYPE_MC68030_ONLY, 3);
    }
}
