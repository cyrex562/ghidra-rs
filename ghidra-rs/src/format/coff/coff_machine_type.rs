// TODO: Need to confirm these 2 TI values are correct. TI datasheet doesn't mention them.
pub const TICOFF1MAGIC: u16 = 0x00c1;
pub const TICOFF2MAGIC: u16 = 0x00c2;

/// The contents of this field are assumed to be applicable to any machine type.
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;

/// Alpha
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;

/// Alpha 64
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;

/// Matsushita AM33
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;

/// x64
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// AMD Am29000 big endian
pub const IMAGE_FILE_MACHINE_AM29KBIGMAGIC: u16 = 0x017a;

/// AMD Am29000 little endian
pub const IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC: u16 = 0x017b;

/// ARM little endian
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;

/// ARM64 little endian
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// ARM Thumb-2 little endian
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;

/// EFI byte code
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0ebc;

/// Intel 386 or later processors and compatible processors
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

/// Intel 386 or later processors and compatible processors (PTX)
pub const IMAGE_FILE_MACHINE_I386_PTX: u16 = 0x0154;

/// Intel 386 or later processors and compatible processors (AIX)
pub const IMAGE_FILE_MACHINE_I386_AIX: u16 = 0x0175;

/// Intel i960 with read-only text segment
pub const IMAGE_FILE_MACHINE_I960ROMAGIC: u16 = 0x0160;

/// Intel i960 with read-write text segment
pub const IMAGE_FILE_MACHINE_I960RWMAGIC: u16 = 0x0161;

/// Intel Itanium processor family
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;

/// Mitsubishi M32R little endian
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;

/// MIPS16
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;

/// MIPS with FPU
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;

/// MIPS16 with FPU
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;

/// Motorola 68000
pub const IMAGE_FILE_MACHINE_M68KMAGIC: u16 = 0x0268;

/// Motorola 68000 Apple A/UX (big endian)
pub const IMAGE_FILE_MACHINE_M68KAUX: u16 = 0x0150;

/// PIC-30 (dsPIC30F)
pub const IMAGE_FILE_MACHINE_PIC30: u16 = 0x1236;

/// Power PC little endian
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;

/// Power PC with floating point support
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;

/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;

/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;

/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;

/// RISC-V 32-bit address space
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;

/// RISC-V 64-bit address space
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;

/// RISC-V 128-bit address space
pub const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;

/// Hitachi SH3
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;

/// Hitachi SH3 DSP
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;

/// Hitachi SH4
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;

/// Hitachi SH5
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;

/// Texas Instruments TMS320C3x/4x
pub const IMAGE_FILE_MACHINE_TI_TMS320C3X4X: u16 = 0x0093;

/// Texas Instruments TMS470
pub const IMAGE_FILE_MACHINE_TI_TMS470: u16 = 0x0097;

/// Texas Instruments TMS320C5400
pub const IMAGE_FILE_MACHINE_TI_TMS320C5400: u16 = 0x0098;

/// Texas Instruments TMS320C6000
pub const IMAGE_FILE_MACHINE_TI_TMS320C6000: u16 = 0x0099;

/// Texas Instruments TMS320C5500
pub const IMAGE_FILE_MACHINE_TI_TMS320C5500: u16 = 0x009c;

/// Texas Instruments TMS320C2800
pub const IMAGE_FILE_MACHINE_TI_TMS320C2800: u16 = 0x009d;

/// Texas Instruments MSP430
pub const IMAGE_FILE_MACHINE_TI_MSP430: u16 = 0x00a0;

/// Texas Instruments TMS320C5500+
pub const IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS: u16 = 0x00a1;

/// Thumb
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;

/// MIPS little-endian WCE v2
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;

const ALL_DEFINED: &[u16] = &[
    TICOFF1MAGIC,
    TICOFF2MAGIC,
    IMAGE_FILE_MACHINE_ALPHA,
    IMAGE_FILE_MACHINE_ALPHA64,
    IMAGE_FILE_MACHINE_AM33,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_AM29KBIGMAGIC,
    IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_EBC,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_I386_PTX,
    IMAGE_FILE_MACHINE_I386_AIX,
    IMAGE_FILE_MACHINE_I960ROMAGIC,
    IMAGE_FILE_MACHINE_I960RWMAGIC,
    IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_M32R,
    IMAGE_FILE_MACHINE_MIPS16,
    IMAGE_FILE_MACHINE_MIPSFPU,
    IMAGE_FILE_MACHINE_MIPSFPU16,
    IMAGE_FILE_MACHINE_M68KMAGIC,
    IMAGE_FILE_MACHINE_M68KAUX,
    IMAGE_FILE_MACHINE_PIC30,
    IMAGE_FILE_MACHINE_POWERPC,
    IMAGE_FILE_MACHINE_POWERPCFP,
    IMAGE_FILE_MACHINE_R3000,
    IMAGE_FILE_MACHINE_R4000,
    IMAGE_FILE_MACHINE_R10000,
    IMAGE_FILE_MACHINE_RISCV32,
    IMAGE_FILE_MACHINE_RISCV64,
    IMAGE_FILE_MACHINE_RISCV128,
    IMAGE_FILE_MACHINE_SH3,
    IMAGE_FILE_MACHINE_SH3DSP,
    IMAGE_FILE_MACHINE_SH4,
    IMAGE_FILE_MACHINE_SH5,
    IMAGE_FILE_MACHINE_TI_TMS320C3X4X,
    IMAGE_FILE_MACHINE_TI_TMS470,
    IMAGE_FILE_MACHINE_TI_TMS320C5400,
    IMAGE_FILE_MACHINE_TI_TMS320C6000,
    IMAGE_FILE_MACHINE_TI_TMS320C5500,
    IMAGE_FILE_MACHINE_TI_TMS320C2800,
    IMAGE_FILE_MACHINE_TI_MSP430,
    IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS,
    IMAGE_FILE_MACHINE_THUMB,
    IMAGE_FILE_MACHINE_WCEMIPSV2,
];

/// Returns `true` if `machine_type` matches one of the defined (non-UNKNOWN) constants.
///
/// Mirrors `CoffMachineType.isMachineTypeDefined`: `IMAGE_FILE_MACHINE_UNKNOWN` is explicitly
/// excluded because it is defined only for completeness and should be treated as unsupported.
pub fn is_machine_type_defined(machine_type: u16) -> bool {
    if machine_type == IMAGE_FILE_MACHINE_UNKNOWN {
        return false;
    }
    ALL_DEFINED.contains(&machine_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_defined() {
        assert!(!is_machine_type_defined(IMAGE_FILE_MACHINE_UNKNOWN));
    }

    #[test]
    fn zero_is_not_defined() {
        assert!(!is_machine_type_defined(0x0000));
    }

    #[test]
    fn known_types_are_defined() {
        let known = [
            IMAGE_FILE_MACHINE_ALPHA,
            IMAGE_FILE_MACHINE_ALPHA64,
            IMAGE_FILE_MACHINE_AM33,
            IMAGE_FILE_MACHINE_AMD64,
            IMAGE_FILE_MACHINE_AM29KBIGMAGIC,
            IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC,
            IMAGE_FILE_MACHINE_ARM,
            IMAGE_FILE_MACHINE_ARM64,
            IMAGE_FILE_MACHINE_ARMNT,
            IMAGE_FILE_MACHINE_EBC,
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_I386_PTX,
            IMAGE_FILE_MACHINE_I386_AIX,
            IMAGE_FILE_MACHINE_I960ROMAGIC,
            IMAGE_FILE_MACHINE_I960RWMAGIC,
            IMAGE_FILE_MACHINE_IA64,
            IMAGE_FILE_MACHINE_M32R,
            IMAGE_FILE_MACHINE_MIPS16,
            IMAGE_FILE_MACHINE_MIPSFPU,
            IMAGE_FILE_MACHINE_MIPSFPU16,
            IMAGE_FILE_MACHINE_M68KMAGIC,
            IMAGE_FILE_MACHINE_M68KAUX,
            IMAGE_FILE_MACHINE_PIC30,
            IMAGE_FILE_MACHINE_POWERPC,
            IMAGE_FILE_MACHINE_POWERPCFP,
            IMAGE_FILE_MACHINE_R3000,
            IMAGE_FILE_MACHINE_R4000,
            IMAGE_FILE_MACHINE_R10000,
            IMAGE_FILE_MACHINE_RISCV32,
            IMAGE_FILE_MACHINE_RISCV64,
            IMAGE_FILE_MACHINE_RISCV128,
            IMAGE_FILE_MACHINE_SH3,
            IMAGE_FILE_MACHINE_SH3DSP,
            IMAGE_FILE_MACHINE_SH4,
            IMAGE_FILE_MACHINE_SH5,
            IMAGE_FILE_MACHINE_TI_TMS320C3X4X,
            IMAGE_FILE_MACHINE_TI_TMS470,
            IMAGE_FILE_MACHINE_TI_TMS320C5400,
            IMAGE_FILE_MACHINE_TI_TMS320C6000,
            IMAGE_FILE_MACHINE_TI_TMS320C5500,
            IMAGE_FILE_MACHINE_TI_TMS320C2800,
            IMAGE_FILE_MACHINE_TI_MSP430,
            IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS,
            IMAGE_FILE_MACHINE_THUMB,
            IMAGE_FILE_MACHINE_WCEMIPSV2,
            TICOFF1MAGIC,
            TICOFF2MAGIC,
        ];
        for t in known {
            assert!(is_machine_type_defined(t), "expected defined: {t:#06x}");
        }
    }

    #[test]
    fn arbitrary_value_is_not_defined() {
        assert!(!is_machine_type_defined(0xffff));
        assert!(!is_machine_type_defined(0x0001));
        assert!(!is_machine_type_defined(0x1234));
    }

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(IMAGE_FILE_MACHINE_UNKNOWN, 0x0000);
        assert_eq!(IMAGE_FILE_MACHINE_ALPHA,   0x0184);
        assert_eq!(IMAGE_FILE_MACHINE_AMD64,   0x8664);
        assert_eq!(IMAGE_FILE_MACHINE_ARM64,   0xaa64);
        assert_eq!(IMAGE_FILE_MACHINE_M32R,    0x9041);
        assert_eq!(IMAGE_FILE_MACHINE_I386,    0x014c);
        assert_eq!(IMAGE_FILE_MACHINE_RISCV32, 0x5032);
        assert_eq!(IMAGE_FILE_MACHINE_RISCV64, 0x5064);
        assert_eq!(TICOFF1MAGIC,               0x00c1);
        assert_eq!(TICOFF2MAGIC,               0x00c2);
    }
}
