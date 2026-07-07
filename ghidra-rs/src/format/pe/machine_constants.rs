/// PE machine ID constants defined by standard header file `ntimage.h`.
///
/// See [Image File Machine Constants](https://msdn.microsoft.com/en-us/library/windows/desktop/mt804345%28v=vs.85%29.aspx).
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
/// Intel 386.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
/// MIPS little-endian (0x160 big-endian).
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
/// MIPS little-endian.
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
/// MIPS little-endian.
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
/// MIPS little-endian WCE v2.
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
/// Alpha AXP.
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
/// SH3 little-endian.
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
/// SH3E little-endian.
pub const IMAGE_FILE_MACHINE_SH3E: u16 = 0x01a4;
/// SH4 little-endian.
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
/// SH5.
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
/// ARM little-endian.
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
/// ARM Thumb/Thumb-2 little-endian.
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
/// ARM Thumb-2 little-endian.
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
/// PowerPC little-endian.
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;
/// PowerPC with floating-point support.
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
/// Intel 64.
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
/// ALPHA64.
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
/// Infineon.
pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0CEF;
/// EFI byte code.
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;
/// AMD64 (K8).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// M32R little-endian.
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
/// ARM v8 64-bit.
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xC0EE;
/// Alias for [`IMAGE_FILE_MACHINE_ALPHA64`].
pub const IMAGE_FILE_MACHINE_AXP64: u16 = IMAGE_FILE_MACHINE_ALPHA64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(IMAGE_FILE_MACHINE_UNKNOWN, 0x0000);
        assert_eq!(IMAGE_FILE_MACHINE_I386, 0x014c);
        assert_eq!(IMAGE_FILE_MACHINE_AMD64, 0x8664);
        assert_eq!(IMAGE_FILE_MACHINE_ARM64, 0xaa64);
        assert_eq!(IMAGE_FILE_MACHINE_IA64, 0x0200);
        assert_eq!(IMAGE_FILE_MACHINE_ARM, 0x01c0);
        assert_eq!(IMAGE_FILE_MACHINE_POWERPC, 0x01F0);
    }

    #[test]
    fn axp64_aliases_alpha64() {
        assert_eq!(IMAGE_FILE_MACHINE_AXP64, IMAGE_FILE_MACHINE_ALPHA64);
        assert_eq!(IMAGE_FILE_MACHINE_AXP64, 0x0284);
    }

    #[test]
    fn all_fit_u16() {
        // Verify none of the constants exceed u16::MAX (sanity check)
        let all: &[u16] = &[
            IMAGE_FILE_MACHINE_UNKNOWN,
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_R3000,
            IMAGE_FILE_MACHINE_R4000,
            IMAGE_FILE_MACHINE_R10000,
            IMAGE_FILE_MACHINE_WCEMIPSV2,
            IMAGE_FILE_MACHINE_ALPHA,
            IMAGE_FILE_MACHINE_SH3,
            IMAGE_FILE_MACHINE_SH3DSP,
            IMAGE_FILE_MACHINE_SH3E,
            IMAGE_FILE_MACHINE_SH4,
            IMAGE_FILE_MACHINE_SH5,
            IMAGE_FILE_MACHINE_ARM,
            IMAGE_FILE_MACHINE_THUMB,
            IMAGE_FILE_MACHINE_ARMNT,
            IMAGE_FILE_MACHINE_AM33,
            IMAGE_FILE_MACHINE_POWERPC,
            IMAGE_FILE_MACHINE_POWERPCFP,
            IMAGE_FILE_MACHINE_IA64,
            IMAGE_FILE_MACHINE_MIPS16,
            IMAGE_FILE_MACHINE_ALPHA64,
            IMAGE_FILE_MACHINE_MIPSFPU,
            IMAGE_FILE_MACHINE_MIPSFPU16,
            IMAGE_FILE_MACHINE_TRICORE,
            IMAGE_FILE_MACHINE_CEF,
            IMAGE_FILE_MACHINE_EBC,
            IMAGE_FILE_MACHINE_AMD64,
            IMAGE_FILE_MACHINE_M32R,
            IMAGE_FILE_MACHINE_ARM64,
            IMAGE_FILE_MACHINE_CEE,
            IMAGE_FILE_MACHINE_AXP64,
        ];
        assert_eq!(all.len(), 31);
    }
}
