//! ARM-specific ELF program header constants.
//!
//! Ported from `ghidra.app.util.bin.format.elf.extend.ARM_ElfProgramHeaderConstants`.

/// Masks bits describing the format of data in subsequent words. The masked value is
/// described in Table 5-3, below.
pub const PT_ARM_ARCHEXT_FMTMSK: u32 = 0xff000000;
/// Masks bits describing the architecture profile required by the executable. The masked
/// value is described in Table 5-4, below.
pub const PT_ARM_ARCHEXT_PROFMSK: u32 = 0x00ff0000;
/// Masks bits describing the base architecture required by the executable. The masked value
/// is described in Table 5-5, below.
pub const PT_ARM_ARCHEXT_ARCHMSK: u32 = 0x000000ff;

// Table 5-3, Architecture compatibility data formats lists the architecture
// compatibility data formats defined by this ABI. All other format
// identifiers are reserved to future revisions of this specification.

/// There are no additional words of data. However, if EF_OSABI is non-zero, the relevant
/// platform ABI may define additional data that follows the initial word.
pub const PT_ARM_ARCHEXT_FMT_OS: u32 = 0x00000000;
/// 5.2.1.1, below describes the format of the following data words.
pub const PT_ARM_ARCHEXT_FMT_ABI: u32 = 0x01000000;

// Table 5-4, Architecture profile compatibility data.
// Lists the values specifying the architectural profile needed by an executable file.

/// The architecture has no profile variants, or the image has no profile-specific
/// constraints.
pub const PT_ARM_ARCHEXT_PROF_NONE: u32 = 0x0;
/// The executable file requires the Application profile.
pub const PT_ARM_ARCHEXT_PROF_ARM: u32 = (b'A' as u32) << 16;
/// The executable file requires the Real-Time profile.
pub const PT_ARM_ARCHEXT_PROF_RT: u32 = (b'R' as u32) << 16;
/// The executable file requires the Microcontroller profile.
pub const PT_ARM_ARCHEXT_PROF_MC: u32 = (b'M' as u32) << 16;
/// The executable file requires the 'classic' ('A' or 'R' profile) exception model.
pub const PT_ARM_ARCHEXT_PROF_CLASSIC: u32 = (b'S' as u32) << 16;

// Table 5-5, Architecture version compatibility data defines the values that
// specify the minimum architecture version needed by this executable file.
// These values are identical to those of the Tag_CPU_arch attribute used
// in the attributes section of a relocatable file.

/// The needed architecture is unknown or specified in some other way.
pub const PT_ARM_ARCHEXT_ARCH_UNKN: u32 = 0x00;
/// Architecture v4.
pub const PT_ARM_ARCHEXT_ARCHV4: u32 = 0x01;
/// Architecture v4T.
pub const PT_ARM_ARCHEXT_ARCHV4T: u32 = 0x02;
/// Architecture v5T.
pub const PT_ARM_ARCHEXT_ARCHV5T: u32 = 0x03;
/// Architecture v5TE.
pub const PT_ARM_ARCHEXT_ARCHV5TE: u32 = 0x04;
/// Architecture v5TEJ.
pub const PT_ARM_ARCHEXT_ARCHV5TEJ: u32 = 0x05;
/// Architecture v6.
pub const PT_ARM_ARCHEXT_ARCHV6: u32 = 0x06;
/// Architecture v6KZ.
pub const PT_ARM_ARCHEXT_ARCHV6KZ: u32 = 0x07;
/// Architecture v6T2.
pub const PT_ARM_ARCHEXT_ARCHV6T2: u32 = 0x08;
/// Architecture v6K.
pub const PT_ARM_ARCHEXT_ARCHV6K: u32 = 0x09;
/// Architecture v7 (in this case the architecture profile may also be required to fully
/// specify the needed execution environment).
pub const PT_ARM_ARCHEXT_ARCHV7: u32 = 0x0A;
/// Architecture v6M (e.g. Cortex M0).
pub const PT_ARM_ARCHEXT_ARCHV6M: u32 = 0x0B;
/// Architecture v6S-M (e.g. Cortex M0).
pub const PT_ARM_ARCHEXT_ARCHV6SM: u32 = 0x0C;
/// Architecture v7E-M.
pub const PT_ARM_ARCHEXT_ARCHV7EM: u32 = 0x0D;

// FLAGS

/// This masks an 8-bit version number, the version of the ABI to which this ELF file
/// conforms. This ABI is version 5. A value of 0 denotes unknown conformance.
pub const EF_ARM_EABIMASK: u32 = 0xFF000000;
/// The ELF file contains BE-8 code, suitable for execution on an ARM Architecture v6
/// processor. This flag must only be set on an executable file.
pub const EF_ARM_BE8: u32 = 0x00800000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archext_masks() {
        assert_eq!(PT_ARM_ARCHEXT_FMTMSK, 0xff000000);
        assert_eq!(PT_ARM_ARCHEXT_PROFMSK, 0x00ff0000);
        assert_eq!(PT_ARM_ARCHEXT_ARCHMSK, 0x000000ff);
        assert_eq!(
            PT_ARM_ARCHEXT_FMTMSK & PT_ARM_ARCHEXT_PROFMSK & PT_ARM_ARCHEXT_ARCHMSK,
            0
        );
    }

    #[test]
    fn archext_formats() {
        assert_eq!(PT_ARM_ARCHEXT_FMT_OS, 0x00000000);
        assert_eq!(PT_ARM_ARCHEXT_FMT_ABI, 0x01000000);
    }

    #[test]
    fn archext_profiles_use_ascii_char_in_high_word() {
        assert_eq!(PT_ARM_ARCHEXT_PROF_NONE, 0x0);
        assert_eq!(PT_ARM_ARCHEXT_PROF_ARM, 0x00410000);
        assert_eq!(PT_ARM_ARCHEXT_PROF_RT, 0x00520000);
        assert_eq!(PT_ARM_ARCHEXT_PROF_MC, 0x004D0000);
        assert_eq!(PT_ARM_ARCHEXT_PROF_CLASSIC, 0x00530000);
    }

    #[test]
    fn archext_versions_are_sequential() {
        assert_eq!(PT_ARM_ARCHEXT_ARCH_UNKN, 0x00);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV4, 0x01);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV4T, 0x02);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV5T, 0x03);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV5TE, 0x04);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV5TEJ, 0x05);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6, 0x06);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6KZ, 0x07);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6T2, 0x08);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6K, 0x09);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV7, 0x0A);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6M, 0x0B);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV6SM, 0x0C);
        assert_eq!(PT_ARM_ARCHEXT_ARCHV7EM, 0x0D);
    }

    #[test]
    fn eabi_flags() {
        assert_eq!(EF_ARM_EABIMASK, 0xFF000000);
        assert_eq!(EF_ARM_BE8, 0x00800000);
    }
}
