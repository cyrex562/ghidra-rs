use std::collections::HashSet;

/// PE section characteristic flags from the `Characteristics` field of a section header.
///
/// Each variant corresponds to one entry in the `IMAGE_SCN_*` bitmask table from the
/// Microsoft PE/COFF specification.  Note that `MemPurgeable` and `Mem16Bit` share the
/// same mask value (0x00020000) — this matches the Java source exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionFlags {
    TypeNoPad,
    Reserved0001,
    CntCode,
    CntInitializedData,
    CntUninitializedData,
    LnkOther,
    LnkInfo,
    Reserved0040,
    LnkRemove,
    LnkComdat,
    Gprel,
    MemPurgeable,
    Mem16Bit,
    MemLocked,
    MemPreload,
    Align1Bytes,
    Align2Bytes,
    Align4Bytes,
    Align8Bytes,
    Align16Bytes,
    Align32Bytes,
    Align64Bytes,
    Align128Bytes,
    Align256Bytes,
    Align512Bytes,
    Align1024Bytes,
    Align2048Bytes,
    Align4096Bytes,
    Align8192Bytes,
    LnkNrelocOvfl,
    MemDiscardable,
    MemNotCached,
    MemNotPaged,
    MemShared,
    MemExecute,
    MemRead,
    MemWrite,
}

impl SectionFlags {
    /// All variants in declaration order, used for iteration.
    pub const ALL: &'static [SectionFlags] = &[
        SectionFlags::TypeNoPad,
        SectionFlags::Reserved0001,
        SectionFlags::CntCode,
        SectionFlags::CntInitializedData,
        SectionFlags::CntUninitializedData,
        SectionFlags::LnkOther,
        SectionFlags::LnkInfo,
        SectionFlags::Reserved0040,
        SectionFlags::LnkRemove,
        SectionFlags::LnkComdat,
        SectionFlags::Gprel,
        SectionFlags::MemPurgeable,
        SectionFlags::Mem16Bit,
        SectionFlags::MemLocked,
        SectionFlags::MemPreload,
        SectionFlags::Align1Bytes,
        SectionFlags::Align2Bytes,
        SectionFlags::Align4Bytes,
        SectionFlags::Align8Bytes,
        SectionFlags::Align16Bytes,
        SectionFlags::Align32Bytes,
        SectionFlags::Align64Bytes,
        SectionFlags::Align128Bytes,
        SectionFlags::Align256Bytes,
        SectionFlags::Align512Bytes,
        SectionFlags::Align1024Bytes,
        SectionFlags::Align2048Bytes,
        SectionFlags::Align4096Bytes,
        SectionFlags::Align8192Bytes,
        SectionFlags::LnkNrelocOvfl,
        SectionFlags::MemDiscardable,
        SectionFlags::MemNotCached,
        SectionFlags::MemNotPaged,
        SectionFlags::MemShared,
        SectionFlags::MemExecute,
        SectionFlags::MemRead,
        SectionFlags::MemWrite,
    ];

    /// Returns the canonical `IMAGE_SCN_*` string alias for this flag.
    pub fn alias(self) -> &'static str {
        match self {
            SectionFlags::TypeNoPad => "IMAGE_SCN_TYPE_NO_PAD",
            SectionFlags::Reserved0001 => "IMAGE_SCN_RESERVED_0001",
            SectionFlags::CntCode => "IMAGE_SCN_CNT_CODE",
            SectionFlags::CntInitializedData => "IMAGE_SCN_CNT_INITIALIZED_DATA",
            SectionFlags::CntUninitializedData => "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            SectionFlags::LnkOther => "IMAGE_SCN_LNK_OTHER",
            SectionFlags::LnkInfo => "IMAGE_SCN_LNK_INFO",
            SectionFlags::Reserved0040 => "IMAGE_SCN_RESERVED_0040",
            SectionFlags::LnkRemove => "IMAGE_SCN_LNK_REMOVE",
            SectionFlags::LnkComdat => "IMAGE_SCN_LNK_COMDAT",
            SectionFlags::Gprel => "IMAGE_SCN_GPREL",
            SectionFlags::MemPurgeable => "IMAGE_SCN_MEM_PURGEABLE",
            SectionFlags::Mem16Bit => "IMAGE_SCN_MEM_16BIT",
            SectionFlags::MemLocked => "IMAGE_SCN_MEM_LOCKED",
            SectionFlags::MemPreload => "IMAGE_SCN_MEM_PRELOAD",
            SectionFlags::Align1Bytes => "IMAGE_SCN_ALIGN_1BYTES",
            SectionFlags::Align2Bytes => "IMAGE_SCN_ALIGN_2BYTES",
            SectionFlags::Align4Bytes => "IMAGE_SCN_ALIGN_4BYTES",
            SectionFlags::Align8Bytes => "IMAGE_SCN_ALIGN_8BYTES",
            SectionFlags::Align16Bytes => "IMAGE_SCN_ALIGN_16BYTES",
            SectionFlags::Align32Bytes => "IMAGE_SCN_ALIGN_32BYTES",
            SectionFlags::Align64Bytes => "IMAGE_SCN_ALIGN_64BYTES",
            SectionFlags::Align128Bytes => "IMAGE_SCN_ALIGN_128BYTES",
            SectionFlags::Align256Bytes => "IMAGE_SCN_ALIGN_256BYTES",
            SectionFlags::Align512Bytes => "IMAGE_SCN_ALIGN_512BYTES",
            SectionFlags::Align1024Bytes => "IMAGE_SCN_ALIGN_1024BYTES",
            SectionFlags::Align2048Bytes => "IMAGE_SCN_ALIGN_2048BYTES",
            SectionFlags::Align4096Bytes => "IMAGE_SCN_ALIGN_4096BYTES",
            SectionFlags::Align8192Bytes => "IMAGE_SCN_ALIGN_8192BYTES",
            SectionFlags::LnkNrelocOvfl => "IMAGE_SCN_LNK_NRELOC_OVFL",
            SectionFlags::MemDiscardable => "IMAGE_SCN_MEM_DISCARDABLE",
            SectionFlags::MemNotCached => "IMAGE_SCN_MEM_NOT_CACHED",
            SectionFlags::MemNotPaged => "IMAGE_SCN_MEM_NOT_PAGED",
            SectionFlags::MemShared => "IMAGE_SCN_MEM_SHARED",
            SectionFlags::MemExecute => "IMAGE_SCN_MEM_EXECUTE",
            SectionFlags::MemRead => "IMAGE_SCN_MEM_READ",
            SectionFlags::MemWrite => "IMAGE_SCN_MEM_WRITE",
        }
    }

    /// Returns the bitmask value for this flag.
    pub fn mask(self) -> u32 {
        match self {
            SectionFlags::TypeNoPad => 0x0000_0008,
            SectionFlags::Reserved0001 => 0x0000_0010,
            SectionFlags::CntCode => 0x0000_0020,
            SectionFlags::CntInitializedData => 0x0000_0040,
            SectionFlags::CntUninitializedData => 0x0000_0080,
            SectionFlags::LnkOther => 0x0000_0100,
            SectionFlags::LnkInfo => 0x0000_0200,
            SectionFlags::Reserved0040 => 0x0000_0400,
            SectionFlags::LnkRemove => 0x0000_0800,
            SectionFlags::LnkComdat => 0x0000_1000,
            SectionFlags::Gprel => 0x0000_8000,
            // MemPurgeable and Mem16Bit intentionally share the same mask value.
            SectionFlags::MemPurgeable => 0x0002_0000,
            SectionFlags::Mem16Bit => 0x0002_0000,
            SectionFlags::MemLocked => 0x0004_0000,
            SectionFlags::MemPreload => 0x0008_0000,
            SectionFlags::Align1Bytes => 0x0010_0000,
            SectionFlags::Align2Bytes => 0x0020_0000,
            SectionFlags::Align4Bytes => 0x0030_0000,
            SectionFlags::Align8Bytes => 0x0040_0000,
            SectionFlags::Align16Bytes => 0x0050_0000,
            SectionFlags::Align32Bytes => 0x0060_0000,
            SectionFlags::Align64Bytes => 0x0070_0000,
            SectionFlags::Align128Bytes => 0x0080_0000,
            SectionFlags::Align256Bytes => 0x0090_0000,
            SectionFlags::Align512Bytes => 0x00A0_0000,
            SectionFlags::Align1024Bytes => 0x00B0_0000,
            SectionFlags::Align2048Bytes => 0x00C0_0000,
            SectionFlags::Align4096Bytes => 0x00D0_0000,
            SectionFlags::Align8192Bytes => 0x00E0_0000,
            SectionFlags::LnkNrelocOvfl => 0x0100_0000,
            SectionFlags::MemDiscardable => 0x0200_0000,
            SectionFlags::MemNotCached => 0x0400_0000,
            SectionFlags::MemNotPaged => 0x0800_0000,
            SectionFlags::MemShared => 0x1000_0000,
            SectionFlags::MemExecute => 0x2000_0000,
            SectionFlags::MemRead => 0x4000_0000,
            SectionFlags::MemWrite => 0x8000_0000,
        }
    }

    /// Returns the human-readable description for this flag.
    pub fn description(self) -> &'static str {
        match self {
            SectionFlags::TypeNoPad => "The section should not be padded to the next boundary.",
            SectionFlags::Reserved0001 => "Reserved for future use.",
            SectionFlags::CntCode => "The section contains executable code.",
            SectionFlags::CntInitializedData => "The section contains initialized data.",
            SectionFlags::CntUninitializedData => "The section contains uninitialized data.",
            SectionFlags::LnkOther => "Reserved for future use.",
            SectionFlags::LnkInfo => "The section contains comments or other information.This is valid for object files only.",
            SectionFlags::Reserved0040 => "Reserved for future use.",
            SectionFlags::LnkRemove => "The section will not become part of the image. This is valid only for object files.",
            SectionFlags::LnkComdat => "The section contains COMDAT data. This is valid only for object files.",
            SectionFlags::Gprel => "The section contains data referenced through the global pointer (GP).",
            SectionFlags::MemPurgeable => "Reserved for future use.",
            SectionFlags::Mem16Bit => "Reserved for future use.",
            SectionFlags::MemLocked => "Reserved for future use.",
            SectionFlags::MemPreload => "Reserved for future use.",
            SectionFlags::Align1Bytes => "Align data on a 1-byte boundary. Valid only for object files.",
            SectionFlags::Align2Bytes => "Align data on a 2-byte boundary. Valid only for object files.",
            SectionFlags::Align4Bytes => "Align data on a 4-byte boundary. Valid only for object files.",
            SectionFlags::Align8Bytes => "Align data on an 8-byte boundary. Valid only for object files.",
            SectionFlags::Align16Bytes => "Align data on a 16-byte boundary. Valid only for object files.",
            SectionFlags::Align32Bytes => "Align data on a 32-byte boundary. Valid only for object files.",
            SectionFlags::Align64Bytes => "Align data on a 64-byte boundary. Valid only for object files.",
            SectionFlags::Align128Bytes => "Align data on a 128-byte boundary. Valid only for object files.",
            SectionFlags::Align256Bytes => "Align data on a 256-byte boundary. Valid only for object files.",
            SectionFlags::Align512Bytes => "Align data on a 512-byte boundary. Valid only for object files.",
            SectionFlags::Align1024Bytes => "Align data on a 1024-byte boundary. Valid only for object files.",
            SectionFlags::Align2048Bytes => "Align data on a 2048-byte boundary. Valid only for object files.",
            SectionFlags::Align4096Bytes => "Align data on a 4096-byte boundary. Valid only for object files.",
            SectionFlags::Align8192Bytes => "Align data on an 8192-byte boundary. Valid only for object files.",
            SectionFlags::LnkNrelocOvfl => "The section contains extended relocations.",
            SectionFlags::MemDiscardable => "The section can be discarded as needed.",
            SectionFlags::MemNotCached => "The section cannot be cached.",
            SectionFlags::MemNotPaged => "The section is not pageable.",
            SectionFlags::MemShared => "The section can be shared in memory.",
            SectionFlags::MemExecute => "The section can be executed as code.",
            SectionFlags::MemRead => "The section can be read.",
            SectionFlags::MemWrite => "The section can be written to.",
        }
    }
}

/// Returns the set of [`SectionFlags`] whose masks are set in `value`.
///
/// Mirrors `SectionFlags.resolveFlags(int)` from the Java source.  Because some masks
/// are multi-bit (the `ALIGN_*` family) and two variants share a mask (`MemPurgeable` /
/// `Mem16Bit`), a single input value may resolve to multiple overlapping entries.
pub fn resolve_flags(value: u32) -> HashSet<SectionFlags> {
    SectionFlags::ALL
        .iter()
        .copied()
        .filter(|f| (value & f.mask()) == f.mask())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_has_correct_count() {
        assert_eq!(SectionFlags::ALL.len(), 37);
    }

    #[test]
    fn mask_spot_checks() {
        assert_eq!(SectionFlags::CntCode.mask(), 0x0000_0020);
        assert_eq!(SectionFlags::MemRead.mask(), 0x4000_0000);
        assert_eq!(SectionFlags::MemWrite.mask(), 0x8000_0000);
        assert_eq!(SectionFlags::LnkNrelocOvfl.mask(), 0x0100_0000);
        assert_eq!(SectionFlags::Align4096Bytes.mask(), 0x00D0_0000);
    }

    #[test]
    fn shared_mask_purgeable_and_16bit() {
        assert_eq!(SectionFlags::MemPurgeable.mask(), SectionFlags::Mem16Bit.mask());
        assert_eq!(SectionFlags::MemPurgeable.mask(), 0x0002_0000);
    }

    #[test]
    fn alias_spot_checks() {
        assert_eq!(SectionFlags::CntCode.alias(), "IMAGE_SCN_CNT_CODE");
        assert_eq!(SectionFlags::MemWrite.alias(), "IMAGE_SCN_MEM_WRITE");
        assert_eq!(SectionFlags::Align8192Bytes.alias(), "IMAGE_SCN_ALIGN_8192BYTES");
        assert_eq!(SectionFlags::MemPurgeable.alias(), "IMAGE_SCN_MEM_PURGEABLE");
        assert_eq!(SectionFlags::Mem16Bit.alias(), "IMAGE_SCN_MEM_16BIT");
    }

    #[test]
    fn description_spot_checks() {
        assert_eq!(
            SectionFlags::CntCode.description(),
            "The section contains executable code."
        );
        assert_eq!(
            SectionFlags::MemWrite.description(),
            "The section can be written to."
        );
        assert_eq!(
            SectionFlags::LnkNrelocOvfl.description(),
            "The section contains extended relocations."
        );
    }

    #[test]
    fn resolve_zero_returns_empty() {
        assert!(resolve_flags(0).is_empty());
    }

    #[test]
    fn resolve_single_flag() {
        let result = resolve_flags(0x0000_0020);
        assert!(result.contains(&SectionFlags::CntCode));
    }

    #[test]
    fn resolve_multiple_flags() {
        let value = 0x0000_0020 | 0x4000_0000 | 0x8000_0000;
        let result = resolve_flags(value);
        assert!(result.contains(&SectionFlags::CntCode));
        assert!(result.contains(&SectionFlags::MemRead));
        assert!(result.contains(&SectionFlags::MemWrite));
    }

    #[test]
    fn resolve_shared_mask_returns_both() {
        // MemPurgeable and Mem16Bit share 0x00020000; both should be returned.
        let result = resolve_flags(0x0002_0000);
        assert!(result.contains(&SectionFlags::MemPurgeable));
        assert!(result.contains(&SectionFlags::Mem16Bit));
    }

    #[test]
    fn resolve_mem_write_high_bit() {
        let result = resolve_flags(0x8000_0000);
        assert!(result.contains(&SectionFlags::MemWrite));
        assert!(!result.contains(&SectionFlags::MemRead));
    }
}
