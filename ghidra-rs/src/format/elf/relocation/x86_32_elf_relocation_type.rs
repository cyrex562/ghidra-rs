//! x86 32-bit ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.X86_32_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// x86 32-bit ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum X86_32ElfRelocationType {
    R_386_NONE,
    R_386_32,
    R_386_PC32,
    R_386_GOT32,
    R_386_PLT32,
    R_386_COPY,
    R_386_GLOB_DAT,
    R_386_JMP_SLOT,
    R_386_RELATIVE,
    R_386_GOTOFF,
    R_386_GOTPC,
    R_386_32PLT,
    R_386_TLS_TPOFF,
    R_386_TLS_IE,
    R_386_TLS_GOTIE,
    R_386_TLS_LE,
    R_386_TLS_GD,
    R_386_TLS_LDM,
    R_386_TLS_GD_32,
    R_386_TLS_GD_PUSH,
    R_386_TLS_GD_CALL,
    R_386_TLS_GD_POP,
    R_386_TLS_LDM_32,
    R_386_TLS_LDM_PUSH,
    R_386_TLS_LDM_CALL,
    R_386_TLS_LDM_POP,
    R_386_TLS_LDO_32,
    R_386_TLS_IE_32,
    R_386_TLS_LE_32,
    R_386_TLS_DTPMOD32,
    R_386_TLS_DTPOFF32,
    R_386_TLS_TPOFF32,
    R_386_TLS_GOTDESC,
    R_386_TLS_DESC_CALL,
    R_386_TLS_DESC,
    R_386_IRELATIVE,
    R_386_GOT32X,
    R_386_USED_BY_INTEL_200,
    R_386_GNU_VTINHERIT,
    R_386_GNU_VTENTRY,
}

impl X86_32ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use X86_32ElfRelocationType::*;
        match self {
            R_386_NONE => 0,
            R_386_32 => 1,
            R_386_PC32 => 2,
            R_386_GOT32 => 3,
            R_386_PLT32 => 4,
            R_386_COPY => 5,
            R_386_GLOB_DAT => 6,
            R_386_JMP_SLOT => 7,
            R_386_RELATIVE => 8,
            R_386_GOTOFF => 9,
            R_386_GOTPC => 10,
            R_386_32PLT => 11,
            R_386_TLS_TPOFF => 14,
            R_386_TLS_IE => 15,
            R_386_TLS_GOTIE => 16,
            R_386_TLS_LE => 17,
            R_386_TLS_GD => 18,
            R_386_TLS_LDM => 19,
            R_386_TLS_GD_32 => 24,
            R_386_TLS_GD_PUSH => 25,
            R_386_TLS_GD_CALL => 26,
            R_386_TLS_GD_POP => 27,
            R_386_TLS_LDM_32 => 28,
            R_386_TLS_LDM_PUSH => 29,
            R_386_TLS_LDM_CALL => 30,
            R_386_TLS_LDM_POP => 31,
            R_386_TLS_LDO_32 => 32,
            R_386_TLS_IE_32 => 33,
            R_386_TLS_LE_32 => 34,
            R_386_TLS_DTPMOD32 => 35,
            R_386_TLS_DTPOFF32 => 36,
            R_386_TLS_TPOFF32 => 37,
            R_386_TLS_GOTDESC => 39,
            R_386_TLS_DESC_CALL => 40,
            R_386_TLS_DESC => 41,
            R_386_IRELATIVE => 42,
            R_386_GOT32X => 43,
            R_386_USED_BY_INTEL_200 => 200,
            R_386_GNU_VTINHERIT => 250,
            R_386_GNU_VTENTRY => 251,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use X86_32ElfRelocationType::*;
        match self {
            R_386_NONE => "R_386_NONE",
            R_386_32 => "R_386_32",
            R_386_PC32 => "R_386_PC32",
            R_386_GOT32 => "R_386_GOT32",
            R_386_PLT32 => "R_386_PLT32",
            R_386_COPY => "R_386_COPY",
            R_386_GLOB_DAT => "R_386_GLOB_DAT",
            R_386_JMP_SLOT => "R_386_JMP_SLOT",
            R_386_RELATIVE => "R_386_RELATIVE",
            R_386_GOTOFF => "R_386_GOTOFF",
            R_386_GOTPC => "R_386_GOTPC",
            R_386_32PLT => "R_386_32PLT",
            R_386_TLS_TPOFF => "R_386_TLS_TPOFF",
            R_386_TLS_IE => "R_386_TLS_IE",
            R_386_TLS_GOTIE => "R_386_TLS_GOTIE",
            R_386_TLS_LE => "R_386_TLS_LE",
            R_386_TLS_GD => "R_386_TLS_GD",
            R_386_TLS_LDM => "R_386_TLS_LDM",
            R_386_TLS_GD_32 => "R_386_TLS_GD_32",
            R_386_TLS_GD_PUSH => "R_386_TLS_GD_PUSH",
            R_386_TLS_GD_CALL => "R_386_TLS_GD_CALL",
            R_386_TLS_GD_POP => "R_386_TLS_GD_POP",
            R_386_TLS_LDM_32 => "R_386_TLS_LDM_32",
            R_386_TLS_LDM_PUSH => "R_386_TLS_LDM_PUSH",
            R_386_TLS_LDM_CALL => "R_386_TLS_LDM_CALL",
            R_386_TLS_LDM_POP => "R_386_TLS_LDM_POP",
            R_386_TLS_LDO_32 => "R_386_TLS_LDO_32",
            R_386_TLS_IE_32 => "R_386_TLS_IE_32",
            R_386_TLS_LE_32 => "R_386_TLS_LE_32",
            R_386_TLS_DTPMOD32 => "R_386_TLS_DTPMOD32",
            R_386_TLS_DTPOFF32 => "R_386_TLS_DTPOFF32",
            R_386_TLS_TPOFF32 => "R_386_TLS_TPOFF32",
            R_386_TLS_GOTDESC => "R_386_TLS_GOTDESC",
            R_386_TLS_DESC_CALL => "R_386_TLS_DESC_CALL",
            R_386_TLS_DESC => "R_386_TLS_DESC",
            R_386_IRELATIVE => "R_386_IRELATIVE",
            R_386_GOT32X => "R_386_GOT32X",
            R_386_USED_BY_INTEL_200 => "R_386_USED_BY_INTEL_200",
            R_386_GNU_VTINHERIT => "R_386_GNU_VTINHERIT",
            R_386_GNU_VTENTRY => "R_386_GNU_VTENTRY",
        }
    }
}

impl ElfRelocationType for X86_32ElfRelocationType {
    fn name(&self) -> &str {
        self.name_str()
    }

    fn type_id(&self) -> i32 {
        self.type_id_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_has_type_id_zero() {
        assert_eq!(X86_32ElfRelocationType::R_386_NONE.type_id(), 0);
        assert_eq!(X86_32ElfRelocationType::R_386_NONE.name(), "R_386_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(X86_32ElfRelocationType::R_386_32.type_id(), 1);
        assert_eq!(X86_32ElfRelocationType::R_386_PC32.type_id(), 2);
        assert_eq!(X86_32ElfRelocationType::R_386_COPY.type_id(), 5);
        assert_eq!(X86_32ElfRelocationType::R_386_GLOB_DAT.type_id(), 6);
        assert_eq!(X86_32ElfRelocationType::R_386_JMP_SLOT.type_id(), 7);
    }

    #[test]
    fn non_contiguous_id_gaps_are_preserved() {
        // Java skips typeIds 12-13 (between R_386_32PLT at 11 and R_386_TLS_TPOFF at 14)
        assert_eq!(X86_32ElfRelocationType::R_386_32PLT.type_id(), 11);
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_TPOFF.type_id(), 14);

        // Java skips typeIds 20-23 (between R_386_TLS_LDM at 19 and R_386_TLS_GD_32 at 24)
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_LDM.type_id(), 19);
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_GD_32.type_id(), 24);

        // Java skips typeIds 38 (between R_386_TLS_TPOFF32 at 37 and R_386_TLS_GOTDESC at 39)
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_TPOFF32.type_id(), 37);
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_GOTDESC.type_id(), 39);
    }

    #[test]
    fn high_range_constants_match_java_ids() {
        assert_eq!(X86_32ElfRelocationType::R_386_IRELATIVE.type_id(), 42);
        assert_eq!(X86_32ElfRelocationType::R_386_GOT32X.type_id(), 43);
        assert_eq!(X86_32ElfRelocationType::R_386_USED_BY_INTEL_200.type_id(), 200);
        assert_eq!(X86_32ElfRelocationType::R_386_GNU_VTINHERIT.type_id(), 250);
        assert_eq!(X86_32ElfRelocationType::R_386_GNU_VTENTRY.type_id(), 251);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &X86_32ElfRelocationType::R_386_GLOB_DAT;
        assert_eq!(r.type_id(), 6);
        assert_eq!(r.name(), "R_386_GLOB_DAT");
    }

    #[test]
    fn tls_relocations_have_correct_ids() {
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_GD.type_id(), 18);
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_LDM.type_id(), 19);
        assert_eq!(X86_32ElfRelocationType::R_386_TLS_DESC.type_id(), 41);
    }
}
