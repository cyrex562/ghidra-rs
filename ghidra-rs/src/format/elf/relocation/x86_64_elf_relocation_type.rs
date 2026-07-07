//! x86 64-bit ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.X86_64_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// x86 64-bit ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum X86_64ElfRelocationType {
    R_X86_64_NONE,
    R_X86_64_64,
    R_X86_64_PC32,
    R_X86_64_GOT32,
    R_X86_64_PLT32,
    R_X86_64_COPY,
    R_X86_64_GLOB_DAT,
    R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE,
    R_X86_64_GOTPCREL,
    R_X86_64_32,
    R_X86_64_32S,
    R_X86_64_16,
    R_X86_64_PC16,
    R_X86_64_8,
    R_X86_64_PC8,
    R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF64,
    R_X86_64_TPOFF64,
    R_X86_64_TLSGD,
    R_X86_64_TLSLD,
    R_X86_64_DTPOFF32,
    R_X86_64_GOTTPOFF,
    R_X86_64_TPOFF32,
    R_X86_64_PC64,
    R_X86_64_GOTOFF64,
    R_X86_64_GOTPC32,
    R_X86_64_GOT64,
    R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64,
    R_X86_64_GOTPLT64,
    R_X86_64_PLTOFF64,
    R_X86_64_SIZE32,
    R_X86_64_SIZE64,
    R_X86_64_GOTPC32_TLSDESC,
    R_X86_64_TLSDESC_CALL,
    R_X86_64_TLSDESC,
    R_X86_64_IRELATIVE,
    R_X86_64_RELATIVE64,
    R_X86_64_PC32_BND,
    R_X86_64_PLT32_BND,
    R_X86_64_GOTPCRELX,
    R_X86_64_REX_GOTPCRELX,
    R_X86_64_CODE_4_GOTPCRELX,
    R_X86_64_CODE_4_GOTTPOFF,
    R_X86_64_CODE_4_GOTPC32_TLSDESC,
    R_X86_64_CODE_5_GOTPCRELX,
    R_X86_64_CODE_5_GOTPC32_TLSDESC,
    R_X86_64_CODE_5_GOTTPOFF,
    R_X86_64_CODE_6_GOTPCRELX,
    R_X86_64_CODE_6_GOTTPOFF,
    R_X86_64_CODE_6_GOTPC32_TLSDESC,
    R_X86_64_GNU_VTINHERIT,
    R_X86_64_GNU_VTENTRY,
}

impl X86_64ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use X86_64ElfRelocationType::*;
        match self {
            R_X86_64_NONE => 0,
            R_X86_64_64 => 1,
            R_X86_64_PC32 => 2,
            R_X86_64_GOT32 => 3,
            R_X86_64_PLT32 => 4,
            R_X86_64_COPY => 5,
            R_X86_64_GLOB_DAT => 6,
            R_X86_64_JUMP_SLOT => 7,
            R_X86_64_RELATIVE => 8,
            R_X86_64_GOTPCREL => 9,
            R_X86_64_32 => 10,
            R_X86_64_32S => 11,
            R_X86_64_16 => 12,
            R_X86_64_PC16 => 13,
            R_X86_64_8 => 14,
            R_X86_64_PC8 => 15,
            R_X86_64_DTPMOD64 => 16,
            R_X86_64_DTPOFF64 => 17,
            R_X86_64_TPOFF64 => 18,
            R_X86_64_TLSGD => 19,
            R_X86_64_TLSLD => 20,
            R_X86_64_DTPOFF32 => 21,
            R_X86_64_GOTTPOFF => 22,
            R_X86_64_TPOFF32 => 23,
            R_X86_64_PC64 => 24,
            R_X86_64_GOTOFF64 => 25,
            R_X86_64_GOTPC32 => 26,
            R_X86_64_GOT64 => 27,
            R_X86_64_GOTPCREL64 => 28,
            R_X86_64_GOTPC64 => 29,
            R_X86_64_GOTPLT64 => 30,
            R_X86_64_PLTOFF64 => 31,
            R_X86_64_SIZE32 => 32,
            R_X86_64_SIZE64 => 33,
            R_X86_64_GOTPC32_TLSDESC => 34,
            R_X86_64_TLSDESC_CALL => 35,
            R_X86_64_TLSDESC => 36,
            R_X86_64_IRELATIVE => 37,
            R_X86_64_RELATIVE64 => 38,
            R_X86_64_PC32_BND => 39,
            R_X86_64_PLT32_BND => 40,
            R_X86_64_GOTPCRELX => 41,
            R_X86_64_REX_GOTPCRELX => 42,
            R_X86_64_CODE_4_GOTPCRELX => 43,
            R_X86_64_CODE_4_GOTTPOFF => 44,
            R_X86_64_CODE_4_GOTPC32_TLSDESC => 45,
            R_X86_64_CODE_5_GOTPCRELX => 46,
            R_X86_64_CODE_5_GOTPC32_TLSDESC => 47,
            R_X86_64_CODE_5_GOTTPOFF => 48,
            R_X86_64_CODE_6_GOTPCRELX => 49,
            R_X86_64_CODE_6_GOTTPOFF => 50,
            R_X86_64_CODE_6_GOTPC32_TLSDESC => 51,
            R_X86_64_GNU_VTINHERIT => 250,
            R_X86_64_GNU_VTENTRY => 251,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use X86_64ElfRelocationType::*;
        match self {
            R_X86_64_NONE => "R_X86_64_NONE",
            R_X86_64_64 => "R_X86_64_64",
            R_X86_64_PC32 => "R_X86_64_PC32",
            R_X86_64_GOT32 => "R_X86_64_GOT32",
            R_X86_64_PLT32 => "R_X86_64_PLT32",
            R_X86_64_COPY => "R_X86_64_COPY",
            R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
            R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
            R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
            R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
            R_X86_64_32 => "R_X86_64_32",
            R_X86_64_32S => "R_X86_64_32S",
            R_X86_64_16 => "R_X86_64_16",
            R_X86_64_PC16 => "R_X86_64_PC16",
            R_X86_64_8 => "R_X86_64_8",
            R_X86_64_PC8 => "R_X86_64_PC8",
            R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
            R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
            R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
            R_X86_64_TLSGD => "R_X86_64_TLSGD",
            R_X86_64_TLSLD => "R_X86_64_TLSLD",
            R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
            R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
            R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
            R_X86_64_PC64 => "R_X86_64_PC64",
            R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
            R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
            R_X86_64_GOT64 => "R_X86_64_GOT64",
            R_X86_64_GOTPCREL64 => "R_X86_64_GOTPCREL64",
            R_X86_64_GOTPC64 => "R_X86_64_GOTPC64",
            R_X86_64_GOTPLT64 => "R_X86_64_GOTPLT64",
            R_X86_64_PLTOFF64 => "R_X86_64_PLTOFF64",
            R_X86_64_SIZE32 => "R_X86_64_SIZE32",
            R_X86_64_SIZE64 => "R_X86_64_SIZE64",
            R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC",
            R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL",
            R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
            R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
            R_X86_64_RELATIVE64 => "R_X86_64_RELATIVE64",
            R_X86_64_PC32_BND => "R_X86_64_PC32_BND",
            R_X86_64_PLT32_BND => "R_X86_64_PLT32_BND",
            R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
            R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
            R_X86_64_CODE_4_GOTPCRELX => "R_X86_64_CODE_4_GOTPCRELX",
            R_X86_64_CODE_4_GOTTPOFF => "R_X86_64_CODE_4_GOTTPOFF",
            R_X86_64_CODE_4_GOTPC32_TLSDESC => "R_X86_64_CODE_4_GOTPC32_TLSDESC",
            R_X86_64_CODE_5_GOTPCRELX => "R_X86_64_CODE_5_GOTPCRELX",
            R_X86_64_CODE_5_GOTPC32_TLSDESC => "R_X86_64_CODE_5_GOTPC32_TLSDESC",
            R_X86_64_CODE_5_GOTTPOFF => "R_X86_64_CODE_5_GOTTPOFF",
            R_X86_64_CODE_6_GOTPCRELX => "R_X86_64_CODE_6_GOTPCRELX",
            R_X86_64_CODE_6_GOTTPOFF => "R_X86_64_CODE_6_GOTTPOFF",
            R_X86_64_CODE_6_GOTPC32_TLSDESC => "R_X86_64_CODE_6_GOTPC32_TLSDESC",
            R_X86_64_GNU_VTINHERIT => "R_X86_64_GNU_VTINHERIT",
            R_X86_64_GNU_VTENTRY => "R_X86_64_GNU_VTENTRY",
        }
    }
}

impl ElfRelocationType for X86_64ElfRelocationType {
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
        assert_eq!(X86_64ElfRelocationType::R_X86_64_NONE.type_id(), 0);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_NONE.name(), "R_X86_64_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_64.type_id(), 1);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC32.type_id(), 2);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOT32.type_id(), 3);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PLT32.type_id(), 4);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_COPY.type_id(), 5);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GLOB_DAT.type_id(), 6);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_JUMP_SLOT.type_id(), 7);
    }

    #[test]
    fn early_relocation_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_NONE.type_id(), 0);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_RELATIVE.type_id(), 8);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPCREL.type_id(), 9);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_32.type_id(), 10);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_32S.type_id(), 11);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_16.type_id(), 12);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC16.type_id(), 13);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_8.type_id(), 14);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC8.type_id(), 15);
    }

    #[test]
    fn tls_relocation_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_DTPMOD64.type_id(), 16);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_DTPOFF64.type_id(), 17);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TPOFF64.type_id(), 18);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TLSGD.type_id(), 19);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TLSLD.type_id(), 20);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_DTPOFF32.type_id(), 21);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTTPOFF.type_id(), 22);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TPOFF32.type_id(), 23);
    }

    #[test]
    fn mid_range_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC64.type_id(), 24);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTOFF64.type_id(), 25);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPC32.type_id(), 26);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOT64.type_id(), 27);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPCREL64.type_id(), 28);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPC64.type_id(), 29);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPLT64.type_id(), 30);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PLTOFF64.type_id(), 31);
    }

    #[test]
    fn size_and_descriptor_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_SIZE32.type_id(), 32);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_SIZE64.type_id(), 33);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPC32_TLSDESC.type_id(), 34);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TLSDESC_CALL.type_id(), 35);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TLSDESC.type_id(), 36);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_IRELATIVE.type_id(), 37);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_RELATIVE64.type_id(), 38);
    }

    #[test]
    fn bnd_and_indirect_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC32_BND.type_id(), 39);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PLT32_BND.type_id(), 40);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GOTPCRELX.type_id(), 41);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_REX_GOTPCRELX.type_id(), 42);
    }

    #[test]
    fn code_4_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_4_GOTPCRELX.type_id(), 43);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_4_GOTTPOFF.type_id(), 44);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_4_GOTPC32_TLSDESC.type_id(), 45);
    }

    #[test]
    fn code_5_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_5_GOTPCRELX.type_id(), 46);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_5_GOTPC32_TLSDESC.type_id(), 47);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_5_GOTTPOFF.type_id(), 48);
    }

    #[test]
    fn code_6_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_6_GOTPCRELX.type_id(), 49);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_6_GOTTPOFF.type_id(), 50);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_6_GOTPC32_TLSDESC.type_id(), 51);
    }

    #[test]
    fn gnu_types_match_java() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GNU_VTINHERIT.type_id(), 250);
        assert_eq!(X86_64ElfRelocationType::R_X86_64_GNU_VTENTRY.type_id(), 251);
    }

    #[test]
    fn all_names_match_constant_names() {
        assert_eq!(X86_64ElfRelocationType::R_X86_64_64.name(), "R_X86_64_64");
        assert_eq!(X86_64ElfRelocationType::R_X86_64_PC32.name(), "R_X86_64_PC32");
        assert_eq!(X86_64ElfRelocationType::R_X86_64_COPY.name(), "R_X86_64_COPY");
        assert_eq!(X86_64ElfRelocationType::R_X86_64_TLSGD.name(), "R_X86_64_TLSGD");
        assert_eq!(X86_64ElfRelocationType::R_X86_64_IRELATIVE.name(), "R_X86_64_IRELATIVE");
        assert_eq!(X86_64ElfRelocationType::R_X86_64_CODE_6_GOTPC32_TLSDESC.name(), "R_X86_64_CODE_6_GOTPC32_TLSDESC");
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &X86_64ElfRelocationType::R_X86_64_COPY;
        assert_eq!(r.type_id(), 5);
        assert_eq!(r.name(), "R_X86_64_COPY");
    }

    #[test]
    fn trait_object_dispatch_for_multiple_types() {
        let types = vec![
            X86_64ElfRelocationType::R_X86_64_NONE,
            X86_64ElfRelocationType::R_X86_64_64,
            X86_64ElfRelocationType::R_X86_64_TLSGD,
            X86_64ElfRelocationType::R_X86_64_GNU_VTENTRY,
        ];
        let trait_objects: Vec<&dyn ElfRelocationType> = types.iter().map(|t| t as &dyn ElfRelocationType).collect();

        assert_eq!(trait_objects[0].type_id(), 0);
        assert_eq!(trait_objects[1].type_id(), 1);
        assert_eq!(trait_objects[2].type_id(), 19);
        assert_eq!(trait_objects[3].type_id(), 251);
    }
}
