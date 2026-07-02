//! Atmel AVR32 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.AVR32_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Atmel AVR32 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Avr32ElfRelocationType {
    R_AVR32_NONE,
    R_AVR32_32,
    R_AVR32_16,
    R_AVR32_8,
    R_AVR32_32_PCREL,
    R_AVR32_16_PCREL,
    R_AVR32_8_PCREL,
    R_AVR32_DIFF32,
    R_AVR32_DIFF16,
    R_AVR32_DIFF8,
    R_AVR32_GOT32,
    R_AVR32_GOT16,
    R_AVR32_GOT8,
    R_AVR32_21S,
    R_AVR32_16U,
    R_AVR32_16S,
    R_AVR32_8S,
    R_AVR32_8S_EXT,
    R_AVR32_22H_PCREL,
    R_AVR32_18W_PCREL,
    R_AVR32_16B_PCREL,
    R_AVR32_16N_PCREL,
    R_AVR32_14UW_PCREL,
    R_AVR32_11H_PCREL,
    R_AVR32_10UW_PCREL,
    R_AVR32_9H_PCREL,
    R_AVR32_9UW_PCREL,
    R_AVR32_HI16,
    R_AVR32_LO16,
    R_AVR32_GOTPC,
    R_AVR32_GOTCALL,
    R_AVR32_LDA_GOT,
    R_AVR32_GOT21S,
    R_AVR32_GOT18SW,
    R_AVR32_GOT16S,
    R_AVR32_GOT7UW,
    R_AVR32_32_CPENT,
    R_AVR32_CPCALL,
    R_AVR32_16_CP,
    R_AVR32_9W_CP,
    R_AVR32_RELATIVE,
    R_AVR32_GLOB_DAT,
    R_AVR32_JMP_SLOT,
    R_AVR32_ALIGN,
    R_AVR32_NUM,
    /// Total size in bytes of the Global Offset Table.
    DT_AVR32_GOTSZ,
    /// CPU-specific flag for the ELF header `e_flags` field.
    EF_AVR32_LINKRELAX,
    /// CPU-specific flag for the ELF header `e_flags` field.
    EF_AVR32_PIC,
}

impl Avr32ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Avr32ElfRelocationType::*;
        match self {
            R_AVR32_NONE => 0,
            R_AVR32_32 => 1,
            R_AVR32_16 => 2,
            R_AVR32_8 => 3,
            R_AVR32_32_PCREL => 4,
            R_AVR32_16_PCREL => 5,
            R_AVR32_8_PCREL => 6,
            R_AVR32_DIFF32 => 7,
            R_AVR32_DIFF16 => 8,
            R_AVR32_DIFF8 => 9,
            R_AVR32_GOT32 => 10,
            R_AVR32_GOT16 => 11,
            R_AVR32_GOT8 => 12,
            R_AVR32_21S => 13,
            R_AVR32_16U => 14,
            R_AVR32_16S => 15,
            R_AVR32_8S => 16,
            R_AVR32_8S_EXT => 17,
            R_AVR32_22H_PCREL => 18,
            R_AVR32_18W_PCREL => 19,
            R_AVR32_16B_PCREL => 20,
            R_AVR32_16N_PCREL => 21,
            R_AVR32_14UW_PCREL => 22,
            R_AVR32_11H_PCREL => 23,
            R_AVR32_10UW_PCREL => 24,
            R_AVR32_9H_PCREL => 25,
            R_AVR32_9UW_PCREL => 26,
            R_AVR32_HI16 => 27,
            R_AVR32_LO16 => 28,
            R_AVR32_GOTPC => 29,
            R_AVR32_GOTCALL => 30,
            R_AVR32_LDA_GOT => 31,
            R_AVR32_GOT21S => 32,
            R_AVR32_GOT18SW => 33,
            R_AVR32_GOT16S => 34,
            R_AVR32_GOT7UW => 35,
            R_AVR32_32_CPENT => 36,
            R_AVR32_CPCALL => 37,
            R_AVR32_16_CP => 38,
            R_AVR32_9W_CP => 39,
            R_AVR32_RELATIVE => 40,
            R_AVR32_GLOB_DAT => 41,
            R_AVR32_JMP_SLOT => 42,
            R_AVR32_ALIGN => 43,
            R_AVR32_NUM => 44,
            DT_AVR32_GOTSZ => 0x70000001,
            EF_AVR32_LINKRELAX => 0x01,
            EF_AVR32_PIC => 0x02,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Avr32ElfRelocationType::*;
        match self {
            R_AVR32_NONE => "R_AVR32_NONE",
            R_AVR32_32 => "R_AVR32_32",
            R_AVR32_16 => "R_AVR32_16",
            R_AVR32_8 => "R_AVR32_8",
            R_AVR32_32_PCREL => "R_AVR32_32_PCREL",
            R_AVR32_16_PCREL => "R_AVR32_16_PCREL",
            R_AVR32_8_PCREL => "R_AVR32_8_PCREL",
            R_AVR32_DIFF32 => "R_AVR32_DIFF32",
            R_AVR32_DIFF16 => "R_AVR32_DIFF16",
            R_AVR32_DIFF8 => "R_AVR32_DIFF8",
            R_AVR32_GOT32 => "R_AVR32_GOT32",
            R_AVR32_GOT16 => "R_AVR32_GOT16",
            R_AVR32_GOT8 => "R_AVR32_GOT8",
            R_AVR32_21S => "R_AVR32_21S",
            R_AVR32_16U => "R_AVR32_16U",
            R_AVR32_16S => "R_AVR32_16S",
            R_AVR32_8S => "R_AVR32_8S",
            R_AVR32_8S_EXT => "R_AVR32_8S_EXT",
            R_AVR32_22H_PCREL => "R_AVR32_22H_PCREL",
            R_AVR32_18W_PCREL => "R_AVR32_18W_PCREL",
            R_AVR32_16B_PCREL => "R_AVR32_16B_PCREL",
            R_AVR32_16N_PCREL => "R_AVR32_16N_PCREL",
            R_AVR32_14UW_PCREL => "R_AVR32_14UW_PCREL",
            R_AVR32_11H_PCREL => "R_AVR32_11H_PCREL",
            R_AVR32_10UW_PCREL => "R_AVR32_10UW_PCREL",
            R_AVR32_9H_PCREL => "R_AVR32_9H_PCREL",
            R_AVR32_9UW_PCREL => "R_AVR32_9UW_PCREL",
            R_AVR32_HI16 => "R_AVR32_HI16",
            R_AVR32_LO16 => "R_AVR32_LO16",
            R_AVR32_GOTPC => "R_AVR32_GOTPC",
            R_AVR32_GOTCALL => "R_AVR32_GOTCALL",
            R_AVR32_LDA_GOT => "R_AVR32_LDA_GOT",
            R_AVR32_GOT21S => "R_AVR32_GOT21S",
            R_AVR32_GOT18SW => "R_AVR32_GOT18SW",
            R_AVR32_GOT16S => "R_AVR32_GOT16S",
            R_AVR32_GOT7UW => "R_AVR32_GOT7UW",
            R_AVR32_32_CPENT => "R_AVR32_32_CPENT",
            R_AVR32_CPCALL => "R_AVR32_CPCALL",
            R_AVR32_16_CP => "R_AVR32_16_CP",
            R_AVR32_9W_CP => "R_AVR32_9W_CP",
            R_AVR32_RELATIVE => "R_AVR32_RELATIVE",
            R_AVR32_GLOB_DAT => "R_AVR32_GLOB_DAT",
            R_AVR32_JMP_SLOT => "R_AVR32_JMP_SLOT",
            R_AVR32_ALIGN => "R_AVR32_ALIGN",
            R_AVR32_NUM => "R_AVR32_NUM",
            DT_AVR32_GOTSZ => "DT_AVR32_GOTSZ",
            EF_AVR32_LINKRELAX => "EF_AVR32_LINKRELAX",
            EF_AVR32_PIC => "EF_AVR32_PIC",
        }
    }
}

impl ElfRelocationType for Avr32ElfRelocationType {
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
        assert_eq!(Avr32ElfRelocationType::R_AVR32_NONE.type_id(), 0);
        assert_eq!(Avr32ElfRelocationType::R_AVR32_NONE.name(), "R_AVR32_NONE");
    }

    #[test]
    fn data_relocations_match_java_ids() {
        assert_eq!(Avr32ElfRelocationType::R_AVR32_32.type_id(), 1);
        assert_eq!(Avr32ElfRelocationType::R_AVR32_16.type_id(), 2);
        assert_eq!(Avr32ElfRelocationType::R_AVR32_8.type_id(), 3);
    }

    #[test]
    fn final_normal_relocation_matches_java_id() {
        assert_eq!(Avr32ElfRelocationType::R_AVR32_NUM.type_id(), 44);
    }

    #[test]
    fn dynamic_tag_constant_matches_java_id() {
        assert_eq!(Avr32ElfRelocationType::DT_AVR32_GOTSZ.type_id(), 0x70000001);
    }

    #[test]
    fn header_flag_constants_match_java_ids() {
        assert_eq!(Avr32ElfRelocationType::EF_AVR32_LINKRELAX.type_id(), 0x01);
        assert_eq!(Avr32ElfRelocationType::EF_AVR32_PIC.type_id(), 0x02);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &Avr32ElfRelocationType::R_AVR32_GLOB_DAT;
        assert_eq!(r.type_id(), 41);
        assert_eq!(r.name(), "R_AVR32_GLOB_DAT");
    }
}
