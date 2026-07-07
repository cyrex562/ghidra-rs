//! Atmel AVR8 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.AVR8_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Atmel AVR8 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Avr8ElfRelocationType {
    R_AVR_NONE,
    R_AVR_32,
    R_AVR_7_PCREL,
    R_AVR_13_PCREL,
    R_AVR_16,
    R_AVR_16_PM,
    R_AVR_LO8_LDI,
    R_AVR_HI8_LDI,
    R_AVR_HH8_LDI,
    R_AVR_LO8_LDI_NEG,
    R_AVR_HI8_LDI_NEG,
    R_AVR_HH8_LDI_NEG,
    R_AVR_LO8_LDI_PM,
    R_AVR_HI8_LDI_PM,
    R_AVR_HH8_LDI_PM,
    R_AVR_LO8_LDI_PM_NEG,
    R_AVR_HI8_LDI_PM_NEG,
    R_AVR_HH8_LDI_PM_NEG,
    R_AVR_CALL,
    R_AVR_LDI,
    R_AVR_6,
    R_AVR_6_ADIW,
    R_AVR_MS8_LDI,
    R_AVR_MS8_LDI_NEG,
    R_AVR_LO8_LDI_GS,
    R_AVR_HI8_LDI_GS,
    R_AVR_8,
    R_AVR_8_LO8,
    R_AVR_8_HI8,
    R_AVR_8_HLO8,
    R_AVR_DIFF8,
    R_AVR_DIFF16,
    R_AVR_DIFF32,
    R_AVR_LDS_STS_16,
    R_AVR_PORT6,
    R_AVR_PORT5,
    R_AVR_32_PCREL,
}

impl Avr8ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Avr8ElfRelocationType::*;
        match self {
            R_AVR_NONE => 0,
            R_AVR_32 => 1,
            R_AVR_7_PCREL => 2,
            R_AVR_13_PCREL => 3,
            R_AVR_16 => 4,
            R_AVR_16_PM => 5,
            R_AVR_LO8_LDI => 6,
            R_AVR_HI8_LDI => 7,
            R_AVR_HH8_LDI => 8,
            R_AVR_LO8_LDI_NEG => 9,
            R_AVR_HI8_LDI_NEG => 10,
            R_AVR_HH8_LDI_NEG => 11,
            R_AVR_LO8_LDI_PM => 12,
            R_AVR_HI8_LDI_PM => 13,
            R_AVR_HH8_LDI_PM => 14,
            R_AVR_LO8_LDI_PM_NEG => 15,
            R_AVR_HI8_LDI_PM_NEG => 16,
            R_AVR_HH8_LDI_PM_NEG => 17,
            R_AVR_CALL => 18,
            R_AVR_LDI => 19,
            R_AVR_6 => 20,
            R_AVR_6_ADIW => 21,
            R_AVR_MS8_LDI => 22,
            R_AVR_MS8_LDI_NEG => 23,
            R_AVR_LO8_LDI_GS => 24,
            R_AVR_HI8_LDI_GS => 25,
            R_AVR_8 => 26,
            R_AVR_8_LO8 => 27,
            R_AVR_8_HI8 => 28,
            R_AVR_8_HLO8 => 29,
            R_AVR_DIFF8 => 30,
            R_AVR_DIFF16 => 31,
            R_AVR_DIFF32 => 32,
            R_AVR_LDS_STS_16 => 33,
            R_AVR_PORT6 => 34,
            R_AVR_PORT5 => 35,
            R_AVR_32_PCREL => 36,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Avr8ElfRelocationType::*;
        match self {
            R_AVR_NONE => "R_AVR_NONE",
            R_AVR_32 => "R_AVR_32",
            R_AVR_7_PCREL => "R_AVR_7_PCREL",
            R_AVR_13_PCREL => "R_AVR_13_PCREL",
            R_AVR_16 => "R_AVR_16",
            R_AVR_16_PM => "R_AVR_16_PM",
            R_AVR_LO8_LDI => "R_AVR_LO8_LDI",
            R_AVR_HI8_LDI => "R_AVR_HI8_LDI",
            R_AVR_HH8_LDI => "R_AVR_HH8_LDI",
            R_AVR_LO8_LDI_NEG => "R_AVR_LO8_LDI_NEG",
            R_AVR_HI8_LDI_NEG => "R_AVR_HI8_LDI_NEG",
            R_AVR_HH8_LDI_NEG => "R_AVR_HH8_LDI_NEG",
            R_AVR_LO8_LDI_PM => "R_AVR_LO8_LDI_PM",
            R_AVR_HI8_LDI_PM => "R_AVR_HI8_LDI_PM",
            R_AVR_HH8_LDI_PM => "R_AVR_HH8_LDI_PM",
            R_AVR_LO8_LDI_PM_NEG => "R_AVR_LO8_LDI_PM_NEG",
            R_AVR_HI8_LDI_PM_NEG => "R_AVR_HI8_LDI_PM_NEG",
            R_AVR_HH8_LDI_PM_NEG => "R_AVR_HH8_LDI_PM_NEG",
            R_AVR_CALL => "R_AVR_CALL",
            R_AVR_LDI => "R_AVR_LDI",
            R_AVR_6 => "R_AVR_6",
            R_AVR_6_ADIW => "R_AVR_6_ADIW",
            R_AVR_MS8_LDI => "R_AVR_MS8_LDI",
            R_AVR_MS8_LDI_NEG => "R_AVR_MS8_LDI_NEG",
            R_AVR_LO8_LDI_GS => "R_AVR_LO8_LDI_GS",
            R_AVR_HI8_LDI_GS => "R_AVR_HI8_LDI_GS",
            R_AVR_8 => "R_AVR_8",
            R_AVR_8_LO8 => "R_AVR_8_LO8",
            R_AVR_8_HI8 => "R_AVR_8_HI8",
            R_AVR_8_HLO8 => "R_AVR_8_HLO8",
            R_AVR_DIFF8 => "R_AVR_DIFF8",
            R_AVR_DIFF16 => "R_AVR_DIFF16",
            R_AVR_DIFF32 => "R_AVR_DIFF32",
            R_AVR_LDS_STS_16 => "R_AVR_LDS_STS_16",
            R_AVR_PORT6 => "R_AVR_PORT6",
            R_AVR_PORT5 => "R_AVR_PORT5",
            R_AVR_32_PCREL => "R_AVR_32_PCREL",
        }
    }
}

impl ElfRelocationType for Avr8ElfRelocationType {
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
        assert_eq!(Avr8ElfRelocationType::R_AVR_NONE.type_id(), 0);
        assert_eq!(Avr8ElfRelocationType::R_AVR_NONE.name(), "R_AVR_NONE");
    }

    #[test]
    fn relocation_types_match_java_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_32.type_id(), 1);
        assert_eq!(Avr8ElfRelocationType::R_AVR_7_PCREL.type_id(), 2);
        assert_eq!(Avr8ElfRelocationType::R_AVR_13_PCREL.type_id(), 3);
        assert_eq!(Avr8ElfRelocationType::R_AVR_16.type_id(), 4);
    }

    #[test]
    fn pcrel_relocations_have_correct_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_7_PCREL.type_id(), 2);
        assert_eq!(Avr8ElfRelocationType::R_AVR_13_PCREL.type_id(), 3);
    }

    #[test]
    fn ldi_variants_have_correct_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_LO8_LDI.type_id(), 6);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HI8_LDI.type_id(), 7);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HH8_LDI.type_id(), 8);
    }

    #[test]
    fn neg_ldi_variants_have_correct_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_LO8_LDI_NEG.type_id(), 9);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HI8_LDI_NEG.type_id(), 10);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HH8_LDI_NEG.type_id(), 11);
    }

    #[test]
    fn pm_variants_have_correct_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_LO8_LDI_PM.type_id(), 12);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HI8_LDI_PM.type_id(), 13);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HH8_LDI_PM.type_id(), 14);
    }

    #[test]
    fn pm_neg_variants_have_correct_ids() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_LO8_LDI_PM_NEG.type_id(), 15);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HI8_LDI_PM_NEG.type_id(), 16);
        assert_eq!(Avr8ElfRelocationType::R_AVR_HH8_LDI_PM_NEG.type_id(), 17);
    }

    #[test]
    fn final_relocation_matches_java_id() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_32_PCREL.type_id(), 36);
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(Avr8ElfRelocationType::R_AVR_CALL.name(), "R_AVR_CALL");
        assert_eq!(Avr8ElfRelocationType::R_AVR_LDI.name(), "R_AVR_LDI");
        assert_eq!(Avr8ElfRelocationType::R_AVR_DIFF8.name(), "R_AVR_DIFF8");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &Avr8ElfRelocationType::R_AVR_8;
        assert_eq!(r.type_id(), 26);
        assert_eq!(r.name(), "R_AVR_8");
    }
}
