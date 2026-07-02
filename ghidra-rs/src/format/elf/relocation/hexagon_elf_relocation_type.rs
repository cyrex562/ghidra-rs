//! Hexagon ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.Hexagon_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Hexagon ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum HexagonElfRelocationType {
    // V2
    R_HEXAGON_NONE,
    R_HEXAGON_B22_PCREL,
    R_HEXAGON_B15_PCREL,
    R_HEXAGON_B7_PCREL,
    R_HEXAGON_LO16,
    R_HEXAGON_HI16,
    R_HEXAGON_32,
    R_HEXAGON_16,
    R_HEXAGON_8,
    R_HEXAGON_GPREL16_0,
    R_HEXAGON_GPREL16_1,
    R_HEXAGON_GPREL16_2,
    R_HEXAGON_GPREL16_3,
    R_HEXAGON_HL16,
    // V3
    R_HEXAGON_B13_PCREL,
    // V4
    R_HEXAGON_B9_PCREL,
    // V4 (extenders)
    R_HEXAGON_B32_PCREL_X,
    R_HEXAGON_32_6_X,
    // V4 (extended)
    R_HEXAGON_B22_PCREL_X,
    R_HEXAGON_B15_PCREL_X,
    R_HEXAGON_B13_PCREL_X,
    R_HEXAGON_B9_PCREL_X,
    R_HEXAGON_B7_PCREL_X,
    R_HEXAGON_16_X,
    R_HEXAGON_12_X,
    R_HEXAGON_11_X,
    R_HEXAGON_10_X,
    R_HEXAGON_9_X,
    R_HEXAGON_8_X,
    R_HEXAGON_7_X,
    R_HEXAGON_6_X,
    // V2 PIC
    R_HEXAGON_32_PCREL,
    R_HEXAGON_COPY,
    R_HEXAGON_GLOB_DAT,
    R_HEXAGON_JMP_SLOT,
    R_HEXAGON_RELATIVE,
    R_HEXAGON_PLT_B22_PCREL,
    R_HEXAGON_GOTOFF_LO16,
    R_HEXAGON_GOTOFF_HI16,
    R_HEXAGON_GOTOFF_32,
    R_HEXAGON_GOT_LO16,
    R_HEXAGON_GOT_HI16,
    R_HEXAGON_GOT_32,
    R_HEXAGON_GOT_16,
    R_HEXAGON_DTPMOD_32,
    R_HEXAGON_DTPREL_LO16,
    R_HEXAGON_DTPREL_HI16,
    R_HEXAGON_DTPREL_32,
    R_HEXAGON_DTPREL_16,
    R_HEXAGON_GD_PLT_B22_PCREL,
    R_HEXAGON_GD_GOT_LO16,
    R_HEXAGON_GD_GOT_HI16,
    R_HEXAGON_GD_GOT_32,
    R_HEXAGON_GD_GOT_16,
    R_HEXAGON_IE_LO16,
    R_HEXAGON_IE_HI16,
    R_HEXAGON_IE_32,
    R_HEXAGON_IE_GOT_LO16,
    R_HEXAGON_IE_GOT_HI16,
    R_HEXAGON_IE_GOT_32,
    R_HEXAGON_IE_GOT_16,
    R_HEXAGON_TPREL_LO16,
    R_HEXAGON_TPREL_HI16,
    R_HEXAGON_TPREL_32,
    R_HEXAGON_TPREL_16,
    R_HEXAGON_6_PCREL_X,
    R_HEXAGON_GOTREL_32_6_X,
    R_HEXAGON_GOTREL_16_X,
    R_HEXAGON_GOTREL_11_X,
    R_HEXAGON_GOT_32_6_X,
    R_HEXAGON_GOT_16_X,
    R_HEXAGON_GOT_11_X,
    R_HEXAGON_DTPREL_32_6_X,
    R_HEXAGON_DTPREL_16_X,
    R_HEXAGON_DTPREL_11_X,
    R_HEXAGON_GD_GOT_32_6_X,
    R_HEXAGON_GD_GOT_16_X,
    R_HEXAGON_GD_GOT_11_X,
    R_HEXAGON_IE_32_6_X,
    R_HEXAGON_IE_16_X,
    R_HEXAGON_IE_GOT_32_6_X,
    R_HEXAGON_IE_GOT_16_X,
    R_HEXAGON_IE_GOT_11_X,
    R_HEXAGON_TPREL_32_6_X,
    R_HEXAGON_TPREL_16_X,
    R_HEXAGON_TPREL_11_X,
    R_HEXAGON_LD_PLT_B22_PCREL,
    R_HEXAGON_LD_GOT_LO16,
    R_HEXAGON_LD_GOT_HI16,
    R_HEXAGON_LD_GOT_32,
    R_HEXAGON_LD_GOT_16,
    R_HEXAGON_LD_GOT_32_6_X,
    R_HEXAGON_LD_GOT_16_X,
    R_HEXAGON_LD_GOT_11_X,
    R_HEXAGON_23_REG,
    R_HEXAGON_GD_PLT_B22_PCREL_X,
    R_HEXAGON_GD_PLT_B32_PCREL_X,
    R_HEXAGON_LD_PLT_B22_PCREL_X,
    R_HEXAGON_LD_PLT_B32_PCREL_X,
    R_HEXAGON_27_REG,
}

impl HexagonElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use HexagonElfRelocationType::*;
        match self {
            R_HEXAGON_NONE => 0,
            R_HEXAGON_B22_PCREL => 1,
            R_HEXAGON_B15_PCREL => 2,
            R_HEXAGON_B7_PCREL => 3,
            R_HEXAGON_LO16 => 4,
            R_HEXAGON_HI16 => 5,
            R_HEXAGON_32 => 6,
            R_HEXAGON_16 => 7,
            R_HEXAGON_8 => 8,
            R_HEXAGON_GPREL16_0 => 9,
            R_HEXAGON_GPREL16_1 => 10,
            R_HEXAGON_GPREL16_2 => 11,
            R_HEXAGON_GPREL16_3 => 12,
            R_HEXAGON_HL16 => 13,
            R_HEXAGON_B13_PCREL => 14,
            R_HEXAGON_B9_PCREL => 15,
            R_HEXAGON_B32_PCREL_X => 16,
            R_HEXAGON_32_6_X => 17,
            R_HEXAGON_B22_PCREL_X => 18,
            R_HEXAGON_B15_PCREL_X => 19,
            R_HEXAGON_B13_PCREL_X => 20,
            R_HEXAGON_B9_PCREL_X => 21,
            R_HEXAGON_B7_PCREL_X => 22,
            R_HEXAGON_16_X => 23,
            R_HEXAGON_12_X => 24,
            R_HEXAGON_11_X => 25,
            R_HEXAGON_10_X => 26,
            R_HEXAGON_9_X => 27,
            R_HEXAGON_8_X => 28,
            R_HEXAGON_7_X => 29,
            R_HEXAGON_6_X => 30,
            R_HEXAGON_32_PCREL => 31,
            R_HEXAGON_COPY => 32,
            R_HEXAGON_GLOB_DAT => 33,
            R_HEXAGON_JMP_SLOT => 34,
            R_HEXAGON_RELATIVE => 35,
            R_HEXAGON_PLT_B22_PCREL => 36,
            R_HEXAGON_GOTOFF_LO16 => 37,
            R_HEXAGON_GOTOFF_HI16 => 38,
            R_HEXAGON_GOTOFF_32 => 39,
            R_HEXAGON_GOT_LO16 => 40,
            R_HEXAGON_GOT_HI16 => 41,
            R_HEXAGON_GOT_32 => 42,
            R_HEXAGON_GOT_16 => 43,
            R_HEXAGON_DTPMOD_32 => 44,
            R_HEXAGON_DTPREL_LO16 => 45,
            R_HEXAGON_DTPREL_HI16 => 46,
            R_HEXAGON_DTPREL_32 => 47,
            R_HEXAGON_DTPREL_16 => 48,
            R_HEXAGON_GD_PLT_B22_PCREL => 49,
            R_HEXAGON_GD_GOT_LO16 => 50,
            R_HEXAGON_GD_GOT_HI16 => 51,
            R_HEXAGON_GD_GOT_32 => 52,
            R_HEXAGON_GD_GOT_16 => 53,
            R_HEXAGON_IE_LO16 => 54,
            R_HEXAGON_IE_HI16 => 55,
            R_HEXAGON_IE_32 => 56,
            R_HEXAGON_IE_GOT_LO16 => 57,
            R_HEXAGON_IE_GOT_HI16 => 58,
            R_HEXAGON_IE_GOT_32 => 59,
            R_HEXAGON_IE_GOT_16 => 60,
            R_HEXAGON_TPREL_LO16 => 61,
            R_HEXAGON_TPREL_HI16 => 62,
            R_HEXAGON_TPREL_32 => 63,
            R_HEXAGON_TPREL_16 => 64,
            R_HEXAGON_6_PCREL_X => 65,
            R_HEXAGON_GOTREL_32_6_X => 66,
            R_HEXAGON_GOTREL_16_X => 67,
            R_HEXAGON_GOTREL_11_X => 68,
            R_HEXAGON_GOT_32_6_X => 69,
            R_HEXAGON_GOT_16_X => 70,
            R_HEXAGON_GOT_11_X => 71,
            R_HEXAGON_DTPREL_32_6_X => 72,
            R_HEXAGON_DTPREL_16_X => 73,
            R_HEXAGON_DTPREL_11_X => 74,
            R_HEXAGON_GD_GOT_32_6_X => 75,
            R_HEXAGON_GD_GOT_16_X => 76,
            R_HEXAGON_GD_GOT_11_X => 77,
            R_HEXAGON_IE_32_6_X => 78,
            R_HEXAGON_IE_16_X => 79,
            R_HEXAGON_IE_GOT_32_6_X => 80,
            R_HEXAGON_IE_GOT_16_X => 81,
            R_HEXAGON_IE_GOT_11_X => 82,
            R_HEXAGON_TPREL_32_6_X => 83,
            R_HEXAGON_TPREL_16_X => 84,
            R_HEXAGON_TPREL_11_X => 85,
            R_HEXAGON_LD_PLT_B22_PCREL => 86,
            R_HEXAGON_LD_GOT_LO16 => 87,
            R_HEXAGON_LD_GOT_HI16 => 88,
            R_HEXAGON_LD_GOT_32 => 89,
            R_HEXAGON_LD_GOT_16 => 90,
            R_HEXAGON_LD_GOT_32_6_X => 91,
            R_HEXAGON_LD_GOT_16_X => 92,
            R_HEXAGON_LD_GOT_11_X => 93,
            R_HEXAGON_23_REG => 94,
            R_HEXAGON_GD_PLT_B22_PCREL_X => 95,
            R_HEXAGON_GD_PLT_B32_PCREL_X => 96,
            R_HEXAGON_LD_PLT_B22_PCREL_X => 97,
            R_HEXAGON_LD_PLT_B32_PCREL_X => 98,
            R_HEXAGON_27_REG => 99,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use HexagonElfRelocationType::*;
        match self {
            R_HEXAGON_NONE => "R_HEXAGON_NONE",
            R_HEXAGON_B22_PCREL => "R_HEXAGON_B22_PCREL",
            R_HEXAGON_B15_PCREL => "R_HEXAGON_B15_PCREL",
            R_HEXAGON_B7_PCREL => "R_HEXAGON_B7_PCREL",
            R_HEXAGON_LO16 => "R_HEXAGON_LO16",
            R_HEXAGON_HI16 => "R_HEXAGON_HI16",
            R_HEXAGON_32 => "R_HEXAGON_32",
            R_HEXAGON_16 => "R_HEXAGON_16",
            R_HEXAGON_8 => "R_HEXAGON_8",
            R_HEXAGON_GPREL16_0 => "R_HEXAGON_GPREL16_0",
            R_HEXAGON_GPREL16_1 => "R_HEXAGON_GPREL16_1",
            R_HEXAGON_GPREL16_2 => "R_HEXAGON_GPREL16_2",
            R_HEXAGON_GPREL16_3 => "R_HEXAGON_GPREL16_3",
            R_HEXAGON_HL16 => "R_HEXAGON_HL16",
            R_HEXAGON_B13_PCREL => "R_HEXAGON_B13_PCREL",
            R_HEXAGON_B9_PCREL => "R_HEXAGON_B9_PCREL",
            R_HEXAGON_B32_PCREL_X => "R_HEXAGON_B32_PCREL_X",
            R_HEXAGON_32_6_X => "R_HEXAGON_32_6_X",
            R_HEXAGON_B22_PCREL_X => "R_HEXAGON_B22_PCREL_X",
            R_HEXAGON_B15_PCREL_X => "R_HEXAGON_B15_PCREL_X",
            R_HEXAGON_B13_PCREL_X => "R_HEXAGON_B13_PCREL_X",
            R_HEXAGON_B9_PCREL_X => "R_HEXAGON_B9_PCREL_X",
            R_HEXAGON_B7_PCREL_X => "R_HEXAGON_B7_PCREL_X",
            R_HEXAGON_16_X => "R_HEXAGON_16_X",
            R_HEXAGON_12_X => "R_HEXAGON_12_X",
            R_HEXAGON_11_X => "R_HEXAGON_11_X",
            R_HEXAGON_10_X => "R_HEXAGON_10_X",
            R_HEXAGON_9_X => "R_HEXAGON_9_X",
            R_HEXAGON_8_X => "R_HEXAGON_8_X",
            R_HEXAGON_7_X => "R_HEXAGON_7_X",
            R_HEXAGON_6_X => "R_HEXAGON_6_X",
            R_HEXAGON_32_PCREL => "R_HEXAGON_32_PCREL",
            R_HEXAGON_COPY => "R_HEXAGON_COPY",
            R_HEXAGON_GLOB_DAT => "R_HEXAGON_GLOB_DAT",
            R_HEXAGON_JMP_SLOT => "R_HEXAGON_JMP_SLOT",
            R_HEXAGON_RELATIVE => "R_HEXAGON_RELATIVE",
            R_HEXAGON_PLT_B22_PCREL => "R_HEXAGON_PLT_B22_PCREL",
            R_HEXAGON_GOTOFF_LO16 => "R_HEXAGON_GOTOFF_LO16",
            R_HEXAGON_GOTOFF_HI16 => "R_HEXAGON_GOTOFF_HI16",
            R_HEXAGON_GOTOFF_32 => "R_HEXAGON_GOTOFF_32",
            R_HEXAGON_GOT_LO16 => "R_HEXAGON_GOT_LO16",
            R_HEXAGON_GOT_HI16 => "R_HEXAGON_GOT_HI16",
            R_HEXAGON_GOT_32 => "R_HEXAGON_GOT_32",
            R_HEXAGON_GOT_16 => "R_HEXAGON_GOT_16",
            R_HEXAGON_DTPMOD_32 => "R_HEXAGON_DTPMOD_32",
            R_HEXAGON_DTPREL_LO16 => "R_HEXAGON_DTPREL_LO16",
            R_HEXAGON_DTPREL_HI16 => "R_HEXAGON_DTPREL_HI16",
            R_HEXAGON_DTPREL_32 => "R_HEXAGON_DTPREL_32",
            R_HEXAGON_DTPREL_16 => "R_HEXAGON_DTPREL_16",
            R_HEXAGON_GD_PLT_B22_PCREL => "R_HEXAGON_GD_PLT_B22_PCREL",
            R_HEXAGON_GD_GOT_LO16 => "R_HEXAGON_GD_GOT_LO16",
            R_HEXAGON_GD_GOT_HI16 => "R_HEXAGON_GD_GOT_HI16",
            R_HEXAGON_GD_GOT_32 => "R_HEXAGON_GD_GOT_32",
            R_HEXAGON_GD_GOT_16 => "R_HEXAGON_GD_GOT_16",
            R_HEXAGON_IE_LO16 => "R_HEXAGON_IE_LO16",
            R_HEXAGON_IE_HI16 => "R_HEXAGON_IE_HI16",
            R_HEXAGON_IE_32 => "R_HEXAGON_IE_32",
            R_HEXAGON_IE_GOT_LO16 => "R_HEXAGON_IE_GOT_LO16",
            R_HEXAGON_IE_GOT_HI16 => "R_HEXAGON_IE_GOT_HI16",
            R_HEXAGON_IE_GOT_32 => "R_HEXAGON_IE_GOT_32",
            R_HEXAGON_IE_GOT_16 => "R_HEXAGON_IE_GOT_16",
            R_HEXAGON_TPREL_LO16 => "R_HEXAGON_TPREL_LO16",
            R_HEXAGON_TPREL_HI16 => "R_HEXAGON_TPREL_HI16",
            R_HEXAGON_TPREL_32 => "R_HEXAGON_TPREL_32",
            R_HEXAGON_TPREL_16 => "R_HEXAGON_TPREL_16",
            R_HEXAGON_6_PCREL_X => "R_HEXAGON_6_PCREL_X",
            R_HEXAGON_GOTREL_32_6_X => "R_HEXAGON_GOTREL_32_6_X",
            R_HEXAGON_GOTREL_16_X => "R_HEXAGON_GOTREL_16_X",
            R_HEXAGON_GOTREL_11_X => "R_HEXAGON_GOTREL_11_X",
            R_HEXAGON_GOT_32_6_X => "R_HEXAGON_GOT_32_6_X",
            R_HEXAGON_GOT_16_X => "R_HEXAGON_GOT_16_X",
            R_HEXAGON_GOT_11_X => "R_HEXAGON_GOT_11_X",
            R_HEXAGON_DTPREL_32_6_X => "R_HEXAGON_DTPREL_32_6_X",
            R_HEXAGON_DTPREL_16_X => "R_HEXAGON_DTPREL_16_X",
            R_HEXAGON_DTPREL_11_X => "R_HEXAGON_DTPREL_11_X",
            R_HEXAGON_GD_GOT_32_6_X => "R_HEXAGON_GD_GOT_32_6_X",
            R_HEXAGON_GD_GOT_16_X => "R_HEXAGON_GD_GOT_16_X",
            R_HEXAGON_GD_GOT_11_X => "R_HEXAGON_GD_GOT_11_X",
            R_HEXAGON_IE_32_6_X => "R_HEXAGON_IE_32_6_X",
            R_HEXAGON_IE_16_X => "R_HEXAGON_IE_16_X",
            R_HEXAGON_IE_GOT_32_6_X => "R_HEXAGON_IE_GOT_32_6_X",
            R_HEXAGON_IE_GOT_16_X => "R_HEXAGON_IE_GOT_16_X",
            R_HEXAGON_IE_GOT_11_X => "R_HEXAGON_IE_GOT_11_X",
            R_HEXAGON_TPREL_32_6_X => "R_HEXAGON_TPREL_32_6_X",
            R_HEXAGON_TPREL_16_X => "R_HEXAGON_TPREL_16_X",
            R_HEXAGON_TPREL_11_X => "R_HEXAGON_TPREL_11_X",
            R_HEXAGON_LD_PLT_B22_PCREL => "R_HEXAGON_LD_PLT_B22_PCREL",
            R_HEXAGON_LD_GOT_LO16 => "R_HEXAGON_LD_GOT_LO16",
            R_HEXAGON_LD_GOT_HI16 => "R_HEXAGON_LD_GOT_HI16",
            R_HEXAGON_LD_GOT_32 => "R_HEXAGON_LD_GOT_32",
            R_HEXAGON_LD_GOT_16 => "R_HEXAGON_LD_GOT_16",
            R_HEXAGON_LD_GOT_32_6_X => "R_HEXAGON_LD_GOT_32_6_X",
            R_HEXAGON_LD_GOT_16_X => "R_HEXAGON_LD_GOT_16_X",
            R_HEXAGON_LD_GOT_11_X => "R_HEXAGON_LD_GOT_11_X",
            R_HEXAGON_23_REG => "R_HEXAGON_23_REG",
            R_HEXAGON_GD_PLT_B22_PCREL_X => "R_HEXAGON_GD_PLT_B22_PCREL_X",
            R_HEXAGON_GD_PLT_B32_PCREL_X => "R_HEXAGON_GD_PLT_B32_PCREL_X",
            R_HEXAGON_LD_PLT_B22_PCREL_X => "R_HEXAGON_LD_PLT_B22_PCREL_X",
            R_HEXAGON_LD_PLT_B32_PCREL_X => "R_HEXAGON_LD_PLT_B32_PCREL_X",
            R_HEXAGON_27_REG => "R_HEXAGON_27_REG",
        }
    }
}

impl ElfRelocationType for HexagonElfRelocationType {
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
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_NONE.type_id(), 0);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_NONE.name(), "R_HEXAGON_NONE");
    }

    #[test]
    fn v2_relocation_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B22_PCREL.type_id(), 1);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B15_PCREL.type_id(), 2);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B7_PCREL.type_id(), 3);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LO16.type_id(), 4);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_HI16.type_id(), 5);
    }

    #[test]
    fn v2_continuation_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_32.type_id(), 6);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_16.type_id(), 7);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_8.type_id(), 8);
    }

    #[test]
    fn gprel_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GPREL16_0.type_id(), 9);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GPREL16_1.type_id(), 10);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GPREL16_2.type_id(), 11);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GPREL16_3.type_id(), 12);
    }

    #[test]
    fn hl16_type_matches_java_id() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_HL16.type_id(), 13);
    }

    #[test]
    fn v3_type_matches_java_id() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B13_PCREL.type_id(), 14);
    }

    #[test]
    fn v4_type_matches_java_id() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B9_PCREL.type_id(), 15);
    }

    #[test]
    fn v4_extenders_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B32_PCREL_X.type_id(), 16);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_32_6_X.type_id(), 17);
    }

    #[test]
    fn v4_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B22_PCREL_X.type_id(), 18);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B15_PCREL_X.type_id(), 19);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B13_PCREL_X.type_id(), 20);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B9_PCREL_X.type_id(), 21);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_B7_PCREL_X.type_id(), 22);
    }

    #[test]
    fn x_suffixed_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_16_X.type_id(), 23);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_12_X.type_id(), 24);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_11_X.type_id(), 25);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_10_X.type_id(), 26);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_9_X.type_id(), 27);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_8_X.type_id(), 28);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_7_X.type_id(), 29);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_6_X.type_id(), 30);
    }

    #[test]
    fn v2_pic_base_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_32_PCREL.type_id(), 31);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_COPY.type_id(), 32);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GLOB_DAT.type_id(), 33);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_JMP_SLOT.type_id(), 34);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_RELATIVE.type_id(), 35);
    }

    #[test]
    fn plt_and_got_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_PLT_B22_PCREL.type_id(), 36);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTOFF_LO16.type_id(), 37);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTOFF_HI16.type_id(), 38);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTOFF_32.type_id(), 39);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_LO16.type_id(), 40);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_HI16.type_id(), 41);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_32.type_id(), 42);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_16.type_id(), 43);
    }

    #[test]
    fn dtpmod_and_dtprel_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPMOD_32.type_id(), 44);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_LO16.type_id(), 45);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_HI16.type_id(), 46);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_32.type_id(), 47);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_16.type_id(), 48);
    }

    #[test]
    fn gd_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_PLT_B22_PCREL.type_id(), 49);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_LO16.type_id(), 50);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_HI16.type_id(), 51);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_32.type_id(), 52);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_16.type_id(), 53);
    }

    #[test]
    fn ie_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_LO16.type_id(), 54);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_HI16.type_id(), 55);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_32.type_id(), 56);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_LO16.type_id(), 57);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_HI16.type_id(), 58);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_32.type_id(), 59);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_16.type_id(), 60);
    }

    #[test]
    fn tprel_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_LO16.type_id(), 61);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_HI16.type_id(), 62);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_32.type_id(), 63);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_16.type_id(), 64);
    }

    #[test]
    fn pcrel_x_and_gotrel_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_6_PCREL_X.type_id(), 65);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTREL_32_6_X.type_id(), 66);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTREL_16_X.type_id(), 67);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOTREL_11_X.type_id(), 68);
    }

    #[test]
    fn got_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_32_6_X.type_id(), 69);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_16_X.type_id(), 70);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GOT_11_X.type_id(), 71);
    }

    #[test]
    fn dtprel_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_32_6_X.type_id(), 72);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_16_X.type_id(), 73);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_DTPREL_11_X.type_id(), 74);
    }

    #[test]
    fn gd_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_32_6_X.type_id(), 75);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_16_X.type_id(), 76);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_GOT_11_X.type_id(), 77);
    }

    #[test]
    fn ie_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_32_6_X.type_id(), 78);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_16_X.type_id(), 79);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_32_6_X.type_id(), 80);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_16_X.type_id(), 81);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_IE_GOT_11_X.type_id(), 82);
    }

    #[test]
    fn tprel_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_32_6_X.type_id(), 83);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_16_X.type_id(), 84);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_TPREL_11_X.type_id(), 85);
    }

    #[test]
    fn ld_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_PLT_B22_PCREL.type_id(), 86);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_LO16.type_id(), 87);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_HI16.type_id(), 88);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_32.type_id(), 89);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_16.type_id(), 90);
    }

    #[test]
    fn ld_extended_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_32_6_X.type_id(), 91);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_16_X.type_id(), 92);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_GOT_11_X.type_id(), 93);
    }

    #[test]
    fn reg_and_gd_plt_x_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_23_REG.type_id(), 94);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_PLT_B22_PCREL_X.type_id(), 95);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_GD_PLT_B32_PCREL_X.type_id(), 96);
    }

    #[test]
    fn final_ld_plt_x_types_match_java_ids() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_PLT_B22_PCREL_X.type_id(), 97);
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LD_PLT_B32_PCREL_X.type_id(), 98);
    }

    #[test]
    fn final_relocation_matches_java_id() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_27_REG.type_id(), 99);
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_NONE.name(), "R_HEXAGON_NONE");
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_32.name(), "R_HEXAGON_32");
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_LO16.name(), "R_HEXAGON_LO16");
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_HI16.name(), "R_HEXAGON_HI16");
        assert_eq!(HexagonElfRelocationType::R_HEXAGON_RELATIVE.name(), "R_HEXAGON_RELATIVE");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &HexagonElfRelocationType::R_HEXAGON_RELATIVE;
        assert_eq!(r.type_id(), 35);
        assert_eq!(r.name(), "R_HEXAGON_RELATIVE");
    }
}
