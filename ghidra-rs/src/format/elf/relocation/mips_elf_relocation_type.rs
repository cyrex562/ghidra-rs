//! MIPS ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// MIPS ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum MipsElfRelocationType {
    R_MIPS_NONE,
    R_MIPS_16,
    R_MIPS_32,
    R_MIPS_REL32,
    R_MIPS_26,
    R_MIPS_HI16,
    R_MIPS_LO16,
    R_MIPS_GPREL16,
    R_MIPS_LITERAL,
    R_MIPS_GOT16,
    R_MIPS_PC16,
    R_MIPS_CALL16,
    R_MIPS_GPREL32,
    R_MIPS_UNUSED1,
    R_MIPS_UNUSED2,
    R_MIPS_UNUSED3,
    R_MIPS_SHIFT5,
    R_MIPS_SHIFT6,
    R_MIPS_64,
    R_MIPS_GOT_DISP,
    R_MIPS_GOT_PAGE,
    R_MIPS_GOT_OFST,
    R_MIPS_GOT_HI16,
    R_MIPS_GOT_LO16,
    R_MIPS_SUB,
    R_MIPS_INSERT_A,
    R_MIPS_INSERT_B,
    R_MIPS_DELETE,
    R_MIPS_HIGHER,
    R_MIPS_HIGHEST,
    R_MIPS_CALL_HI16,
    R_MIPS_CALL_LO16,
    R_MIPS_SCN_DISP,
    R_MIPS_REL16,
    R_MIPS_ADD_IMMEDIATE,
    R_MIPS_PJUMP,
    R_MIPS_RELGOT,
    R_MIPS_JALR,
    R_MIPS_TLS_DTPMOD32,
    R_MIPS_TLS_DTPREL32,
    R_MIPS_TLS_DTPMOD64,
    R_MIPS_TLS_DTPREL64,
    R_MIPS_TLS_GD,
    R_MIPS_TLS_LDM,
    R_MIPS_TLS_DTPREL_HI16,
    R_MIPS_TLS_DTPREL_LO16,
    R_MIPS_TLS_GOTTPREL,
    R_MIPS_TLS_TPREL32,
    R_MIPS_TLS_TPREL64,
    R_MIPS_TLS_TPREL_HI16,
    R_MIPS_TLS_TPREL_LO16,
    R_MIPS_GLOB_DAT,
    R_MIPS_PC21_S2,
    R_MIPS_PC26_S2,
    R_MIPS_PC18_S3,
    R_MIPS_PC19_S2,
    R_MIPS_PCHI16,
    R_MIPS_PCLO16,
    R_MIPS16_26,
    R_MIPS16_GPREL,
    R_MIPS16_GOT16,
    R_MIPS16_CALL16,
    R_MIPS16_HI16,
    R_MIPS16_LO16,
    R_MIPS16_TLS_GD,
    R_MIPS16_TLS_LDM,
    R_MIPS16_TLS_DTPREL_HI16,
    R_MIPS16_TLS_DTPREL_LO16,
    R_MIPS16_TLS_GOTTPREL,
    R_MIPS16_TLS_TPREL_HI16,
    R_MIPS16_TLS_TPREL_LO16,
    R_MIPS16_PC16_S1,
    R_MIPS_COPY,
    R_MIPS_JUMP_SLOT,
    R_MICROMIPS_26_S1,
    R_MICROMIPS_HI16,
    R_MICROMIPS_LO16,
    R_MICROMIPS_GPREL16,
    R_MICROMIPS_LITERAL,
    R_MICROMIPS_GOT16,
    R_MICROMIPS_PC7_S1,
    R_MICROMIPS_PC10_S1,
    R_MICROMIPS_PC16_S1,
    R_MICROMIPS_CALL16,
    R_MICROMIPS_GOT_DISP,
    R_MICROMIPS_GOT_PAGE,
    R_MICROMIPS_GOT_OFST,
    R_MICROMIPS_GOT_HI16,
    R_MICROMIPS_GOT_LO16,
    R_MICROMIPS_SUB,
    R_MICROMIPS_HIGHER,
    R_MICROMIPS_HIGHEST,
    R_MICROMIPS_CALL_HI16,
    R_MICROMIPS_CALL_LO16,
    R_MICROMIPS_SCN_DISP,
    R_MICROMIPS_JALR,
    R_MICROMIPS_HI0_LO16,
    R_MICROMIPS_TLS_GD,
    R_MICROMIPS_TLS_LDM,
    R_MICROMIPS_TLS_DTPREL_HI16,
    R_MICROMIPS_TLS_DTPREL_LO16,
    R_MICROMIPS_TLS_GOTTPREL,
    R_MICROMIPS_TLS_TPREL_HI16,
    R_MICROMIPS_TLS_TPREL_LO16,
    R_MICROMIPS_GPREL7_S2,
    R_MICROMIPS_PC23_S2,
    R_MIPS_PC32,
    R_MIPS_EH,
    R_MIPS_GNU_REL16_S2,
    R_MIPS_GNU_VTINHERIT,
    R_MIPS_GNU_VTENTRY,
}

impl MipsElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use MipsElfRelocationType::*;
        match self {
            R_MIPS_NONE => 0,
            R_MIPS_16 => 1,
            R_MIPS_32 => 2,
            R_MIPS_REL32 => 3,
            R_MIPS_26 => 4,
            R_MIPS_HI16 => 5,
            R_MIPS_LO16 => 6,
            R_MIPS_GPREL16 => 7,
            R_MIPS_LITERAL => 8,
            R_MIPS_GOT16 => 9,
            R_MIPS_PC16 => 10,
            R_MIPS_CALL16 => 11,
            R_MIPS_GPREL32 => 12,
            R_MIPS_UNUSED1 => 13,
            R_MIPS_UNUSED2 => 14,
            R_MIPS_UNUSED3 => 15,
            R_MIPS_SHIFT5 => 16,
            R_MIPS_SHIFT6 => 17,
            R_MIPS_64 => 18,
            R_MIPS_GOT_DISP => 19,
            R_MIPS_GOT_PAGE => 20,
            R_MIPS_GOT_OFST => 21,
            R_MIPS_GOT_HI16 => 22,
            R_MIPS_GOT_LO16 => 23,
            R_MIPS_SUB => 24,
            R_MIPS_INSERT_A => 25,
            R_MIPS_INSERT_B => 26,
            R_MIPS_DELETE => 27,
            R_MIPS_HIGHER => 28,
            R_MIPS_HIGHEST => 29,
            R_MIPS_CALL_HI16 => 30,
            R_MIPS_CALL_LO16 => 31,
            R_MIPS_SCN_DISP => 32,
            R_MIPS_REL16 => 33,
            R_MIPS_ADD_IMMEDIATE => 34,
            R_MIPS_PJUMP => 35,
            R_MIPS_RELGOT => 36,
            R_MIPS_JALR => 37,
            R_MIPS_TLS_DTPMOD32 => 38,
            R_MIPS_TLS_DTPREL32 => 39,
            R_MIPS_TLS_DTPMOD64 => 40,
            R_MIPS_TLS_DTPREL64 => 41,
            R_MIPS_TLS_GD => 42,
            R_MIPS_TLS_LDM => 43,
            R_MIPS_TLS_DTPREL_HI16 => 44,
            R_MIPS_TLS_DTPREL_LO16 => 45,
            R_MIPS_TLS_GOTTPREL => 46,
            R_MIPS_TLS_TPREL32 => 47,
            R_MIPS_TLS_TPREL64 => 48,
            R_MIPS_TLS_TPREL_HI16 => 49,
            R_MIPS_TLS_TPREL_LO16 => 50,
            R_MIPS_GLOB_DAT => 51,
            R_MIPS_PC21_S2 => 60,
            R_MIPS_PC26_S2 => 61,
            R_MIPS_PC18_S3 => 62,
            R_MIPS_PC19_S2 => 63,
            R_MIPS_PCHI16 => 64,
            R_MIPS_PCLO16 => 65,
            R_MIPS16_26 => 100,
            R_MIPS16_GPREL => 101,
            R_MIPS16_GOT16 => 102,
            R_MIPS16_CALL16 => 103,
            R_MIPS16_HI16 => 104,
            R_MIPS16_LO16 => 105,
            R_MIPS16_TLS_GD => 106,
            R_MIPS16_TLS_LDM => 107,
            R_MIPS16_TLS_DTPREL_HI16 => 108,
            R_MIPS16_TLS_DTPREL_LO16 => 109,
            R_MIPS16_TLS_GOTTPREL => 110,
            R_MIPS16_TLS_TPREL_HI16 => 111,
            R_MIPS16_TLS_TPREL_LO16 => 112,
            R_MIPS16_PC16_S1 => 113,
            R_MIPS_COPY => 126,
            R_MIPS_JUMP_SLOT => 127,
            R_MICROMIPS_26_S1 => 133,
            R_MICROMIPS_HI16 => 134,
            R_MICROMIPS_LO16 => 135,
            R_MICROMIPS_GPREL16 => 136,
            R_MICROMIPS_LITERAL => 137,
            R_MICROMIPS_GOT16 => 138,
            R_MICROMIPS_PC7_S1 => 139,
            R_MICROMIPS_PC10_S1 => 140,
            R_MICROMIPS_PC16_S1 => 141,
            R_MICROMIPS_CALL16 => 142,
            R_MICROMIPS_GOT_DISP => 145,
            R_MICROMIPS_GOT_PAGE => 146,
            R_MICROMIPS_GOT_OFST => 147,
            R_MICROMIPS_GOT_HI16 => 148,
            R_MICROMIPS_GOT_LO16 => 149,
            R_MICROMIPS_SUB => 150,
            R_MICROMIPS_HIGHER => 151,
            R_MICROMIPS_HIGHEST => 152,
            R_MICROMIPS_CALL_HI16 => 153,
            R_MICROMIPS_CALL_LO16 => 154,
            R_MICROMIPS_SCN_DISP => 155,
            R_MICROMIPS_JALR => 156,
            R_MICROMIPS_HI0_LO16 => 157,
            R_MICROMIPS_TLS_GD => 162,
            R_MICROMIPS_TLS_LDM => 163,
            R_MICROMIPS_TLS_DTPREL_HI16 => 164,
            R_MICROMIPS_TLS_DTPREL_LO16 => 165,
            R_MICROMIPS_TLS_GOTTPREL => 166,
            R_MICROMIPS_TLS_TPREL_HI16 => 169,
            R_MICROMIPS_TLS_TPREL_LO16 => 170,
            R_MICROMIPS_GPREL7_S2 => 172,
            R_MICROMIPS_PC23_S2 => 173,
            R_MIPS_PC32 => 248,
            R_MIPS_EH => 249,
            R_MIPS_GNU_REL16_S2 => 250,
            R_MIPS_GNU_VTINHERIT => 253,
            R_MIPS_GNU_VTENTRY => 254,
        }
    }

    /// Returns the name of this relocation type.
    pub const fn name_str(self) -> &'static str {
        use MipsElfRelocationType::*;
        match self {
            R_MIPS_NONE => "R_MIPS_NONE",
            R_MIPS_16 => "R_MIPS_16",
            R_MIPS_32 => "R_MIPS_32",
            R_MIPS_REL32 => "R_MIPS_REL32",
            R_MIPS_26 => "R_MIPS_26",
            R_MIPS_HI16 => "R_MIPS_HI16",
            R_MIPS_LO16 => "R_MIPS_LO16",
            R_MIPS_GPREL16 => "R_MIPS_GPREL16",
            R_MIPS_LITERAL => "R_MIPS_LITERAL",
            R_MIPS_GOT16 => "R_MIPS_GOT16",
            R_MIPS_PC16 => "R_MIPS_PC16",
            R_MIPS_CALL16 => "R_MIPS_CALL16",
            R_MIPS_GPREL32 => "R_MIPS_GPREL32",
            R_MIPS_UNUSED1 => "R_MIPS_UNUSED1",
            R_MIPS_UNUSED2 => "R_MIPS_UNUSED2",
            R_MIPS_UNUSED3 => "R_MIPS_UNUSED3",
            R_MIPS_SHIFT5 => "R_MIPS_SHIFT5",
            R_MIPS_SHIFT6 => "R_MIPS_SHIFT6",
            R_MIPS_64 => "R_MIPS_64",
            R_MIPS_GOT_DISP => "R_MIPS_GOT_DISP",
            R_MIPS_GOT_PAGE => "R_MIPS_GOT_PAGE",
            R_MIPS_GOT_OFST => "R_MIPS_GOT_OFST",
            R_MIPS_GOT_HI16 => "R_MIPS_GOT_HI16",
            R_MIPS_GOT_LO16 => "R_MIPS_GOT_LO16",
            R_MIPS_SUB => "R_MIPS_SUB",
            R_MIPS_INSERT_A => "R_MIPS_INSERT_A",
            R_MIPS_INSERT_B => "R_MIPS_INSERT_B",
            R_MIPS_DELETE => "R_MIPS_DELETE",
            R_MIPS_HIGHER => "R_MIPS_HIGHER",
            R_MIPS_HIGHEST => "R_MIPS_HIGHEST",
            R_MIPS_CALL_HI16 => "R_MIPS_CALL_HI16",
            R_MIPS_CALL_LO16 => "R_MIPS_CALL_LO16",
            R_MIPS_SCN_DISP => "R_MIPS_SCN_DISP",
            R_MIPS_REL16 => "R_MIPS_REL16",
            R_MIPS_ADD_IMMEDIATE => "R_MIPS_ADD_IMMEDIATE",
            R_MIPS_PJUMP => "R_MIPS_PJUMP",
            R_MIPS_RELGOT => "R_MIPS_RELGOT",
            R_MIPS_JALR => "R_MIPS_JALR",
            R_MIPS_TLS_DTPMOD32 => "R_MIPS_TLS_DTPMOD32",
            R_MIPS_TLS_DTPREL32 => "R_MIPS_TLS_DTPREL32",
            R_MIPS_TLS_DTPMOD64 => "R_MIPS_TLS_DTPMOD64",
            R_MIPS_TLS_DTPREL64 => "R_MIPS_TLS_DTPREL64",
            R_MIPS_TLS_GD => "R_MIPS_TLS_GD",
            R_MIPS_TLS_LDM => "R_MIPS_TLS_LDM",
            R_MIPS_TLS_DTPREL_HI16 => "R_MIPS_TLS_DTPREL_HI16",
            R_MIPS_TLS_DTPREL_LO16 => "R_MIPS_TLS_DTPREL_LO16",
            R_MIPS_TLS_GOTTPREL => "R_MIPS_TLS_GOTTPREL",
            R_MIPS_TLS_TPREL32 => "R_MIPS_TLS_TPREL32",
            R_MIPS_TLS_TPREL64 => "R_MIPS_TLS_TPREL64",
            R_MIPS_TLS_TPREL_HI16 => "R_MIPS_TLS_TPREL_HI16",
            R_MIPS_TLS_TPREL_LO16 => "R_MIPS_TLS_TPREL_LO16",
            R_MIPS_GLOB_DAT => "R_MIPS_GLOB_DAT",
            R_MIPS_PC21_S2 => "R_MIPS_PC21_S2",
            R_MIPS_PC26_S2 => "R_MIPS_PC26_S2",
            R_MIPS_PC18_S3 => "R_MIPS_PC18_S3",
            R_MIPS_PC19_S2 => "R_MIPS_PC19_S2",
            R_MIPS_PCHI16 => "R_MIPS_PCHI16",
            R_MIPS_PCLO16 => "R_MIPS_PCLO16",
            R_MIPS16_26 => "R_MIPS16_26",
            R_MIPS16_GPREL => "R_MIPS16_GPREL",
            R_MIPS16_GOT16 => "R_MIPS16_GOT16",
            R_MIPS16_CALL16 => "R_MIPS16_CALL16",
            R_MIPS16_HI16 => "R_MIPS16_HI16",
            R_MIPS16_LO16 => "R_MIPS16_LO16",
            R_MIPS16_TLS_GD => "R_MIPS16_TLS_GD",
            R_MIPS16_TLS_LDM => "R_MIPS16_TLS_LDM",
            R_MIPS16_TLS_DTPREL_HI16 => "R_MIPS16_TLS_DTPREL_HI16",
            R_MIPS16_TLS_DTPREL_LO16 => "R_MIPS16_TLS_DTPREL_LO16",
            R_MIPS16_TLS_GOTTPREL => "R_MIPS16_TLS_GOTTPREL",
            R_MIPS16_TLS_TPREL_HI16 => "R_MIPS16_TLS_TPREL_HI16",
            R_MIPS16_TLS_TPREL_LO16 => "R_MIPS16_TLS_TPREL_LO16",
            R_MIPS16_PC16_S1 => "R_MIPS16_PC16_S1",
            R_MIPS_COPY => "R_MIPS_COPY",
            R_MIPS_JUMP_SLOT => "R_MIPS_JUMP_SLOT",
            R_MICROMIPS_26_S1 => "R_MICROMIPS_26_S1",
            R_MICROMIPS_HI16 => "R_MICROMIPS_HI16",
            R_MICROMIPS_LO16 => "R_MICROMIPS_LO16",
            R_MICROMIPS_GPREL16 => "R_MICROMIPS_GPREL16",
            R_MICROMIPS_LITERAL => "R_MICROMIPS_LITERAL",
            R_MICROMIPS_GOT16 => "R_MICROMIPS_GOT16",
            R_MICROMIPS_PC7_S1 => "R_MICROMIPS_PC7_S1",
            R_MICROMIPS_PC10_S1 => "R_MICROMIPS_PC10_S1",
            R_MICROMIPS_PC16_S1 => "R_MICROMIPS_PC16_S1",
            R_MICROMIPS_CALL16 => "R_MICROMIPS_CALL16",
            R_MICROMIPS_GOT_DISP => "R_MICROMIPS_GOT_DISP",
            R_MICROMIPS_GOT_PAGE => "R_MICROMIPS_GOT_PAGE",
            R_MICROMIPS_GOT_OFST => "R_MICROMIPS_GOT_OFST",
            R_MICROMIPS_GOT_HI16 => "R_MICROMIPS_GOT_HI16",
            R_MICROMIPS_GOT_LO16 => "R_MICROMIPS_GOT_LO16",
            R_MICROMIPS_SUB => "R_MICROMIPS_SUB",
            R_MICROMIPS_HIGHER => "R_MICROMIPS_HIGHER",
            R_MICROMIPS_HIGHEST => "R_MICROMIPS_HIGHEST",
            R_MICROMIPS_CALL_HI16 => "R_MICROMIPS_CALL_HI16",
            R_MICROMIPS_CALL_LO16 => "R_MICROMIPS_CALL_LO16",
            R_MICROMIPS_SCN_DISP => "R_MICROMIPS_SCN_DISP",
            R_MICROMIPS_JALR => "R_MICROMIPS_JALR",
            R_MICROMIPS_HI0_LO16 => "R_MICROMIPS_HI0_LO16",
            R_MICROMIPS_TLS_GD => "R_MICROMIPS_TLS_GD",
            R_MICROMIPS_TLS_LDM => "R_MICROMIPS_TLS_LDM",
            R_MICROMIPS_TLS_DTPREL_HI16 => "R_MICROMIPS_TLS_DTPREL_HI16",
            R_MICROMIPS_TLS_DTPREL_LO16 => "R_MICROMIPS_TLS_DTPREL_LO16",
            R_MICROMIPS_TLS_GOTTPREL => "R_MICROMIPS_TLS_GOTTPREL",
            R_MICROMIPS_TLS_TPREL_HI16 => "R_MICROMIPS_TLS_TPREL_HI16",
            R_MICROMIPS_TLS_TPREL_LO16 => "R_MICROMIPS_TLS_TPREL_LO16",
            R_MICROMIPS_GPREL7_S2 => "R_MICROMIPS_GPREL7_S2",
            R_MICROMIPS_PC23_S2 => "R_MICROMIPS_PC23_S2",
            R_MIPS_PC32 => "R_MIPS_PC32",
            R_MIPS_EH => "R_MIPS_EH",
            R_MIPS_GNU_REL16_S2 => "R_MIPS_GNU_REL16_S2",
            R_MIPS_GNU_VTINHERIT => "R_MIPS_GNU_VTINHERIT",
            R_MIPS_GNU_VTENTRY => "R_MIPS_GNU_VTENTRY",
        }
    }
}

impl ElfRelocationType for MipsElfRelocationType {
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
        assert_eq!(MipsElfRelocationType::R_MIPS_NONE.type_id(), 0);
        assert_eq!(MipsElfRelocationType::R_MIPS_NONE.name(), "R_MIPS_NONE");
    }

    #[test]
    fn basic_relocation_types_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MIPS_16.type_id(), 1);
        assert_eq!(MipsElfRelocationType::R_MIPS_32.type_id(), 2);
        assert_eq!(MipsElfRelocationType::R_MIPS_REL32.type_id(), 3);
        assert_eq!(MipsElfRelocationType::R_MIPS_26.type_id(), 4);
    }

    #[test]
    fn got_relocations_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MIPS_GOT16.type_id(), 9);
        assert_eq!(MipsElfRelocationType::R_MIPS_GOT_DISP.type_id(), 19);
        assert_eq!(MipsElfRelocationType::R_MIPS_GOT_PAGE.type_id(), 20);
    }

    #[test]
    fn tls_relocations_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MIPS_TLS_DTPMOD32.type_id(), 38);
        assert_eq!(MipsElfRelocationType::R_MIPS_TLS_DTPREL32.type_id(), 39);
        assert_eq!(MipsElfRelocationType::R_MIPS_TLS_GD.type_id(), 42);
    }

    #[test]
    fn mips16_relocations_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MIPS16_26.type_id(), 100);
        assert_eq!(MipsElfRelocationType::R_MIPS16_GPREL.type_id(), 101);
        assert_eq!(MipsElfRelocationType::R_MIPS16_PC16_S1.type_id(), 113);
    }

    #[test]
    fn micromips_relocations_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MICROMIPS_26_S1.type_id(), 133);
        assert_eq!(MipsElfRelocationType::R_MICROMIPS_HI16.type_id(), 134);
        assert_eq!(MipsElfRelocationType::R_MICROMIPS_LO16.type_id(), 135);
        assert_eq!(MipsElfRelocationType::R_MICROMIPS_PC23_S2.type_id(), 173);
    }

    #[test]
    fn special_relocations_match_java_ids() {
        assert_eq!(MipsElfRelocationType::R_MIPS_COPY.type_id(), 126);
        assert_eq!(MipsElfRelocationType::R_MIPS_JUMP_SLOT.type_id(), 127);
        assert_eq!(MipsElfRelocationType::R_MIPS_PC32.type_id(), 248);
        assert_eq!(MipsElfRelocationType::R_MIPS_EH.type_id(), 249);
        assert_eq!(MipsElfRelocationType::R_MIPS_GNU_VTENTRY.type_id(), 254);
    }

    #[test]
    fn all_variants_have_unique_names() {
        let variants = [
            MipsElfRelocationType::R_MIPS_NONE,
            MipsElfRelocationType::R_MIPS_16,
            MipsElfRelocationType::R_MIPS_32,
            MipsElfRelocationType::R_MIPS_REL32,
            MipsElfRelocationType::R_MIPS_26,
            MipsElfRelocationType::R_MIPS_HI16,
            MipsElfRelocationType::R_MIPS_LO16,
            MipsElfRelocationType::R_MIPS_GPREL16,
            MipsElfRelocationType::R_MIPS_LITERAL,
            MipsElfRelocationType::R_MIPS_GOT16,
        ];
        for v in variants.iter() {
            let name = v.name();
            assert!(!name.is_empty());
            assert!(name.starts_with("R_MIPS"));
        }
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &MipsElfRelocationType::R_MIPS_GLOB_DAT;
        assert_eq!(r.type_id(), 51);
        assert_eq!(r.name(), "R_MIPS_GLOB_DAT");
    }

    #[test]
    fn non_contiguous_id_gaps_are_preserved() {
        assert_eq!(MipsElfRelocationType::R_MIPS_GLOB_DAT.type_id(), 51);
        assert_eq!(MipsElfRelocationType::R_MIPS_PC21_S2.type_id(), 60);
        assert_eq!(MipsElfRelocationType::R_MIPS16_26.type_id(), 100);
        assert_eq!(MipsElfRelocationType::R_MIPS_COPY.type_id(), 126);
        assert_eq!(MipsElfRelocationType::R_MICROMIPS_26_S1.type_id(), 133);
    }
}
