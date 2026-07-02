//! ARM ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.ARM_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// ARM ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum ArmElfRelocationType {
    R_ARM_NONE,               // No operation needed
    R_ARM_PC24,                // ((S + A) | T) - P [DEPRECATED]
    R_ARM_ABS32,                // (S + A) | T
    R_ARM_REL32,                // ((S + A) | T) - P
    R_ARM_LDR_PC_G0,             // S + A - P
    R_ARM_ABS16,                // S + A
    R_ARM_ABS12,                // S + A
    R_ARM_THM_ABS5,              // S + A
    R_ARM_ABS_8,                // S + A
    R_ARM_SBREL32,               // ((S + A) | T) - B(S)
    R_ARM_THM_CALL,              // ((S + A) | T) - P
    R_ARM_THM_PC8,               // S + A - Pa
    R_ARM_BREL_ADJ,              // DELTA(B(S)) + A
    R_ARM_TLS_DESC,
    R_ARM_THM_SWI8,              // [OBSOLETE]
    R_ARM_XPC25,                 // [OBSOLETE]
    R_ARM_THM_XPC22,             // [OBSOLETE]
    R_ARM_TLS_DTPMOD32,          // Module[S]
    R_ARM_TLS_DTPOFF32,          // S + A - TLS
    R_ARM_TLS_TPOFF32,           // S + A - TLS
    R_ARM_COPY,                  // Miscellaneous
    R_ARM_GLOB_DAT,              // (S + A) | T
    R_ARM_JUMP_SLOT,             // (S + A) | T
    R_ARM_RELATIVE,              // B(S) + A [Note: see Table 4-16]
    R_ARM_GOTOFF32,              // ((S + A) | T) - GOT_ORG
    R_ARM_BASE_PREL,             // B(S) + A - P
    R_ARM_GOT_BREL,              // GOT(S) + A - GOT_ORG
    R_ARM_PLT32,                 // ((S + A) | T) - P
    R_ARM_CALL,                  // ((S + A) | T) - P
    R_ARM_JUMP24,                // ((S + A) | T) - P
    R_ARM_THM_JUMP24,            // ((S + A) | T) - P
    R_ARM_BASE_ABS,              // B(S) + A
    R_ARM_ALU_PCREL_7_0,         // Obsolete
    R_ARM_ALU_PCREL_15_8,        // Obsolete
    R_ARM_ALU_PCREL_23_15,       // Obsolete
    R_ARM_LDR_SBREL_11_0_NC,     // S + A - B(S)
    R_ARM_ALU_SBREL_19_12_NC,    // S + A - B(S)
    R_ARM_ALU_SBREL_27_20_CK,    // S + A - B(S)
    R_ARM_TARGET1,               // (S + A) | T or ((S + A) | T) - P
    R_ARM_SBREL31,               // ((S + A) | T) - B(S)
    R_ARM_V4BX,                  // Miscellaneous
    R_ARM_TARGET2,               // Miscellaneous
    R_ARM_PREL31,                // ((S + A) | T) - P
    R_ARM_MOVW_ABS_NC,           // (S + A) | T
    R_ARM_MOVT_ABS,              // S + A
    R_ARM_MOVW_PREL_NC,          // ((S + A) | T) - P
    R_ARM_MOVT_PREL,             // S + A - P
    R_ARM_THM_MOVW_ABS_NC,       // (S + A) | T
    R_ARM_THM_MOVT_ABS,          // S + A
    R_ARM_THM_MOVW_PREL_NC,      // ((S + A) | T) - P
    R_ARM_THM_MOVT_PREL,         // S + A - P
    R_ARM_THM_JUMP19,            // ((S + A) | T) - P
    R_ARM_THM_JUMP6,             // S + A - P
    R_ARM_THM_ALU_PREL_11_0,     // ((S + A) | T) - Pa
    R_ARM_THM_PC12,              // S + A - Pa
    R_ARM_ABS32_NOI,             // S + A
    R_ARM_REL32_NOI,             // S + A - P
    R_ARM_ALU_PC_G0_NC,          // ((S + A) | T) - P
    R_ARM_ALU_PC_G0,             // ((S + A) | T) - P
    R_ARM_ALU_PC_G1_NC,          // ((S + A) | T) - P
    R_ARM_ALU_PC_G1,             // ((S + A) | T) - P
    R_ARM_ALU_PC_G2,             // ((S + A) | T) - P
    R_ARM_LDR_PC_G1,             // S + A - P
    R_ARM_LDR_PC_G2,             // S + A - P
    R_ARM_LDRS_PC_G0,            // S + A - P
    R_ARM_LDRS_PC_G1,            // S + A - P
    R_ARM_LDRS_PC_G2,            // S + A - P
    R_ARM_LDC_PC_G0,             // S + A - P
    R_ARM_LDC_PC_G1,             // S + A - P
    R_ARM_LDC_PC_G2,             // S + A - P
    R_ARM_ALU_SB_G0_NC,          // ((S + A) | T) - B(S)
    R_ARM_ALU_SB_G0,             // ((S + A) | T) - B(S)
    R_ARM_ALU_SB_G1_NC,          // ((S + A) | T) - B(S)
    R_ARM_ALU_SB_G1,             // ((S + A) | T) - B(S)
    R_ARM_ALU_SB_G2,             // ((S + A) | T) - B(S)
    R_ARM_LDR_SB_G0,             // S + A - B(S)
    R_ARM_LDR_SB_G1,             // S + A - B(S)
    R_ARM_LDR_SB_G2,             // S + A - B(S)
    R_ARM_LDRS_SB_G0,            // S + A - B(S)
    R_ARM_LDRS_SB_G1,            // S + A - B(S)
    R_ARM_LDRS_SB_G2,            // S + A - B(S)
    R_ARM_LDC_SB_G0,             // S + A - B(S)
    R_ARM_LDC_SB_G1,             // S + A - B(S)
    R_ARM_LDC_SB_G2,             // S + A - B(S)
    R_ARM_MOVW_BREL_NC,          // ((S + A) | T) - B(S)
    R_ARM_MOVT_BREL,             // S + A - B(S)
    R_ARM_MOVW_BREL,             // ((S + A) | T) - B(S)
    R_ARM_THM_MOVW_BREL_NC,      // ((S + A) | T) - B(S)
    R_ARM_THM_MOVT_BREL,         // S + A - B(S)
    R_ARM_THM_MOVW_BREL,         // ((S + A) | T) - B(S)
    R_ARM_TLS_GOTDESC,
    R_ARM_TLS_CALL,
    R_ARM_TLS_DESCSEQ,           // TLS relaxation
    R_ARM_THM_TLS_CALL,
    R_ARM_PLT32_ABS,             // PLT(S) + A
    R_ARM_GOT_ABS,               // GOT(S) + A
    R_ARM_GOT_PREL,              // GOT(S) + A - P
    R_ARM_GOT_BREL12,            // GOT(S) + A - GOT_ORG
    R_ARM_GOTOFF12,              // S + A - GOT_ORG
    R_ARM_GOTRELAX,
    R_ARM_GNU_VTENTRY,
    R_ARM_GNU_VTINHERIT,
    R_ARM_THM_JUMP11,            // S + A - P
    R_ARM_THM_JUMP8,             // S + A - P
    R_ARM_TLS_GD32,              // GOT(S) + A - P
    R_ARM_TLS_LDM32,             // GOT(S) + A - P
    R_ARM_TLS_LDO32,             // S + A - TLS
    R_ARM_TLS_IE32,              // GOT(S) + A - P
    R_ARM_TLS_LE32,              // S + A - tp
    R_ARM_TLS_LDO12,             // S + A - TLS
    R_ARM_TLS_LE12,              // S + A - tp
    R_ARM_TLS_IE12GP,            // GOT(S) + A - GOT_ORG
    R_ARM_PRIVATE_0,
    R_ARM_PRIVATE_1,
    R_ARM_PRIVATE_2,
    R_ARM_PRIVATE_3,
    R_ARM_PRIVATE_4,
    R_ARM_PRIVATE_5,
    R_ARM_PRIVATE_6,
    R_ARM_PRIVATE_7,
    R_ARM_PRIVATE_8,
    R_ARM_PRIVATE_9,
    R_ARM_PRIVATE_10,
    R_ARM_PRIVATE_11,
    R_ARM_PRIVATE_12,
    R_ARM_PRIVATE_13,
    R_ARM_PRIVATE_14,
    R_ARM_PRIVATE_15,
    R_ARM_ME_TOO,
    R_ARM_THM_TLS_DESCSEQ16,
    R_ARM_THM_TLS_DESCSEQ32,
    R_ARM_THM_ALU_ABS_G0_NC,
    R_ARM_THM_ALU_ABS_G1_NC,
    R_ARM_THM_ALU_ABS_G2_NC,
    R_ARM_THM_ALU_ABS_G3_NC,
    R_ARM_THM_BF16,
    R_ARM_THM_BF12,
    R_ARM_THM_BF18,
    R_ARM_IRELATIVE,
    R_ARM_GOTFUNCDEC,
    R_ARM_GOTOFFFUNCDESC,
    R_ARM_FUNCESC,
    R_ARM_FUNCDESC_VALUE,
    R_ARM_TLS_GD32_FDPIC,
    R_ARM_TLS_LDM32_FDPIC,
    R_ARM_TLS_IE32_FDPIC,
    R_ARM_RXPC25,
    R_ARM_RSBREL32,
    R_ARM_THM_RPC22,
    R_ARM_RREL32,
    R_ARM_RABS32,
    R_ARM_RPC24,
    R_ARM_RBASE,
}

impl ArmElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use ArmElfRelocationType::*;
        match self {
            R_ARM_NONE => 0,
            R_ARM_PC24 => 1,
            R_ARM_ABS32 => 2,
            R_ARM_REL32 => 3,
            R_ARM_LDR_PC_G0 => 4,
            R_ARM_ABS16 => 5,
            R_ARM_ABS12 => 6,
            R_ARM_THM_ABS5 => 7,
            R_ARM_ABS_8 => 8,
            R_ARM_SBREL32 => 9,
            R_ARM_THM_CALL => 10,
            R_ARM_THM_PC8 => 11,
            R_ARM_BREL_ADJ => 12,
            R_ARM_TLS_DESC => 13,
            R_ARM_THM_SWI8 => 14,
            R_ARM_XPC25 => 15,
            R_ARM_THM_XPC22 => 16,
            R_ARM_TLS_DTPMOD32 => 17,
            R_ARM_TLS_DTPOFF32 => 18,
            R_ARM_TLS_TPOFF32 => 19,
            R_ARM_COPY => 20,
            R_ARM_GLOB_DAT => 21,
            R_ARM_JUMP_SLOT => 22,
            R_ARM_RELATIVE => 23,
            R_ARM_GOTOFF32 => 24,
            R_ARM_BASE_PREL => 25,
            R_ARM_GOT_BREL => 26,
            R_ARM_PLT32 => 27,
            R_ARM_CALL => 28,
            R_ARM_JUMP24 => 29,
            R_ARM_THM_JUMP24 => 30,
            R_ARM_BASE_ABS => 31,
            R_ARM_ALU_PCREL_7_0 => 32,
            R_ARM_ALU_PCREL_15_8 => 33,
            R_ARM_ALU_PCREL_23_15 => 34,
            R_ARM_LDR_SBREL_11_0_NC => 35,
            R_ARM_ALU_SBREL_19_12_NC => 36,
            R_ARM_ALU_SBREL_27_20_CK => 37,
            R_ARM_TARGET1 => 38,
            R_ARM_SBREL31 => 39,
            R_ARM_V4BX => 40,
            R_ARM_TARGET2 => 41,
            R_ARM_PREL31 => 42,
            R_ARM_MOVW_ABS_NC => 43,
            R_ARM_MOVT_ABS => 44,
            R_ARM_MOVW_PREL_NC => 45,
            R_ARM_MOVT_PREL => 46,
            R_ARM_THM_MOVW_ABS_NC => 47,
            R_ARM_THM_MOVT_ABS => 48,
            R_ARM_THM_MOVW_PREL_NC => 49,
            R_ARM_THM_MOVT_PREL => 50,
            R_ARM_THM_JUMP19 => 51,
            R_ARM_THM_JUMP6 => 52,
            R_ARM_THM_ALU_PREL_11_0 => 53,
            R_ARM_THM_PC12 => 54,
            R_ARM_ABS32_NOI => 55,
            R_ARM_REL32_NOI => 56,
            R_ARM_ALU_PC_G0_NC => 57,
            R_ARM_ALU_PC_G0 => 58,
            R_ARM_ALU_PC_G1_NC => 59,
            R_ARM_ALU_PC_G1 => 60,
            R_ARM_ALU_PC_G2 => 61,
            R_ARM_LDR_PC_G1 => 62,
            R_ARM_LDR_PC_G2 => 63,
            R_ARM_LDRS_PC_G0 => 64,
            R_ARM_LDRS_PC_G1 => 65,
            R_ARM_LDRS_PC_G2 => 66,
            R_ARM_LDC_PC_G0 => 67,
            R_ARM_LDC_PC_G1 => 68,
            R_ARM_LDC_PC_G2 => 69,
            R_ARM_ALU_SB_G0_NC => 70,
            R_ARM_ALU_SB_G0 => 71,
            R_ARM_ALU_SB_G1_NC => 72,
            R_ARM_ALU_SB_G1 => 73,
            R_ARM_ALU_SB_G2 => 74,
            R_ARM_LDR_SB_G0 => 75,
            R_ARM_LDR_SB_G1 => 76,
            R_ARM_LDR_SB_G2 => 77,
            R_ARM_LDRS_SB_G0 => 78,
            R_ARM_LDRS_SB_G1 => 79,
            R_ARM_LDRS_SB_G2 => 80,
            R_ARM_LDC_SB_G0 => 81,
            R_ARM_LDC_SB_G1 => 82,
            R_ARM_LDC_SB_G2 => 83,
            R_ARM_MOVW_BREL_NC => 84,
            R_ARM_MOVT_BREL => 85,
            R_ARM_MOVW_BREL => 86,
            R_ARM_THM_MOVW_BREL_NC => 87,
            R_ARM_THM_MOVT_BREL => 88,
            R_ARM_THM_MOVW_BREL => 89,
            R_ARM_TLS_GOTDESC => 90,
            R_ARM_TLS_CALL => 91,
            R_ARM_TLS_DESCSEQ => 92,
            R_ARM_THM_TLS_CALL => 93,
            R_ARM_PLT32_ABS => 94,
            R_ARM_GOT_ABS => 95,
            R_ARM_GOT_PREL => 96,
            R_ARM_GOT_BREL12 => 97,
            R_ARM_GOTOFF12 => 98,
            R_ARM_GOTRELAX => 99,
            R_ARM_GNU_VTENTRY => 100,
            R_ARM_GNU_VTINHERIT => 101,
            R_ARM_THM_JUMP11 => 102,
            R_ARM_THM_JUMP8 => 103,
            R_ARM_TLS_GD32 => 104,
            R_ARM_TLS_LDM32 => 105,
            R_ARM_TLS_LDO32 => 106,
            R_ARM_TLS_IE32 => 107,
            R_ARM_TLS_LE32 => 108,
            R_ARM_TLS_LDO12 => 109,
            R_ARM_TLS_LE12 => 110,
            R_ARM_TLS_IE12GP => 111,
            R_ARM_PRIVATE_0 => 112,
            R_ARM_PRIVATE_1 => 113,
            R_ARM_PRIVATE_2 => 114,
            R_ARM_PRIVATE_3 => 115,
            R_ARM_PRIVATE_4 => 116,
            R_ARM_PRIVATE_5 => 117,
            R_ARM_PRIVATE_6 => 118,
            R_ARM_PRIVATE_7 => 119,
            R_ARM_PRIVATE_8 => 120,
            R_ARM_PRIVATE_9 => 121,
            R_ARM_PRIVATE_10 => 122,
            R_ARM_PRIVATE_11 => 123,
            R_ARM_PRIVATE_12 => 124,
            R_ARM_PRIVATE_13 => 125,
            R_ARM_PRIVATE_14 => 126,
            R_ARM_PRIVATE_15 => 127,
            R_ARM_ME_TOO => 128,
            R_ARM_THM_TLS_DESCSEQ16 => 129,
            R_ARM_THM_TLS_DESCSEQ32 => 130,
            R_ARM_THM_ALU_ABS_G0_NC => 132,
            R_ARM_THM_ALU_ABS_G1_NC => 133,
            R_ARM_THM_ALU_ABS_G2_NC => 134,
            R_ARM_THM_ALU_ABS_G3_NC => 135,
            R_ARM_THM_BF16 => 136,
            R_ARM_THM_BF12 => 137,
            R_ARM_THM_BF18 => 138,
            R_ARM_IRELATIVE => 160,
            R_ARM_GOTFUNCDEC => 161,
            R_ARM_GOTOFFFUNCDESC => 162,
            R_ARM_FUNCESC => 163,
            R_ARM_FUNCDESC_VALUE => 164,
            R_ARM_TLS_GD32_FDPIC => 165,
            R_ARM_TLS_LDM32_FDPIC => 166,
            R_ARM_TLS_IE32_FDPIC => 167,
            R_ARM_RXPC25 => 249,
            R_ARM_RSBREL32 => 250,
            R_ARM_THM_RPC22 => 251,
            R_ARM_RREL32 => 252,
            R_ARM_RABS32 => 253,
            R_ARM_RPC24 => 254,
            R_ARM_RBASE => 255,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use ArmElfRelocationType::*;
        match self {
            R_ARM_NONE => "R_ARM_NONE",
            R_ARM_PC24 => "R_ARM_PC24",
            R_ARM_ABS32 => "R_ARM_ABS32",
            R_ARM_REL32 => "R_ARM_REL32",
            R_ARM_LDR_PC_G0 => "R_ARM_LDR_PC_G0",
            R_ARM_ABS16 => "R_ARM_ABS16",
            R_ARM_ABS12 => "R_ARM_ABS12",
            R_ARM_THM_ABS5 => "R_ARM_THM_ABS5",
            R_ARM_ABS_8 => "R_ARM_ABS_8",
            R_ARM_SBREL32 => "R_ARM_SBREL32",
            R_ARM_THM_CALL => "R_ARM_THM_CALL",
            R_ARM_THM_PC8 => "R_ARM_THM_PC8",
            R_ARM_BREL_ADJ => "R_ARM_BREL_ADJ",
            R_ARM_TLS_DESC => "R_ARM_TLS_DESC",
            R_ARM_THM_SWI8 => "R_ARM_THM_SWI8",
            R_ARM_XPC25 => "R_ARM_XPC25",
            R_ARM_THM_XPC22 => "R_ARM_THM_XPC22",
            R_ARM_TLS_DTPMOD32 => "R_ARM_TLS_DTPMOD32",
            R_ARM_TLS_DTPOFF32 => "R_ARM_TLS_DTPOFF32",
            R_ARM_TLS_TPOFF32 => "R_ARM_TLS_TPOFF32",
            R_ARM_COPY => "R_ARM_COPY",
            R_ARM_GLOB_DAT => "R_ARM_GLOB_DAT",
            R_ARM_JUMP_SLOT => "R_ARM_JUMP_SLOT",
            R_ARM_RELATIVE => "R_ARM_RELATIVE",
            R_ARM_GOTOFF32 => "R_ARM_GOTOFF32",
            R_ARM_BASE_PREL => "R_ARM_BASE_PREL",
            R_ARM_GOT_BREL => "R_ARM_GOT_BREL",
            R_ARM_PLT32 => "R_ARM_PLT32",
            R_ARM_CALL => "R_ARM_CALL",
            R_ARM_JUMP24 => "R_ARM_JUMP24",
            R_ARM_THM_JUMP24 => "R_ARM_THM_JUMP24",
            R_ARM_BASE_ABS => "R_ARM_BASE_ABS",
            R_ARM_ALU_PCREL_7_0 => "R_ARM_ALU_PCREL_7_0",
            R_ARM_ALU_PCREL_15_8 => "R_ARM_ALU_PCREL_15_8",
            R_ARM_ALU_PCREL_23_15 => "R_ARM_ALU_PCREL_23_15",
            R_ARM_LDR_SBREL_11_0_NC => "R_ARM_LDR_SBREL_11_0_NC",
            R_ARM_ALU_SBREL_19_12_NC => "R_ARM_ALU_SBREL_19_12_NC",
            R_ARM_ALU_SBREL_27_20_CK => "R_ARM_ALU_SBREL_27_20_CK",
            R_ARM_TARGET1 => "R_ARM_TARGET1",
            R_ARM_SBREL31 => "R_ARM_SBREL31",
            R_ARM_V4BX => "R_ARM_V4BX",
            R_ARM_TARGET2 => "R_ARM_TARGET2",
            R_ARM_PREL31 => "R_ARM_PREL31",
            R_ARM_MOVW_ABS_NC => "R_ARM_MOVW_ABS_NC",
            R_ARM_MOVT_ABS => "R_ARM_MOVT_ABS",
            R_ARM_MOVW_PREL_NC => "R_ARM_MOVW_PREL_NC",
            R_ARM_MOVT_PREL => "R_ARM_MOVT_PREL",
            R_ARM_THM_MOVW_ABS_NC => "R_ARM_THM_MOVW_ABS_NC",
            R_ARM_THM_MOVT_ABS => "R_ARM_THM_MOVT_ABS",
            R_ARM_THM_MOVW_PREL_NC => "R_ARM_THM_MOVW_PREL_NC",
            R_ARM_THM_MOVT_PREL => "R_ARM_THM_MOVT_PREL",
            R_ARM_THM_JUMP19 => "R_ARM_THM_JUMP19",
            R_ARM_THM_JUMP6 => "R_ARM_THM_JUMP6",
            R_ARM_THM_ALU_PREL_11_0 => "R_ARM_THM_ALU_PREL_11_0",
            R_ARM_THM_PC12 => "R_ARM_THM_PC12",
            R_ARM_ABS32_NOI => "R_ARM_ABS32_NOI",
            R_ARM_REL32_NOI => "R_ARM_REL32_NOI",
            R_ARM_ALU_PC_G0_NC => "R_ARM_ALU_PC_G0_NC",
            R_ARM_ALU_PC_G0 => "R_ARM_ALU_PC_G0",
            R_ARM_ALU_PC_G1_NC => "R_ARM_ALU_PC_G1_NC",
            R_ARM_ALU_PC_G1 => "R_ARM_ALU_PC_G1",
            R_ARM_ALU_PC_G2 => "R_ARM_ALU_PC_G2",
            R_ARM_LDR_PC_G1 => "R_ARM_LDR_PC_G1",
            R_ARM_LDR_PC_G2 => "R_ARM_LDR_PC_G2",
            R_ARM_LDRS_PC_G0 => "R_ARM_LDRS_PC_G0",
            R_ARM_LDRS_PC_G1 => "R_ARM_LDRS_PC_G1",
            R_ARM_LDRS_PC_G2 => "R_ARM_LDRS_PC_G2",
            R_ARM_LDC_PC_G0 => "R_ARM_LDC_PC_G0",
            R_ARM_LDC_PC_G1 => "R_ARM_LDC_PC_G1",
            R_ARM_LDC_PC_G2 => "R_ARM_LDC_PC_G2",
            R_ARM_ALU_SB_G0_NC => "R_ARM_ALU_SB_G0_NC",
            R_ARM_ALU_SB_G0 => "R_ARM_ALU_SB_G0",
            R_ARM_ALU_SB_G1_NC => "R_ARM_ALU_SB_G1_NC",
            R_ARM_ALU_SB_G1 => "R_ARM_ALU_SB_G1",
            R_ARM_ALU_SB_G2 => "R_ARM_ALU_SB_G2",
            R_ARM_LDR_SB_G0 => "R_ARM_LDR_SB_G0",
            R_ARM_LDR_SB_G1 => "R_ARM_LDR_SB_G1",
            R_ARM_LDR_SB_G2 => "R_ARM_LDR_SB_G2",
            R_ARM_LDRS_SB_G0 => "R_ARM_LDRS_SB_G0",
            R_ARM_LDRS_SB_G1 => "R_ARM_LDRS_SB_G1",
            R_ARM_LDRS_SB_G2 => "R_ARM_LDRS_SB_G2",
            R_ARM_LDC_SB_G0 => "R_ARM_LDC_SB_G0",
            R_ARM_LDC_SB_G1 => "R_ARM_LDC_SB_G1",
            R_ARM_LDC_SB_G2 => "R_ARM_LDC_SB_G2",
            R_ARM_MOVW_BREL_NC => "R_ARM_MOVW_BREL_NC",
            R_ARM_MOVT_BREL => "R_ARM_MOVT_BREL",
            R_ARM_MOVW_BREL => "R_ARM_MOVW_BREL",
            R_ARM_THM_MOVW_BREL_NC => "R_ARM_THM_MOVW_BREL_NC",
            R_ARM_THM_MOVT_BREL => "R_ARM_THM_MOVT_BREL",
            R_ARM_THM_MOVW_BREL => "R_ARM_THM_MOVW_BREL",
            R_ARM_TLS_GOTDESC => "R_ARM_TLS_GOTDESC",
            R_ARM_TLS_CALL => "R_ARM_TLS_CALL",
            R_ARM_TLS_DESCSEQ => "R_ARM_TLS_DESCSEQ",
            R_ARM_THM_TLS_CALL => "R_ARM_THM_TLS_CALL",
            R_ARM_PLT32_ABS => "R_ARM_PLT32_ABS",
            R_ARM_GOT_ABS => "R_ARM_GOT_ABS",
            R_ARM_GOT_PREL => "R_ARM_GOT_PREL",
            R_ARM_GOT_BREL12 => "R_ARM_GOT_BREL12",
            R_ARM_GOTOFF12 => "R_ARM_GOTOFF12",
            R_ARM_GOTRELAX => "R_ARM_GOTRELAX",
            R_ARM_GNU_VTENTRY => "R_ARM_GNU_VTENTRY",
            R_ARM_GNU_VTINHERIT => "R_ARM_GNU_VTINHERIT",
            R_ARM_THM_JUMP11 => "R_ARM_THM_JUMP11",
            R_ARM_THM_JUMP8 => "R_ARM_THM_JUMP8",
            R_ARM_TLS_GD32 => "R_ARM_TLS_GD32",
            R_ARM_TLS_LDM32 => "R_ARM_TLS_LDM32",
            R_ARM_TLS_LDO32 => "R_ARM_TLS_LDO32",
            R_ARM_TLS_IE32 => "R_ARM_TLS_IE32",
            R_ARM_TLS_LE32 => "R_ARM_TLS_LE32",
            R_ARM_TLS_LDO12 => "R_ARM_TLS_LDO12",
            R_ARM_TLS_LE12 => "R_ARM_TLS_LE12",
            R_ARM_TLS_IE12GP => "R_ARM_TLS_IE12GP",
            R_ARM_PRIVATE_0 => "R_ARM_PRIVATE_0",
            R_ARM_PRIVATE_1 => "R_ARM_PRIVATE_1",
            R_ARM_PRIVATE_2 => "R_ARM_PRIVATE_2",
            R_ARM_PRIVATE_3 => "R_ARM_PRIVATE_3",
            R_ARM_PRIVATE_4 => "R_ARM_PRIVATE_4",
            R_ARM_PRIVATE_5 => "R_ARM_PRIVATE_5",
            R_ARM_PRIVATE_6 => "R_ARM_PRIVATE_6",
            R_ARM_PRIVATE_7 => "R_ARM_PRIVATE_7",
            R_ARM_PRIVATE_8 => "R_ARM_PRIVATE_8",
            R_ARM_PRIVATE_9 => "R_ARM_PRIVATE_9",
            R_ARM_PRIVATE_10 => "R_ARM_PRIVATE_10",
            R_ARM_PRIVATE_11 => "R_ARM_PRIVATE_11",
            R_ARM_PRIVATE_12 => "R_ARM_PRIVATE_12",
            R_ARM_PRIVATE_13 => "R_ARM_PRIVATE_13",
            R_ARM_PRIVATE_14 => "R_ARM_PRIVATE_14",
            R_ARM_PRIVATE_15 => "R_ARM_PRIVATE_15",
            R_ARM_ME_TOO => "R_ARM_ME_TOO",
            R_ARM_THM_TLS_DESCSEQ16 => "R_ARM_THM_TLS_DESCSEQ16",
            R_ARM_THM_TLS_DESCSEQ32 => "R_ARM_THM_TLS_DESCSEQ32",
            R_ARM_THM_ALU_ABS_G0_NC => "R_ARM_THM_ALU_ABS_G0_NC",
            R_ARM_THM_ALU_ABS_G1_NC => "R_ARM_THM_ALU_ABS_G1_NC",
            R_ARM_THM_ALU_ABS_G2_NC => "R_ARM_THM_ALU_ABS_G2_NC",
            R_ARM_THM_ALU_ABS_G3_NC => "R_ARM_THM_ALU_ABS_G3_NC",
            R_ARM_THM_BF16 => "R_ARM_THM_BF16",
            R_ARM_THM_BF12 => "R_ARM_THM_BF12",
            R_ARM_THM_BF18 => "R_ARM_THM_BF18",
            R_ARM_IRELATIVE => "R_ARM_IRELATIVE",
            R_ARM_GOTFUNCDEC => "R_ARM_GOTFUNCDEC",
            R_ARM_GOTOFFFUNCDESC => "R_ARM_GOTOFFFUNCDESC",
            R_ARM_FUNCESC => "R_ARM_FUNCESC",
            R_ARM_FUNCDESC_VALUE => "R_ARM_FUNCDESC_VALUE",
            R_ARM_TLS_GD32_FDPIC => "R_ARM_TLS_GD32_FDPIC",
            R_ARM_TLS_LDM32_FDPIC => "R_ARM_TLS_LDM32_FDPIC",
            R_ARM_TLS_IE32_FDPIC => "R_ARM_TLS_IE32_FDPIC",
            R_ARM_RXPC25 => "R_ARM_RXPC25",
            R_ARM_RSBREL32 => "R_ARM_RSBREL32",
            R_ARM_THM_RPC22 => "R_ARM_THM_RPC22",
            R_ARM_RREL32 => "R_ARM_RREL32",
            R_ARM_RABS32 => "R_ARM_RABS32",
            R_ARM_RPC24 => "R_ARM_RPC24",
            R_ARM_RBASE => "R_ARM_RBASE",
        }
    }
}

impl ElfRelocationType for ArmElfRelocationType {
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
        assert_eq!(ArmElfRelocationType::R_ARM_NONE.type_id(), 0);
        assert_eq!(ArmElfRelocationType::R_ARM_NONE.name(), "R_ARM_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(ArmElfRelocationType::R_ARM_ABS32.type_id(), 2);
        assert_eq!(ArmElfRelocationType::R_ARM_REL32.type_id(), 3);
        assert_eq!(ArmElfRelocationType::R_ARM_COPY.type_id(), 20);
        assert_eq!(ArmElfRelocationType::R_ARM_JUMP_SLOT.type_id(), 22);
    }

    #[test]
    fn non_contiguous_id_gap_is_preserved() {
        // Java skips typeId 131 between R_ARM_THM_TLS_DESCSEQ32 (130) and
        // R_ARM_THM_ALU_ABS_G0_NC (132).
        assert_eq!(ArmElfRelocationType::R_ARM_THM_TLS_DESCSEQ32.type_id(), 130);
        assert_eq!(ArmElfRelocationType::R_ARM_THM_ALU_ABS_G0_NC.type_id(), 132);
    }

    #[test]
    fn high_range_reserved_constants_match_java_ids() {
        assert_eq!(ArmElfRelocationType::R_ARM_IRELATIVE.type_id(), 160);
        assert_eq!(ArmElfRelocationType::R_ARM_RXPC25.type_id(), 249);
        assert_eq!(ArmElfRelocationType::R_ARM_RBASE.type_id(), 255);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &ArmElfRelocationType::R_ARM_GLOB_DAT;
        assert_eq!(r.type_id(), 21);
        assert_eq!(r.name(), "R_ARM_GLOB_DAT");
    }
}
