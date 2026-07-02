//! Loongarch ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.Loongarch_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Loongarch ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum LoongarchElfRelocationType {
    R_LARCH_NONE,
    R_LARCH_32,
    R_LARCH_64,
    R_LARCH_RELATIVE,
    R_LARCH_COPY,
    R_LARCH_JUMP_SLOT,
    R_LARCH_TLS_DTPMOD32,
    R_LARCH_TLS_DTPMOD64,
    R_LARCH_TLS_DTPREL32,
    R_LARCH_TLS_DTPREL64,
    R_LARCH_TLS_TPREL32,
    R_LARCH_TLS_TPREL64,
    R_LARCH_IRELATIVE,
    R_LARCH_TLS_DESC32,
    R_LARCH_TLS_DESC64,
    R_LARCH_MARK_LA,
    R_LARCH_MARK_PCREL,
    R_LARCH_SOP_PUSH_PCREL,
    R_LARCH_SOP_PUSH_ABSOLUTE,
    R_LARCH_SOP_PUSH_DUP,
    R_LARCH_SOP_PUSH_GPREL,
    R_LARCH_SOP_PUSH_TLS_TPREL,
    R_LARCH_SOP_PUSH_TLS_GOT,
    R_LARCH_SOP_PUSH_TLS_GD,
    R_LARCH_SOP_PUSH_PLT_PCREL,
    R_LARCH_SOP_ASSERT,
    R_LARCH_SOP_NOT,
    R_LARCH_SOP_SUB,
    R_LARCH_SOP_SL,
    R_LARCH_SOP_SR,
    R_LARCH_SOP_ADD,
    R_LARCH_SOP_AND,
    R_LARCH_SOP_IF_ELSE,
    R_LARCH_SOP_POP_32_S_10_5,
    R_LARCH_SOP_POP_32_U_10_12,
    R_LARCH_SOP_POP_32_S_10_12,
    R_LARCH_SOP_POP_32_S_10_16,
    R_LARCH_SOP_POP_32_S_10_16_S2,
    R_LARCH_SOP_POP_32_S_5_20,
    R_LARCH_SOP_POP_32_S_0_5_10_16_S2,
    R_LARCH_SOP_POP_32_S_0_10_10_16_S2,
    R_LARCH_SOP_POP_32_U,
    R_LARCH_ADD8,
    R_LARCH_ADD16,
    R_LARCH_ADD24,
    R_LARCH_ADD32,
    R_LARCH_ADD64,
    R_LARCH_SUB8,
    R_LARCH_SUB16,
    R_LARCH_SUB24,
    R_LARCH_SUB32,
    R_LARCH_SUB64,
    R_LARCH_GNU_VTINHERIT,
    R_LARCH_GNU_VTENTRY,
    R_LARCH_B16,
    R_LARCH_B21,
    R_LARCH_B26,
    R_LARCH_ABS_HI20,
    R_LARCH_ABS_LO12,
    R_LARCH_ABS64_LO20,
    R_LARCH_ABS64_HI12,
    R_LARCH_PCALA_HI20,
    R_LARCH_PCALA_LO12,
    R_LARCH_PCALA64_LO20,
    R_LARCH_PCALA64_HI12,
    R_LARCH_GOT_PC_HI20,
    R_LARCH_GOT_PC_LO12,
    R_LARCH_GOT64_PC_LO20,
    R_LARCH_GOT64_PC_HI12,
    R_LARCH_GOT_HI20,
    R_LARCH_GOT_LO12,
    R_LARCH_GOT64_LO20,
    R_LARCH_GOT64_HI12,
    R_LARCH_TLS_LE_HI20,
    R_LARCH_TLS_LE_LO12,
    R_LARCH_TLS_LE64_LO20,
    R_LARCH_TLS_LE64_HI12,
    R_LARCH_TLS_IE_PC_HI20,
    R_LARCH_TLS_IE_PC_LO12,
    R_LARCH_TLS_IE64_PC_LO20,
    R_LARCH_TLS_IE64_PC_HI12,
    R_LARCH_TLS_IE_HI20,
    R_LARCH_TLS_IE_LO12,
    R_LARCH_TLS_IE64_LO20,
    R_LARCH_TLS_IE64_HI12,
    R_LARCH_TLS_LD_PC_HI20,
    R_LARCH_TLS_LD_HI20,
    R_LARCH_TLS_GD_PC_HI20,
    R_LARCH_TLS_GD_HI20,
    R_LARCH_32_PCREL,
    R_LARCH_RELAX,
    R_LARCH_DELETE,
    R_LARCH_ALIGN,
    R_LARCH_PCREL20_S2,
    R_LARCH_CFA,
    R_LARCH_ADD6,
    R_LARCH_SUB6,
    R_LARCH_ADD_ULEB128,
    R_LARCH_SUB_ULEB128,
    R_LARCH_64_PCREL,
    R_LARCH_CALL32,
    R_LARCH_TLS_DESC_PC_HI20,
    R_LARCH_TLS_DESC_PC_LO12,
    R_LARCH_TLS_DESC64_PC_LO20,
    R_LARCH_TLS_DESC64_PC_HI12,
    R_LARCH_TLS_DESC_HI20,
    R_LARCH_TLS_DESC_LO12,
    R_LARCH_TLS_DESC64_LO20,
    R_LARCH_TLS_DESC64_HI12,
    R_LARCH_TLS_DESC_LD,
    R_LARCH_TLS_DESC_CALL,
    R_LARCH_TLS_TLS_LE_HI20_R,
    R_LARCH_TLS_TLS_LE_ADD_R,
    R_LARCH_TLS_TLS_LE_LO12_R,
    R_LARCH_TLS_TLS_LD_PCREL20_S2,
    R_LARCH_TLS_TLS_GD_PCREL20_S2,
    R_LARCH_TLS_TLS_DESC_PCREL20_S2,
}

impl LoongarchElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use LoongarchElfRelocationType::*;
        match self {
            R_LARCH_NONE => 0,
            R_LARCH_32 => 1,
            R_LARCH_64 => 2,
            R_LARCH_RELATIVE => 3,
            R_LARCH_COPY => 4,
            R_LARCH_JUMP_SLOT => 5,
            R_LARCH_TLS_DTPMOD32 => 6,
            R_LARCH_TLS_DTPMOD64 => 7,
            R_LARCH_TLS_DTPREL32 => 8,
            R_LARCH_TLS_DTPREL64 => 9,
            R_LARCH_TLS_TPREL32 => 10,
            R_LARCH_TLS_TPREL64 => 11,
            R_LARCH_IRELATIVE => 12,
            R_LARCH_TLS_DESC32 => 13,
            R_LARCH_TLS_DESC64 => 14,
            R_LARCH_MARK_LA => 20,
            R_LARCH_MARK_PCREL => 21,
            R_LARCH_SOP_PUSH_PCREL => 22,
            R_LARCH_SOP_PUSH_ABSOLUTE => 23,
            R_LARCH_SOP_PUSH_DUP => 24,
            R_LARCH_SOP_PUSH_GPREL => 25,
            R_LARCH_SOP_PUSH_TLS_TPREL => 26,
            R_LARCH_SOP_PUSH_TLS_GOT => 27,
            R_LARCH_SOP_PUSH_TLS_GD => 28,
            R_LARCH_SOP_PUSH_PLT_PCREL => 29,
            R_LARCH_SOP_ASSERT => 30,
            R_LARCH_SOP_NOT => 31,
            R_LARCH_SOP_SUB => 32,
            R_LARCH_SOP_SL => 33,
            R_LARCH_SOP_SR => 34,
            R_LARCH_SOP_ADD => 35,
            R_LARCH_SOP_AND => 36,
            R_LARCH_SOP_IF_ELSE => 37,
            R_LARCH_SOP_POP_32_S_10_5 => 38,
            R_LARCH_SOP_POP_32_U_10_12 => 39,
            R_LARCH_SOP_POP_32_S_10_12 => 40,
            R_LARCH_SOP_POP_32_S_10_16 => 41,
            R_LARCH_SOP_POP_32_S_10_16_S2 => 42,
            R_LARCH_SOP_POP_32_S_5_20 => 43,
            R_LARCH_SOP_POP_32_S_0_5_10_16_S2 => 44,
            R_LARCH_SOP_POP_32_S_0_10_10_16_S2 => 45,
            R_LARCH_SOP_POP_32_U => 46,
            R_LARCH_ADD8 => 47,
            R_LARCH_ADD16 => 48,
            R_LARCH_ADD24 => 49,
            R_LARCH_ADD32 => 50,
            R_LARCH_ADD64 => 51,
            R_LARCH_SUB8 => 52,
            R_LARCH_SUB16 => 53,
            R_LARCH_SUB24 => 54,
            R_LARCH_SUB32 => 55,
            R_LARCH_SUB64 => 56,
            R_LARCH_GNU_VTINHERIT => 57,
            R_LARCH_GNU_VTENTRY => 58,
            R_LARCH_B16 => 64,
            R_LARCH_B21 => 65,
            R_LARCH_B26 => 66,
            R_LARCH_ABS_HI20 => 67,
            R_LARCH_ABS_LO12 => 68,
            R_LARCH_ABS64_LO20 => 69,
            R_LARCH_ABS64_HI12 => 70,
            R_LARCH_PCALA_HI20 => 71,
            R_LARCH_PCALA_LO12 => 72,
            R_LARCH_PCALA64_LO20 => 73,
            R_LARCH_PCALA64_HI12 => 74,
            R_LARCH_GOT_PC_HI20 => 75,
            R_LARCH_GOT_PC_LO12 => 76,
            R_LARCH_GOT64_PC_LO20 => 77,
            R_LARCH_GOT64_PC_HI12 => 78,
            R_LARCH_GOT_HI20 => 79,
            R_LARCH_GOT_LO12 => 80,
            R_LARCH_GOT64_LO20 => 81,
            R_LARCH_GOT64_HI12 => 82,
            R_LARCH_TLS_LE_HI20 => 83,
            R_LARCH_TLS_LE_LO12 => 84,
            R_LARCH_TLS_LE64_LO20 => 85,
            R_LARCH_TLS_LE64_HI12 => 86,
            R_LARCH_TLS_IE_PC_HI20 => 87,
            R_LARCH_TLS_IE_PC_LO12 => 88,
            R_LARCH_TLS_IE64_PC_LO20 => 89,
            R_LARCH_TLS_IE64_PC_HI12 => 90,
            R_LARCH_TLS_IE_HI20 => 91,
            R_LARCH_TLS_IE_LO12 => 92,
            R_LARCH_TLS_IE64_LO20 => 93,
            R_LARCH_TLS_IE64_HI12 => 94,
            R_LARCH_TLS_LD_PC_HI20 => 95,
            R_LARCH_TLS_LD_HI20 => 96,
            R_LARCH_TLS_GD_PC_HI20 => 97,
            R_LARCH_TLS_GD_HI20 => 98,
            R_LARCH_32_PCREL => 99,
            R_LARCH_RELAX => 100,
            R_LARCH_DELETE => 101,
            R_LARCH_ALIGN => 102,
            R_LARCH_PCREL20_S2 => 103,
            R_LARCH_CFA => 104,
            R_LARCH_ADD6 => 105,
            R_LARCH_SUB6 => 106,
            R_LARCH_ADD_ULEB128 => 107,
            R_LARCH_SUB_ULEB128 => 108,
            R_LARCH_64_PCREL => 109,
            R_LARCH_CALL32 => 110,
            R_LARCH_TLS_DESC_PC_HI20 => 111,
            R_LARCH_TLS_DESC_PC_LO12 => 112,
            R_LARCH_TLS_DESC64_PC_LO20 => 113,
            R_LARCH_TLS_DESC64_PC_HI12 => 114,
            R_LARCH_TLS_DESC_HI20 => 115,
            R_LARCH_TLS_DESC_LO12 => 116,
            R_LARCH_TLS_DESC64_LO20 => 117,
            R_LARCH_TLS_DESC64_HI12 => 118,
            R_LARCH_TLS_DESC_LD => 119,
            R_LARCH_TLS_DESC_CALL => 120,
            R_LARCH_TLS_TLS_LE_HI20_R => 121,
            R_LARCH_TLS_TLS_LE_ADD_R => 122,
            R_LARCH_TLS_TLS_LE_LO12_R => 123,
            R_LARCH_TLS_TLS_LD_PCREL20_S2 => 124,
            R_LARCH_TLS_TLS_GD_PCREL20_S2 => 125,
            R_LARCH_TLS_TLS_DESC_PCREL20_S2 => 126,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use LoongarchElfRelocationType::*;
        match self {
            R_LARCH_NONE => "R_LARCH_NONE",
            R_LARCH_32 => "R_LARCH_32",
            R_LARCH_64 => "R_LARCH_64",
            R_LARCH_RELATIVE => "R_LARCH_RELATIVE",
            R_LARCH_COPY => "R_LARCH_COPY",
            R_LARCH_JUMP_SLOT => "R_LARCH_JUMP_SLOT",
            R_LARCH_TLS_DTPMOD32 => "R_LARCH_TLS_DTPMOD32",
            R_LARCH_TLS_DTPMOD64 => "R_LARCH_TLS_DTPMOD64",
            R_LARCH_TLS_DTPREL32 => "R_LARCH_TLS_DTPREL32",
            R_LARCH_TLS_DTPREL64 => "R_LARCH_TLS_DTPREL64",
            R_LARCH_TLS_TPREL32 => "R_LARCH_TLS_TPREL32",
            R_LARCH_TLS_TPREL64 => "R_LARCH_TLS_TPREL64",
            R_LARCH_IRELATIVE => "R_LARCH_IRELATIVE",
            R_LARCH_TLS_DESC32 => "R_LARCH_TLS_DESC32",
            R_LARCH_TLS_DESC64 => "R_LARCH_TLS_DESC64",
            R_LARCH_MARK_LA => "R_LARCH_MARK_LA",
            R_LARCH_MARK_PCREL => "R_LARCH_MARK_PCREL",
            R_LARCH_SOP_PUSH_PCREL => "R_LARCH_SOP_PUSH_PCREL",
            R_LARCH_SOP_PUSH_ABSOLUTE => "R_LARCH_SOP_PUSH_ABSOLUTE",
            R_LARCH_SOP_PUSH_DUP => "R_LARCH_SOP_PUSH_DUP",
            R_LARCH_SOP_PUSH_GPREL => "R_LARCH_SOP_PUSH_GPREL",
            R_LARCH_SOP_PUSH_TLS_TPREL => "R_LARCH_SOP_PUSH_TLS_TPREL",
            R_LARCH_SOP_PUSH_TLS_GOT => "R_LARCH_SOP_PUSH_TLS_GOT",
            R_LARCH_SOP_PUSH_TLS_GD => "R_LARCH_SOP_PUSH_TLS_GD",
            R_LARCH_SOP_PUSH_PLT_PCREL => "R_LARCH_SOP_PUSH_PLT_PCREL",
            R_LARCH_SOP_ASSERT => "R_LARCH_SOP_ASSERT",
            R_LARCH_SOP_NOT => "R_LARCH_SOP_NOT",
            R_LARCH_SOP_SUB => "R_LARCH_SOP_SUB",
            R_LARCH_SOP_SL => "R_LARCH_SOP_SL",
            R_LARCH_SOP_SR => "R_LARCH_SOP_SR",
            R_LARCH_SOP_ADD => "R_LARCH_SOP_ADD",
            R_LARCH_SOP_AND => "R_LARCH_SOP_AND",
            R_LARCH_SOP_IF_ELSE => "R_LARCH_SOP_IF_ELSE",
            R_LARCH_SOP_POP_32_S_10_5 => "R_LARCH_SOP_POP_32_S_10_5",
            R_LARCH_SOP_POP_32_U_10_12 => "R_LARCH_SOP_POP_32_U_10_12",
            R_LARCH_SOP_POP_32_S_10_12 => "R_LARCH_SOP_POP_32_S_10_12",
            R_LARCH_SOP_POP_32_S_10_16 => "R_LARCH_SOP_POP_32_S_10_16",
            R_LARCH_SOP_POP_32_S_10_16_S2 => "R_LARCH_SOP_POP_32_S_10_16_S2",
            R_LARCH_SOP_POP_32_S_5_20 => "R_LARCH_SOP_POP_32_S_5_20",
            R_LARCH_SOP_POP_32_S_0_5_10_16_S2 => "R_LARCH_SOP_POP_32_S_0_5_10_16_S2",
            R_LARCH_SOP_POP_32_S_0_10_10_16_S2 => "R_LARCH_SOP_POP_32_S_0_10_10_16_S2",
            R_LARCH_SOP_POP_32_U => "R_LARCH_SOP_POP_32_U",
            R_LARCH_ADD8 => "R_LARCH_ADD8",
            R_LARCH_ADD16 => "R_LARCH_ADD16",
            R_LARCH_ADD24 => "R_LARCH_ADD24",
            R_LARCH_ADD32 => "R_LARCH_ADD32",
            R_LARCH_ADD64 => "R_LARCH_ADD64",
            R_LARCH_SUB8 => "R_LARCH_SUB8",
            R_LARCH_SUB16 => "R_LARCH_SUB16",
            R_LARCH_SUB24 => "R_LARCH_SUB24",
            R_LARCH_SUB32 => "R_LARCH_SUB32",
            R_LARCH_SUB64 => "R_LARCH_SUB64",
            R_LARCH_GNU_VTINHERIT => "R_LARCH_GNU_VTINHERIT",
            R_LARCH_GNU_VTENTRY => "R_LARCH_GNU_VTENTRY",
            R_LARCH_B16 => "R_LARCH_B16",
            R_LARCH_B21 => "R_LARCH_B21",
            R_LARCH_B26 => "R_LARCH_B26",
            R_LARCH_ABS_HI20 => "R_LARCH_ABS_HI20",
            R_LARCH_ABS_LO12 => "R_LARCH_ABS_LO12",
            R_LARCH_ABS64_LO20 => "R_LARCH_ABS64_LO20",
            R_LARCH_ABS64_HI12 => "R_LARCH_ABS64_HI12",
            R_LARCH_PCALA_HI20 => "R_LARCH_PCALA_HI20",
            R_LARCH_PCALA_LO12 => "R_LARCH_PCALA_LO12",
            R_LARCH_PCALA64_LO20 => "R_LARCH_PCALA64_LO20",
            R_LARCH_PCALA64_HI12 => "R_LARCH_PCALA64_HI12",
            R_LARCH_GOT_PC_HI20 => "R_LARCH_GOT_PC_HI20",
            R_LARCH_GOT_PC_LO12 => "R_LARCH_GOT_PC_LO12",
            R_LARCH_GOT64_PC_LO20 => "R_LARCH_GOT64_PC_LO20",
            R_LARCH_GOT64_PC_HI12 => "R_LARCH_GOT64_PC_HI12",
            R_LARCH_GOT_HI20 => "R_LARCH_GOT_HI20",
            R_LARCH_GOT_LO12 => "R_LARCH_GOT_LO12",
            R_LARCH_GOT64_LO20 => "R_LARCH_GOT64_LO20",
            R_LARCH_GOT64_HI12 => "R_LARCH_GOT64_HI12",
            R_LARCH_TLS_LE_HI20 => "R_LARCH_TLS_LE_HI20",
            R_LARCH_TLS_LE_LO12 => "R_LARCH_TLS_LE_LO12",
            R_LARCH_TLS_LE64_LO20 => "R_LARCH_TLS_LE64_LO20",
            R_LARCH_TLS_LE64_HI12 => "R_LARCH_TLS_LE64_HI12",
            R_LARCH_TLS_IE_PC_HI20 => "R_LARCH_TLS_IE_PC_HI20",
            R_LARCH_TLS_IE_PC_LO12 => "R_LARCH_TLS_IE_PC_LO12",
            R_LARCH_TLS_IE64_PC_LO20 => "R_LARCH_TLS_IE64_PC_LO20",
            R_LARCH_TLS_IE64_PC_HI12 => "R_LARCH_TLS_IE64_PC_HI12",
            R_LARCH_TLS_IE_HI20 => "R_LARCH_TLS_IE_HI20",
            R_LARCH_TLS_IE_LO12 => "R_LARCH_TLS_IE_LO12",
            R_LARCH_TLS_IE64_LO20 => "R_LARCH_TLS_IE64_LO20",
            R_LARCH_TLS_IE64_HI12 => "R_LARCH_TLS_IE64_HI12",
            R_LARCH_TLS_LD_PC_HI20 => "R_LARCH_TLS_LD_PC_HI20",
            R_LARCH_TLS_LD_HI20 => "R_LARCH_TLS_LD_HI20",
            R_LARCH_TLS_GD_PC_HI20 => "R_LARCH_TLS_GD_PC_HI20",
            R_LARCH_TLS_GD_HI20 => "R_LARCH_TLS_GD_HI20",
            R_LARCH_32_PCREL => "R_LARCH_32_PCREL",
            R_LARCH_RELAX => "R_LARCH_RELAX",
            R_LARCH_DELETE => "R_LARCH_DELETE",
            R_LARCH_ALIGN => "R_LARCH_ALIGN",
            R_LARCH_PCREL20_S2 => "R_LARCH_PCREL20_S2",
            R_LARCH_CFA => "R_LARCH_CFA",
            R_LARCH_ADD6 => "R_LARCH_ADD6",
            R_LARCH_SUB6 => "R_LARCH_SUB6",
            R_LARCH_ADD_ULEB128 => "R_LARCH_ADD_ULEB128",
            R_LARCH_SUB_ULEB128 => "R_LARCH_SUB_ULEB128",
            R_LARCH_64_PCREL => "R_LARCH_64_PCREL",
            R_LARCH_CALL32 => "R_LARCH_CALL32",
            R_LARCH_TLS_DESC_PC_HI20 => "R_LARCH_TLS_DESC_PC_HI20",
            R_LARCH_TLS_DESC_PC_LO12 => "R_LARCH_TLS_DESC_PC_LO12",
            R_LARCH_TLS_DESC64_PC_LO20 => "R_LARCH_TLS_DESC64_PC_LO20",
            R_LARCH_TLS_DESC64_PC_HI12 => "R_LARCH_TLS_DESC64_PC_HI12",
            R_LARCH_TLS_DESC_HI20 => "R_LARCH_TLS_DESC_HI20",
            R_LARCH_TLS_DESC_LO12 => "R_LARCH_TLS_DESC_LO12",
            R_LARCH_TLS_DESC64_LO20 => "R_LARCH_TLS_DESC64_LO20",
            R_LARCH_TLS_DESC64_HI12 => "R_LARCH_TLS_DESC64_HI12",
            R_LARCH_TLS_DESC_LD => "R_LARCH_TLS_DESC_LD",
            R_LARCH_TLS_DESC_CALL => "R_LARCH_TLS_DESC_CALL",
            R_LARCH_TLS_TLS_LE_HI20_R => "R_LARCH_TLS_TLS_LE_HI20_R",
            R_LARCH_TLS_TLS_LE_ADD_R => "R_LARCH_TLS_TLS_LE_ADD_R",
            R_LARCH_TLS_TLS_LE_LO12_R => "R_LARCH_TLS_TLS_LE_LO12_R",
            R_LARCH_TLS_TLS_LD_PCREL20_S2 => "R_LARCH_TLS_TLS_LD_PCREL20_S2",
            R_LARCH_TLS_TLS_GD_PCREL20_S2 => "R_LARCH_TLS_TLS_GD_PCREL20_S2",
            R_LARCH_TLS_TLS_DESC_PCREL20_S2 => "R_LARCH_TLS_TLS_DESC_PCREL20_S2",
        }
    }
}

impl ElfRelocationType for LoongarchElfRelocationType {
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
        assert_eq!(LoongarchElfRelocationType::R_LARCH_NONE.type_id(), 0);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_NONE.name(), "R_LARCH_NONE");
    }

    #[test]
    fn basic_relocation_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_32.type_id(), 1);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_64.type_id(), 2);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_RELATIVE.type_id(), 3);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_COPY.type_id(), 4);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_JUMP_SLOT.type_id(), 5);
    }

    #[test]
    fn tls_dtpmod_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DTPMOD32.type_id(), 6);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DTPMOD64.type_id(), 7);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DTPREL32.type_id(), 8);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DTPREL64.type_id(), 9);
    }

    #[test]
    fn tls_tprel_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TPREL32.type_id(), 10);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TPREL64.type_id(), 11);
    }

    #[test]
    fn irelative_and_tls_desc_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_IRELATIVE.type_id(), 12);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC32.type_id(), 13);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC64.type_id(), 14);
    }

    #[test]
    fn mark_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_MARK_LA.type_id(), 20);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_MARK_PCREL.type_id(), 21);
    }

    #[test]
    fn sop_push_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_PCREL.type_id(), 22);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_ABSOLUTE.type_id(), 23);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_DUP.type_id(), 24);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_GPREL.type_id(), 25);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_TLS_TPREL.type_id(), 26);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_TLS_GOT.type_id(), 27);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_TLS_GD.type_id(), 28);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_PUSH_PLT_PCREL.type_id(), 29);
    }

    #[test]
    fn sop_assert_and_bitwise_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_ASSERT.type_id(), 30);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_NOT.type_id(), 31);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_SUB.type_id(), 32);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_SL.type_id(), 33);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_SR.type_id(), 34);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_ADD.type_id(), 35);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_AND.type_id(), 36);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_IF_ELSE.type_id(), 37);
    }

    #[test]
    fn sop_pop_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_10_5.type_id(), 38);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_U_10_12.type_id(), 39);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_10_12.type_id(), 40);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_10_16.type_id(), 41);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_10_16_S2.type_id(), 42);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_5_20.type_id(), 43);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_0_5_10_16_S2.type_id(), 44);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_S_0_10_10_16_S2.type_id(), 45);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SOP_POP_32_U.type_id(), 46);
    }

    #[test]
    fn add_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD8.type_id(), 47);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD16.type_id(), 48);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD24.type_id(), 49);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD32.type_id(), 50);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD64.type_id(), 51);
    }

    #[test]
    fn sub_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB8.type_id(), 52);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB16.type_id(), 53);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB24.type_id(), 54);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB32.type_id(), 55);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB64.type_id(), 56);
    }

    #[test]
    fn gnu_vt_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GNU_VTINHERIT.type_id(), 57);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GNU_VTENTRY.type_id(), 58);
    }

    #[test]
    fn branch_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_B16.type_id(), 64);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_B21.type_id(), 65);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_B26.type_id(), 66);
    }

    #[test]
    fn abs_address_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ABS_HI20.type_id(), 67);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ABS_LO12.type_id(), 68);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ABS64_LO20.type_id(), 69);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ABS64_HI12.type_id(), 70);
    }

    #[test]
    fn pcala_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_PCALA_HI20.type_id(), 71);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_PCALA_LO12.type_id(), 72);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_PCALA64_LO20.type_id(), 73);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_PCALA64_HI12.type_id(), 74);
    }

    #[test]
    fn got_pc_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT_PC_HI20.type_id(), 75);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT_PC_LO12.type_id(), 76);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT64_PC_LO20.type_id(), 77);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT64_PC_HI12.type_id(), 78);
    }

    #[test]
    fn got_absolute_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT_HI20.type_id(), 79);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT_LO12.type_id(), 80);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT64_LO20.type_id(), 81);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_GOT64_HI12.type_id(), 82);
    }

    #[test]
    fn tls_le_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LE_HI20.type_id(), 83);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LE_LO12.type_id(), 84);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LE64_LO20.type_id(), 85);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LE64_HI12.type_id(), 86);
    }

    #[test]
    fn tls_ie_pc_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE_PC_HI20.type_id(), 87);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE_PC_LO12.type_id(), 88);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE64_PC_LO20.type_id(), 89);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE64_PC_HI12.type_id(), 90);
    }

    #[test]
    fn tls_ie_absolute_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE_HI20.type_id(), 91);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE_LO12.type_id(), 92);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE64_LO20.type_id(), 93);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_IE64_HI12.type_id(), 94);
    }

    #[test]
    fn tls_ld_gd_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LD_PC_HI20.type_id(), 95);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_LD_HI20.type_id(), 96);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_GD_PC_HI20.type_id(), 97);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_GD_HI20.type_id(), 98);
    }

    #[test]
    fn pcrel_and_relax_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_32_PCREL.type_id(), 99);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_RELAX.type_id(), 100);
    }

    #[test]
    fn binutils_extension_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_DELETE.type_id(), 101);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ALIGN.type_id(), 102);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_PCREL20_S2.type_id(), 103);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_CFA.type_id(), 104);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD6.type_id(), 105);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB6.type_id(), 106);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_ADD_ULEB128.type_id(), 107);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_SUB_ULEB128.type_id(), 108);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_64_PCREL.type_id(), 109);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_CALL32.type_id(), 110);
    }

    #[test]
    fn tls_desc_pc_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_PC_HI20.type_id(), 111);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_PC_LO12.type_id(), 112);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC64_PC_LO20.type_id(), 113);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC64_PC_HI12.type_id(), 114);
    }

    #[test]
    fn tls_desc_absolute_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_HI20.type_id(), 115);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_LO12.type_id(), 116);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC64_LO20.type_id(), 117);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC64_HI12.type_id(), 118);
    }

    #[test]
    fn tls_desc_ld_call_types_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_LD.type_id(), 119);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_DESC_CALL.type_id(), 120);
    }

    #[test]
    fn tls_ie_ld_gd_variants_match_java_ids() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_LE_HI20_R.type_id(), 121);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_LE_ADD_R.type_id(), 122);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_LE_LO12_R.type_id(), 123);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_LD_PCREL20_S2.type_id(), 124);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_GD_PCREL20_S2.type_id(), 125);
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_DESC_PCREL20_S2.type_id(), 126);
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(LoongarchElfRelocationType::R_LARCH_NONE.name(), "R_LARCH_NONE");
        assert_eq!(LoongarchElfRelocationType::R_LARCH_32.name(), "R_LARCH_32");
        assert_eq!(LoongarchElfRelocationType::R_LARCH_64.name(), "R_LARCH_64");
        assert_eq!(LoongarchElfRelocationType::R_LARCH_RELATIVE.name(), "R_LARCH_RELATIVE");
        assert_eq!(LoongarchElfRelocationType::R_LARCH_TLS_TLS_DESC_PCREL20_S2.name(), "R_LARCH_TLS_TLS_DESC_PCREL20_S2");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &LoongarchElfRelocationType::R_LARCH_RELATIVE;
        assert_eq!(r.type_id(), 3);
        assert_eq!(r.name(), "R_LARCH_RELATIVE");
    }
}
