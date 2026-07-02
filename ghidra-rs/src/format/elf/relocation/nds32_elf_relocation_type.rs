//! NDS32 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.NDS32_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// NDS32 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Nds32ElfRelocationType {
    // REL relocations.
    R_NDS32_16,
    R_NDS32_32,
    R_NDS32_20,
    R_NDS32_9_PCREL,
    R_NDS32_15_PCREL,
    R_NDS32_17_PCREL,
    R_NDS32_25_PCREL,
    R_NDS32_HI20,
    R_NDS32_LO12S3,
    R_NDS32_LO12S2,
    R_NDS32_LO12S1,
    R_NDS32_LO12S0,
    R_NDS32_SDA15S3,
    R_NDS32_SDA15S2,
    R_NDS32_SDA15S1,
    R_NDS32_SDA15S0,
    R_NDS32_GNU_VTINHERIT,
    R_NDS32_GNU_VTENTRY,
    // RELA relocations.
    R_NDS32_16_RELA,
    R_NDS32_32_RELA,
    R_NDS32_20_RELA,
    R_NDS32_9_PCREL_RELA,
    R_NDS32_15_PCREL_RELA,
    R_NDS32_17_PCREL_RELA,
    R_NDS32_25_PCREL_RELA,
    R_NDS32_HI20_RELA,
    R_NDS32_LO12S3_RELA,
    R_NDS32_LO12S2_RELA,
    R_NDS32_LO12S1_RELA,
    R_NDS32_LO12S0_RELA,
    R_NDS32_SDA15S3_RELA,
    R_NDS32_SDA15S2_RELA,
    R_NDS32_SDA15S1_RELA,
    R_NDS32_SDA15S0_RELA,
    R_NDS32_RELA_GNU_VTINHERIT,
    R_NDS32_RELA_GNU_VTENTRY,
    // GOT and PLT.
    R_NDS32_GOT20,
    R_NDS32_25_PLTREL,
    R_NDS32_COPY,
    R_NDS32_GLOB_DAT,
    R_NDS32_JMP_SLOT,
    R_NDS32_RELATIVE,
    R_NDS32_GOTOFF,
    R_NDS32_GOTPC20,
    R_NDS32_GOT_HI20,
    R_NDS32_GOT_LO12,
    R_NDS32_GOTPC_HI20,
    R_NDS32_GOTPC_LO12,
    R_NDS32_GOTOFF_HI20,
    R_NDS32_GOTOFF_LO12,
    // 32_to_16 relaxations.
    R_NDS32_INSN16,
    // Alignment tag.
    R_NDS32_LABEL,
    R_NDS32_LONGCALL1,
    R_NDS32_LONGCALL2,
    R_NDS32_LONGCALL3,
    R_NDS32_LONGJUMP1,
    R_NDS32_LONGJUMP2,
    R_NDS32_LONGJUMP3,
    R_NDS32_LOADSTORE,
    R_NDS32_9_FIXED_RELA,
    R_NDS32_15_FIXED_RELA,
    R_NDS32_17_FIXED_RELA,
    R_NDS32_25_FIXED_RELA,
    R_NDS32_PLTREL_HI20,
    R_NDS32_PLTREL_LO12,
    R_NDS32_PLT_GOTREL_HI20,
    R_NDS32_PLT_GOTREL_LO12,
    R_NDS32_SDA12S2_DP_RELA,
    R_NDS32_SDA12S2_SP_RELA,
    R_NDS32_LO12S2_DP_RELA,
    R_NDS32_LO12S2_SP_RELA,
    R_NDS32_LO12S0_ORI_RELA,
    R_NDS32_SDA16S3_RELA,
    R_NDS32_SDA17S2_RELA,
    R_NDS32_SDA18S1_RELA,
    R_NDS32_SDA19S0_RELA,
    R_NDS32_DWARF2_OP1_RELA,
    R_NDS32_DWARF2_OP2_RELA,
    R_NDS32_DWARF2_LEB_RELA,
    R_NDS32_UPDATE_TA_RELA,
    R_NDS32_9_PLTREL,
    R_NDS32_PLT_GOTREL_LO20,
    R_NDS32_PLT_GOTREL_LO15,
    R_NDS32_PLT_GOTREL_LO19,
    R_NDS32_GOT_LO15,
    R_NDS32_GOT_LO19,
    R_NDS32_GOTOFF_LO15,
    R_NDS32_GOTOFF_LO19,
    R_NDS32_GOT15S2_RELA,
    R_NDS32_GOT17S2_RELA,
    R_NDS32_5_RELA,
    R_NDS32_10_UPCREL_RELA,
    R_NDS32_SDA_FP7U2_RELA,
    R_NDS32_WORD_9_PCREL_RELA,
    R_NDS32_25_ABS_RELA,
    R_NDS32_17IFC_PCREL_RELA,
    R_NDS32_10IFCU_PCREL_RELA,
    // TLS support.
    R_NDS32_TLS_LE_HI20,
    R_NDS32_TLS_LE_LO12,
    R_NDS32_TLS_IE_HI20,
    R_NDS32_TLS_IE_LO12S2,
    R_NDS32_TLS_TPOFF,
    R_NDS32_TLS_LE_20,
    R_NDS32_TLS_LE_15S0,
    R_NDS32_TLS_LE_15S1,
    R_NDS32_TLS_LE_15S2,
    R_NDS32_LONGCALL4,
    R_NDS32_LONGCALL5,
    R_NDS32_LONGCALL6,
    R_NDS32_LONGJUMP4,
    R_NDS32_LONGJUMP5,
    R_NDS32_LONGJUMP6,
    R_NDS32_LONGJUMP7,
    // Reserved numbers: 114.
    // TLS support
    R_NDS32_TLS_IE_LO12,
    R_NDS32_TLS_IEGP_HI20,
    R_NDS32_TLS_IEGP_LO12,
    R_NDS32_TLS_IEGP_LO12S2,
    R_NDS32_TLS_DESC,
    R_NDS32_TLS_DESC_HI20,
    R_NDS32_TLS_DESC_LO12,
    R_NDS32_TLS_DESC_20,
    R_NDS32_TLS_DESC_SDA17S2,
    // Reserved numbers: 124-191.

    // These used only for relaxations
    R_NDS32_RELAX_ENTRY,
    R_NDS32_GOT_SUFF,
    R_NDS32_GOTOFF_SUFF,
    R_NDS32_PLT_GOT_SUFF,
    R_NDS32_MULCALL_SUFF,
    R_NDS32_PTR,
    R_NDS32_PTR_COUNT,
    R_NDS32_PTR_RESOLVED,
    R_NDS32_PLTBLOCK,
    R_NDS32_RELAX_REGION_BEGIN,
    R_NDS32_RELAX_REGION_END,
    R_NDS32_MINUEND,
    R_NDS32_SUBTRAHEND,
    R_NDS32_DIFF8,
    R_NDS32_DIFF16,
    R_NDS32_DIFF32,
    R_NDS32_DIFF_ULEB128,
    R_NDS32_DATA,
    R_NDS32_TRAN,
    // TLS support
    R_NDS32_TLS_LE_ADD,
    R_NDS32_TLS_LE_LS,
    R_NDS32_EMPTY,
    R_NDS32_TLS_DESC_ADD,
    R_NDS32_TLS_DESC_FUNC,
    R_NDS32_TLS_DESC_CALL,
    R_NDS32_TLS_DESC_MEM,
    R_NDS32_RELAX_REMOVE,
    R_NDS32_RELAX_GROUP,
    R_NDS32_TLS_IEGP_LW,
    R_NDS32_LSI,
    R_NDS32_RELA_NOP_MAX,
}

impl Nds32ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Nds32ElfRelocationType::*;
        match self {
            R_NDS32_16 => 1,
            R_NDS32_32 => 2,
            R_NDS32_20 => 3,
            R_NDS32_9_PCREL => 4,
            R_NDS32_15_PCREL => 5,
            R_NDS32_17_PCREL => 6,
            R_NDS32_25_PCREL => 7,
            R_NDS32_HI20 => 8,
            R_NDS32_LO12S3 => 9,
            R_NDS32_LO12S2 => 10,
            R_NDS32_LO12S1 => 11,
            R_NDS32_LO12S0 => 12,
            R_NDS32_SDA15S3 => 13,
            R_NDS32_SDA15S2 => 14,
            R_NDS32_SDA15S1 => 15,
            R_NDS32_SDA15S0 => 16,
            R_NDS32_GNU_VTINHERIT => 17,
            R_NDS32_GNU_VTENTRY => 18,
            R_NDS32_16_RELA => 19,
            R_NDS32_32_RELA => 20,
            R_NDS32_20_RELA => 21,
            R_NDS32_9_PCREL_RELA => 22,
            R_NDS32_15_PCREL_RELA => 23,
            R_NDS32_17_PCREL_RELA => 24,
            R_NDS32_25_PCREL_RELA => 25,
            R_NDS32_HI20_RELA => 26,
            R_NDS32_LO12S3_RELA => 27,
            R_NDS32_LO12S2_RELA => 28,
            R_NDS32_LO12S1_RELA => 29,
            R_NDS32_LO12S0_RELA => 30,
            R_NDS32_SDA15S3_RELA => 31,
            R_NDS32_SDA15S2_RELA => 32,
            R_NDS32_SDA15S1_RELA => 33,
            R_NDS32_SDA15S0_RELA => 34,
            R_NDS32_RELA_GNU_VTINHERIT => 35,
            R_NDS32_RELA_GNU_VTENTRY => 36,
            R_NDS32_GOT20 => 37,
            R_NDS32_25_PLTREL => 38,
            R_NDS32_COPY => 39,
            R_NDS32_GLOB_DAT => 40,
            R_NDS32_JMP_SLOT => 41,
            R_NDS32_RELATIVE => 42,
            R_NDS32_GOTOFF => 43,
            R_NDS32_GOTPC20 => 44,
            R_NDS32_GOT_HI20 => 45,
            R_NDS32_GOT_LO12 => 46,
            R_NDS32_GOTPC_HI20 => 47,
            R_NDS32_GOTPC_LO12 => 48,
            R_NDS32_GOTOFF_HI20 => 49,
            R_NDS32_GOTOFF_LO12 => 50,
            R_NDS32_INSN16 => 51,
            R_NDS32_LABEL => 52,
            R_NDS32_LONGCALL1 => 53,
            R_NDS32_LONGCALL2 => 54,
            R_NDS32_LONGCALL3 => 55,
            R_NDS32_LONGJUMP1 => 56,
            R_NDS32_LONGJUMP2 => 57,
            R_NDS32_LONGJUMP3 => 58,
            R_NDS32_LOADSTORE => 59,
            R_NDS32_9_FIXED_RELA => 60,
            R_NDS32_15_FIXED_RELA => 61,
            R_NDS32_17_FIXED_RELA => 62,
            R_NDS32_25_FIXED_RELA => 63,
            R_NDS32_PLTREL_HI20 => 64,
            R_NDS32_PLTREL_LO12 => 65,
            R_NDS32_PLT_GOTREL_HI20 => 66,
            R_NDS32_PLT_GOTREL_LO12 => 67,
            R_NDS32_SDA12S2_DP_RELA => 68,
            R_NDS32_SDA12S2_SP_RELA => 69,
            R_NDS32_LO12S2_DP_RELA => 70,
            R_NDS32_LO12S2_SP_RELA => 71,
            R_NDS32_LO12S0_ORI_RELA => 72,
            R_NDS32_SDA16S3_RELA => 73,
            R_NDS32_SDA17S2_RELA => 74,
            R_NDS32_SDA18S1_RELA => 75,
            R_NDS32_SDA19S0_RELA => 76,
            R_NDS32_DWARF2_OP1_RELA => 77,
            R_NDS32_DWARF2_OP2_RELA => 78,
            R_NDS32_DWARF2_LEB_RELA => 79,
            R_NDS32_UPDATE_TA_RELA => 80,
            R_NDS32_9_PLTREL => 81,
            R_NDS32_PLT_GOTREL_LO20 => 82,
            R_NDS32_PLT_GOTREL_LO15 => 83,
            R_NDS32_PLT_GOTREL_LO19 => 84,
            R_NDS32_GOT_LO15 => 85,
            R_NDS32_GOT_LO19 => 86,
            R_NDS32_GOTOFF_LO15 => 87,
            R_NDS32_GOTOFF_LO19 => 88,
            R_NDS32_GOT15S2_RELA => 89,
            R_NDS32_GOT17S2_RELA => 90,
            R_NDS32_5_RELA => 91,
            R_NDS32_10_UPCREL_RELA => 92,
            R_NDS32_SDA_FP7U2_RELA => 93,
            R_NDS32_WORD_9_PCREL_RELA => 94,
            R_NDS32_25_ABS_RELA => 95,
            R_NDS32_17IFC_PCREL_RELA => 96,
            R_NDS32_10IFCU_PCREL_RELA => 97,
            R_NDS32_TLS_LE_HI20 => 98,
            R_NDS32_TLS_LE_LO12 => 99,
            R_NDS32_TLS_IE_HI20 => 100,
            R_NDS32_TLS_IE_LO12S2 => 101,
            R_NDS32_TLS_TPOFF => 102,
            R_NDS32_TLS_LE_20 => 103,
            R_NDS32_TLS_LE_15S0 => 104,
            R_NDS32_TLS_LE_15S1 => 105,
            R_NDS32_TLS_LE_15S2 => 106,
            R_NDS32_LONGCALL4 => 107,
            R_NDS32_LONGCALL5 => 108,
            R_NDS32_LONGCALL6 => 109,
            R_NDS32_LONGJUMP4 => 110,
            R_NDS32_LONGJUMP5 => 111,
            R_NDS32_LONGJUMP6 => 112,
            R_NDS32_LONGJUMP7 => 113,
            R_NDS32_TLS_IE_LO12 => 115,
            R_NDS32_TLS_IEGP_HI20 => 116,
            R_NDS32_TLS_IEGP_LO12 => 117,
            R_NDS32_TLS_IEGP_LO12S2 => 118,
            R_NDS32_TLS_DESC => 119,
            R_NDS32_TLS_DESC_HI20 => 120,
            R_NDS32_TLS_DESC_LO12 => 121,
            R_NDS32_TLS_DESC_20 => 122,
            R_NDS32_TLS_DESC_SDA17S2 => 123,
            R_NDS32_RELAX_ENTRY => 192,
            R_NDS32_GOT_SUFF => 193,
            R_NDS32_GOTOFF_SUFF => 194,
            R_NDS32_PLT_GOT_SUFF => 195,
            R_NDS32_MULCALL_SUFF => 196,
            R_NDS32_PTR => 197,
            R_NDS32_PTR_COUNT => 198,
            R_NDS32_PTR_RESOLVED => 199,
            R_NDS32_PLTBLOCK => 200,
            R_NDS32_RELAX_REGION_BEGIN => 201,
            R_NDS32_RELAX_REGION_END => 202,
            R_NDS32_MINUEND => 203,
            R_NDS32_SUBTRAHEND => 204,
            R_NDS32_DIFF8 => 205,
            R_NDS32_DIFF16 => 206,
            R_NDS32_DIFF32 => 207,
            R_NDS32_DIFF_ULEB128 => 208,
            R_NDS32_DATA => 209,
            R_NDS32_TRAN => 210,
            R_NDS32_TLS_LE_ADD => 211,
            R_NDS32_TLS_LE_LS => 212,
            R_NDS32_EMPTY => 213,
            R_NDS32_TLS_DESC_ADD => 214,
            R_NDS32_TLS_DESC_FUNC => 215,
            R_NDS32_TLS_DESC_CALL => 216,
            R_NDS32_TLS_DESC_MEM => 217,
            R_NDS32_RELAX_REMOVE => 218,
            R_NDS32_RELAX_GROUP => 219,
            R_NDS32_TLS_IEGP_LW => 220,
            R_NDS32_LSI => 221,
            R_NDS32_RELA_NOP_MAX => 255,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Nds32ElfRelocationType::*;
        match self {
            R_NDS32_16 => "R_NDS32_16",
            R_NDS32_32 => "R_NDS32_32",
            R_NDS32_20 => "R_NDS32_20",
            R_NDS32_9_PCREL => "R_NDS32_9_PCREL",
            R_NDS32_15_PCREL => "R_NDS32_15_PCREL",
            R_NDS32_17_PCREL => "R_NDS32_17_PCREL",
            R_NDS32_25_PCREL => "R_NDS32_25_PCREL",
            R_NDS32_HI20 => "R_NDS32_HI20",
            R_NDS32_LO12S3 => "R_NDS32_LO12S3",
            R_NDS32_LO12S2 => "R_NDS32_LO12S2",
            R_NDS32_LO12S1 => "R_NDS32_LO12S1",
            R_NDS32_LO12S0 => "R_NDS32_LO12S0",
            R_NDS32_SDA15S3 => "R_NDS32_SDA15S3",
            R_NDS32_SDA15S2 => "R_NDS32_SDA15S2",
            R_NDS32_SDA15S1 => "R_NDS32_SDA15S1",
            R_NDS32_SDA15S0 => "R_NDS32_SDA15S0",
            R_NDS32_GNU_VTINHERIT => "R_NDS32_GNU_VTINHERIT",
            R_NDS32_GNU_VTENTRY => "R_NDS32_GNU_VTENTRY",
            R_NDS32_16_RELA => "R_NDS32_16_RELA",
            R_NDS32_32_RELA => "R_NDS32_32_RELA",
            R_NDS32_20_RELA => "R_NDS32_20_RELA",
            R_NDS32_9_PCREL_RELA => "R_NDS32_9_PCREL_RELA",
            R_NDS32_15_PCREL_RELA => "R_NDS32_15_PCREL_RELA",
            R_NDS32_17_PCREL_RELA => "R_NDS32_17_PCREL_RELA",
            R_NDS32_25_PCREL_RELA => "R_NDS32_25_PCREL_RELA",
            R_NDS32_HI20_RELA => "R_NDS32_HI20_RELA",
            R_NDS32_LO12S3_RELA => "R_NDS32_LO12S3_RELA",
            R_NDS32_LO12S2_RELA => "R_NDS32_LO12S2_RELA",
            R_NDS32_LO12S1_RELA => "R_NDS32_LO12S1_RELA",
            R_NDS32_LO12S0_RELA => "R_NDS32_LO12S0_RELA",
            R_NDS32_SDA15S3_RELA => "R_NDS32_SDA15S3_RELA",
            R_NDS32_SDA15S2_RELA => "R_NDS32_SDA15S2_RELA",
            R_NDS32_SDA15S1_RELA => "R_NDS32_SDA15S1_RELA",
            R_NDS32_SDA15S0_RELA => "R_NDS32_SDA15S0_RELA",
            R_NDS32_RELA_GNU_VTINHERIT => "R_NDS32_RELA_GNU_VTINHERIT",
            R_NDS32_RELA_GNU_VTENTRY => "R_NDS32_RELA_GNU_VTENTRY",
            R_NDS32_GOT20 => "R_NDS32_GOT20",
            R_NDS32_25_PLTREL => "R_NDS32_25_PLTREL",
            R_NDS32_COPY => "R_NDS32_COPY",
            R_NDS32_GLOB_DAT => "R_NDS32_GLOB_DAT",
            R_NDS32_JMP_SLOT => "R_NDS32_JMP_SLOT",
            R_NDS32_RELATIVE => "R_NDS32_RELATIVE",
            R_NDS32_GOTOFF => "R_NDS32_GOTOFF",
            R_NDS32_GOTPC20 => "R_NDS32_GOTPC20",
            R_NDS32_GOT_HI20 => "R_NDS32_GOT_HI20",
            R_NDS32_GOT_LO12 => "R_NDS32_GOT_LO12",
            R_NDS32_GOTPC_HI20 => "R_NDS32_GOTPC_HI20",
            R_NDS32_GOTPC_LO12 => "R_NDS32_GOTPC_LO12",
            R_NDS32_GOTOFF_HI20 => "R_NDS32_GOTOFF_HI20",
            R_NDS32_GOTOFF_LO12 => "R_NDS32_GOTOFF_LO12",
            R_NDS32_INSN16 => "R_NDS32_INSN16",
            R_NDS32_LABEL => "R_NDS32_LABEL",
            R_NDS32_LONGCALL1 => "R_NDS32_LONGCALL1",
            R_NDS32_LONGCALL2 => "R_NDS32_LONGCALL2",
            R_NDS32_LONGCALL3 => "R_NDS32_LONGCALL3",
            R_NDS32_LONGJUMP1 => "R_NDS32_LONGJUMP1",
            R_NDS32_LONGJUMP2 => "R_NDS32_LONGJUMP2",
            R_NDS32_LONGJUMP3 => "R_NDS32_LONGJUMP3",
            R_NDS32_LOADSTORE => "R_NDS32_LOADSTORE",
            R_NDS32_9_FIXED_RELA => "R_NDS32_9_FIXED_RELA",
            R_NDS32_15_FIXED_RELA => "R_NDS32_15_FIXED_RELA",
            R_NDS32_17_FIXED_RELA => "R_NDS32_17_FIXED_RELA",
            R_NDS32_25_FIXED_RELA => "R_NDS32_25_FIXED_RELA",
            R_NDS32_PLTREL_HI20 => "R_NDS32_PLTREL_HI20",
            R_NDS32_PLTREL_LO12 => "R_NDS32_PLTREL_LO12",
            R_NDS32_PLT_GOTREL_HI20 => "R_NDS32_PLT_GOTREL_HI20",
            R_NDS32_PLT_GOTREL_LO12 => "R_NDS32_PLT_GOTREL_LO12",
            R_NDS32_SDA12S2_DP_RELA => "R_NDS32_SDA12S2_DP_RELA",
            R_NDS32_SDA12S2_SP_RELA => "R_NDS32_SDA12S2_SP_RELA",
            R_NDS32_LO12S2_DP_RELA => "R_NDS32_LO12S2_DP_RELA",
            R_NDS32_LO12S2_SP_RELA => "R_NDS32_LO12S2_SP_RELA",
            R_NDS32_LO12S0_ORI_RELA => "R_NDS32_LO12S0_ORI_RELA",
            R_NDS32_SDA16S3_RELA => "R_NDS32_SDA16S3_RELA",
            R_NDS32_SDA17S2_RELA => "R_NDS32_SDA17S2_RELA",
            R_NDS32_SDA18S1_RELA => "R_NDS32_SDA18S1_RELA",
            R_NDS32_SDA19S0_RELA => "R_NDS32_SDA19S0_RELA",
            R_NDS32_DWARF2_OP1_RELA => "R_NDS32_DWARF2_OP1_RELA",
            R_NDS32_DWARF2_OP2_RELA => "R_NDS32_DWARF2_OP2_RELA",
            R_NDS32_DWARF2_LEB_RELA => "R_NDS32_DWARF2_LEB_RELA",
            R_NDS32_UPDATE_TA_RELA => "R_NDS32_UPDATE_TA_RELA",
            R_NDS32_9_PLTREL => "R_NDS32_9_PLTREL",
            R_NDS32_PLT_GOTREL_LO20 => "R_NDS32_PLT_GOTREL_LO20",
            R_NDS32_PLT_GOTREL_LO15 => "R_NDS32_PLT_GOTREL_LO15",
            R_NDS32_PLT_GOTREL_LO19 => "R_NDS32_PLT_GOTREL_LO19",
            R_NDS32_GOT_LO15 => "R_NDS32_GOT_LO15",
            R_NDS32_GOT_LO19 => "R_NDS32_GOT_LO19",
            R_NDS32_GOTOFF_LO15 => "R_NDS32_GOTOFF_LO15",
            R_NDS32_GOTOFF_LO19 => "R_NDS32_GOTOFF_LO19",
            R_NDS32_GOT15S2_RELA => "R_NDS32_GOT15S2_RELA",
            R_NDS32_GOT17S2_RELA => "R_NDS32_GOT17S2_RELA",
            R_NDS32_5_RELA => "R_NDS32_5_RELA",
            R_NDS32_10_UPCREL_RELA => "R_NDS32_10_UPCREL_RELA",
            R_NDS32_SDA_FP7U2_RELA => "R_NDS32_SDA_FP7U2_RELA",
            R_NDS32_WORD_9_PCREL_RELA => "R_NDS32_WORD_9_PCREL_RELA",
            R_NDS32_25_ABS_RELA => "R_NDS32_25_ABS_RELA",
            R_NDS32_17IFC_PCREL_RELA => "R_NDS32_17IFC_PCREL_RELA",
            R_NDS32_10IFCU_PCREL_RELA => "R_NDS32_10IFCU_PCREL_RELA",
            R_NDS32_TLS_LE_HI20 => "R_NDS32_TLS_LE_HI20",
            R_NDS32_TLS_LE_LO12 => "R_NDS32_TLS_LE_LO12",
            R_NDS32_TLS_IE_HI20 => "R_NDS32_TLS_IE_HI20",
            R_NDS32_TLS_IE_LO12S2 => "R_NDS32_TLS_IE_LO12S2",
            R_NDS32_TLS_TPOFF => "R_NDS32_TLS_TPOFF",
            R_NDS32_TLS_LE_20 => "R_NDS32_TLS_LE_20",
            R_NDS32_TLS_LE_15S0 => "R_NDS32_TLS_LE_15S0",
            R_NDS32_TLS_LE_15S1 => "R_NDS32_TLS_LE_15S1",
            R_NDS32_TLS_LE_15S2 => "R_NDS32_TLS_LE_15S2",
            R_NDS32_LONGCALL4 => "R_NDS32_LONGCALL4",
            R_NDS32_LONGCALL5 => "R_NDS32_LONGCALL5",
            R_NDS32_LONGCALL6 => "R_NDS32_LONGCALL6",
            R_NDS32_LONGJUMP4 => "R_NDS32_LONGJUMP4",
            R_NDS32_LONGJUMP5 => "R_NDS32_LONGJUMP5",
            R_NDS32_LONGJUMP6 => "R_NDS32_LONGJUMP6",
            R_NDS32_LONGJUMP7 => "R_NDS32_LONGJUMP7",
            R_NDS32_TLS_IE_LO12 => "R_NDS32_TLS_IE_LO12",
            R_NDS32_TLS_IEGP_HI20 => "R_NDS32_TLS_IEGP_HI20",
            R_NDS32_TLS_IEGP_LO12 => "R_NDS32_TLS_IEGP_LO12",
            R_NDS32_TLS_IEGP_LO12S2 => "R_NDS32_TLS_IEGP_LO12S2",
            R_NDS32_TLS_DESC => "R_NDS32_TLS_DESC",
            R_NDS32_TLS_DESC_HI20 => "R_NDS32_TLS_DESC_HI20",
            R_NDS32_TLS_DESC_LO12 => "R_NDS32_TLS_DESC_LO12",
            R_NDS32_TLS_DESC_20 => "R_NDS32_TLS_DESC_20",
            R_NDS32_TLS_DESC_SDA17S2 => "R_NDS32_TLS_DESC_SDA17S2",
            R_NDS32_RELAX_ENTRY => "R_NDS32_RELAX_ENTRY",
            R_NDS32_GOT_SUFF => "R_NDS32_GOT_SUFF",
            R_NDS32_GOTOFF_SUFF => "R_NDS32_GOTOFF_SUFF",
            R_NDS32_PLT_GOT_SUFF => "R_NDS32_PLT_GOT_SUFF",
            R_NDS32_MULCALL_SUFF => "R_NDS32_MULCALL_SUFF",
            R_NDS32_PTR => "R_NDS32_PTR",
            R_NDS32_PTR_COUNT => "R_NDS32_PTR_COUNT",
            R_NDS32_PTR_RESOLVED => "R_NDS32_PTR_RESOLVED",
            R_NDS32_PLTBLOCK => "R_NDS32_PLTBLOCK",
            R_NDS32_RELAX_REGION_BEGIN => "R_NDS32_RELAX_REGION_BEGIN",
            R_NDS32_RELAX_REGION_END => "R_NDS32_RELAX_REGION_END",
            R_NDS32_MINUEND => "R_NDS32_MINUEND",
            R_NDS32_SUBTRAHEND => "R_NDS32_SUBTRAHEND",
            R_NDS32_DIFF8 => "R_NDS32_DIFF8",
            R_NDS32_DIFF16 => "R_NDS32_DIFF16",
            R_NDS32_DIFF32 => "R_NDS32_DIFF32",
            R_NDS32_DIFF_ULEB128 => "R_NDS32_DIFF_ULEB128",
            R_NDS32_DATA => "R_NDS32_DATA",
            R_NDS32_TRAN => "R_NDS32_TRAN",
            R_NDS32_TLS_LE_ADD => "R_NDS32_TLS_LE_ADD",
            R_NDS32_TLS_LE_LS => "R_NDS32_TLS_LE_LS",
            R_NDS32_EMPTY => "R_NDS32_EMPTY",
            R_NDS32_TLS_DESC_ADD => "R_NDS32_TLS_DESC_ADD",
            R_NDS32_TLS_DESC_FUNC => "R_NDS32_TLS_DESC_FUNC",
            R_NDS32_TLS_DESC_CALL => "R_NDS32_TLS_DESC_CALL",
            R_NDS32_TLS_DESC_MEM => "R_NDS32_TLS_DESC_MEM",
            R_NDS32_RELAX_REMOVE => "R_NDS32_RELAX_REMOVE",
            R_NDS32_RELAX_GROUP => "R_NDS32_RELAX_GROUP",
            R_NDS32_TLS_IEGP_LW => "R_NDS32_TLS_IEGP_LW",
            R_NDS32_LSI => "R_NDS32_LSI",
            R_NDS32_RELA_NOP_MAX => "R_NDS32_RELA_NOP_MAX",
        }
    }
}

impl ElfRelocationType for Nds32ElfRelocationType {
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
    fn first_variant_has_type_id_one() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_16.type_id(), 1);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_16.name(), "R_NDS32_16");
    }

    #[test]
    fn rel_relocation_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_32.type_id(), 2);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_20.type_id(), 3);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_9_PCREL.type_id(), 4);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_15_PCREL.type_id(), 5);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_17_PCREL.type_id(), 6);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_25_PCREL.type_id(), 7);
    }

    #[test]
    fn hi_lo_and_sda_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_HI20.type_id(), 8);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S3.type_id(), 9);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S2.type_id(), 10);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S1.type_id(), 11);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S0.type_id(), 12);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA15S3.type_id(), 13);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA15S2.type_id(), 14);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA15S1.type_id(), 15);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA15S0.type_id(), 16);
    }

    #[test]
    fn gnu_vt_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GNU_VTINHERIT.type_id(), 17);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GNU_VTENTRY.type_id(), 18);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELA_GNU_VTINHERIT.type_id(), 35);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELA_GNU_VTENTRY.type_id(), 36);
    }

    #[test]
    fn rela_relocation_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_16_RELA.type_id(), 19);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_32_RELA.type_id(), 20);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_20_RELA.type_id(), 21);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_9_PCREL_RELA.type_id(), 22);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_15_PCREL_RELA.type_id(), 23);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_17_PCREL_RELA.type_id(), 24);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_25_PCREL_RELA.type_id(), 25);
    }

    #[test]
    fn got_and_plt_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT20.type_id(), 37);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_25_PLTREL.type_id(), 38);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_COPY.type_id(), 39);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GLOB_DAT.type_id(), 40);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_JMP_SLOT.type_id(), 41);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELATIVE.type_id(), 42);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF.type_id(), 43);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTPC20.type_id(), 44);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT_HI20.type_id(), 45);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT_LO12.type_id(), 46);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTPC_HI20.type_id(), 47);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTPC_LO12.type_id(), 48);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF_HI20.type_id(), 49);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF_LO12.type_id(), 50);
    }

    #[test]
    fn relaxation_and_longcall_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_INSN16.type_id(), 51);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LABEL.type_id(), 52);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL1.type_id(), 53);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL2.type_id(), 54);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL3.type_id(), 55);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP1.type_id(), 56);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP2.type_id(), 57);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP3.type_id(), 58);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LOADSTORE.type_id(), 59);
    }

    #[test]
    fn fixed_rela_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_9_FIXED_RELA.type_id(), 60);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_15_FIXED_RELA.type_id(), 61);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_17_FIXED_RELA.type_id(), 62);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_25_FIXED_RELA.type_id(), 63);
    }

    #[test]
    fn pltrel_and_gotrel_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLTREL_HI20.type_id(), 64);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLTREL_LO12.type_id(), 65);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOTREL_HI20.type_id(), 66);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOTREL_LO12.type_id(), 67);
    }

    #[test]
    fn sda_dp_sp_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA12S2_DP_RELA.type_id(), 68);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA12S2_SP_RELA.type_id(), 69);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S2_DP_RELA.type_id(), 70);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S2_SP_RELA.type_id(), 71);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LO12S0_ORI_RELA.type_id(), 72);
    }

    #[test]
    fn sda_size_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA16S3_RELA.type_id(), 73);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA17S2_RELA.type_id(), 74);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA18S1_RELA.type_id(), 75);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA19S0_RELA.type_id(), 76);
    }

    #[test]
    fn dwarf2_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DWARF2_OP1_RELA.type_id(), 77);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DWARF2_OP2_RELA.type_id(), 78);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DWARF2_LEB_RELA.type_id(), 79);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_UPDATE_TA_RELA.type_id(), 80);
    }

    #[test]
    fn plt_gotrel_lo_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_9_PLTREL.type_id(), 81);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOTREL_LO20.type_id(), 82);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOTREL_LO15.type_id(), 83);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOTREL_LO19.type_id(), 84);
    }

    #[test]
    fn got_lo_and_gotoff_lo_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT_LO15.type_id(), 85);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT_LO19.type_id(), 86);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF_LO15.type_id(), 87);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF_LO19.type_id(), 88);
    }

    #[test]
    fn got_s2_and_misc_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT15S2_RELA.type_id(), 89);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT17S2_RELA.type_id(), 90);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_5_RELA.type_id(), 91);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_10_UPCREL_RELA.type_id(), 92);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SDA_FP7U2_RELA.type_id(), 93);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_WORD_9_PCREL_RELA.type_id(), 94);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_25_ABS_RELA.type_id(), 95);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_17IFC_PCREL_RELA.type_id(), 96);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_10IFCU_PCREL_RELA.type_id(), 97);
    }

    #[test]
    fn tls_le_ie_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_HI20.type_id(), 98);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_LO12.type_id(), 99);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IE_HI20.type_id(), 100);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IE_LO12S2.type_id(), 101);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_TPOFF.type_id(), 102);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_20.type_id(), 103);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_15S0.type_id(), 104);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_15S1.type_id(), 105);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_15S2.type_id(), 106);
    }

    #[test]
    fn longcall_longjump_extended_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL4.type_id(), 107);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL5.type_id(), 108);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGCALL6.type_id(), 109);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP4.type_id(), 110);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP5.type_id(), 111);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP6.type_id(), 112);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LONGJUMP7.type_id(), 113);
    }

    #[test]
    fn tls_iegp_and_desc_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IE_LO12.type_id(), 115);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IEGP_HI20.type_id(), 116);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IEGP_LO12.type_id(), 117);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IEGP_LO12S2.type_id(), 118);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC.type_id(), 119);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_HI20.type_id(), 120);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_LO12.type_id(), 121);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_20.type_id(), 122);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_SDA17S2.type_id(), 123);
    }

    #[test]
    fn relax_only_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELAX_ENTRY.type_id(), 192);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOT_SUFF.type_id(), 193);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_GOTOFF_SUFF.type_id(), 194);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLT_GOT_SUFF.type_id(), 195);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_MULCALL_SUFF.type_id(), 196);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PTR.type_id(), 197);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PTR_COUNT.type_id(), 198);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PTR_RESOLVED.type_id(), 199);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_PLTBLOCK.type_id(), 200);
    }

    #[test]
    fn relax_region_and_diff_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELAX_REGION_BEGIN.type_id(), 201);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELAX_REGION_END.type_id(), 202);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_MINUEND.type_id(), 203);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_SUBTRAHEND.type_id(), 204);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DIFF8.type_id(), 205);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DIFF16.type_id(), 206);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DIFF32.type_id(), 207);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DIFF_ULEB128.type_id(), 208);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_DATA.type_id(), 209);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TRAN.type_id(), 210);
    }

    #[test]
    fn tls_le_add_and_desc_final_types_match_java_ids() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_ADD.type_id(), 211);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_LE_LS.type_id(), 212);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_EMPTY.type_id(), 213);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_ADD.type_id(), 214);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_FUNC.type_id(), 215);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_CALL.type_id(), 216);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_DESC_MEM.type_id(), 217);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELAX_REMOVE.type_id(), 218);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELAX_GROUP.type_id(), 219);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_TLS_IEGP_LW.type_id(), 220);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_LSI.type_id(), 221);
    }

    #[test]
    fn last_variant_has_max_type_id() {
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELA_NOP_MAX.type_id(), 255);
        assert_eq!(Nds32ElfRelocationType::R_NDS32_RELA_NOP_MAX.name(), "R_NDS32_RELA_NOP_MAX");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &Nds32ElfRelocationType::R_NDS32_RELATIVE;
        assert_eq!(r.type_id(), 42);
        assert_eq!(r.name(), "R_NDS32_RELATIVE");
    }
}
