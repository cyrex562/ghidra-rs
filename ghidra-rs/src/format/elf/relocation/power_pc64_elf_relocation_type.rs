//! PowerPC64 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.PowerPC64_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// PowerPC64 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum PowerPc64ElfRelocationType {
    R_PPC64_NONE,
    R_PPC64_ADDR32,
    R_PPC64_ADDR24,
    R_PPC64_ADDR16,
    R_PPC64_ADDR16_LO,
    R_PPC64_ADDR16_HI,
    R_PPC64_ADDR16_HA,
    R_PPC64_ADDR14,
    R_PPC64_ADDR14_BRTAKEN,
    R_PPC64_ADDR14_BRNTAKEN,
    R_PPC64_REL24,
    R_PPC64_REL14,
    R_PPC64_REL14_BRTAKEN,
    R_PPC64_REL14_BRNTAKEN,
    R_PPC64_GOT16,
    R_PPC64_GOT16_LO,
    R_PPC64_GOT16_HI,
    R_PPC64_GOT16_HA,
    R_PPC64_COPY,
    R_PPC64_GLOB_DAT,
    R_PPC64_JMP_SLOT,
    R_PPC64_RELATIVE,
    R_PPC64_UADDR32,
    R_PPC64_UADDR16,
    R_PPC64_REL32,
    R_PPC64_PLT32,
    R_PPC64_PLTREL32,
    R_PPC64_PLT16_LO,
    R_PPC64_PLT16_HI,
    R_PPC64_PLT16_HA,
    R_PPC64_SECTOFF,
    R_PPC64_SECTOFF_LO,
    R_PPC64_SECTOFF_HI,
    R_PPC64_SECTOFF_HA,
    R_PPC64_ADDR30,
    R_PPC64_ADDR64,
    R_PPC64_ADDR16_HIGHER,
    R_PPC64_ADDR16_HIGHERA,
    R_PPC64_ADDR16_HIGHEST,
    R_PPC64_ADDR16_HIGHESTA,
    R_PPC64_UADDR64,
    R_PPC64_REL64,
    R_PPC64_PLT64,
    R_PPC64_PLTREL64,
    R_PPC64_TOC16,
    R_PPC64_TOC16_LO,
    R_PPC64_TOC16_HI,
    R_PPC64_TOC16_HA,
    R_PPC64_TOC,
    R_PPC64_PLTGOT16,
    R_PPC64_PLTGOT16_LO,
    R_PPC64_PLTGOT16_HI,
    R_PPC64_PLTGOT16_HA,
    R_PPC64_ADDR16_DS,
    R_PPC64_ADDR16_LO_DS,
    R_PPC64_GOT16_DS,
    R_PPC64_GOT16_LO_DS,
    R_PPC64_PLT16_LO_DS,
    R_PPC64_SECTOFF_DS,
    R_PPC64_SECTOFF_LO_DS,
    R_PPC64_TOC16_DS,
    R_PPC64_TOC16_LO_DS,
    R_PPC64_PLTGOT16_DS,
    R_PPC64_PLTGOT16_LO_DS,
    R_PPC64_TLS,
    R_PPC64_DTPMOD64,
    R_PPC64_TPREL16,
    R_PPC64_TPREL16_LO,
    R_PPC64_TPREL16_HI,
    R_PPC64_TPREL16_HA,
    R_PPC64_TPREL64,
    R_PPC64_DTPREL16,
    R_PPC64_DTPREL16_LO,
    R_PPC64_DTPREL16_HI,
    R_PPC64_DTPREL16_HA,
    R_PPC64_DTPREL64,
    R_PPC64_GOT_TLSGD16,
    R_PPC64_GOT_TLSGD16_LO,
    R_PPC64_GOT_TLSGD16_HI,
    R_PPC64_GOT_TLSGD16_HA,
    R_PPC64_GOT_TLSLD16,
    R_PPC64_GOT_TLSLD16_LO,
    R_PPC64_GOT_TLSLD16_HI,
    R_PPC64_GOT_TLSLD16_HA,
    R_PPC64_GOT_TPREL16_DS,
    R_PPC64_GOT_TPREL16_LO_DS,
    R_PPC64_GOT_TPREL16_HI,
    R_PPC64_GOT_TPREL16_HA,
    R_PPC64_GOT_DTPREL16_DS,
    R_PPC64_GOT_DTPREL16_LO_DS,
    R_PPC64_GOT_DTPREL16_HI,
    R_PPC64_GOT_DTPREL16_HA,
    R_PPC64_TPREL16_DS,
    R_PPC64_TPREL16_LO_DS,
    R_PPC64_TPREL16_HIGHER,
    R_PPC64_TPREL16_HIGHERA,
    R_PPC64_TPREL16_HIGHEST,
    R_PPC64_TPREL16_HIGHESTA,
    R_PPC64_DTPREL16_DS,
    R_PPC64_DTPREL16_LO_DS,
    R_PPC64_DTPREL16_HIGHER,
    R_PPC64_DTPREL16_HIGHERA,
    R_PPC64_DTPREL16_HIGHEST,
    R_PPC64_DTPREL16_HIGHESTA,
    R_PPC64_TLSGD,
    R_PPC64_TLSLD,
    R_PPC64_TOCSAVE,
    R_PPC64_ADDR16_HIGH,
    R_PPC64_ADDR16_HIGHA,
    R_PPC64_TPREL16_HIGH,
    R_PPC64_TPREL16_HIGHA,
    R_PPC64_DTPREL16_HIGH,
    R_PPC64_DTPREL16_HIGHA,
    R_PPC64_REL24_NOTOC,
    R_PPC64_ADDR64_LOCAL,
    R_PPC64_ENTRY,
    R_PPC64_PLTSEQ,
    R_PPC64_PLTCALL,
    R_PPC64_PLTSEQ_NOTOC,
    R_PPC64_PLTCALL_NOTOC,
    R_PPC64_PCREL_OPT,
    R_PPC64_REL24_P9NOTOC,
    R_PPC64_D34,
    R_PPC64_D34_LO,
    R_PPC64_D34_HI30,
    R_PPC64_D34_HA30,
    R_PPC64_PCREL34,
    R_PPC64_GOT_PCREL34,
    R_PPC64_PLT_PCREL34,
    R_PPC64_PLT_PCREL34_NOTOC,
    R_PPC64_ADDR16_HIGHER34,
    R_PPC64_ADDR16_HIGHERA34,
    R_PPC64_ADDR16_HIGHEST34,
    R_PPC64_ADDR16_HIGHESTA34,
    R_PPC64_REL16_HIGHER34,
    R_PPC64_REL16_HIGHERA34,
    R_PPC64_REL16_HIGHEST34,
    R_PPC64_REL16_HIGHESTA34,
    R_PPC64_D28,
    R_PPC64_PCREL28,
    R_PPC64_TPREL34,
    R_PPC64_DTPREL34,
    R_PPC64_GOT_TLSGD_PCREL34,
    R_PPC64_GOT_TLSLD_PCREL34,
    R_PPC64_GOT_TPREL_PCREL34,
    R_PPC64_GOT_DTPREL_PCREL34,
    R_PPC64_REL16_HIGH,
    R_PPC64_REL16_HIGHA,
    R_PPC64_REL16_HIGHER,
    R_PPC64_REL16_HIGHERA,
    R_PPC64_REL16_HIGHEST,
    R_PPC64_REL16_HIGHESTA,
    R_PPC64_REL16DX_HA,
    R_PPC64_JMP_IREL,
    R_PPC64_IRELATIVE,
    R_PPC64_REL16,
    R_PPC64_REL16_LO,
    R_PPC64_REL16_HI,
    R_PPC64_REL16_HA,
    R_PPC64_VTINHERIT,
    R_PPC64_VTENTRY,
}

impl PowerPc64ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use PowerPc64ElfRelocationType::*;
        match self {
            R_PPC64_NONE => 0,
            R_PPC64_ADDR32 => 1,
            R_PPC64_ADDR24 => 2,
            R_PPC64_ADDR16 => 3,
            R_PPC64_ADDR16_LO => 4,
            R_PPC64_ADDR16_HI => 5,
            R_PPC64_ADDR16_HA => 6,
            R_PPC64_ADDR14 => 7,
            R_PPC64_ADDR14_BRTAKEN => 8,
            R_PPC64_ADDR14_BRNTAKEN => 9,
            R_PPC64_REL24 => 10,
            R_PPC64_REL14 => 11,
            R_PPC64_REL14_BRTAKEN => 12,
            R_PPC64_REL14_BRNTAKEN => 13,
            R_PPC64_GOT16 => 14,
            R_PPC64_GOT16_LO => 15,
            R_PPC64_GOT16_HI => 16,
            R_PPC64_GOT16_HA => 17,
            R_PPC64_COPY => 19,
            R_PPC64_GLOB_DAT => 20,
            R_PPC64_JMP_SLOT => 21,
            R_PPC64_RELATIVE => 22,
            R_PPC64_UADDR32 => 24,
            R_PPC64_UADDR16 => 25,
            R_PPC64_REL32 => 26,
            R_PPC64_PLT32 => 27,
            R_PPC64_PLTREL32 => 28,
            R_PPC64_PLT16_LO => 29,
            R_PPC64_PLT16_HI => 30,
            R_PPC64_PLT16_HA => 31,
            R_PPC64_SECTOFF => 33,
            R_PPC64_SECTOFF_LO => 34,
            R_PPC64_SECTOFF_HI => 35,
            R_PPC64_SECTOFF_HA => 36,
            R_PPC64_ADDR30 => 37,
            R_PPC64_ADDR64 => 38,
            R_PPC64_ADDR16_HIGHER => 39,
            R_PPC64_ADDR16_HIGHERA => 40,
            R_PPC64_ADDR16_HIGHEST => 41,
            R_PPC64_ADDR16_HIGHESTA => 42,
            R_PPC64_UADDR64 => 43,
            R_PPC64_REL64 => 44,
            R_PPC64_PLT64 => 45,
            R_PPC64_PLTREL64 => 46,
            R_PPC64_TOC16 => 47,
            R_PPC64_TOC16_LO => 48,
            R_PPC64_TOC16_HI => 49,
            R_PPC64_TOC16_HA => 50,
            R_PPC64_TOC => 51,
            R_PPC64_PLTGOT16 => 52,
            R_PPC64_PLTGOT16_LO => 53,
            R_PPC64_PLTGOT16_HI => 54,
            R_PPC64_PLTGOT16_HA => 55,
            R_PPC64_ADDR16_DS => 56,
            R_PPC64_ADDR16_LO_DS => 57,
            R_PPC64_GOT16_DS => 58,
            R_PPC64_GOT16_LO_DS => 59,
            R_PPC64_PLT16_LO_DS => 60,
            R_PPC64_SECTOFF_DS => 61,
            R_PPC64_SECTOFF_LO_DS => 62,
            R_PPC64_TOC16_DS => 63,
            R_PPC64_TOC16_LO_DS => 64,
            R_PPC64_PLTGOT16_DS => 65,
            R_PPC64_PLTGOT16_LO_DS => 66,
            R_PPC64_TLS => 67,
            R_PPC64_DTPMOD64 => 68,
            R_PPC64_TPREL16 => 69,
            // NOTE: matches the Java source's typeId of 60, which duplicates
            // R_PPC64_PLT16_LO_DS's value (a pre-existing upstream quirk).
            R_PPC64_TPREL16_LO => 60,
            R_PPC64_TPREL16_HI => 71,
            R_PPC64_TPREL16_HA => 72,
            R_PPC64_TPREL64 => 73,
            R_PPC64_DTPREL16 => 74,
            R_PPC64_DTPREL16_LO => 75,
            R_PPC64_DTPREL16_HI => 76,
            R_PPC64_DTPREL16_HA => 77,
            R_PPC64_DTPREL64 => 78,
            R_PPC64_GOT_TLSGD16 => 79,
            R_PPC64_GOT_TLSGD16_LO => 80,
            R_PPC64_GOT_TLSGD16_HI => 81,
            R_PPC64_GOT_TLSGD16_HA => 82,
            R_PPC64_GOT_TLSLD16 => 83,
            R_PPC64_GOT_TLSLD16_LO => 84,
            R_PPC64_GOT_TLSLD16_HI => 85,
            R_PPC64_GOT_TLSLD16_HA => 86,
            R_PPC64_GOT_TPREL16_DS => 87,
            R_PPC64_GOT_TPREL16_LO_DS => 88,
            R_PPC64_GOT_TPREL16_HI => 89,
            R_PPC64_GOT_TPREL16_HA => 90,
            R_PPC64_GOT_DTPREL16_DS => 91,
            R_PPC64_GOT_DTPREL16_LO_DS => 92,
            R_PPC64_GOT_DTPREL16_HI => 93,
            R_PPC64_GOT_DTPREL16_HA => 94,
            R_PPC64_TPREL16_DS => 95,
            R_PPC64_TPREL16_LO_DS => 96,
            R_PPC64_TPREL16_HIGHER => 97,
            R_PPC64_TPREL16_HIGHERA => 98,
            R_PPC64_TPREL16_HIGHEST => 99,
            R_PPC64_TPREL16_HIGHESTA => 100,
            R_PPC64_DTPREL16_DS => 101,
            R_PPC64_DTPREL16_LO_DS => 102,
            R_PPC64_DTPREL16_HIGHER => 103,
            R_PPC64_DTPREL16_HIGHERA => 104,
            R_PPC64_DTPREL16_HIGHEST => 105,
            R_PPC64_DTPREL16_HIGHESTA => 106,
            R_PPC64_TLSGD => 107,
            R_PPC64_TLSLD => 108,
            R_PPC64_TOCSAVE => 109,
            R_PPC64_ADDR16_HIGH => 110,
            R_PPC64_ADDR16_HIGHA => 111,
            R_PPC64_TPREL16_HIGH => 112,
            R_PPC64_TPREL16_HIGHA => 113,
            R_PPC64_DTPREL16_HIGH => 114,
            R_PPC64_DTPREL16_HIGHA => 115,
            R_PPC64_REL24_NOTOC => 116,
            R_PPC64_ADDR64_LOCAL => 117,
            R_PPC64_ENTRY => 118,
            R_PPC64_PLTSEQ => 119,
            R_PPC64_PLTCALL => 120,
            R_PPC64_PLTSEQ_NOTOC => 121,
            R_PPC64_PLTCALL_NOTOC => 122,
            R_PPC64_PCREL_OPT => 123,
            R_PPC64_REL24_P9NOTOC => 124,
            R_PPC64_D34 => 128,
            R_PPC64_D34_LO => 129,
            R_PPC64_D34_HI30 => 130,
            R_PPC64_D34_HA30 => 131,
            R_PPC64_PCREL34 => 132,
            R_PPC64_GOT_PCREL34 => 133,
            R_PPC64_PLT_PCREL34 => 134,
            R_PPC64_PLT_PCREL34_NOTOC => 135,
            R_PPC64_ADDR16_HIGHER34 => 136,
            R_PPC64_ADDR16_HIGHERA34 => 137,
            R_PPC64_ADDR16_HIGHEST34 => 138,
            R_PPC64_ADDR16_HIGHESTA34 => 139,
            R_PPC64_REL16_HIGHER34 => 140,
            R_PPC64_REL16_HIGHERA34 => 141,
            R_PPC64_REL16_HIGHEST34 => 142,
            R_PPC64_REL16_HIGHESTA34 => 143,
            R_PPC64_D28 => 144,
            R_PPC64_PCREL28 => 145,
            R_PPC64_TPREL34 => 146,
            R_PPC64_DTPREL34 => 147,
            R_PPC64_GOT_TLSGD_PCREL34 => 148,
            R_PPC64_GOT_TLSLD_PCREL34 => 149,
            R_PPC64_GOT_TPREL_PCREL34 => 150,
            R_PPC64_GOT_DTPREL_PCREL34 => 151,
            R_PPC64_REL16_HIGH => 240,
            R_PPC64_REL16_HIGHA => 241,
            R_PPC64_REL16_HIGHER => 242,
            R_PPC64_REL16_HIGHERA => 243,
            R_PPC64_REL16_HIGHEST => 244,
            R_PPC64_REL16_HIGHESTA => 245,
            R_PPC64_REL16DX_HA => 246,
            R_PPC64_JMP_IREL => 247,
            R_PPC64_IRELATIVE => 248,
            R_PPC64_REL16 => 249,
            R_PPC64_REL16_LO => 250,
            R_PPC64_REL16_HI => 251,
            R_PPC64_REL16_HA => 252,
            R_PPC64_VTINHERIT => 253,
            R_PPC64_VTENTRY => 254,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use PowerPc64ElfRelocationType::*;
        match self {
            R_PPC64_NONE => "R_PPC64_NONE",
            R_PPC64_ADDR32 => "R_PPC64_ADDR32",
            R_PPC64_ADDR24 => "R_PPC64_ADDR24",
            R_PPC64_ADDR16 => "R_PPC64_ADDR16",
            R_PPC64_ADDR16_LO => "R_PPC64_ADDR16_LO",
            R_PPC64_ADDR16_HI => "R_PPC64_ADDR16_HI",
            R_PPC64_ADDR16_HA => "R_PPC64_ADDR16_HA",
            R_PPC64_ADDR14 => "R_PPC64_ADDR14",
            R_PPC64_ADDR14_BRTAKEN => "R_PPC64_ADDR14_BRTAKEN",
            R_PPC64_ADDR14_BRNTAKEN => "R_PPC64_ADDR14_BRNTAKEN",
            R_PPC64_REL24 => "R_PPC64_REL24",
            R_PPC64_REL14 => "R_PPC64_REL14",
            R_PPC64_REL14_BRTAKEN => "R_PPC64_REL14_BRTAKEN",
            R_PPC64_REL14_BRNTAKEN => "R_PPC64_REL14_BRNTAKEN",
            R_PPC64_GOT16 => "R_PPC64_GOT16",
            R_PPC64_GOT16_LO => "R_PPC64_GOT16_LO",
            R_PPC64_GOT16_HI => "R_PPC64_GOT16_HI",
            R_PPC64_GOT16_HA => "R_PPC64_GOT16_HA",
            R_PPC64_COPY => "R_PPC64_COPY",
            R_PPC64_GLOB_DAT => "R_PPC64_GLOB_DAT",
            R_PPC64_JMP_SLOT => "R_PPC64_JMP_SLOT",
            R_PPC64_RELATIVE => "R_PPC64_RELATIVE",
            R_PPC64_UADDR32 => "R_PPC64_UADDR32",
            R_PPC64_UADDR16 => "R_PPC64_UADDR16",
            R_PPC64_REL32 => "R_PPC64_REL32",
            R_PPC64_PLT32 => "R_PPC64_PLT32",
            R_PPC64_PLTREL32 => "R_PPC64_PLTREL32",
            R_PPC64_PLT16_LO => "R_PPC64_PLT16_LO",
            R_PPC64_PLT16_HI => "R_PPC64_PLT16_HI",
            R_PPC64_PLT16_HA => "R_PPC64_PLT16_HA",
            R_PPC64_SECTOFF => "R_PPC64_SECTOFF",
            R_PPC64_SECTOFF_LO => "R_PPC64_SECTOFF_LO",
            R_PPC64_SECTOFF_HI => "R_PPC64_SECTOFF_HI",
            R_PPC64_SECTOFF_HA => "R_PPC64_SECTOFF_HA",
            R_PPC64_ADDR30 => "R_PPC64_ADDR30",
            R_PPC64_ADDR64 => "R_PPC64_ADDR64",
            R_PPC64_ADDR16_HIGHER => "R_PPC64_ADDR16_HIGHER",
            R_PPC64_ADDR16_HIGHERA => "R_PPC64_ADDR16_HIGHERA",
            R_PPC64_ADDR16_HIGHEST => "R_PPC64_ADDR16_HIGHEST",
            R_PPC64_ADDR16_HIGHESTA => "R_PPC64_ADDR16_HIGHESTA",
            R_PPC64_UADDR64 => "R_PPC64_UADDR64",
            R_PPC64_REL64 => "R_PPC64_REL64",
            R_PPC64_PLT64 => "R_PPC64_PLT64",
            R_PPC64_PLTREL64 => "R_PPC64_PLTREL64",
            R_PPC64_TOC16 => "R_PPC64_TOC16",
            R_PPC64_TOC16_LO => "R_PPC64_TOC16_LO",
            R_PPC64_TOC16_HI => "R_PPC64_TOC16_HI",
            R_PPC64_TOC16_HA => "R_PPC64_TOC16_HA",
            R_PPC64_TOC => "R_PPC64_TOC",
            R_PPC64_PLTGOT16 => "R_PPC64_PLTGOT16",
            R_PPC64_PLTGOT16_LO => "R_PPC64_PLTGOT16_LO",
            R_PPC64_PLTGOT16_HI => "R_PPC64_PLTGOT16_HI",
            R_PPC64_PLTGOT16_HA => "R_PPC64_PLTGOT16_HA",
            R_PPC64_ADDR16_DS => "R_PPC64_ADDR16_DS",
            R_PPC64_ADDR16_LO_DS => "R_PPC64_ADDR16_LO_DS",
            R_PPC64_GOT16_DS => "R_PPC64_GOT16_DS",
            R_PPC64_GOT16_LO_DS => "R_PPC64_GOT16_LO_DS",
            R_PPC64_PLT16_LO_DS => "R_PPC64_PLT16_LO_DS",
            R_PPC64_SECTOFF_DS => "R_PPC64_SECTOFF_DS",
            R_PPC64_SECTOFF_LO_DS => "R_PPC64_SECTOFF_LO_DS",
            R_PPC64_TOC16_DS => "R_PPC64_TOC16_DS",
            R_PPC64_TOC16_LO_DS => "R_PPC64_TOC16_LO_DS",
            R_PPC64_PLTGOT16_DS => "R_PPC64_PLTGOT16_DS",
            R_PPC64_PLTGOT16_LO_DS => "R_PPC64_PLTGOT16_LO_DS",
            R_PPC64_TLS => "R_PPC64_TLS",
            R_PPC64_DTPMOD64 => "R_PPC64_DTPMOD64",
            R_PPC64_TPREL16 => "R_PPC64_TPREL16",
            R_PPC64_TPREL16_LO => "R_PPC64_TPREL16_LO",
            R_PPC64_TPREL16_HI => "R_PPC64_TPREL16_HI",
            R_PPC64_TPREL16_HA => "R_PPC64_TPREL16_HA",
            R_PPC64_TPREL64 => "R_PPC64_TPREL64",
            R_PPC64_DTPREL16 => "R_PPC64_DTPREL16",
            R_PPC64_DTPREL16_LO => "R_PPC64_DTPREL16_LO",
            R_PPC64_DTPREL16_HI => "R_PPC64_DTPREL16_HI",
            R_PPC64_DTPREL16_HA => "R_PPC64_DTPREL16_HA",
            R_PPC64_DTPREL64 => "R_PPC64_DTPREL64",
            R_PPC64_GOT_TLSGD16 => "R_PPC64_GOT_TLSGD16",
            R_PPC64_GOT_TLSGD16_LO => "R_PPC64_GOT_TLSGD16_LO",
            R_PPC64_GOT_TLSGD16_HI => "R_PPC64_GOT_TLSGD16_HI",
            R_PPC64_GOT_TLSGD16_HA => "R_PPC64_GOT_TLSGD16_HA",
            R_PPC64_GOT_TLSLD16 => "R_PPC64_GOT_TLSLD16",
            R_PPC64_GOT_TLSLD16_LO => "R_PPC64_GOT_TLSLD16_LO",
            R_PPC64_GOT_TLSLD16_HI => "R_PPC64_GOT_TLSLD16_HI",
            R_PPC64_GOT_TLSLD16_HA => "R_PPC64_GOT_TLSLD16_HA",
            R_PPC64_GOT_TPREL16_DS => "R_PPC64_GOT_TPREL16_DS",
            R_PPC64_GOT_TPREL16_LO_DS => "R_PPC64_GOT_TPREL16_LO_DS",
            R_PPC64_GOT_TPREL16_HI => "R_PPC64_GOT_TPREL16_HI",
            R_PPC64_GOT_TPREL16_HA => "R_PPC64_GOT_TPREL16_HA",
            R_PPC64_GOT_DTPREL16_DS => "R_PPC64_GOT_DTPREL16_DS",
            R_PPC64_GOT_DTPREL16_LO_DS => "R_PPC64_GOT_DTPREL16_LO_DS",
            R_PPC64_GOT_DTPREL16_HI => "R_PPC64_GOT_DTPREL16_HI",
            R_PPC64_GOT_DTPREL16_HA => "R_PPC64_GOT_DTPREL16_HA",
            R_PPC64_TPREL16_DS => "R_PPC64_TPREL16_DS",
            R_PPC64_TPREL16_LO_DS => "R_PPC64_TPREL16_LO_DS",
            R_PPC64_TPREL16_HIGHER => "R_PPC64_TPREL16_HIGHER",
            R_PPC64_TPREL16_HIGHERA => "R_PPC64_TPREL16_HIGHERA",
            R_PPC64_TPREL16_HIGHEST => "R_PPC64_TPREL16_HIGHEST",
            R_PPC64_TPREL16_HIGHESTA => "R_PPC64_TPREL16_HIGHESTA",
            R_PPC64_DTPREL16_DS => "R_PPC64_DTPREL16_DS",
            R_PPC64_DTPREL16_LO_DS => "R_PPC64_DTPREL16_LO_DS",
            R_PPC64_DTPREL16_HIGHER => "R_PPC64_DTPREL16_HIGHER",
            R_PPC64_DTPREL16_HIGHERA => "R_PPC64_DTPREL16_HIGHERA",
            R_PPC64_DTPREL16_HIGHEST => "R_PPC64_DTPREL16_HIGHEST",
            R_PPC64_DTPREL16_HIGHESTA => "R_PPC64_DTPREL16_HIGHESTA",
            R_PPC64_TLSGD => "R_PPC64_TLSGD",
            R_PPC64_TLSLD => "R_PPC64_TLSLD",
            R_PPC64_TOCSAVE => "R_PPC64_TOCSAVE",
            R_PPC64_ADDR16_HIGH => "R_PPC64_ADDR16_HIGH",
            R_PPC64_ADDR16_HIGHA => "R_PPC64_ADDR16_HIGHA",
            R_PPC64_TPREL16_HIGH => "R_PPC64_TPREL16_HIGH",
            R_PPC64_TPREL16_HIGHA => "R_PPC64_TPREL16_HIGHA",
            R_PPC64_DTPREL16_HIGH => "R_PPC64_DTPREL16_HIGH",
            R_PPC64_DTPREL16_HIGHA => "R_PPC64_DTPREL16_HIGHA",
            R_PPC64_REL24_NOTOC => "R_PPC64_REL24_NOTOC",
            R_PPC64_ADDR64_LOCAL => "R_PPC64_ADDR64_LOCAL",
            R_PPC64_ENTRY => "R_PPC64_ENTRY",
            R_PPC64_PLTSEQ => "R_PPC64_PLTSEQ",
            R_PPC64_PLTCALL => "R_PPC64_PLTCALL",
            R_PPC64_PLTSEQ_NOTOC => "R_PPC64_PLTSEQ_NOTOC",
            R_PPC64_PLTCALL_NOTOC => "R_PPC64_PLTCALL_NOTOC",
            R_PPC64_PCREL_OPT => "R_PPC64_PCREL_OPT",
            R_PPC64_REL24_P9NOTOC => "R_PPC64_REL24_P9NOTOC",
            R_PPC64_D34 => "R_PPC64_D34",
            R_PPC64_D34_LO => "R_PPC64_D34_LO",
            R_PPC64_D34_HI30 => "R_PPC64_D34_HI30",
            R_PPC64_D34_HA30 => "R_PPC64_D34_HA30",
            R_PPC64_PCREL34 => "R_PPC64_PCREL34",
            R_PPC64_GOT_PCREL34 => "R_PPC64_GOT_PCREL34",
            R_PPC64_PLT_PCREL34 => "R_PPC64_PLT_PCREL34",
            R_PPC64_PLT_PCREL34_NOTOC => "R_PPC64_PLT_PCREL34_NOTOC",
            R_PPC64_ADDR16_HIGHER34 => "R_PPC64_ADDR16_HIGHER34",
            R_PPC64_ADDR16_HIGHERA34 => "R_PPC64_ADDR16_HIGHERA34",
            R_PPC64_ADDR16_HIGHEST34 => "R_PPC64_ADDR16_HIGHEST34",
            R_PPC64_ADDR16_HIGHESTA34 => "R_PPC64_ADDR16_HIGHESTA34",
            R_PPC64_REL16_HIGHER34 => "R_PPC64_REL16_HIGHER34",
            R_PPC64_REL16_HIGHERA34 => "R_PPC64_REL16_HIGHERA34",
            R_PPC64_REL16_HIGHEST34 => "R_PPC64_REL16_HIGHEST34",
            R_PPC64_REL16_HIGHESTA34 => "R_PPC64_REL16_HIGHESTA34",
            R_PPC64_D28 => "R_PPC64_D28",
            R_PPC64_PCREL28 => "R_PPC64_PCREL28",
            R_PPC64_TPREL34 => "R_PPC64_TPREL34",
            R_PPC64_DTPREL34 => "R_PPC64_DTPREL34",
            R_PPC64_GOT_TLSGD_PCREL34 => "R_PPC64_GOT_TLSGD_PCREL34",
            R_PPC64_GOT_TLSLD_PCREL34 => "R_PPC64_GOT_TLSLD_PCREL34",
            R_PPC64_GOT_TPREL_PCREL34 => "R_PPC64_GOT_TPREL_PCREL34",
            R_PPC64_GOT_DTPREL_PCREL34 => "R_PPC64_GOT_DTPREL_PCREL34",
            R_PPC64_REL16_HIGH => "R_PPC64_REL16_HIGH",
            R_PPC64_REL16_HIGHA => "R_PPC64_REL16_HIGHA",
            R_PPC64_REL16_HIGHER => "R_PPC64_REL16_HIGHER",
            R_PPC64_REL16_HIGHERA => "R_PPC64_REL16_HIGHERA",
            R_PPC64_REL16_HIGHEST => "R_PPC64_REL16_HIGHEST",
            R_PPC64_REL16_HIGHESTA => "R_PPC64_REL16_HIGHESTA",
            R_PPC64_REL16DX_HA => "R_PPC64_REL16DX_HA",
            R_PPC64_JMP_IREL => "R_PPC64_JMP_IREL",
            R_PPC64_IRELATIVE => "R_PPC64_IRELATIVE",
            R_PPC64_REL16 => "R_PPC64_REL16",
            R_PPC64_REL16_LO => "R_PPC64_REL16_LO",
            R_PPC64_REL16_HI => "R_PPC64_REL16_HI",
            R_PPC64_REL16_HA => "R_PPC64_REL16_HA",
            R_PPC64_VTINHERIT => "R_PPC64_VTINHERIT",
            R_PPC64_VTENTRY => "R_PPC64_VTENTRY",
        }
    }
}

impl ElfRelocationType for PowerPc64ElfRelocationType {
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
    fn first_variant_has_type_id_zero() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_NONE.type_id(), 0);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_NONE.name(), "R_PPC64_NONE");
    }

    #[test]
    fn addr_and_rel_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ADDR32.type_id(), 1);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ADDR24.type_id(), 2);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ADDR16.type_id(), 3);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_REL24.type_id(), 10);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_REL14_BRNTAKEN.type_id(), 13);
    }

    #[test]
    fn got_and_dynamic_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_GOT16_HA.type_id(), 17);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_COPY.type_id(), 19);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_GLOB_DAT.type_id(), 20);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_JMP_SLOT.type_id(), 21);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_RELATIVE.type_id(), 22);
    }

    #[test]
    fn addr64_and_toc_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ADDR64.type_id(), 38);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TOC16.type_id(), 47);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TOC.type_id(), 51);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ADDR16_DS.type_id(), 56);
    }

    #[test]
    fn tprel16_lo_preserves_java_typo_duplicate_id() {
        // The Java source declares R_PPC64_TPREL16_LO(60), which collides with
        // R_PPC64_PLT16_LO_DS(60) — an existing upstream quirk, ported verbatim.
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TPREL16_LO.type_id(), 60);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_PLT16_LO_DS.type_id(), 60);
        assert_eq!(
            PowerPc64ElfRelocationType::R_PPC64_TPREL16_LO.name(),
            "R_PPC64_TPREL16_LO"
        );
    }

    #[test]
    fn tls_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TLS.type_id(), 67);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_DTPMOD64.type_id(), 68);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TPREL16.type_id(), 69);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_TPREL64.type_id(), 73);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_DTPREL64.type_id(), 78);
    }

    #[test]
    fn power9_and_prefixed_isa_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_REL24_NOTOC.type_id(), 116);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_ENTRY.type_id(), 118);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_PCREL_OPT.type_id(), 123);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_REL24_P9NOTOC.type_id(), 124);
    }

    #[test]
    fn power10_prefixed_types_match_java_ids() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_D34.type_id(), 128);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_PCREL34.type_id(), 132);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_GOT_TLSGD_PCREL34.type_id(), 148);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_GOT_DTPREL_PCREL34.type_id(), 151);
    }

    #[test]
    fn last_variant_has_max_type_id() {
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_VTENTRY.type_id(), 254);
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_VTENTRY.name(), "R_PPC64_VTENTRY");
        assert_eq!(PowerPc64ElfRelocationType::R_PPC64_VTINHERIT.type_id(), 253);
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &PowerPc64ElfRelocationType::R_PPC64_RELATIVE;
        assert_eq!(r.type_id(), 22);
        assert_eq!(r.name(), "R_PPC64_RELATIVE");
    }
}
