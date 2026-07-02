//! SuperH ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.SH_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// SuperH ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum ShElfRelocationType {
    R_SH_NONE,
    R_SH_DIR32,
    R_SH_REL32,
    R_SH_DIR8WPN,
    R_SH_IND12W,
    R_SH_DIR8WPL,
    R_SH_DIR8WPZ,
    R_SH_DIR8BP,
    R_SH_DIR8W,
    R_SH_DIR8L,
    R_SH_LOOP_START,
    R_SH_LOOP_END,
    R_SH_GNU_VTINHERIT,
    R_SH_GNU_VTENTRY,
    R_SH_SWITCH8,
    R_SH_SWITCH16,
    R_SH_SWITCH32,
    R_SH_USES,
    R_SH_COUNT,
    R_SH_ALIGN,
    R_SH_CODE,
    R_SH_DATA,
    R_SH_LABEL,
    R_SH_DIR16,
    R_SH_DIR8,
    R_SH_DIR8UL,
    R_SH_DIR8UW,
    R_SH_DIR8U,
    R_SH_DIR8SW,
    R_SH_DIR8S,
    R_SH_DIR4UL,
    R_SH_DIR4UW,
    R_SH_DIR4U,
    R_SH_PSHA,
    R_SH_PSHL,
    R_SH_DIR5U,
    R_SH_DIR6U,
    R_SH_DIR6S,
    R_SH_DIR10S,
    R_SH_DIR10SW,
    R_SH_DIR10SL,
    R_SH_DIR10SQ,
    R_SH_DIR16S,
    R_SH_TLS_GD_32,
    R_SH_TLS_LD_32,
    R_SH_TLS_LDO_32,
    R_SH_TLS_IE_32,
    R_SH_TLS_LE_32,
    R_SH_TLS_DTPMOD32,
    R_SH_TLS_DTPOFF32,
    R_SH_TLS_TPOFF32,
    R_SH_GOT32,
    R_SH_PLT32,
    R_SH_COPY,
    R_SH_GLOB_DAT,
    R_SH_JMP_SLOT,
    R_SH_RELATIVE,
    R_SH_GOTOFF,
    R_SH_GOTPC,
    R_SH_GOTPLT32,
    R_SH_GOT_LOW16,
    R_SH_GOT_MEDLOW16,
    R_SH_GOT_MEDHI16,
    R_SH_GOT_HI16,
    R_SH_GOTPLT_LOW16,
    R_SH_GOTPLT_MEDLOW16,
    R_SH_GOTPLT_MEDHI16,
    R_SH_GOTPLT_HI16,
    R_SH_PLT_LOW16,
    R_SH_PLT_MEDLOW16,
    R_SH_PLT_MEDHI16,
    R_SH_PLT_HI16,
    R_SH_GOTOFF_LOW16,
    R_SH_GOTOFF_MEDLOW16,
    R_SH_GOTOFF_MEDHI16,
    R_SH_GOTOFF_HI16,
    R_SH_GOTPC_LOW16,
    R_SH_GOTPC_MEDLOW16,
    R_SH_GOTPC_MEDHI16,
    R_SH_GOTPC_HI16,
    R_SH_GOT10BY4,
    R_SH_GOTPLT10BY4,
    R_SH_GOT10BY8,
    R_SH_GOTPLT10BY8,
    R_SH_COPY64,
    R_SH_GLOB_DAT64,
    R_SH_JMP_SLOT64,
    R_SH_RELATIVE64,
    R_SH_GOT20,
    R_SH_GOTOFF20,
    R_SH_GOTFUNCDESC,
    R_SH_GOTFUNCDESC20,
    R_SH_GOTOFFFUNCDESC,
    R_SH_GOTOFFFUNCDESC20,
    R_SH_FUNCDESC,
    R_SH_FUNCDESC_VALUE,
    R_SH_SHMEDIA_CODE,
    R_SH_PT_16,
    R_SH_IMMS16,
    R_SH_IMMU16,
    R_SH_IMM_LOW16,
    R_SH_IMM_LOW16_PCREL,
    R_SH_IMM_MEDLOW16,
    R_SH_IMM_MEDLOW16_PCREL,
    R_SH_IMM_MEDHI16,
    R_SH_IMM_MEDHI16_PCREL,
    R_SH_IMM_HI16,
    R_SH_IMM_HI16_PCREL,
    R_SH_64,
    R_SH_64_PCREL,
}

impl ShElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use ShElfRelocationType::*;
        match self {
            R_SH_NONE => 0,
            R_SH_DIR32 => 1,
            R_SH_REL32 => 2,
            R_SH_DIR8WPN => 3,
            R_SH_IND12W => 4,
            R_SH_DIR8WPL => 5,
            R_SH_DIR8WPZ => 6,
            R_SH_DIR8BP => 7,
            R_SH_DIR8W => 8,
            R_SH_DIR8L => 9,
            R_SH_LOOP_START => 10,
            R_SH_LOOP_END => 11,
            R_SH_GNU_VTINHERIT => 22,
            R_SH_GNU_VTENTRY => 23,
            R_SH_SWITCH8 => 24,
            R_SH_SWITCH16 => 25,
            R_SH_SWITCH32 => 26,
            R_SH_USES => 27,
            R_SH_COUNT => 28,
            R_SH_ALIGN => 29,
            R_SH_CODE => 30,
            R_SH_DATA => 31,
            R_SH_LABEL => 32,
            R_SH_DIR16 => 33,
            R_SH_DIR8 => 34,
            R_SH_DIR8UL => 35,
            R_SH_DIR8UW => 36,
            R_SH_DIR8U => 37,
            R_SH_DIR8SW => 38,
            R_SH_DIR8S => 39,
            R_SH_DIR4UL => 40,
            R_SH_DIR4UW => 41,
            R_SH_DIR4U => 42,
            R_SH_PSHA => 43,
            R_SH_PSHL => 44,
            R_SH_DIR5U => 45,
            R_SH_DIR6U => 46,
            R_SH_DIR6S => 47,
            R_SH_DIR10S => 48,
            R_SH_DIR10SW => 49,
            R_SH_DIR10SL => 50,
            R_SH_DIR10SQ => 51,
            R_SH_DIR16S => 53,
            R_SH_TLS_GD_32 => 144,
            R_SH_TLS_LD_32 => 145,
            R_SH_TLS_LDO_32 => 146,
            R_SH_TLS_IE_32 => 147,
            R_SH_TLS_LE_32 => 148,
            R_SH_TLS_DTPMOD32 => 149,
            R_SH_TLS_DTPOFF32 => 150,
            R_SH_TLS_TPOFF32 => 151,
            R_SH_GOT32 => 160,
            R_SH_PLT32 => 161,
            R_SH_COPY => 162,
            R_SH_GLOB_DAT => 163,
            R_SH_JMP_SLOT => 164,
            R_SH_RELATIVE => 165,
            R_SH_GOTOFF => 166,
            R_SH_GOTPC => 167,
            R_SH_GOTPLT32 => 168,
            R_SH_GOT_LOW16 => 169,
            R_SH_GOT_MEDLOW16 => 170,
            R_SH_GOT_MEDHI16 => 171,
            R_SH_GOT_HI16 => 172,
            R_SH_GOTPLT_LOW16 => 173,
            R_SH_GOTPLT_MEDLOW16 => 174,
            R_SH_GOTPLT_MEDHI16 => 175,
            R_SH_GOTPLT_HI16 => 176,
            R_SH_PLT_LOW16 => 177,
            R_SH_PLT_MEDLOW16 => 178,
            R_SH_PLT_MEDHI16 => 179,
            R_SH_PLT_HI16 => 180,
            R_SH_GOTOFF_LOW16 => 181,
            R_SH_GOTOFF_MEDLOW16 => 182,
            R_SH_GOTOFF_MEDHI16 => 183,
            R_SH_GOTOFF_HI16 => 184,
            R_SH_GOTPC_LOW16 => 185,
            R_SH_GOTPC_MEDLOW16 => 186,
            R_SH_GOTPC_MEDHI16 => 187,
            R_SH_GOTPC_HI16 => 188,
            R_SH_GOT10BY4 => 189,
            R_SH_GOTPLT10BY4 => 190,
            R_SH_GOT10BY8 => 191,
            R_SH_GOTPLT10BY8 => 192,
            R_SH_COPY64 => 193,
            R_SH_GLOB_DAT64 => 194,
            R_SH_JMP_SLOT64 => 195,
            R_SH_RELATIVE64 => 196,
            R_SH_GOT20 => 201,
            R_SH_GOTOFF20 => 202,
            R_SH_GOTFUNCDESC => 203,
            R_SH_GOTFUNCDESC20 => 204,
            R_SH_GOTOFFFUNCDESC => 205,
            R_SH_GOTOFFFUNCDESC20 => 206,
            R_SH_FUNCDESC => 207,
            R_SH_FUNCDESC_VALUE => 208,
            R_SH_SHMEDIA_CODE => 242,
            R_SH_PT_16 => 243,
            R_SH_IMMS16 => 244,
            R_SH_IMMU16 => 245,
            R_SH_IMM_LOW16 => 246,
            R_SH_IMM_LOW16_PCREL => 247,
            R_SH_IMM_MEDLOW16 => 248,
            R_SH_IMM_MEDLOW16_PCREL => 249,
            R_SH_IMM_MEDHI16 => 250,
            R_SH_IMM_MEDHI16_PCREL => 251,
            R_SH_IMM_HI16 => 252,
            R_SH_IMM_HI16_PCREL => 253,
            R_SH_64 => 254,
            R_SH_64_PCREL => 255,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use ShElfRelocationType::*;
        match self {
            R_SH_NONE => "R_SH_NONE",
            R_SH_DIR32 => "R_SH_DIR32",
            R_SH_REL32 => "R_SH_REL32",
            R_SH_DIR8WPN => "R_SH_DIR8WPN",
            R_SH_IND12W => "R_SH_IND12W",
            R_SH_DIR8WPL => "R_SH_DIR8WPL",
            R_SH_DIR8WPZ => "R_SH_DIR8WPZ",
            R_SH_DIR8BP => "R_SH_DIR8BP",
            R_SH_DIR8W => "R_SH_DIR8W",
            R_SH_DIR8L => "R_SH_DIR8L",
            R_SH_LOOP_START => "R_SH_LOOP_START",
            R_SH_LOOP_END => "R_SH_LOOP_END",
            R_SH_GNU_VTINHERIT => "R_SH_GNU_VTINHERIT",
            R_SH_GNU_VTENTRY => "R_SH_GNU_VTENTRY",
            R_SH_SWITCH8 => "R_SH_SWITCH8",
            R_SH_SWITCH16 => "R_SH_SWITCH16",
            R_SH_SWITCH32 => "R_SH_SWITCH32",
            R_SH_USES => "R_SH_USES",
            R_SH_COUNT => "R_SH_COUNT",
            R_SH_ALIGN => "R_SH_ALIGN",
            R_SH_CODE => "R_SH_CODE",
            R_SH_DATA => "R_SH_DATA",
            R_SH_LABEL => "R_SH_LABEL",
            R_SH_DIR16 => "R_SH_DIR16",
            R_SH_DIR8 => "R_SH_DIR8",
            R_SH_DIR8UL => "R_SH_DIR8UL",
            R_SH_DIR8UW => "R_SH_DIR8UW",
            R_SH_DIR8U => "R_SH_DIR8U",
            R_SH_DIR8SW => "R_SH_DIR8SW",
            R_SH_DIR8S => "R_SH_DIR8S",
            R_SH_DIR4UL => "R_SH_DIR4UL",
            R_SH_DIR4UW => "R_SH_DIR4UW",
            R_SH_DIR4U => "R_SH_DIR4U",
            R_SH_PSHA => "R_SH_PSHA",
            R_SH_PSHL => "R_SH_PSHL",
            R_SH_DIR5U => "R_SH_DIR5U",
            R_SH_DIR6U => "R_SH_DIR6U",
            R_SH_DIR6S => "R_SH_DIR6S",
            R_SH_DIR10S => "R_SH_DIR10S",
            R_SH_DIR10SW => "R_SH_DIR10SW",
            R_SH_DIR10SL => "R_SH_DIR10SL",
            R_SH_DIR10SQ => "R_SH_DIR10SQ",
            R_SH_DIR16S => "R_SH_DIR16S",
            R_SH_TLS_GD_32 => "R_SH_TLS_GD_32",
            R_SH_TLS_LD_32 => "R_SH_TLS_LD_32",
            R_SH_TLS_LDO_32 => "R_SH_TLS_LDO_32",
            R_SH_TLS_IE_32 => "R_SH_TLS_IE_32",
            R_SH_TLS_LE_32 => "R_SH_TLS_LE_32",
            R_SH_TLS_DTPMOD32 => "R_SH_TLS_DTPMOD32",
            R_SH_TLS_DTPOFF32 => "R_SH_TLS_DTPOFF32",
            R_SH_TLS_TPOFF32 => "R_SH_TLS_TPOFF32",
            R_SH_GOT32 => "R_SH_GOT32",
            R_SH_PLT32 => "R_SH_PLT32",
            R_SH_COPY => "R_SH_COPY",
            R_SH_GLOB_DAT => "R_SH_GLOB_DAT",
            R_SH_JMP_SLOT => "R_SH_JMP_SLOT",
            R_SH_RELATIVE => "R_SH_RELATIVE",
            R_SH_GOTOFF => "R_SH_GOTOFF",
            R_SH_GOTPC => "R_SH_GOTPC",
            R_SH_GOTPLT32 => "R_SH_GOTPLT32",
            R_SH_GOT_LOW16 => "R_SH_GOT_LOW16",
            R_SH_GOT_MEDLOW16 => "R_SH_GOT_MEDLOW16",
            R_SH_GOT_MEDHI16 => "R_SH_GOT_MEDHI16",
            R_SH_GOT_HI16 => "R_SH_GOT_HI16",
            R_SH_GOTPLT_LOW16 => "R_SH_GOTPLT_LOW16",
            R_SH_GOTPLT_MEDLOW16 => "R_SH_GOTPLT_MEDLOW16",
            R_SH_GOTPLT_MEDHI16 => "R_SH_GOTPLT_MEDHI16",
            R_SH_GOTPLT_HI16 => "R_SH_GOTPLT_HI16",
            R_SH_PLT_LOW16 => "R_SH_PLT_LOW16",
            R_SH_PLT_MEDLOW16 => "R_SH_PLT_MEDLOW16",
            R_SH_PLT_MEDHI16 => "R_SH_PLT_MEDHI16",
            R_SH_PLT_HI16 => "R_SH_PLT_HI16",
            R_SH_GOTOFF_LOW16 => "R_SH_GOTOFF_LOW16",
            R_SH_GOTOFF_MEDLOW16 => "R_SH_GOTOFF_MEDLOW16",
            R_SH_GOTOFF_MEDHI16 => "R_SH_GOTOFF_MEDHI16",
            R_SH_GOTOFF_HI16 => "R_SH_GOTOFF_HI16",
            R_SH_GOTPC_LOW16 => "R_SH_GOTPC_LOW16",
            R_SH_GOTPC_MEDLOW16 => "R_SH_GOTPC_MEDLOW16",
            R_SH_GOTPC_MEDHI16 => "R_SH_GOTPC_MEDHI16",
            R_SH_GOTPC_HI16 => "R_SH_GOTPC_HI16",
            R_SH_GOT10BY4 => "R_SH_GOT10BY4",
            R_SH_GOTPLT10BY4 => "R_SH_GOTPLT10BY4",
            R_SH_GOT10BY8 => "R_SH_GOT10BY8",
            R_SH_GOTPLT10BY8 => "R_SH_GOTPLT10BY8",
            R_SH_COPY64 => "R_SH_COPY64",
            R_SH_GLOB_DAT64 => "R_SH_GLOB_DAT64",
            R_SH_JMP_SLOT64 => "R_SH_JMP_SLOT64",
            R_SH_RELATIVE64 => "R_SH_RELATIVE64",
            R_SH_GOT20 => "R_SH_GOT20",
            R_SH_GOTOFF20 => "R_SH_GOTOFF20",
            R_SH_GOTFUNCDESC => "R_SH_GOTFUNCDESC",
            R_SH_GOTFUNCDESC20 => "R_SH_GOTFUNCDESC20",
            R_SH_GOTOFFFUNCDESC => "R_SH_GOTOFFFUNCDESC",
            R_SH_GOTOFFFUNCDESC20 => "R_SH_GOTOFFFUNCDESC20",
            R_SH_FUNCDESC => "R_SH_FUNCDESC",
            R_SH_FUNCDESC_VALUE => "R_SH_FUNCDESC_VALUE",
            R_SH_SHMEDIA_CODE => "R_SH_SHMEDIA_CODE",
            R_SH_PT_16 => "R_SH_PT_16",
            R_SH_IMMS16 => "R_SH_IMMS16",
            R_SH_IMMU16 => "R_SH_IMMU16",
            R_SH_IMM_LOW16 => "R_SH_IMM_LOW16",
            R_SH_IMM_LOW16_PCREL => "R_SH_IMM_LOW16_PCREL",
            R_SH_IMM_MEDLOW16 => "R_SH_IMM_MEDLOW16",
            R_SH_IMM_MEDLOW16_PCREL => "R_SH_IMM_MEDLOW16_PCREL",
            R_SH_IMM_MEDHI16 => "R_SH_IMM_MEDHI16",
            R_SH_IMM_MEDHI16_PCREL => "R_SH_IMM_MEDHI16_PCREL",
            R_SH_IMM_HI16 => "R_SH_IMM_HI16",
            R_SH_IMM_HI16_PCREL => "R_SH_IMM_HI16_PCREL",
            R_SH_64 => "R_SH_64",
            R_SH_64_PCREL => "R_SH_64_PCREL",
        }
    }
}

impl ElfRelocationType for ShElfRelocationType {
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
        assert_eq!(ShElfRelocationType::R_SH_NONE.type_id(), 0);
        assert_eq!(ShElfRelocationType::R_SH_NONE.name(), "R_SH_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(ShElfRelocationType::R_SH_DIR32.type_id(), 1);
        assert_eq!(ShElfRelocationType::R_SH_REL32.type_id(), 2);
        assert_eq!(ShElfRelocationType::R_SH_COPY.type_id(), 162);
        assert_eq!(ShElfRelocationType::R_SH_JMP_SLOT.type_id(), 164);
    }

    #[test]
    fn non_contiguous_id_gap_is_preserved() {
        // Java skips typeId 52 between R_SH_DIR10SQ (51) and R_SH_DIR16S (53)
        assert_eq!(ShElfRelocationType::R_SH_DIR10SQ.type_id(), 51);
        assert_eq!(ShElfRelocationType::R_SH_DIR16S.type_id(), 53);
    }

    #[test]
    fn large_gaps_in_id_space_are_preserved() {
        // Java skips 12..21 and 54..143 ranges
        assert_eq!(ShElfRelocationType::R_SH_LOOP_END.type_id(), 11);
        assert_eq!(ShElfRelocationType::R_SH_GNU_VTINHERIT.type_id(), 22);
        assert_eq!(ShElfRelocationType::R_SH_DIR16S.type_id(), 53);
        assert_eq!(ShElfRelocationType::R_SH_TLS_GD_32.type_id(), 144);
    }

    #[test]
    fn high_range_relocations_match_java_ids() {
        assert_eq!(ShElfRelocationType::R_SH_SHMEDIA_CODE.type_id(), 242);
        assert_eq!(ShElfRelocationType::R_SH_64.type_id(), 254);
        assert_eq!(ShElfRelocationType::R_SH_64_PCREL.type_id(), 255);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &ShElfRelocationType::R_SH_GLOB_DAT;
        assert_eq!(r.type_id(), 163);
        assert_eq!(r.name(), "R_SH_GLOB_DAT");
    }
}
