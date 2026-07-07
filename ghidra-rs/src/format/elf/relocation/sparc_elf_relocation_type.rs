//! SPARC ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.SPARC_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// SPARC ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SparcElfRelocationType {
    R_SPARC_NONE,
    R_SPARC_8,
    R_SPARC_16,
    R_SPARC_32,
    R_SPARC_DISP8,
    R_SPARC_DISP16,
    R_SPARC_DISP32,
    R_SPARC_WDISP30,
    R_SPARC_WDISP22,
    R_SPARC_HI22,
    R_SPARC_22,
    R_SPARC_13,
    R_SPARC_LO10,
    R_SPARC_GOT10,
    R_SPARC_GOT13,
    R_SPARC_GOT22,
    R_SPARC_PC10,
    R_SPARC_PC22,
    R_SPARC_WPLT30,
    R_SPARC_COPY,
    R_SPARC_GLOB_DAT,
    R_SPARC_JMP_SLOT,
    R_SPARC_RELATIVE,
    R_SPARC_UA32,
    R_SPARC_PLT32,
    R_SPARC_HIPLT22,
    R_SPARC_LOPLT10,
    R_SPARC_PCPLT32,
    R_SPARC_PCPLT22,
    R_SPARC_PCPLT10,
    R_SPARC_10,
    R_SPARC_11,
    R_SPARC_64,
    R_SPARC_OLO10,
    R_SPARC_HH22,
    R_SPARC_HM10,
    R_SPARC_LM22,
    R_SPARC_PC_HH22,
    R_SPARC_PC_HM10,
    R_SPARC_PC_LM22,
    R_SPARC_WDISP16,
    R_SPARC_WDISP19,
    R_SPARC_UNUSED_42,
    R_SPARC_7,
    R_SPARC_5,
    R_SPARC_6,
    R_SPARC_DISP64,
    R_SPARC_PLT64,
    R_SPARC_HIX22,
    R_SPARC_LOX10,
    R_SPARC_H44,
    R_SPARC_M44,
    R_SPARC_L44,
    R_SPARC_REGISTER,
    R_SPARC_UA64,
    R_SPARC_UA16,
    R_SPARC_TLS_GD_HI22,
    R_SPARC_TLS_GD_LO10,
    R_SPARC_TLS_GD_ADD,
    R_SPARC_TLS_GD_CALL,
    R_SPARC_TLS_LDM_HI22,
    R_SPARC_TLS_LDM_LO10,
    R_SPARC_TLS_LDM_ADD,
    R_SPARC_TLS_LDM_CALL,
    R_SPARC_TLS_LDO_HIX22,
    R_SPARC_TLS_LDO_LO10,
    R_SPARC_TLS_LDO_DD,
    R_SPARC_TLS_IE_HI22,
    R_SPARC_TLS_IE_LO10,
    R_SPARC_TLS_IE_,
    R_SPARC_TLS_IE_LDX,
    R_SPARC_TLS_IE_ADD,
    R_SPARC_TLS_LE_HIX22,
    R_SPARC_TLS_LE_LOX10,
    R_SPARC_TLS_DTPMOD32,
    R_SPARC_TLS_DTPMOD64,
    R_SPARC_TLS_DTPOFF32,
    R_SPARC_TLS_DTPOFF64,
    R_SPARC_TLS_TPOFF32,
    R_SPARC_TLS_TPOFF64,
    R_SPARC_GOTDATA_HIX22,
    R_SPARC_GOTDATA_LOX10,
    R_SPARC_GOTDATA_OP_HIX22,
    R_SPARC_GOTDATA_OP_LOX10,
    R_SPARC_GOTDATA_OP,
    R_SPARC_H34,
    R_SPARC_SIZE32,
    R_SPARC_SIZE64,
    R_SPARC_WDISP10,
    R_SPARC_JMP_IREL,
    R_SPARC_IRELATIVE,
    R_SPARC_GNU_VTIHERIT,
    R_SPARC_GNU_VTENTRY,
    R_SPARC_REV32,
}

impl SparcElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use SparcElfRelocationType::*;
        match self {
            R_SPARC_NONE => 0,
            R_SPARC_8 => 1,
            R_SPARC_16 => 2,
            R_SPARC_32 => 3,
            R_SPARC_DISP8 => 4,
            R_SPARC_DISP16 => 5,
            R_SPARC_DISP32 => 6,
            R_SPARC_WDISP30 => 7,
            R_SPARC_WDISP22 => 8,
            R_SPARC_HI22 => 9,
            R_SPARC_22 => 10,
            R_SPARC_13 => 11,
            R_SPARC_LO10 => 12,
            R_SPARC_GOT10 => 13,
            R_SPARC_GOT13 => 14,
            R_SPARC_GOT22 => 15,
            R_SPARC_PC10 => 16,
            R_SPARC_PC22 => 17,
            R_SPARC_WPLT30 => 18,
            R_SPARC_COPY => 19,
            R_SPARC_GLOB_DAT => 20,
            R_SPARC_JMP_SLOT => 21,
            R_SPARC_RELATIVE => 22,
            R_SPARC_UA32 => 23,
            R_SPARC_PLT32 => 24,
            R_SPARC_HIPLT22 => 25,
            R_SPARC_LOPLT10 => 26,
            R_SPARC_PCPLT32 => 27,
            R_SPARC_PCPLT22 => 28,
            R_SPARC_PCPLT10 => 29,
            R_SPARC_10 => 30,
            R_SPARC_11 => 31,
            R_SPARC_64 => 32,
            R_SPARC_OLO10 => 33,
            R_SPARC_HH22 => 34,
            R_SPARC_HM10 => 35,
            R_SPARC_LM22 => 36,
            R_SPARC_PC_HH22 => 37,
            R_SPARC_PC_HM10 => 38,
            R_SPARC_PC_LM22 => 39,
            R_SPARC_WDISP16 => 40,
            R_SPARC_WDISP19 => 41,
            R_SPARC_UNUSED_42 => 42,
            R_SPARC_7 => 43,
            R_SPARC_5 => 44,
            R_SPARC_6 => 45,
            R_SPARC_DISP64 => 46,
            R_SPARC_PLT64 => 47,
            R_SPARC_HIX22 => 48,
            R_SPARC_LOX10 => 49,
            R_SPARC_H44 => 50,
            R_SPARC_M44 => 51,
            R_SPARC_L44 => 52,
            R_SPARC_REGISTER => 53,
            R_SPARC_UA64 => 54,
            R_SPARC_UA16 => 55,
            R_SPARC_TLS_GD_HI22 => 56,
            R_SPARC_TLS_GD_LO10 => 57,
            R_SPARC_TLS_GD_ADD => 58,
            R_SPARC_TLS_GD_CALL => 59,
            R_SPARC_TLS_LDM_HI22 => 60,
            R_SPARC_TLS_LDM_LO10 => 61,
            R_SPARC_TLS_LDM_ADD => 62,
            R_SPARC_TLS_LDM_CALL => 63,
            R_SPARC_TLS_LDO_HIX22 => 64,
            R_SPARC_TLS_LDO_LO10 => 65,
            R_SPARC_TLS_LDO_DD => 66,
            R_SPARC_TLS_IE_HI22 => 67,
            R_SPARC_TLS_IE_LO10 => 68,
            R_SPARC_TLS_IE_ => 69,
            R_SPARC_TLS_IE_LDX => 70,
            R_SPARC_TLS_IE_ADD => 71,
            R_SPARC_TLS_LE_HIX22 => 72,
            R_SPARC_TLS_LE_LOX10 => 73,
            R_SPARC_TLS_DTPMOD32 => 74,
            R_SPARC_TLS_DTPMOD64 => 75,
            R_SPARC_TLS_DTPOFF32 => 76,
            R_SPARC_TLS_DTPOFF64 => 77,
            R_SPARC_TLS_TPOFF32 => 78,
            R_SPARC_TLS_TPOFF64 => 79,
            R_SPARC_GOTDATA_HIX22 => 80,
            R_SPARC_GOTDATA_LOX10 => 81,
            R_SPARC_GOTDATA_OP_HIX22 => 82,
            R_SPARC_GOTDATA_OP_LOX10 => 83,
            R_SPARC_GOTDATA_OP => 84,
            R_SPARC_H34 => 85,
            R_SPARC_SIZE32 => 86,
            R_SPARC_SIZE64 => 87,
            R_SPARC_WDISP10 => 88,
            R_SPARC_JMP_IREL => 248,
            R_SPARC_IRELATIVE => 249,
            R_SPARC_GNU_VTIHERIT => 250,
            R_SPARC_GNU_VTENTRY => 251,
            R_SPARC_REV32 => 252,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use SparcElfRelocationType::*;
        match self {
            R_SPARC_NONE => "R_SPARC_NONE",
            R_SPARC_8 => "R_SPARC_8",
            R_SPARC_16 => "R_SPARC_16",
            R_SPARC_32 => "R_SPARC_32",
            R_SPARC_DISP8 => "R_SPARC_DISP8",
            R_SPARC_DISP16 => "R_SPARC_DISP16",
            R_SPARC_DISP32 => "R_SPARC_DISP32",
            R_SPARC_WDISP30 => "R_SPARC_WDISP30",
            R_SPARC_WDISP22 => "R_SPARC_WDISP22",
            R_SPARC_HI22 => "R_SPARC_HI22",
            R_SPARC_22 => "R_SPARC_22",
            R_SPARC_13 => "R_SPARC_13",
            R_SPARC_LO10 => "R_SPARC_LO10",
            R_SPARC_GOT10 => "R_SPARC_GOT10",
            R_SPARC_GOT13 => "R_SPARC_GOT13",
            R_SPARC_GOT22 => "R_SPARC_GOT22",
            R_SPARC_PC10 => "R_SPARC_PC10",
            R_SPARC_PC22 => "R_SPARC_PC22",
            R_SPARC_WPLT30 => "R_SPARC_WPLT30",
            R_SPARC_COPY => "R_SPARC_COPY",
            R_SPARC_GLOB_DAT => "R_SPARC_GLOB_DAT",
            R_SPARC_JMP_SLOT => "R_SPARC_JMP_SLOT",
            R_SPARC_RELATIVE => "R_SPARC_RELATIVE",
            R_SPARC_UA32 => "R_SPARC_UA32",
            R_SPARC_PLT32 => "R_SPARC_PLT32",
            R_SPARC_HIPLT22 => "R_SPARC_HIPLT22",
            R_SPARC_LOPLT10 => "R_SPARC_LOPLT10",
            R_SPARC_PCPLT32 => "R_SPARC_PCPLT32",
            R_SPARC_PCPLT22 => "R_SPARC_PCPLT22",
            R_SPARC_PCPLT10 => "R_SPARC_PCPLT10",
            R_SPARC_10 => "R_SPARC_10",
            R_SPARC_11 => "R_SPARC_11",
            R_SPARC_64 => "R_SPARC_64",
            R_SPARC_OLO10 => "R_SPARC_OLO10",
            R_SPARC_HH22 => "R_SPARC_HH22",
            R_SPARC_HM10 => "R_SPARC_HM10",
            R_SPARC_LM22 => "R_SPARC_LM22",
            R_SPARC_PC_HH22 => "R_SPARC_PC_HH22",
            R_SPARC_PC_HM10 => "R_SPARC_PC_HM10",
            R_SPARC_PC_LM22 => "R_SPARC_PC_LM22",
            R_SPARC_WDISP16 => "R_SPARC_WDISP16",
            R_SPARC_WDISP19 => "R_SPARC_WDISP19",
            R_SPARC_UNUSED_42 => "R_SPARC_UNUSED_42",
            R_SPARC_7 => "R_SPARC_7",
            R_SPARC_5 => "R_SPARC_5",
            R_SPARC_6 => "R_SPARC_6",
            R_SPARC_DISP64 => "R_SPARC_DISP64",
            R_SPARC_PLT64 => "R_SPARC_PLT64",
            R_SPARC_HIX22 => "R_SPARC_HIX22",
            R_SPARC_LOX10 => "R_SPARC_LOX10",
            R_SPARC_H44 => "R_SPARC_H44",
            R_SPARC_M44 => "R_SPARC_M44",
            R_SPARC_L44 => "R_SPARC_L44",
            R_SPARC_REGISTER => "R_SPARC_REGISTER",
            R_SPARC_UA64 => "R_SPARC_UA64",
            R_SPARC_UA16 => "R_SPARC_UA16",
            R_SPARC_TLS_GD_HI22 => "R_SPARC_TLS_GD_HI22",
            R_SPARC_TLS_GD_LO10 => "R_SPARC_TLS_GD_LO10",
            R_SPARC_TLS_GD_ADD => "R_SPARC_TLS_GD_ADD",
            R_SPARC_TLS_GD_CALL => "R_SPARC_TLS_GD_CALL",
            R_SPARC_TLS_LDM_HI22 => "R_SPARC_TLS_LDM_HI22",
            R_SPARC_TLS_LDM_LO10 => "R_SPARC_TLS_LDM_LO10",
            R_SPARC_TLS_LDM_ADD => "R_SPARC_TLS_LDM_ADD",
            R_SPARC_TLS_LDM_CALL => "R_SPARC_TLS_LDM_CALL",
            R_SPARC_TLS_LDO_HIX22 => "R_SPARC_TLS_LDO_HIX22",
            R_SPARC_TLS_LDO_LO10 => "R_SPARC_TLS_LDO_LO10",
            R_SPARC_TLS_LDO_DD => "R_SPARC_TLS_LDO_DD",
            R_SPARC_TLS_IE_HI22 => "R_SPARC_TLS_IE_HI22",
            R_SPARC_TLS_IE_LO10 => "R_SPARC_TLS_IE_LO10",
            R_SPARC_TLS_IE_ => "R_SPARC_TLS_IE_",
            R_SPARC_TLS_IE_LDX => "R_SPARC_TLS_IE_LDX",
            R_SPARC_TLS_IE_ADD => "R_SPARC_TLS_IE_ADD",
            R_SPARC_TLS_LE_HIX22 => "R_SPARC_TLS_LE_HIX22",
            R_SPARC_TLS_LE_LOX10 => "R_SPARC_TLS_LE_LOX10",
            R_SPARC_TLS_DTPMOD32 => "R_SPARC_TLS_DTPMOD32",
            R_SPARC_TLS_DTPMOD64 => "R_SPARC_TLS_DTPMOD64",
            R_SPARC_TLS_DTPOFF32 => "R_SPARC_TLS_DTPOFF32",
            R_SPARC_TLS_DTPOFF64 => "R_SPARC_TLS_DTPOFF64",
            R_SPARC_TLS_TPOFF32 => "R_SPARC_TLS_TPOFF32",
            R_SPARC_TLS_TPOFF64 => "R_SPARC_TLS_TPOFF64",
            R_SPARC_GOTDATA_HIX22 => "R_SPARC_GOTDATA_HIX22",
            R_SPARC_GOTDATA_LOX10 => "R_SPARC_GOTDATA_LOX10",
            R_SPARC_GOTDATA_OP_HIX22 => "R_SPARC_GOTDATA_OP_HIX22",
            R_SPARC_GOTDATA_OP_LOX10 => "R_SPARC_GOTDATA_OP_LOX10",
            R_SPARC_GOTDATA_OP => "R_SPARC_GOTDATA_OP",
            R_SPARC_H34 => "R_SPARC_H34",
            R_SPARC_SIZE32 => "R_SPARC_SIZE32",
            R_SPARC_SIZE64 => "R_SPARC_SIZE64",
            R_SPARC_WDISP10 => "R_SPARC_WDISP10",
            R_SPARC_JMP_IREL => "R_SPARC_JMP_IREL",
            R_SPARC_IRELATIVE => "R_SPARC_IRELATIVE",
            R_SPARC_GNU_VTIHERIT => "R_SPARC_GNU_VTIHERIT",
            R_SPARC_GNU_VTENTRY => "R_SPARC_GNU_VTENTRY",
            R_SPARC_REV32 => "R_SPARC_REV32",
        }
    }
}

impl ElfRelocationType for SparcElfRelocationType {
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
        assert_eq!(SparcElfRelocationType::R_SPARC_NONE.type_id(), 0);
        assert_eq!(SparcElfRelocationType::R_SPARC_NONE.name(), "R_SPARC_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_8.type_id(), 1);
        assert_eq!(SparcElfRelocationType::R_SPARC_32.type_id(), 3);
        assert_eq!(SparcElfRelocationType::R_SPARC_COPY.type_id(), 19);
        assert_eq!(SparcElfRelocationType::R_SPARC_GLOB_DAT.type_id(), 20);
        assert_eq!(SparcElfRelocationType::R_SPARC_JMP_SLOT.type_id(), 21);
        assert_eq!(SparcElfRelocationType::R_SPARC_RELATIVE.type_id(), 22);
    }

    #[test]
    fn displacement_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_DISP8.type_id(), 4);
        assert_eq!(SparcElfRelocationType::R_SPARC_DISP16.type_id(), 5);
        assert_eq!(SparcElfRelocationType::R_SPARC_DISP32.type_id(), 6);
        assert_eq!(SparcElfRelocationType::R_SPARC_DISP64.type_id(), 46);
    }

    #[test]
    fn hi_lo_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_HI22.type_id(), 9);
        assert_eq!(SparcElfRelocationType::R_SPARC_LO10.type_id(), 12);
        assert_eq!(SparcElfRelocationType::R_SPARC_HH22.type_id(), 34);
        assert_eq!(SparcElfRelocationType::R_SPARC_HM10.type_id(), 35);
        assert_eq!(SparcElfRelocationType::R_SPARC_LM22.type_id(), 36);
    }

    #[test]
    fn got_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_GOT10.type_id(), 13);
        assert_eq!(SparcElfRelocationType::R_SPARC_GOT13.type_id(), 14);
        assert_eq!(SparcElfRelocationType::R_SPARC_GOT22.type_id(), 15);
    }

    #[test]
    fn plt_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_PLT32.type_id(), 24);
        assert_eq!(SparcElfRelocationType::R_SPARC_HIPLT22.type_id(), 25);
        assert_eq!(SparcElfRelocationType::R_SPARC_LOPLT10.type_id(), 26);
    }

    #[test]
    fn tls_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_TLS_GD_HI22.type_id(), 56);
        assert_eq!(SparcElfRelocationType::R_SPARC_TLS_DTPMOD32.type_id(), 74);
        assert_eq!(SparcElfRelocationType::R_SPARC_TLS_DTPMOD64.type_id(), 75);
        assert_eq!(SparcElfRelocationType::R_SPARC_TLS_TPOFF32.type_id(), 78);
        assert_eq!(SparcElfRelocationType::R_SPARC_TLS_TPOFF64.type_id(), 79);
    }

    #[test]
    fn gotdata_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_GOTDATA_HIX22.type_id(), 80);
        assert_eq!(SparcElfRelocationType::R_SPARC_GOTDATA_LOX10.type_id(), 81);
    }

    #[test]
    fn high_range_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_JMP_IREL.type_id(), 248);
        assert_eq!(SparcElfRelocationType::R_SPARC_IRELATIVE.type_id(), 249);
        assert_eq!(SparcElfRelocationType::R_SPARC_GNU_VTIHERIT.type_id(), 250);
        assert_eq!(SparcElfRelocationType::R_SPARC_GNU_VTENTRY.type_id(), 251);
        assert_eq!(SparcElfRelocationType::R_SPARC_REV32.type_id(), 252);
    }

    #[test]
    fn wdisp_relocations_match_java_ids() {
        assert_eq!(SparcElfRelocationType::R_SPARC_WDISP30.type_id(), 7);
        assert_eq!(SparcElfRelocationType::R_SPARC_WDISP22.type_id(), 8);
        assert_eq!(SparcElfRelocationType::R_SPARC_WDISP16.type_id(), 40);
        assert_eq!(SparcElfRelocationType::R_SPARC_WDISP19.type_id(), 41);
        assert_eq!(SparcElfRelocationType::R_SPARC_WDISP10.type_id(), 88);
    }

    #[test]
    fn unused_42_matches_java_id() {
        assert_eq!(SparcElfRelocationType::R_SPARC_UNUSED_42.type_id(), 42);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &SparcElfRelocationType::R_SPARC_JMP_SLOT;
        assert_eq!(r.type_id(), 21);
        assert_eq!(r.name(), "R_SPARC_JMP_SLOT");
    }
}
