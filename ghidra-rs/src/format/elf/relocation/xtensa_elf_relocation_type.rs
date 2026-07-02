//! Tensilica Xtensa ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.Xtensa_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Tensilica Xtensa ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum XtensaElfRelocationType {
    R_XTENSA_NONE,
    R_XTENSA_32,
    R_XTENSA_RTLD,
    R_XTENSA_GLOB_DAT,
    R_XTENSA_JMP_SLOT,
    R_XTENSA_RELATIVE,
    R_XTENSA_PLT,
    R_XTENSA_OP0,
    R_XTENSA_OP1,
    R_XTENSA_OP2,
    R_XTENSA_ASM_EXPAND,
    R_XTENSA_ASM_SIMPLIFY,
    R_XTENSA_32_PCREL,
    R_XTENSA_GNU_VTINHERIT,
    R_XTENSA_GNU_VTENTRY,
    R_XTENSA_DIFF8,
    R_XTENSA_DIFF16,
    R_XTENSA_DIFF32,
    R_XTENSA_SLOT0_OP,
    R_XTENSA_SLOT1_OP,
    R_XTENSA_SLOT2_OP,
    R_XTENSA_SLOT3_OP,
    R_XTENSA_SLOT4_OP,
    R_XTENSA_SLOT5_OP,
    R_XTENSA_SLOT6_OP,
    R_XTENSA_SLOT7_OP,
    R_XTENSA_SLOT8_OP,
    R_XTENSA_SLOT9_OP,
    R_XTENSA_SLOT10_OP,
    R_XTENSA_SLOT11_OP,
    R_XTENSA_SLOT12_OP,
    R_XTENSA_SLOT13_OP,
    R_XTENSA_SLOT14_OP,
    R_XTENSA_SLOT0_ALT,
    R_XTENSA_SLOT1_ALT,
    R_XTENSA_SLOT2_ALT,
    R_XTENSA_SLOT3_ALT,
    R_XTENSA_SLOT4_ALT,
    R_XTENSA_SLOT5_ALT,
    R_XTENSA_SLOT6_ALT,
    R_XTENSA_SLOT7_ALT,
    R_XTENSA_SLOT8_ALT,
    R_XTENSA_SLOT9_ALT,
    R_XTENSA_SLOT10_ALT,
    R_XTENSA_SLOT11_ALT,
    R_XTENSA_SLOT12_ALT,
    R_XTENSA_SLOT13_ALT,
    R_XTENSA_SLOT14_ALT,
    R_XTENSA_TLSDESC_FN,
    R_XTENSA_TLSDESC_ARG,
    R_XTENSA_TLS_DTPOFF,
    R_XTENSA_TLS_TPOFF,
    R_XTENSA_TLS_FUNC,
    R_XTENSA_TLS_ARG,
    R_XTENSA_TLS_CALL,
    R_XTENSA_PDIFF8,
    R_XTENSA_PDIFF16,
    R_XTENSA_PDIFF32,
    R_XTENSA_NDIFF8,
    R_XTENSA_NDIFF16,
    R_XTENSA_NDIFF32,
}

impl XtensaElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use XtensaElfRelocationType::*;
        match self {
            R_XTENSA_NONE => 0,
            R_XTENSA_32 => 1,
            R_XTENSA_RTLD => 2,
            R_XTENSA_GLOB_DAT => 3,
            R_XTENSA_JMP_SLOT => 4,
            R_XTENSA_RELATIVE => 5,
            R_XTENSA_PLT => 6,
            R_XTENSA_OP0 => 8,
            R_XTENSA_OP1 => 9,
            R_XTENSA_OP2 => 10,
            R_XTENSA_ASM_EXPAND => 11,
            R_XTENSA_ASM_SIMPLIFY => 12,
            R_XTENSA_32_PCREL => 14,
            R_XTENSA_GNU_VTINHERIT => 15,
            R_XTENSA_GNU_VTENTRY => 16,
            R_XTENSA_DIFF8 => 17,
            R_XTENSA_DIFF16 => 18,
            R_XTENSA_DIFF32 => 19,
            R_XTENSA_SLOT0_OP => 20,
            R_XTENSA_SLOT1_OP => 21,
            R_XTENSA_SLOT2_OP => 22,
            R_XTENSA_SLOT3_OP => 23,
            R_XTENSA_SLOT4_OP => 24,
            R_XTENSA_SLOT5_OP => 25,
            R_XTENSA_SLOT6_OP => 26,
            R_XTENSA_SLOT7_OP => 27,
            R_XTENSA_SLOT8_OP => 28,
            R_XTENSA_SLOT9_OP => 29,
            R_XTENSA_SLOT10_OP => 30,
            R_XTENSA_SLOT11_OP => 31,
            R_XTENSA_SLOT12_OP => 32,
            R_XTENSA_SLOT13_OP => 33,
            R_XTENSA_SLOT14_OP => 34,
            R_XTENSA_SLOT0_ALT => 35,
            R_XTENSA_SLOT1_ALT => 36,
            R_XTENSA_SLOT2_ALT => 37,
            R_XTENSA_SLOT3_ALT => 38,
            R_XTENSA_SLOT4_ALT => 39,
            R_XTENSA_SLOT5_ALT => 40,
            R_XTENSA_SLOT6_ALT => 41,
            R_XTENSA_SLOT7_ALT => 42,
            R_XTENSA_SLOT8_ALT => 43,
            R_XTENSA_SLOT9_ALT => 44,
            R_XTENSA_SLOT10_ALT => 45,
            R_XTENSA_SLOT11_ALT => 46,
            R_XTENSA_SLOT12_ALT => 47,
            R_XTENSA_SLOT13_ALT => 48,
            R_XTENSA_SLOT14_ALT => 49,
            R_XTENSA_TLSDESC_FN => 50,
            R_XTENSA_TLSDESC_ARG => 51,
            R_XTENSA_TLS_DTPOFF => 52,
            R_XTENSA_TLS_TPOFF => 53,
            R_XTENSA_TLS_FUNC => 54,
            R_XTENSA_TLS_ARG => 55,
            R_XTENSA_TLS_CALL => 56,
            R_XTENSA_PDIFF8 => 57,
            R_XTENSA_PDIFF16 => 58,
            R_XTENSA_PDIFF32 => 59,
            R_XTENSA_NDIFF8 => 60,
            R_XTENSA_NDIFF16 => 61,
            R_XTENSA_NDIFF32 => 62,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use XtensaElfRelocationType::*;
        match self {
            R_XTENSA_NONE => "R_XTENSA_NONE",
            R_XTENSA_32 => "R_XTENSA_32",
            R_XTENSA_RTLD => "R_XTENSA_RTLD",
            R_XTENSA_GLOB_DAT => "R_XTENSA_GLOB_DAT",
            R_XTENSA_JMP_SLOT => "R_XTENSA_JMP_SLOT",
            R_XTENSA_RELATIVE => "R_XTENSA_RELATIVE",
            R_XTENSA_PLT => "R_XTENSA_PLT",
            R_XTENSA_OP0 => "R_XTENSA_OP0",
            R_XTENSA_OP1 => "R_XTENSA_OP1",
            R_XTENSA_OP2 => "R_XTENSA_OP2",
            R_XTENSA_ASM_EXPAND => "R_XTENSA_ASM_EXPAND",
            R_XTENSA_ASM_SIMPLIFY => "R_XTENSA_ASM_SIMPLIFY",
            R_XTENSA_32_PCREL => "R_XTENSA_32_PCREL",
            R_XTENSA_GNU_VTINHERIT => "R_XTENSA_GNU_VTINHERIT",
            R_XTENSA_GNU_VTENTRY => "R_XTENSA_GNU_VTENTRY",
            R_XTENSA_DIFF8 => "R_XTENSA_DIFF8",
            R_XTENSA_DIFF16 => "R_XTENSA_DIFF16",
            R_XTENSA_DIFF32 => "R_XTENSA_DIFF32",
            R_XTENSA_SLOT0_OP => "R_XTENSA_SLOT0_OP",
            R_XTENSA_SLOT1_OP => "R_XTENSA_SLOT1_OP",
            R_XTENSA_SLOT2_OP => "R_XTENSA_SLOT2_OP",
            R_XTENSA_SLOT3_OP => "R_XTENSA_SLOT3_OP",
            R_XTENSA_SLOT4_OP => "R_XTENSA_SLOT4_OP",
            R_XTENSA_SLOT5_OP => "R_XTENSA_SLOT5_OP",
            R_XTENSA_SLOT6_OP => "R_XTENSA_SLOT6_OP",
            R_XTENSA_SLOT7_OP => "R_XTENSA_SLOT7_OP",
            R_XTENSA_SLOT8_OP => "R_XTENSA_SLOT8_OP",
            R_XTENSA_SLOT9_OP => "R_XTENSA_SLOT9_OP",
            R_XTENSA_SLOT10_OP => "R_XTENSA_SLOT10_OP",
            R_XTENSA_SLOT11_OP => "R_XTENSA_SLOT11_OP",
            R_XTENSA_SLOT12_OP => "R_XTENSA_SLOT12_OP",
            R_XTENSA_SLOT13_OP => "R_XTENSA_SLOT13_OP",
            R_XTENSA_SLOT14_OP => "R_XTENSA_SLOT14_OP",
            R_XTENSA_SLOT0_ALT => "R_XTENSA_SLOT0_ALT",
            R_XTENSA_SLOT1_ALT => "R_XTENSA_SLOT1_ALT",
            R_XTENSA_SLOT2_ALT => "R_XTENSA_SLOT2_ALT",
            R_XTENSA_SLOT3_ALT => "R_XTENSA_SLOT3_ALT",
            R_XTENSA_SLOT4_ALT => "R_XTENSA_SLOT4_ALT",
            R_XTENSA_SLOT5_ALT => "R_XTENSA_SLOT5_ALT",
            R_XTENSA_SLOT6_ALT => "R_XTENSA_SLOT6_ALT",
            R_XTENSA_SLOT7_ALT => "R_XTENSA_SLOT7_ALT",
            R_XTENSA_SLOT8_ALT => "R_XTENSA_SLOT8_ALT",
            R_XTENSA_SLOT9_ALT => "R_XTENSA_SLOT9_ALT",
            R_XTENSA_SLOT10_ALT => "R_XTENSA_SLOT10_ALT",
            R_XTENSA_SLOT11_ALT => "R_XTENSA_SLOT11_ALT",
            R_XTENSA_SLOT12_ALT => "R_XTENSA_SLOT12_ALT",
            R_XTENSA_SLOT13_ALT => "R_XTENSA_SLOT13_ALT",
            R_XTENSA_SLOT14_ALT => "R_XTENSA_SLOT14_ALT",
            R_XTENSA_TLSDESC_FN => "R_XTENSA_TLSDESC_FN",
            R_XTENSA_TLSDESC_ARG => "R_XTENSA_TLSDESC_ARG",
            R_XTENSA_TLS_DTPOFF => "R_XTENSA_TLS_DTPOFF",
            R_XTENSA_TLS_TPOFF => "R_XTENSA_TLS_TPOFF",
            R_XTENSA_TLS_FUNC => "R_XTENSA_TLS_FUNC",
            R_XTENSA_TLS_ARG => "R_XTENSA_TLS_ARG",
            R_XTENSA_TLS_CALL => "R_XTENSA_TLS_CALL",
            R_XTENSA_PDIFF8 => "R_XTENSA_PDIFF8",
            R_XTENSA_PDIFF16 => "R_XTENSA_PDIFF16",
            R_XTENSA_PDIFF32 => "R_XTENSA_PDIFF32",
            R_XTENSA_NDIFF8 => "R_XTENSA_NDIFF8",
            R_XTENSA_NDIFF16 => "R_XTENSA_NDIFF16",
            R_XTENSA_NDIFF32 => "R_XTENSA_NDIFF32",
        }
    }
}

impl ElfRelocationType for XtensaElfRelocationType {
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
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NONE.type_id(), 0);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NONE.name(), "R_XTENSA_NONE");
    }

    #[test]
    fn r_xtensa_32_has_correct_type_id() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_32.type_id(), 1);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_32.name(), "R_XTENSA_32");
    }

    #[test]
    fn relocation_ops_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_OP0.type_id(), 8);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_OP1.type_id(), 9);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_OP2.type_id(), 10);
    }

    #[test]
    fn asm_operations_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_ASM_EXPAND.type_id(), 11);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_ASM_SIMPLIFY.type_id(), 12);
    }

    #[test]
    fn pcrel_and_gnu_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_32_PCREL.type_id(), 14);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_GNU_VTINHERIT.type_id(), 15);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_GNU_VTENTRY.type_id(), 16);
    }

    #[test]
    fn diff_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_DIFF8.type_id(), 17);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_DIFF16.type_id(), 18);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_DIFF32.type_id(), 19);
    }

    #[test]
    fn slot_op_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT0_OP.type_id(), 20);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT7_OP.type_id(), 27);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT14_OP.type_id(), 34);
    }

    #[test]
    fn slot_alt_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT0_ALT.type_id(), 35);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT7_ALT.type_id(), 42);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT14_ALT.type_id(), 49);
    }

    #[test]
    fn tls_descriptor_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLSDESC_FN.type_id(), 50);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLSDESC_ARG.type_id(), 51);
    }

    #[test]
    fn tls_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_DTPOFF.type_id(), 52);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_TPOFF.type_id(), 53);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_FUNC.type_id(), 54);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_ARG.type_id(), 55);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_CALL.type_id(), 56);
    }

    #[test]
    fn pdiff_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_PDIFF8.type_id(), 57);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_PDIFF16.type_id(), 58);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_PDIFF32.type_id(), 59);
    }

    #[test]
    fn ndiff_types_have_correct_type_ids() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NDIFF8.type_id(), 60);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NDIFF16.type_id(), 61);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NDIFF32.type_id(), 62);
    }

    #[test]
    fn final_relocation_matches_java_id() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NDIFF32.type_id(), 62);
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NDIFF32.name(), "R_XTENSA_NDIFF32");
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(XtensaElfRelocationType::R_XTENSA_NONE.name(), "R_XTENSA_NONE");
        assert_eq!(XtensaElfRelocationType::R_XTENSA_32.name(), "R_XTENSA_32");
        assert_eq!(XtensaElfRelocationType::R_XTENSA_SLOT0_OP.name(), "R_XTENSA_SLOT0_OP");
        assert_eq!(XtensaElfRelocationType::R_XTENSA_TLS_CALL.name(), "R_XTENSA_TLS_CALL");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &XtensaElfRelocationType::R_XTENSA_32;
        assert_eq!(r.type_id(), 1);
        assert_eq!(r.name(), "R_XTENSA_32");
    }

    #[test]
    fn all_variants_have_unique_type_ids() {
        let variants = [
            XtensaElfRelocationType::R_XTENSA_NONE,
            XtensaElfRelocationType::R_XTENSA_32,
            XtensaElfRelocationType::R_XTENSA_RTLD,
            XtensaElfRelocationType::R_XTENSA_GLOB_DAT,
            XtensaElfRelocationType::R_XTENSA_JMP_SLOT,
            XtensaElfRelocationType::R_XTENSA_RELATIVE,
            XtensaElfRelocationType::R_XTENSA_PLT,
            XtensaElfRelocationType::R_XTENSA_OP0,
            XtensaElfRelocationType::R_XTENSA_OP1,
            XtensaElfRelocationType::R_XTENSA_OP2,
            XtensaElfRelocationType::R_XTENSA_ASM_EXPAND,
            XtensaElfRelocationType::R_XTENSA_ASM_SIMPLIFY,
            XtensaElfRelocationType::R_XTENSA_32_PCREL,
            XtensaElfRelocationType::R_XTENSA_GNU_VTINHERIT,
            XtensaElfRelocationType::R_XTENSA_GNU_VTENTRY,
            XtensaElfRelocationType::R_XTENSA_DIFF8,
            XtensaElfRelocationType::R_XTENSA_DIFF16,
            XtensaElfRelocationType::R_XTENSA_DIFF32,
            XtensaElfRelocationType::R_XTENSA_SLOT0_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT1_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT2_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT3_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT4_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT5_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT6_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT7_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT8_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT9_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT10_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT11_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT12_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT13_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT14_OP,
            XtensaElfRelocationType::R_XTENSA_SLOT0_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT1_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT2_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT3_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT4_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT5_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT6_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT7_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT8_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT9_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT10_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT11_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT12_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT13_ALT,
            XtensaElfRelocationType::R_XTENSA_SLOT14_ALT,
            XtensaElfRelocationType::R_XTENSA_TLSDESC_FN,
            XtensaElfRelocationType::R_XTENSA_TLSDESC_ARG,
            XtensaElfRelocationType::R_XTENSA_TLS_DTPOFF,
            XtensaElfRelocationType::R_XTENSA_TLS_TPOFF,
            XtensaElfRelocationType::R_XTENSA_TLS_FUNC,
            XtensaElfRelocationType::R_XTENSA_TLS_ARG,
            XtensaElfRelocationType::R_XTENSA_TLS_CALL,
            XtensaElfRelocationType::R_XTENSA_PDIFF8,
            XtensaElfRelocationType::R_XTENSA_PDIFF16,
            XtensaElfRelocationType::R_XTENSA_PDIFF32,
            XtensaElfRelocationType::R_XTENSA_NDIFF8,
            XtensaElfRelocationType::R_XTENSA_NDIFF16,
            XtensaElfRelocationType::R_XTENSA_NDIFF32,
        ];

        let mut ids = [0; 62];
        for (i, v) in variants.iter().enumerate() {
            ids[i] = v.type_id();
        }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "Variant {} and {} both have type_id {}", i, j, ids[i]);
            }
        }
    }
}
