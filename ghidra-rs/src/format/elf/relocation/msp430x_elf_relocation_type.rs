//! Texas Instruments MSP430X ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.MSP430X_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Texas Instruments MSP430X ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Msp430xElfRelocationType {
    R_MSP430_NONE,
    R_MSP430_ABS32,
    R_MSP430_ABS16,
    R_MSP430_ABS8,
    R_MSP430_PCR16,
    R_MSP430X_PCR20_EXT_SRC,
    R_MSP430X_PCR20_EXT_DST,
    R_MSP430X_PCR20_EXT_ODST,
    R_MSP430X_ABS20_EXT_SRC,
    R_MSP430X_ABS20_EXT_DST,
    R_MSP430X_ABS20_EXT_ODST,
    R_MSP430X_ABS20_ADR_SRC,
    R_MSP430X_ABS20_ADR_DST,
    R_MSP430X_PCR16,
    R_MSP430X_PCR20_CALL,
    R_MSP430X_ABS16,
    R_MSP430_ABS_HI16,
    R_MSP430_PREL31,
    R_MSP430_EHTYPE,
    R_MSP430X_10_PCREL,
    R_MSP430X_2X_PCREL,
    R_MSP430X_SYM_DIFF,
    R_MSP430X_SET_ULEB128,
    R_MSP430X_SUB_ULEB128,
}

impl Msp430xElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Msp430xElfRelocationType::*;
        match self {
            R_MSP430_NONE => 0,
            R_MSP430_ABS32 => 1,
            R_MSP430_ABS16 => 2,
            R_MSP430_ABS8 => 3,
            R_MSP430_PCR16 => 4,
            R_MSP430X_PCR20_EXT_SRC => 5,
            R_MSP430X_PCR20_EXT_DST => 6,
            R_MSP430X_PCR20_EXT_ODST => 7,
            R_MSP430X_ABS20_EXT_SRC => 8,
            R_MSP430X_ABS20_EXT_DST => 9,
            R_MSP430X_ABS20_EXT_ODST => 10,
            R_MSP430X_ABS20_ADR_SRC => 11,
            R_MSP430X_ABS20_ADR_DST => 12,
            R_MSP430X_PCR16 => 13,
            R_MSP430X_PCR20_CALL => 14,
            R_MSP430X_ABS16 => 15,
            R_MSP430_ABS_HI16 => 16,
            R_MSP430_PREL31 => 17,
            R_MSP430_EHTYPE => 18,
            R_MSP430X_10_PCREL => 19,
            R_MSP430X_2X_PCREL => 20,
            R_MSP430X_SYM_DIFF => 21,
            R_MSP430X_SET_ULEB128 => 22,
            R_MSP430X_SUB_ULEB128 => 23,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Msp430xElfRelocationType::*;
        match self {
            R_MSP430_NONE => "R_MSP430_NONE",
            R_MSP430_ABS32 => "R_MSP430_ABS32",
            R_MSP430_ABS16 => "R_MSP430_ABS16",
            R_MSP430_ABS8 => "R_MSP430_ABS8",
            R_MSP430_PCR16 => "R_MSP430_PCR16",
            R_MSP430X_PCR20_EXT_SRC => "R_MSP430X_PCR20_EXT_SRC",
            R_MSP430X_PCR20_EXT_DST => "R_MSP430X_PCR20_EXT_DST",
            R_MSP430X_PCR20_EXT_ODST => "R_MSP430X_PCR20_EXT_ODST",
            R_MSP430X_ABS20_EXT_SRC => "R_MSP430X_ABS20_EXT_SRC",
            R_MSP430X_ABS20_EXT_DST => "R_MSP430X_ABS20_EXT_DST",
            R_MSP430X_ABS20_EXT_ODST => "R_MSP430X_ABS20_EXT_ODST",
            R_MSP430X_ABS20_ADR_SRC => "R_MSP430X_ABS20_ADR_SRC",
            R_MSP430X_ABS20_ADR_DST => "R_MSP430X_ABS20_ADR_DST",
            R_MSP430X_PCR16 => "R_MSP430X_PCR16",
            R_MSP430X_PCR20_CALL => "R_MSP430X_PCR20_CALL",
            R_MSP430X_ABS16 => "R_MSP430X_ABS16",
            R_MSP430_ABS_HI16 => "R_MSP430_ABS_HI16",
            R_MSP430_PREL31 => "R_MSP430_PREL31",
            R_MSP430_EHTYPE => "R_MSP430_EHTYPE",
            R_MSP430X_10_PCREL => "R_MSP430X_10_PCREL",
            R_MSP430X_2X_PCREL => "R_MSP430X_2X_PCREL",
            R_MSP430X_SYM_DIFF => "R_MSP430X_SYM_DIFF",
            R_MSP430X_SET_ULEB128 => "R_MSP430X_SET_ULEB128",
            R_MSP430X_SUB_ULEB128 => "R_MSP430X_SUB_ULEB128",
        }
    }
}

impl ElfRelocationType for Msp430xElfRelocationType {
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
        assert_eq!(Msp430xElfRelocationType::R_MSP430_NONE.type_id(), 0);
        assert_eq!(Msp430xElfRelocationType::R_MSP430_NONE.name(), "R_MSP430_NONE");
    }

    #[test]
    fn abs32_has_correct_type_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS32.type_id(), 1);
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS32.name(), "R_MSP430_ABS32");
    }

    #[test]
    fn abs16_has_correct_type_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS16.type_id(), 2);
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS16.name(), "R_MSP430_ABS16");
    }

    #[test]
    fn abs8_has_correct_type_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS8.type_id(), 3);
    }

    #[test]
    fn pcr16_variants_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_PCR16.type_id(), 4);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR16.type_id(), 13);
    }

    #[test]
    fn pcr20_ext_variants_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_SRC.type_id(), 5);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_DST.type_id(), 6);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_ODST.type_id(), 7);
    }

    #[test]
    fn abs20_ext_variants_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_SRC.type_id(), 8);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_DST.type_id(), 9);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_ODST.type_id(), 10);
    }

    #[test]
    fn abs20_adr_variants_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_ADR_SRC.type_id(), 11);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_ADR_DST.type_id(), 12);
    }

    #[test]
    fn pcr20_call_has_correct_type_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR20_CALL.type_id(), 14);
    }

    #[test]
    fn abs16_x_has_correct_type_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS16.type_id(), 15);
        assert_eq!(Msp430xElfRelocationType::R_MSP430_ABS_HI16.type_id(), 16);
    }

    #[test]
    fn prel31_and_ehtype_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_PREL31.type_id(), 17);
        assert_eq!(Msp430xElfRelocationType::R_MSP430_EHTYPE.type_id(), 18);
    }

    #[test]
    fn red_hat_inventions_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_10_PCREL.type_id(), 19);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_2X_PCREL.type_id(), 20);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SYM_DIFF.type_id(), 21);
    }

    #[test]
    fn gnu_only_types_have_correct_ids() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SET_ULEB128.type_id(), 22);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SUB_ULEB128.type_id(), 23);
    }

    #[test]
    fn final_relocation_matches_java_id() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SUB_ULEB128.type_id(), 23);
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SUB_ULEB128.name(), "R_MSP430X_SUB_ULEB128");
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(Msp430xElfRelocationType::R_MSP430_NONE.name(), "R_MSP430_NONE");
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_SRC.name(), "R_MSP430X_PCR20_EXT_SRC");
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_ODST.name(), "R_MSP430X_ABS20_EXT_ODST");
        assert_eq!(Msp430xElfRelocationType::R_MSP430X_SYM_DIFF.name(), "R_MSP430X_SYM_DIFF");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &Msp430xElfRelocationType::R_MSP430_ABS32;
        assert_eq!(r.type_id(), 1);
        assert_eq!(r.name(), "R_MSP430_ABS32");
    }

    #[test]
    fn all_variants_have_unique_type_ids() {
        let variants = [
            Msp430xElfRelocationType::R_MSP430_NONE,
            Msp430xElfRelocationType::R_MSP430_ABS32,
            Msp430xElfRelocationType::R_MSP430_ABS16,
            Msp430xElfRelocationType::R_MSP430_ABS8,
            Msp430xElfRelocationType::R_MSP430_PCR16,
            Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_SRC,
            Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_DST,
            Msp430xElfRelocationType::R_MSP430X_PCR20_EXT_ODST,
            Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_SRC,
            Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_DST,
            Msp430xElfRelocationType::R_MSP430X_ABS20_EXT_ODST,
            Msp430xElfRelocationType::R_MSP430X_ABS20_ADR_SRC,
            Msp430xElfRelocationType::R_MSP430X_ABS20_ADR_DST,
            Msp430xElfRelocationType::R_MSP430X_PCR16,
            Msp430xElfRelocationType::R_MSP430X_PCR20_CALL,
            Msp430xElfRelocationType::R_MSP430X_ABS16,
            Msp430xElfRelocationType::R_MSP430_ABS_HI16,
            Msp430xElfRelocationType::R_MSP430_PREL31,
            Msp430xElfRelocationType::R_MSP430_EHTYPE,
            Msp430xElfRelocationType::R_MSP430X_10_PCREL,
            Msp430xElfRelocationType::R_MSP430X_2X_PCREL,
            Msp430xElfRelocationType::R_MSP430X_SYM_DIFF,
            Msp430xElfRelocationType::R_MSP430X_SET_ULEB128,
            Msp430xElfRelocationType::R_MSP430X_SUB_ULEB128,
        ];

        let mut ids = [0; 24];
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
