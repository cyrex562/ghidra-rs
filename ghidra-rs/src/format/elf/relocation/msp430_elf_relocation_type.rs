//! Texas Instruments MSP430 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.MSP430_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Texas Instruments MSP430 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Msp430ElfRelocationType {
    R_MSP430_NONE,
    R_MSP430_32,
    R_MSP430_10_PCREL,
    R_MSP430_16,
    R_MSP430_16_PCREL,
    R_MSP430_16_BYTE,
    R_MSP430_16_PCREL_BYTE,
    R_MSP430_2X_PCREL,
    R_MSP430_RL_PCREL,
    R_MSP430_8,
    R_MSP430_SYM_DIFF,
    R_MSP430_SET_ULEB128,
    R_MSP430_SUB_ULEB128,
}

impl Msp430ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Msp430ElfRelocationType::*;
        match self {
            R_MSP430_NONE => 0,
            R_MSP430_32 => 1,
            R_MSP430_10_PCREL => 2,
            R_MSP430_16 => 3,
            R_MSP430_16_PCREL => 4,
            R_MSP430_16_BYTE => 5,
            R_MSP430_16_PCREL_BYTE => 6,
            R_MSP430_2X_PCREL => 7,
            R_MSP430_RL_PCREL => 8,
            R_MSP430_8 => 9,
            R_MSP430_SYM_DIFF => 10,
            R_MSP430_SET_ULEB128 => 11,
            R_MSP430_SUB_ULEB128 => 12,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Msp430ElfRelocationType::*;
        match self {
            R_MSP430_NONE => "R_MSP430_NONE",
            R_MSP430_32 => "R_MSP430_32",
            R_MSP430_10_PCREL => "R_MSP430_10_PCREL",
            R_MSP430_16 => "R_MSP430_16",
            R_MSP430_16_PCREL => "R_MSP430_16_PCREL",
            R_MSP430_16_BYTE => "R_MSP430_16_BYTE",
            R_MSP430_16_PCREL_BYTE => "R_MSP430_16_PCREL_BYTE",
            R_MSP430_2X_PCREL => "R_MSP430_2X_PCREL",
            R_MSP430_RL_PCREL => "R_MSP430_RL_PCREL",
            R_MSP430_8 => "R_MSP430_8",
            R_MSP430_SYM_DIFF => "R_MSP430_SYM_DIFF",
            R_MSP430_SET_ULEB128 => "R_MSP430_SET_ULEB128",
            R_MSP430_SUB_ULEB128 => "R_MSP430_SUB_ULEB128",
        }
    }
}

impl ElfRelocationType for Msp430ElfRelocationType {
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
        assert_eq!(Msp430ElfRelocationType::R_MSP430_NONE.type_id(), 0);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_NONE.name(), "R_MSP430_NONE");
    }

    #[test]
    fn bit_32_has_correct_type_id() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_32.type_id(), 1);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_32.name(), "R_MSP430_32");
    }

    #[test]
    fn pcrel_10_has_correct_type_id() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_10_PCREL.type_id(), 2);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_10_PCREL.name(), "R_MSP430_10_PCREL");
    }

    #[test]
    fn bit_16_variants_have_correct_ids() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_16.type_id(), 3);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_16_PCREL.type_id(), 4);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_16_BYTE.type_id(), 5);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_16_PCREL_BYTE.type_id(), 6);
    }

    #[test]
    fn pcrel_2x_and_rl_have_correct_ids() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_2X_PCREL.type_id(), 7);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_RL_PCREL.type_id(), 8);
    }

    #[test]
    fn bit_8_has_correct_type_id() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_8.type_id(), 9);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_8.name(), "R_MSP430_8");
    }

    #[test]
    fn sym_diff_has_correct_type_id() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SYM_DIFF.type_id(), 10);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SYM_DIFF.name(), "R_MSP430_SYM_DIFF");
    }

    #[test]
    fn gnu_only_types_have_correct_ids() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SET_ULEB128.type_id(), 11);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SUB_ULEB128.type_id(), 12);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SET_ULEB128.name(), "R_MSP430_SET_ULEB128");
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SUB_ULEB128.name(), "R_MSP430_SUB_ULEB128");
    }

    #[test]
    fn final_relocation_matches_java_id() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SUB_ULEB128.type_id(), 12);
        assert_eq!(Msp430ElfRelocationType::R_MSP430_SUB_ULEB128.name(), "R_MSP430_SUB_ULEB128");
    }

    #[test]
    fn name_variants_match_enum_names() {
        assert_eq!(Msp430ElfRelocationType::R_MSP430_NONE.name(), "R_MSP430_NONE");
        assert_eq!(Msp430ElfRelocationType::R_MSP430_32.name(), "R_MSP430_32");
        assert_eq!(Msp430ElfRelocationType::R_MSP430_10_PCREL.name(), "R_MSP430_10_PCREL");
        assert_eq!(Msp430ElfRelocationType::R_MSP430_RL_PCREL.name(), "R_MSP430_RL_PCREL");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &Msp430ElfRelocationType::R_MSP430_32;
        assert_eq!(r.type_id(), 1);
        assert_eq!(r.name(), "R_MSP430_32");
    }

    #[test]
    fn all_variants_have_unique_type_ids() {
        let variants = [
            Msp430ElfRelocationType::R_MSP430_NONE,
            Msp430ElfRelocationType::R_MSP430_32,
            Msp430ElfRelocationType::R_MSP430_10_PCREL,
            Msp430ElfRelocationType::R_MSP430_16,
            Msp430ElfRelocationType::R_MSP430_16_PCREL,
            Msp430ElfRelocationType::R_MSP430_16_BYTE,
            Msp430ElfRelocationType::R_MSP430_16_PCREL_BYTE,
            Msp430ElfRelocationType::R_MSP430_2X_PCREL,
            Msp430ElfRelocationType::R_MSP430_RL_PCREL,
            Msp430ElfRelocationType::R_MSP430_8,
            Msp430ElfRelocationType::R_MSP430_SYM_DIFF,
            Msp430ElfRelocationType::R_MSP430_SET_ULEB128,
            Msp430ElfRelocationType::R_MSP430_SUB_ULEB128,
        ];

        let mut ids = [0; 13];
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
