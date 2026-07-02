//! Microchip PIC30 ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.PIC30_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// Microchip PIC30 ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Pic30ElfRelocationType {
    R_PIC30_NONE,
    R_PIC30_8,
    R_PIC30_16,
    R_PIC30_32,
    R_PIC30_FILE_REG_BYTE,
    R_PIC30_FILE_REG,
    R_PIC30_FILE_REG_WORD,
    R_PIC30_FILE_REG_WORD_WITH_DST,
    R_PIC30_WORD,
    R_PIC30_PBYTE,
    R_PIC30_PWORD,
    R_PIC30_HANDLE,
    R_PIC30_PADDR,
    R_PIC30_P_PADDR,
    R_PIC30_PSVOFFSET,
    R_PIC30_TBLOFFSET,
    R_PIC30_WORD_HANDLE,
    R_PIC30_WORD_PSVOFFSET,
    R_PIC30_PSVPAGE,
    R_PIC30_P_PSVPAGE,
    R_PIC30_WORD_PSVPAGE,
    R_PIC30_WORD_TBLOFFSET,
    R_PIC30_TBLPAGE,
    R_PIC30_P_TBLPAGE,
    R_PIC30_WORD_TBLPAGE,
    R_PIC30_P_HANDLE,
    R_PIC30_P_PSVOFFSET,
    R_PIC30_P_TBLOFFSET,
    R_PIC30_PCREL_BRANCH,
    R_PIC30_BRANCH_ABSOLUTE,
    R_PIC30_PCREL_DO,
    R_PIC30_DO_ABSOLUTE,
    R_PIC30_PGM_ADDR_LSB,
    R_PIC30_PGM_ADDR_MSB,
    R_PIC30_UNSIGNED_4,
    R_PIC30_UNSIGNED_5,
    R_PIC30_BIT_SELECT_3,
    R_PIC30_BIT_SELECT_4_BYTE,
    R_PIC30_BIT_SELECT_4,
    R_PIC30_DSP_6,
    R_PIC30_DSP_PRESHIFT,
    R_PIC30_SIGNED_10_BYTE,
    R_PIC30_UNSIGNED_10,
    R_PIC30_UNSIGNED_14,
    R_PIC30_FRAME_SIZE,
    R_PIC30_PWRSAV_MODE,
    R_PIC30_DMAOFFSET,
    R_PIC30_P_DMAOFFSET,
    R_PIC30_WORD_DMAOFFSET,
    R_PIC30_PSVPTR,
    R_PIC30_P_PSVPTR,
    R_PIC30_L_PSVPTR,
    R_PIC30_WORD_PSVPTR,
    R_PIC30_CALL_ACCESS,
    R_PIC30_PCREL_ACCESS,
    R_PIC30_ACCESS,
    R_PIC30_P_ACCESS,
    R_PIC30_L_ACCESS,
    R_PIC30_WORD_ACCESS,
    R_PIC30_EDSPAGE,
    R_PIC30_P_EDSPAGE,
    R_PIC30_WORD_EDSPAGE,
    R_PIC30_EDSOFFSET,
    R_PIC30_P_EDSOFFSET,
    R_PIC30_WORD_EDSOFFSET,
    R_PIC30_UNSIGNED_8,
}

impl Pic30ElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use Pic30ElfRelocationType::*;
        match self {
            R_PIC30_NONE => 0,
            R_PIC30_8 => 1,
            R_PIC30_16 => 2,
            R_PIC30_32 => 3,
            R_PIC30_FILE_REG_BYTE => 4,
            R_PIC30_FILE_REG => 5,
            R_PIC30_FILE_REG_WORD => 6,
            R_PIC30_FILE_REG_WORD_WITH_DST => 7,
            R_PIC30_WORD => 8,
            R_PIC30_PBYTE => 9,
            R_PIC30_PWORD => 10,
            R_PIC30_HANDLE => 11,
            R_PIC30_PADDR => 12,
            R_PIC30_P_PADDR => 13,
            R_PIC30_PSVOFFSET => 14,
            R_PIC30_TBLOFFSET => 15,
            R_PIC30_WORD_HANDLE => 16,
            R_PIC30_WORD_PSVOFFSET => 17,
            R_PIC30_PSVPAGE => 18,
            R_PIC30_P_PSVPAGE => 19,
            R_PIC30_WORD_PSVPAGE => 20,
            R_PIC30_WORD_TBLOFFSET => 21,
            R_PIC30_TBLPAGE => 22,
            R_PIC30_P_TBLPAGE => 23,
            R_PIC30_WORD_TBLPAGE => 24,
            R_PIC30_P_HANDLE => 25,
            R_PIC30_P_PSVOFFSET => 26,
            R_PIC30_P_TBLOFFSET => 27,
            R_PIC30_PCREL_BRANCH => 28,
            R_PIC30_BRANCH_ABSOLUTE => 29,
            R_PIC30_PCREL_DO => 30,
            R_PIC30_DO_ABSOLUTE => 31,
            R_PIC30_PGM_ADDR_LSB => 32,
            R_PIC30_PGM_ADDR_MSB => 33,
            R_PIC30_UNSIGNED_4 => 34,
            R_PIC30_UNSIGNED_5 => 35,
            R_PIC30_BIT_SELECT_3 => 36,
            R_PIC30_BIT_SELECT_4_BYTE => 37,
            R_PIC30_BIT_SELECT_4 => 38,
            R_PIC30_DSP_6 => 39,
            R_PIC30_DSP_PRESHIFT => 40,
            R_PIC30_SIGNED_10_BYTE => 41,
            R_PIC30_UNSIGNED_10 => 42,
            R_PIC30_UNSIGNED_14 => 43,
            R_PIC30_FRAME_SIZE => 44,
            R_PIC30_PWRSAV_MODE => 45,
            R_PIC30_DMAOFFSET => 46,
            R_PIC30_P_DMAOFFSET => 47,
            R_PIC30_WORD_DMAOFFSET => 48,
            R_PIC30_PSVPTR => 49,
            R_PIC30_P_PSVPTR => 50,
            R_PIC30_L_PSVPTR => 51,
            R_PIC30_WORD_PSVPTR => 52,
            R_PIC30_CALL_ACCESS => 53,
            R_PIC30_PCREL_ACCESS => 54,
            R_PIC30_ACCESS => 55,
            R_PIC30_P_ACCESS => 56,
            R_PIC30_L_ACCESS => 57,
            R_PIC30_WORD_ACCESS => 58,
            R_PIC30_EDSPAGE => 59,
            R_PIC30_P_EDSPAGE => 60,
            R_PIC30_WORD_EDSPAGE => 61,
            R_PIC30_EDSOFFSET => 62,
            R_PIC30_P_EDSOFFSET => 63,
            R_PIC30_WORD_EDSOFFSET => 64,
            R_PIC30_UNSIGNED_8 => 65,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use Pic30ElfRelocationType::*;
        match self {
            R_PIC30_NONE => "R_PIC30_NONE",
            R_PIC30_8 => "R_PIC30_8",
            R_PIC30_16 => "R_PIC30_16",
            R_PIC30_32 => "R_PIC30_32",
            R_PIC30_FILE_REG_BYTE => "R_PIC30_FILE_REG_BYTE",
            R_PIC30_FILE_REG => "R_PIC30_FILE_REG",
            R_PIC30_FILE_REG_WORD => "R_PIC30_FILE_REG_WORD",
            R_PIC30_FILE_REG_WORD_WITH_DST => "R_PIC30_FILE_REG_WORD_WITH_DST",
            R_PIC30_WORD => "R_PIC30_WORD",
            R_PIC30_PBYTE => "R_PIC30_PBYTE",
            R_PIC30_PWORD => "R_PIC30_PWORD",
            R_PIC30_HANDLE => "R_PIC30_HANDLE",
            R_PIC30_PADDR => "R_PIC30_PADDR",
            R_PIC30_P_PADDR => "R_PIC30_P_PADDR",
            R_PIC30_PSVOFFSET => "R_PIC30_PSVOFFSET",
            R_PIC30_TBLOFFSET => "R_PIC30_TBLOFFSET",
            R_PIC30_WORD_HANDLE => "R_PIC30_WORD_HANDLE",
            R_PIC30_WORD_PSVOFFSET => "R_PIC30_WORD_PSVOFFSET",
            R_PIC30_PSVPAGE => "R_PIC30_PSVPAGE",
            R_PIC30_P_PSVPAGE => "R_PIC30_P_PSVPAGE",
            R_PIC30_WORD_PSVPAGE => "R_PIC30_WORD_PSVPAGE",
            R_PIC30_WORD_TBLOFFSET => "R_PIC30_WORD_TBLOFFSET",
            R_PIC30_TBLPAGE => "R_PIC30_TBLPAGE",
            R_PIC30_P_TBLPAGE => "R_PIC30_P_TBLPAGE",
            R_PIC30_WORD_TBLPAGE => "R_PIC30_WORD_TBLPAGE",
            R_PIC30_P_HANDLE => "R_PIC30_P_HANDLE",
            R_PIC30_P_PSVOFFSET => "R_PIC30_P_PSVOFFSET",
            R_PIC30_P_TBLOFFSET => "R_PIC30_P_TBLOFFSET",
            R_PIC30_PCREL_BRANCH => "R_PIC30_PCREL_BRANCH",
            R_PIC30_BRANCH_ABSOLUTE => "R_PIC30_BRANCH_ABSOLUTE",
            R_PIC30_PCREL_DO => "R_PIC30_PCREL_DO",
            R_PIC30_DO_ABSOLUTE => "R_PIC30_DO_ABSOLUTE",
            R_PIC30_PGM_ADDR_LSB => "R_PIC30_PGM_ADDR_LSB",
            R_PIC30_PGM_ADDR_MSB => "R_PIC30_PGM_ADDR_MSB",
            R_PIC30_UNSIGNED_4 => "R_PIC30_UNSIGNED_4",
            R_PIC30_UNSIGNED_5 => "R_PIC30_UNSIGNED_5",
            R_PIC30_BIT_SELECT_3 => "R_PIC30_BIT_SELECT_3",
            R_PIC30_BIT_SELECT_4_BYTE => "R_PIC30_BIT_SELECT_4_BYTE",
            R_PIC30_BIT_SELECT_4 => "R_PIC30_BIT_SELECT_4",
            R_PIC30_DSP_6 => "R_PIC30_DSP_6",
            R_PIC30_DSP_PRESHIFT => "R_PIC30_DSP_PRESHIFT",
            R_PIC30_SIGNED_10_BYTE => "R_PIC30_SIGNED_10_BYTE",
            R_PIC30_UNSIGNED_10 => "R_PIC30_UNSIGNED_10",
            R_PIC30_UNSIGNED_14 => "R_PIC30_UNSIGNED_14",
            R_PIC30_FRAME_SIZE => "R_PIC30_FRAME_SIZE",
            R_PIC30_PWRSAV_MODE => "R_PIC30_PWRSAV_MODE",
            R_PIC30_DMAOFFSET => "R_PIC30_DMAOFFSET",
            R_PIC30_P_DMAOFFSET => "R_PIC30_P_DMAOFFSET",
            R_PIC30_WORD_DMAOFFSET => "R_PIC30_WORD_DMAOFFSET",
            R_PIC30_PSVPTR => "R_PIC30_PSVPTR",
            R_PIC30_P_PSVPTR => "R_PIC30_P_PSVPTR",
            R_PIC30_L_PSVPTR => "R_PIC30_L_PSVPTR",
            R_PIC30_WORD_PSVPTR => "R_PIC30_WORD_PSVPTR",
            R_PIC30_CALL_ACCESS => "R_PIC30_CALL_ACCESS",
            R_PIC30_PCREL_ACCESS => "R_PIC30_PCREL_ACCESS",
            R_PIC30_ACCESS => "R_PIC30_ACCESS",
            R_PIC30_P_ACCESS => "R_PIC30_P_ACCESS",
            R_PIC30_L_ACCESS => "R_PIC30_L_ACCESS",
            R_PIC30_WORD_ACCESS => "R_PIC30_WORD_ACCESS",
            R_PIC30_EDSPAGE => "R_PIC30_EDSPAGE",
            R_PIC30_P_EDSPAGE => "R_PIC30_P_EDSPAGE",
            R_PIC30_WORD_EDSPAGE => "R_PIC30_WORD_EDSPAGE",
            R_PIC30_EDSOFFSET => "R_PIC30_EDSOFFSET",
            R_PIC30_P_EDSOFFSET => "R_PIC30_P_EDSOFFSET",
            R_PIC30_WORD_EDSOFFSET => "R_PIC30_WORD_EDSOFFSET",
            R_PIC30_UNSIGNED_8 => "R_PIC30_UNSIGNED_8",
        }
    }
}

impl ElfRelocationType for Pic30ElfRelocationType {
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
        assert_eq!(Pic30ElfRelocationType::R_PIC30_NONE.type_id(), 0);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_NONE.name(), "R_PIC30_NONE");
    }

    #[test]
    fn basic_relocation_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_8.type_id(), 1);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_16.type_id(), 2);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_32.type_id(), 3);
    }

    #[test]
    fn file_register_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_FILE_REG_BYTE.type_id(), 4);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_FILE_REG.type_id(), 5);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_FILE_REG_WORD.type_id(), 6);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_FILE_REG_WORD_WITH_DST.type_id(), 7);
    }

    #[test]
    fn program_memory_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_PBYTE.type_id(), 9);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_PWORD.type_id(), 10);
    }

    #[test]
    fn handle_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_HANDLE.type_id(), 11);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_P_HANDLE.type_id(), 25);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_WORD_HANDLE.type_id(), 16);
    }

    #[test]
    fn branch_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_PCREL_BRANCH.type_id(), 28);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_BRANCH_ABSOLUTE.type_id(), 29);
    }

    #[test]
    fn do_loop_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_PCREL_DO.type_id(), 30);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_DO_ABSOLUTE.type_id(), 31);
    }

    #[test]
    fn final_relocation_type_matches_java_id() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_UNSIGNED_8.type_id(), 65);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_UNSIGNED_8.name(), "R_PIC30_UNSIGNED_8");
    }

    #[test]
    fn all_variants_have_unique_names() {
        let names = [
            Pic30ElfRelocationType::R_PIC30_NONE.name_str(),
            Pic30ElfRelocationType::R_PIC30_8.name_str(),
            Pic30ElfRelocationType::R_PIC30_16.name_str(),
            Pic30ElfRelocationType::R_PIC30_32.name_str(),
            Pic30ElfRelocationType::R_PIC30_UNSIGNED_8.name_str(),
        ];
        for (i, n1) in names.iter().enumerate() {
            for (j, n2) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(n1, n2, "Duplicate names found");
                }
            }
        }
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &Pic30ElfRelocationType::R_PIC30_PSVPTR;
        assert_eq!(r.type_id(), 49);
        assert_eq!(r.name(), "R_PIC30_PSVPTR");
    }

    #[test]
    fn access_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_CALL_ACCESS.type_id(), 53);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_PCREL_ACCESS.type_id(), 54);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_ACCESS.type_id(), 55);
    }

    #[test]
    fn extended_data_space_types_match_java_ids() {
        assert_eq!(Pic30ElfRelocationType::R_PIC30_EDSPAGE.type_id(), 59);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_P_EDSPAGE.type_id(), 60);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_WORD_EDSPAGE.type_id(), 61);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_EDSOFFSET.type_id(), 62);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_P_EDSOFFSET.type_id(), 63);
        assert_eq!(Pic30ElfRelocationType::R_PIC30_WORD_EDSOFFSET.type_id(), 64);
    }
}
