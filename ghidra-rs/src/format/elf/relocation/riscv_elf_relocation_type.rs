//! RISC-V ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.RISCV_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// RISC-V ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum RiscvElfRelocationType {
    R_RISCV_NONE,
    R_RISCV_32,
    R_RISCV_64,
    R_RISCV_RELATIVE,
    R_RISCV_COPY,
    R_RISCV_JUMP_SLOT,
    R_RISCV_TLS_DTPMOD32,
    R_RISCV_TLS_DTPMOD64,
    R_RISCV_TLS_DTPREL32,
    R_RISCV_TLS_DTPREL64,
    R_RISCV_TLS_TPREL32,
    R_RISCV_TLS_TPREL64,
    R_RISCV_TLSDESC,
    R_RISCV_BRANCH,
    R_RISCV_JAL,
    R_RISCV_CALL,
    R_RISCV_CALL_PLT,
    R_RISCV_GOT_HI20,
    R_RISCV_TLS_GOT_HI20,
    R_RISCV_TLS_GD_HI20,
    R_RISCV_PCREL_HI20,
    R_RISCV_PCREL_LO12_I,
    R_RISCV_PCREL_LO12_S,
    R_RISCV_HI20,
    R_RISCV_LO12_I,
    R_RISCV_LO12_S,
    R_RISCV_TPREL_HI20,
    R_RISCV_TPREL_LO12_I,
    R_RISCV_TPREL_LO12_S,
    R_RISCV_TPREL_ADD,
    R_RISCV_ADD8,
    R_RISCV_ADD16,
    R_RISCV_ADD32,
    R_RISCV_ADD64,
    R_RISCV_SUB8,
    R_RISCV_SUB16,
    R_RISCV_SUB32,
    R_RISCV_SUB64,
    R_RISCV_GNU_VTINHERIT,
    R_RISCV_GNU_VTENTRY,
    R_RISCV_ALIGN,
    R_RISCV_RVC_BRANCH,
    R_RISCV_RVC_JUMP,
    R_RISCV_RVC_LUI,
    R_RISCV_GPREL_I,
    R_RISCV_GPREL_S,
    R_RISCV_TPREL_I,
    R_RISCV_TPREL_S,
    R_RISCV_RELAX,
    R_RISCV_SUB6,
    R_RISCV_SET6,
    R_RISCV_SET8,
    R_RISCV_SET16,
    R_RISCV_SET32,
    R_RISCV_32_PCREL,
    R_RISCV_IRELATIVE,
    R_RISCV_SET_ULEB128,
    R_RISCV_SUB_ULEB128,
    R_RISCV_TLSDESC_HI20,
    R_RISCV_TLSDESC_LOAD_LO12,
    R_RISCV_TLSDESC_ADD_LO12,
    R_RISCV_TLSDESC_CALL,
}

impl RiscvElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use RiscvElfRelocationType::*;
        match self {
            R_RISCV_NONE => 0,
            R_RISCV_32 => 1,
            R_RISCV_64 => 2,
            R_RISCV_RELATIVE => 3,
            R_RISCV_COPY => 4,
            R_RISCV_JUMP_SLOT => 5,
            R_RISCV_TLS_DTPMOD32 => 6,
            R_RISCV_TLS_DTPMOD64 => 7,
            R_RISCV_TLS_DTPREL32 => 8,
            R_RISCV_TLS_DTPREL64 => 9,
            R_RISCV_TLS_TPREL32 => 10,
            R_RISCV_TLS_TPREL64 => 11,
            R_RISCV_TLSDESC => 12,
            R_RISCV_BRANCH => 16,
            R_RISCV_JAL => 17,
            R_RISCV_CALL => 18,
            R_RISCV_CALL_PLT => 19,
            R_RISCV_GOT_HI20 => 20,
            R_RISCV_TLS_GOT_HI20 => 21,
            R_RISCV_TLS_GD_HI20 => 22,
            R_RISCV_PCREL_HI20 => 23,
            R_RISCV_PCREL_LO12_I => 24,
            R_RISCV_PCREL_LO12_S => 25,
            R_RISCV_HI20 => 26,
            R_RISCV_LO12_I => 27,
            R_RISCV_LO12_S => 28,
            R_RISCV_TPREL_HI20 => 29,
            R_RISCV_TPREL_LO12_I => 30,
            R_RISCV_TPREL_LO12_S => 31,
            R_RISCV_TPREL_ADD => 32,
            R_RISCV_ADD8 => 33,
            R_RISCV_ADD16 => 34,
            R_RISCV_ADD32 => 35,
            R_RISCV_ADD64 => 36,
            R_RISCV_SUB8 => 37,
            R_RISCV_SUB16 => 38,
            R_RISCV_SUB32 => 39,
            R_RISCV_SUB64 => 40,
            R_RISCV_GNU_VTINHERIT => 41,
            R_RISCV_GNU_VTENTRY => 42,
            R_RISCV_ALIGN => 43,
            R_RISCV_RVC_BRANCH => 44,
            R_RISCV_RVC_JUMP => 45,
            R_RISCV_RVC_LUI => 46,
            R_RISCV_GPREL_I => 47,
            R_RISCV_GPREL_S => 48,
            R_RISCV_TPREL_I => 49,
            R_RISCV_TPREL_S => 50,
            R_RISCV_RELAX => 51,
            R_RISCV_SUB6 => 52,
            R_RISCV_SET6 => 53,
            R_RISCV_SET8 => 54,
            R_RISCV_SET16 => 55,
            R_RISCV_SET32 => 56,
            R_RISCV_32_PCREL => 57,
            R_RISCV_IRELATIVE => 58,
            R_RISCV_SET_ULEB128 => 60,
            R_RISCV_SUB_ULEB128 => 61,
            R_RISCV_TLSDESC_HI20 => 62,
            R_RISCV_TLSDESC_LOAD_LO12 => 63,
            R_RISCV_TLSDESC_ADD_LO12 => 64,
            R_RISCV_TLSDESC_CALL => 65,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use RiscvElfRelocationType::*;
        match self {
            R_RISCV_NONE => "R_RISCV_NONE",
            R_RISCV_32 => "R_RISCV_32",
            R_RISCV_64 => "R_RISCV_64",
            R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
            R_RISCV_COPY => "R_RISCV_COPY",
            R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
            R_RISCV_TLS_DTPMOD32 => "R_RISCV_TLS_DTPMOD32",
            R_RISCV_TLS_DTPMOD64 => "R_RISCV_TLS_DTPMOD64",
            R_RISCV_TLS_DTPREL32 => "R_RISCV_TLS_DTPREL32",
            R_RISCV_TLS_DTPREL64 => "R_RISCV_TLS_DTPREL64",
            R_RISCV_TLS_TPREL32 => "R_RISCV_TLS_TPREL32",
            R_RISCV_TLS_TPREL64 => "R_RISCV_TLS_TPREL64",
            R_RISCV_TLSDESC => "R_RISCV_TLSDESC",
            R_RISCV_BRANCH => "R_RISCV_BRANCH",
            R_RISCV_JAL => "R_RISCV_JAL",
            R_RISCV_CALL => "R_RISCV_CALL",
            R_RISCV_CALL_PLT => "R_RISCV_CALL_PLT",
            R_RISCV_GOT_HI20 => "R_RISCV_GOT_HI20",
            R_RISCV_TLS_GOT_HI20 => "R_RISCV_TLS_GOT_HI20",
            R_RISCV_TLS_GD_HI20 => "R_RISCV_TLS_GD_HI20",
            R_RISCV_PCREL_HI20 => "R_RISCV_PCREL_HI20",
            R_RISCV_PCREL_LO12_I => "R_RISCV_PCREL_LO12_I",
            R_RISCV_PCREL_LO12_S => "R_RISCV_PCREL_LO12_S",
            R_RISCV_HI20 => "R_RISCV_HI20",
            R_RISCV_LO12_I => "R_RISCV_LO12_I",
            R_RISCV_LO12_S => "R_RISCV_LO12_S",
            R_RISCV_TPREL_HI20 => "R_RISCV_TPREL_HI20",
            R_RISCV_TPREL_LO12_I => "R_RISCV_TPREL_LO12_I",
            R_RISCV_TPREL_LO12_S => "R_RISCV_TPREL_LO12_S",
            R_RISCV_TPREL_ADD => "R_RISCV_TPREL_ADD",
            R_RISCV_ADD8 => "R_RISCV_ADD8",
            R_RISCV_ADD16 => "R_RISCV_ADD16",
            R_RISCV_ADD32 => "R_RISCV_ADD32",
            R_RISCV_ADD64 => "R_RISCV_ADD64",
            R_RISCV_SUB8 => "R_RISCV_SUB8",
            R_RISCV_SUB16 => "R_RISCV_SUB16",
            R_RISCV_SUB32 => "R_RISCV_SUB32",
            R_RISCV_SUB64 => "R_RISCV_SUB64",
            R_RISCV_GNU_VTINHERIT => "R_RISCV_GNU_VTINHERIT",
            R_RISCV_GNU_VTENTRY => "R_RISCV_GNU_VTENTRY",
            R_RISCV_ALIGN => "R_RISCV_ALIGN",
            R_RISCV_RVC_BRANCH => "R_RISCV_RVC_BRANCH",
            R_RISCV_RVC_JUMP => "R_RISCV_RVC_JUMP",
            R_RISCV_RVC_LUI => "R_RISCV_RVC_LUI",
            R_RISCV_GPREL_I => "R_RISCV_GPREL_I",
            R_RISCV_GPREL_S => "R_RISCV_GPREL_S",
            R_RISCV_TPREL_I => "R_RISCV_TPREL_I",
            R_RISCV_TPREL_S => "R_RISCV_TPREL_S",
            R_RISCV_RELAX => "R_RISCV_RELAX",
            R_RISCV_SUB6 => "R_RISCV_SUB6",
            R_RISCV_SET6 => "R_RISCV_SET6",
            R_RISCV_SET8 => "R_RISCV_SET8",
            R_RISCV_SET16 => "R_RISCV_SET16",
            R_RISCV_SET32 => "R_RISCV_SET32",
            R_RISCV_32_PCREL => "R_RISCV_32_PCREL",
            R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
            R_RISCV_SET_ULEB128 => "R_RISCV_SET_ULEB128",
            R_RISCV_SUB_ULEB128 => "R_RISCV_SUB_ULEB128",
            R_RISCV_TLSDESC_HI20 => "R_RISCV_TLSDESC_HI20",
            R_RISCV_TLSDESC_LOAD_LO12 => "R_RISCV_TLSDESC_LOAD_LO12",
            R_RISCV_TLSDESC_ADD_LO12 => "R_RISCV_TLSDESC_ADD_LO12",
            R_RISCV_TLSDESC_CALL => "R_RISCV_TLSDESC_CALL",
        }
    }
}

impl ElfRelocationType for RiscvElfRelocationType {
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
        assert_eq!(RiscvElfRelocationType::R_RISCV_NONE.type_id(), 0);
        assert_eq!(RiscvElfRelocationType::R_RISCV_NONE.name(), "R_RISCV_NONE");
    }

    #[test]
    fn common_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_32.type_id(), 1);
        assert_eq!(RiscvElfRelocationType::R_RISCV_64.type_id(), 2);
        assert_eq!(RiscvElfRelocationType::R_RISCV_COPY.type_id(), 4);
        assert_eq!(RiscvElfRelocationType::R_RISCV_JUMP_SLOT.type_id(), 5);
        assert_eq!(RiscvElfRelocationType::R_RISCV_RELATIVE.type_id(), 3);
    }

    #[test]
    fn tls_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_DTPMOD32.type_id(), 6);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_DTPMOD64.type_id(), 7);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_DTPREL32.type_id(), 8);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_DTPREL64.type_id(), 9);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_TPREL32.type_id(), 10);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLS_TPREL64.type_id(), 11);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLSDESC.type_id(), 12);
    }

    #[test]
    fn instruction_pair_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_BRANCH.type_id(), 16);
        assert_eq!(RiscvElfRelocationType::R_RISCV_JAL.type_id(), 17);
        assert_eq!(RiscvElfRelocationType::R_RISCV_CALL.type_id(), 18);
        assert_eq!(RiscvElfRelocationType::R_RISCV_CALL_PLT.type_id(), 19);
    }

    #[test]
    fn hi_lo_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_GOT_HI20.type_id(), 20);
        assert_eq!(RiscvElfRelocationType::R_RISCV_PCREL_HI20.type_id(), 23);
        assert_eq!(RiscvElfRelocationType::R_RISCV_PCREL_LO12_I.type_id(), 24);
        assert_eq!(RiscvElfRelocationType::R_RISCV_PCREL_LO12_S.type_id(), 25);
        assert_eq!(RiscvElfRelocationType::R_RISCV_HI20.type_id(), 26);
        assert_eq!(RiscvElfRelocationType::R_RISCV_LO12_I.type_id(), 27);
        assert_eq!(RiscvElfRelocationType::R_RISCV_LO12_S.type_id(), 28);
    }

    #[test]
    fn add_sub_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_ADD8.type_id(), 33);
        assert_eq!(RiscvElfRelocationType::R_RISCV_ADD16.type_id(), 34);
        assert_eq!(RiscvElfRelocationType::R_RISCV_ADD32.type_id(), 35);
        assert_eq!(RiscvElfRelocationType::R_RISCV_ADD64.type_id(), 36);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SUB8.type_id(), 37);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SUB16.type_id(), 38);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SUB32.type_id(), 39);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SUB64.type_id(), 40);
    }

    #[test]
    fn rvc_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_RVC_BRANCH.type_id(), 44);
        assert_eq!(RiscvElfRelocationType::R_RISCV_RVC_JUMP.type_id(), 45);
        assert_eq!(RiscvElfRelocationType::R_RISCV_RVC_LUI.type_id(), 46);
    }

    #[test]
    fn gap_at_59_is_preserved() {
        // Java source skips typeId 59, going directly from IRELATIVE (58) to SET_ULEB128 (60)
        assert_eq!(RiscvElfRelocationType::R_RISCV_IRELATIVE.type_id(), 58);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SET_ULEB128.type_id(), 60);
    }

    #[test]
    fn high_range_relocations_match_java_ids() {
        assert_eq!(RiscvElfRelocationType::R_RISCV_SET_ULEB128.type_id(), 60);
        assert_eq!(RiscvElfRelocationType::R_RISCV_SUB_ULEB128.type_id(), 61);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLSDESC_HI20.type_id(), 62);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLSDESC_LOAD_LO12.type_id(), 63);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLSDESC_ADD_LO12.type_id(), 64);
        assert_eq!(RiscvElfRelocationType::R_RISCV_TLSDESC_CALL.type_id(), 65);
    }

    #[test]
    fn implements_elf_relocation_type_trait_object() {
        let r: &dyn ElfRelocationType = &RiscvElfRelocationType::R_RISCV_JUMP_SLOT;
        assert_eq!(r.type_id(), 5);
        assert_eq!(r.name(), "R_RISCV_JUMP_SLOT");
    }
}
