//! Infineon TriCore ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.Tricore_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

// e_flags Identifying TriCore/PCP Derivatives
/// TriCore V1.1 derivative.
pub const EF_TRICORE_V1_1: u32 = 0x80000000;
/// TriCore V1.2 derivative.
pub const EF_TRICORE_V1_2: u32 = 0x40000000;
/// TriCore V1.3 derivative.
pub const EF_TRICORE_V1_3: u32 = 0x20000000;
/// PCP2 derivative.
pub const EF_TRICORE_PCP2: u32 = 0x02000000;

// TriCore Section Attribute Flags
/// Absolute section attribute flag.
pub const SHF_TRICORE_ABS: u32 = 0x400;
/// No-read section attribute flag.
pub const SHF_TRICORE_NOREAD: u32 = 0x800;

/// Infineon TriCore ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum TriCoreElfRelocationType {
    R_TRICORE_NONE,
    R_TRICORE_32REL,
    R_TRICORE_32ABS,
    R_TRICORE_24REL,
    R_TRICORE_24ABS,
    R_TRICORE_16SM,
    R_TRICORE_HI,
    R_TRICORE_LO,
    R_TRICORE_LO2,
    R_TRICORE_18ABS,
    R_TRICORE_10SM,
    R_TRICORE_15REL,
    R_TRICORE_10LI,
    R_TRICORE_16LI,
    R_TRICORE_10A8,
    R_TRICORE_16A8,
    R_TRICORE_10A9,
    R_TRICORE_16A9,
    R_TRICORE_10OFF,
    R_TRICORE_16OFF,
    R_TRICORE_8ABS,
    R_TRICORE_16ABS,
    R_TRICORE_16BIT,
    R_TRICORE_3POS,
    R_TRICORE_5POS,
    R_TRICORE_PCPHI,
    R_TRICORE_PCPLO,
    R_TRICORE_PCPPAGE,
    R_TRICORE_PCPOFF,
    R_TRICORE_PCPTEXT,
    R_TRICORE_5POS2,
    R_TRICORE_BRCC,
    R_TRICORE_BRCZ,
    R_TRICORE_BRNN,
    R_TRICORE_RRN,
    R_TRICORE_4CONST,
    R_TRICORE_4REL,
    R_TRICORE_4REL2,
    R_TRICORE_5POS3,
    R_TRICORE_4OFF,
    R_TRICORE_4OFF2,
    R_TRICORE_4OFF4,
    R_TRICORE_42OFF,
    R_TRICORE_42OFF2,
    R_TRICORE_42OFF4,
    R_TRICORE_2OFF,
    R_TRICORE_8CONST2,
    R_TRICORE_4POS,
    R_TRICORE_16SM2,
    R_TRICORE_5REL,
    R_TRICORE_VTENTRY,
    R_TRICORE_VTINHERIT,
    R_TRICORE_PCREL16,
    R_TRICORE_PCREL8,
    R_TRICORE_GOT,
    R_TRICORE_GOT2,
    R_TRICORE_GOTHI,
    R_TRICORE_GOTLO,
    R_TRICORE_GOTLO2,
    R_TRICORE_GOTUP,
    R_TRICORE_GOTOFF,
    R_TRICORE_GOTOFF2,
    R_TRICORE_GOTOFFHI,
    R_TRICORE_GOTOFFLO,
    R_TRICORE_GOTOFFLO2,
    R_TRICORE_GOTOFFUP,
    R_TRICORE_GOTPC,
    R_TRICORE_GOTPC2,
    R_TRICORE_GOTPCHI,
    R_TRICORE_GOTPCLO,
    R_TRICORE_GOTPCLO2,
    R_TRICORE_GOTCPUP,
    R_TRICORE_PLT,
    R_TRICORE_COPY,
    R_TRICORE_GLOB_DAT,
    R_TRICORE_JMP_SLOT,
    R_TRICORE_RELATIVE,
    R_TRICORE_BITPOS,
    R_TRICORE_SBREG_S2,
    R_TRICORE_SBREG_S1,
    R_TRICORE_SBREG_D,
}

impl TriCoreElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use TriCoreElfRelocationType::*;
        match self {
            R_TRICORE_NONE => 0,
            R_TRICORE_32REL => 1,
            R_TRICORE_32ABS => 2,
            R_TRICORE_24REL => 3,
            R_TRICORE_24ABS => 4,
            R_TRICORE_16SM => 5,
            R_TRICORE_HI => 6,
            R_TRICORE_LO => 7,
            R_TRICORE_LO2 => 8,
            R_TRICORE_18ABS => 9,
            R_TRICORE_10SM => 10,
            R_TRICORE_15REL => 11,
            R_TRICORE_10LI => 12,
            R_TRICORE_16LI => 13,
            R_TRICORE_10A8 => 14,
            R_TRICORE_16A8 => 15,
            R_TRICORE_10A9 => 16,
            R_TRICORE_16A9 => 17,
            R_TRICORE_10OFF => 18,
            R_TRICORE_16OFF => 19,
            R_TRICORE_8ABS => 20,
            R_TRICORE_16ABS => 21,
            R_TRICORE_16BIT => 22,
            R_TRICORE_3POS => 23,
            R_TRICORE_5POS => 24,
            R_TRICORE_PCPHI => 25,
            R_TRICORE_PCPLO => 26,
            R_TRICORE_PCPPAGE => 27,
            R_TRICORE_PCPOFF => 28,
            R_TRICORE_PCPTEXT => 29,
            R_TRICORE_5POS2 => 30,
            R_TRICORE_BRCC => 31,
            R_TRICORE_BRCZ => 32,
            R_TRICORE_BRNN => 33,
            R_TRICORE_RRN => 34,
            R_TRICORE_4CONST => 35,
            R_TRICORE_4REL => 36,
            R_TRICORE_4REL2 => 37,
            R_TRICORE_5POS3 => 38,
            R_TRICORE_4OFF => 39,
            R_TRICORE_4OFF2 => 40,
            R_TRICORE_4OFF4 => 41,
            R_TRICORE_42OFF => 42,
            R_TRICORE_42OFF2 => 43,
            R_TRICORE_42OFF4 => 44,
            R_TRICORE_2OFF => 45,
            R_TRICORE_8CONST2 => 46,
            R_TRICORE_4POS => 47,
            R_TRICORE_16SM2 => 48,
            R_TRICORE_5REL => 49,
            R_TRICORE_VTENTRY => 50,
            R_TRICORE_VTINHERIT => 51,
            R_TRICORE_PCREL16 => 52,
            R_TRICORE_PCREL8 => 53,
            R_TRICORE_GOT => 54,
            R_TRICORE_GOT2 => 55,
            R_TRICORE_GOTHI => 56,
            R_TRICORE_GOTLO => 57,
            R_TRICORE_GOTLO2 => 58,
            R_TRICORE_GOTUP => 59,
            R_TRICORE_GOTOFF => 60,
            R_TRICORE_GOTOFF2 => 61,
            R_TRICORE_GOTOFFHI => 62,
            R_TRICORE_GOTOFFLO => 63,
            R_TRICORE_GOTOFFLO2 => 64,
            R_TRICORE_GOTOFFUP => 65,
            R_TRICORE_GOTPC => 66,
            R_TRICORE_GOTPC2 => 67,
            R_TRICORE_GOTPCHI => 68,
            R_TRICORE_GOTPCLO => 69,
            R_TRICORE_GOTPCLO2 => 70,
            R_TRICORE_GOTCPUP => 71,
            R_TRICORE_PLT => 72,
            R_TRICORE_COPY => 73,
            R_TRICORE_GLOB_DAT => 74,
            R_TRICORE_JMP_SLOT => 75,
            R_TRICORE_RELATIVE => 76,
            R_TRICORE_BITPOS => 77,
            R_TRICORE_SBREG_S2 => 78,
            R_TRICORE_SBREG_S1 => 79,
            R_TRICORE_SBREG_D => 80,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use TriCoreElfRelocationType::*;
        match self {
            R_TRICORE_NONE => "R_TRICORE_NONE",
            R_TRICORE_32REL => "R_TRICORE_32REL",
            R_TRICORE_32ABS => "R_TRICORE_32ABS",
            R_TRICORE_24REL => "R_TRICORE_24REL",
            R_TRICORE_24ABS => "R_TRICORE_24ABS",
            R_TRICORE_16SM => "R_TRICORE_16SM",
            R_TRICORE_HI => "R_TRICORE_HI",
            R_TRICORE_LO => "R_TRICORE_LO",
            R_TRICORE_LO2 => "R_TRICORE_LO2",
            R_TRICORE_18ABS => "R_TRICORE_18ABS",
            R_TRICORE_10SM => "R_TRICORE_10SM",
            R_TRICORE_15REL => "R_TRICORE_15REL",
            R_TRICORE_10LI => "R_TRICORE_10LI",
            R_TRICORE_16LI => "R_TRICORE_16LI",
            R_TRICORE_10A8 => "R_TRICORE_10A8",
            R_TRICORE_16A8 => "R_TRICORE_16A8",
            R_TRICORE_10A9 => "R_TRICORE_10A9",
            R_TRICORE_16A9 => "R_TRICORE_16A9",
            R_TRICORE_10OFF => "R_TRICORE_10OFF",
            R_TRICORE_16OFF => "R_TRICORE_16OFF",
            R_TRICORE_8ABS => "R_TRICORE_8ABS",
            R_TRICORE_16ABS => "R_TRICORE_16ABS",
            R_TRICORE_16BIT => "R_TRICORE_16BIT",
            R_TRICORE_3POS => "R_TRICORE_3POS",
            R_TRICORE_5POS => "R_TRICORE_5POS",
            R_TRICORE_PCPHI => "R_TRICORE_PCPHI",
            R_TRICORE_PCPLO => "R_TRICORE_PCPLO",
            R_TRICORE_PCPPAGE => "R_TRICORE_PCPPAGE",
            R_TRICORE_PCPOFF => "R_TRICORE_PCPOFF",
            R_TRICORE_PCPTEXT => "R_TRICORE_PCPTEXT",
            R_TRICORE_5POS2 => "R_TRICORE_5POS2",
            R_TRICORE_BRCC => "R_TRICORE_BRCC",
            R_TRICORE_BRCZ => "R_TRICORE_BRCZ",
            R_TRICORE_BRNN => "R_TRICORE_BRNN",
            R_TRICORE_RRN => "R_TRICORE_RRN",
            R_TRICORE_4CONST => "R_TRICORE_4CONST",
            R_TRICORE_4REL => "R_TRICORE_4REL",
            R_TRICORE_4REL2 => "R_TRICORE_4REL2",
            R_TRICORE_5POS3 => "R_TRICORE_5POS3",
            R_TRICORE_4OFF => "R_TRICORE_4OFF",
            R_TRICORE_4OFF2 => "R_TRICORE_4OFF2",
            R_TRICORE_4OFF4 => "R_TRICORE_4OFF4",
            R_TRICORE_42OFF => "R_TRICORE_42OFF",
            R_TRICORE_42OFF2 => "R_TRICORE_42OFF2",
            R_TRICORE_42OFF4 => "R_TRICORE_42OFF4",
            R_TRICORE_2OFF => "R_TRICORE_2OFF",
            R_TRICORE_8CONST2 => "R_TRICORE_8CONST2",
            R_TRICORE_4POS => "R_TRICORE_4POS",
            R_TRICORE_16SM2 => "R_TRICORE_16SM2",
            R_TRICORE_5REL => "R_TRICORE_5REL",
            R_TRICORE_VTENTRY => "R_TRICORE_VTENTRY",
            R_TRICORE_VTINHERIT => "R_TRICORE_VTINHERIT",
            R_TRICORE_PCREL16 => "R_TRICORE_PCREL16",
            R_TRICORE_PCREL8 => "R_TRICORE_PCREL8",
            R_TRICORE_GOT => "R_TRICORE_GOT",
            R_TRICORE_GOT2 => "R_TRICORE_GOT2",
            R_TRICORE_GOTHI => "R_TRICORE_GOTHI",
            R_TRICORE_GOTLO => "R_TRICORE_GOTLO",
            R_TRICORE_GOTLO2 => "R_TRICORE_GOTLO2",
            R_TRICORE_GOTUP => "R_TRICORE_GOTUP",
            R_TRICORE_GOTOFF => "R_TRICORE_GOTOFF",
            R_TRICORE_GOTOFF2 => "R_TRICORE_GOTOFF2",
            R_TRICORE_GOTOFFHI => "R_TRICORE_GOTOFFHI",
            R_TRICORE_GOTOFFLO => "R_TRICORE_GOTOFFLO",
            R_TRICORE_GOTOFFLO2 => "R_TRICORE_GOTOFFLO2",
            R_TRICORE_GOTOFFUP => "R_TRICORE_GOTOFFUP",
            R_TRICORE_GOTPC => "R_TRICORE_GOTPC",
            R_TRICORE_GOTPC2 => "R_TRICORE_GOTPC2",
            R_TRICORE_GOTPCHI => "R_TRICORE_GOTPCHI",
            R_TRICORE_GOTPCLO => "R_TRICORE_GOTPCLO",
            R_TRICORE_GOTPCLO2 => "R_TRICORE_GOTPCLO2",
            R_TRICORE_GOTCPUP => "R_TRICORE_GOTCPUP",
            R_TRICORE_PLT => "R_TRICORE_PLT",
            R_TRICORE_COPY => "R_TRICORE_COPY",
            R_TRICORE_GLOB_DAT => "R_TRICORE_GLOB_DAT",
            R_TRICORE_JMP_SLOT => "R_TRICORE_JMP_SLOT",
            R_TRICORE_RELATIVE => "R_TRICORE_RELATIVE",
            R_TRICORE_BITPOS => "R_TRICORE_BITPOS",
            R_TRICORE_SBREG_S2 => "R_TRICORE_SBREG_S2",
            R_TRICORE_SBREG_S1 => "R_TRICORE_SBREG_S1",
            R_TRICORE_SBREG_D => "R_TRICORE_SBREG_D",
        }
    }
}

impl ElfRelocationType for TriCoreElfRelocationType {
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
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_NONE.type_id(), 0);
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_NONE.name(), "R_TRICORE_NONE");
    }

    #[test]
    fn tricore_32rel_has_correct_type_id() {
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_32REL.type_id(), 1);
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_32REL.name(), "R_TRICORE_32REL");
    }

    #[test]
    fn tricore_32abs_has_correct_type_id() {
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_32ABS.type_id(), 2);
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_32ABS.name(), "R_TRICORE_32ABS");
    }

    #[test]
    fn tricore_sbreg_d_has_correct_type_id() {
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_SBREG_D.type_id(), 80);
        assert_eq!(TriCoreElfRelocationType::R_TRICORE_SBREG_D.name(), "R_TRICORE_SBREG_D");
    }

    #[test]
    fn tricore_constants_are_correct() {
        assert_eq!(EF_TRICORE_V1_1, 0x80000000);
        assert_eq!(EF_TRICORE_V1_2, 0x40000000);
        assert_eq!(EF_TRICORE_V1_3, 0x20000000);
        assert_eq!(EF_TRICORE_PCP2, 0x02000000);
        assert_eq!(SHF_TRICORE_ABS, 0x400);
        assert_eq!(SHF_TRICORE_NOREAD, 0x800);
    }

    #[test]
    fn all_relocation_types_have_unique_type_ids() {
        let mut ids = std::collections::HashSet::new();
        for variant in [
            TriCoreElfRelocationType::R_TRICORE_NONE,
            TriCoreElfRelocationType::R_TRICORE_32REL,
            TriCoreElfRelocationType::R_TRICORE_32ABS,
            TriCoreElfRelocationType::R_TRICORE_RELATIVE,
            TriCoreElfRelocationType::R_TRICORE_SBREG_D,
        ] {
            ids.insert(variant.type_id());
        }
        assert_eq!(ids.len(), 5);
    }
}
