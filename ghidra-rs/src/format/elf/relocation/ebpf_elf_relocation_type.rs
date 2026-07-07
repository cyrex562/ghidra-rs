//! eBPF ELF relocation types.
//!
//! Ported from `ghidra.app.util.bin.format.elf.relocation.eBPF_ElfRelocationType`.

use super::elf_relocation_type::ElfRelocationType;

/// eBPF ELF relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum EbpfElfRelocationType {
    R_BPF_NONE,
    R_BPF_64_64,
    R_BPF_64_ABS64,
    R_BPF_64_ABS32,
    R_BPF_64_NODYLD32,
    R_BPF_64_32,
    R_BPF_GNU_64_16,
}

impl EbpfElfRelocationType {
    /// Returns the numeric relocation type identifier, matching the Java `typeId` field.
    pub const fn type_id_value(self) -> i32 {
        use EbpfElfRelocationType::*;
        match self {
            R_BPF_NONE => 0,
            R_BPF_64_64 => 1,
            R_BPF_64_ABS64 => 2,
            R_BPF_64_ABS32 => 3,
            R_BPF_64_NODYLD32 => 4,
            R_BPF_64_32 => 10,
            R_BPF_GNU_64_16 => 256,
        }
    }

    /// Returns the variant name, matching the Java enum constant name.
    pub const fn name_str(self) -> &'static str {
        use EbpfElfRelocationType::*;
        match self {
            R_BPF_NONE => "R_BPF_NONE",
            R_BPF_64_64 => "R_BPF_64_64",
            R_BPF_64_ABS64 => "R_BPF_64_ABS64",
            R_BPF_64_ABS32 => "R_BPF_64_ABS32",
            R_BPF_64_NODYLD32 => "R_BPF_64_NODYLD32",
            R_BPF_64_32 => "R_BPF_64_32",
            R_BPF_GNU_64_16 => "R_BPF_GNU_64_16",
        }
    }
}

impl ElfRelocationType for EbpfElfRelocationType {
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
        assert_eq!(EbpfElfRelocationType::R_BPF_NONE.type_id(), 0);
        assert_eq!(EbpfElfRelocationType::R_BPF_NONE.name(), "R_BPF_NONE");
    }

    #[test]
    fn base_64_relocations_have_correct_ids() {
        assert_eq!(EbpfElfRelocationType::R_BPF_64_64.type_id(), 1);
        assert_eq!(EbpfElfRelocationType::R_BPF_64_ABS64.type_id(), 2);
        assert_eq!(EbpfElfRelocationType::R_BPF_64_ABS32.type_id(), 3);
    }

    #[test]
    fn nodyld32_has_correct_type_id() {
        assert_eq!(EbpfElfRelocationType::R_BPF_64_NODYLD32.type_id(), 4);
        assert_eq!(EbpfElfRelocationType::R_BPF_64_NODYLD32.name(), "R_BPF_64_NODYLD32");
    }

    #[test]
    fn relocation_64_32_has_correct_type_id() {
        assert_eq!(EbpfElfRelocationType::R_BPF_64_32.type_id(), 10);
        assert_eq!(EbpfElfRelocationType::R_BPF_64_32.name(), "R_BPF_64_32");
    }

    #[test]
    fn gnu_relocation_has_large_type_id() {
        assert_eq!(EbpfElfRelocationType::R_BPF_GNU_64_16.type_id(), 256);
        assert_eq!(EbpfElfRelocationType::R_BPF_GNU_64_16.name(), "R_BPF_GNU_64_16");
    }

    #[test]
    fn all_variants_have_correct_names() {
        assert_eq!(EbpfElfRelocationType::R_BPF_NONE.name(), "R_BPF_NONE");
        assert_eq!(EbpfElfRelocationType::R_BPF_64_64.name(), "R_BPF_64_64");
        assert_eq!(EbpfElfRelocationType::R_BPF_64_ABS64.name(), "R_BPF_64_ABS64");
        assert_eq!(EbpfElfRelocationType::R_BPF_64_ABS32.name(), "R_BPF_64_ABS32");
    }

    #[test]
    fn implements_elf_relocation_type_trait() {
        let r: &dyn ElfRelocationType = &EbpfElfRelocationType::R_BPF_64_64;
        assert_eq!(r.type_id(), 1);
        assert_eq!(r.name(), "R_BPF_64_64");
    }

    #[test]
    fn all_variants_have_unique_type_ids() {
        let variants = [
            EbpfElfRelocationType::R_BPF_NONE,
            EbpfElfRelocationType::R_BPF_64_64,
            EbpfElfRelocationType::R_BPF_64_ABS64,
            EbpfElfRelocationType::R_BPF_64_ABS32,
            EbpfElfRelocationType::R_BPF_64_NODYLD32,
            EbpfElfRelocationType::R_BPF_64_32,
            EbpfElfRelocationType::R_BPF_GNU_64_16,
        ];

        let mut ids = [0; 7];
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
