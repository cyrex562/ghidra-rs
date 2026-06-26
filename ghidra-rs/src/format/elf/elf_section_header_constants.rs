//! Constants for ELF section header types, flags, and section indices.
//!
//! Ported from `ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants`.

// Frequently used section names

pub const DOT_BSS: &str = ".bss";
pub const DOT_COMMENT: &str = ".comment";
pub const DOT_DATA: &str = ".data";
pub const DOT_DATA1: &str = ".data1";
pub const DOT_DEBUG: &str = ".debug";
pub const DOT_DYNAMIC: &str = ".dynamic";
pub const DOT_DYNSTR: &str = ".dynstr";
pub const DOT_DYNSYM: &str = ".dynsym";
pub const DOT_FINI: &str = ".fini";
pub const DOT_GOT: &str = ".got";
pub const DOT_HASH: &str = ".hash";
pub const DOT_INIT: &str = ".init";
pub const DOT_INTERP: &str = ".interp";
pub const DOT_LINE: &str = ".line";
pub const DOT_NOTE: &str = ".note";
pub const DOT_PLT: &str = ".plt";
pub const DOT_RODATA: &str = ".rodata";
pub const DOT_RODATA1: &str = ".rodata1";
pub const DOT_SHSTRTAB: &str = ".shstrtab";
pub const DOT_STRTAB: &str = ".strtab";
pub const DOT_SYMTAB: &str = ".symtab";
pub const DOT_TEXT: &str = ".text";
pub const DOT_TBSS: &str = ".tbss";
pub const DOT_TDATA: &str = ".tdata";
pub const DOT_TDATA1: &str = ".tdata1";

// Section Header Types

/// Inactive section header.
pub const SHT_NULL: u32 = 0;
/// Program defined.
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table for link editing and dynamic linking.
pub const SHT_SYMTAB: u32 = 2;
/// String table.
pub const SHT_STRTAB: u32 = 3;
/// Relocation entries with explicit addends.
pub const SHT_RELA: u32 = 4;
/// Symbol hash table for dynamic linking.
pub const SHT_HASH: u32 = 5;
/// Dynamic linking information.
pub const SHT_DYNAMIC: u32 = 6;
/// Section holds information that marks the file.
pub const SHT_NOTE: u32 = 7;
/// Section contains no bytes.
pub const SHT_NOBITS: u32 = 8;
/// Relocation entries without explicit addends.
pub const SHT_REL: u32 = 9;
/// Undefined.
pub const SHT_SHLIB: u32 = 10;
/// Symbol table for dynamic linking.
pub const SHT_DYNSYM: u32 = 11;
/// Array of constructors.
pub const SHT_INIT_ARRAY: u32 = 14;
/// Array of destructors.
pub const SHT_FINI_ARRAY: u32 = 15;
/// Array of pre-constructors.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section group.
pub const SHT_GROUP: u32 = 17;
/// Extended section index table for linked symbol table.
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Relative relocation table section.
pub const SHT_RELR: u32 = 19;

// OS-Specific Section Types

/// Android relocation entries without explicit addends.
pub const SHT_ANDROID_REL: u32 = 0x60000001;
/// Android relocation entries with explicit addends.
pub const SHT_ANDROID_RELA: u32 = 0x60000002;
/// Android's experimental support for SHT_RELR sections.
pub const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;

/// LLVM ODR table.
pub const SHT_LLVM_ODRTAB: u32 = 0x6fff_4c00;
/// LLVM Linker Options.
pub const SHT_LLVM_LINKER_OPTIONS: u32 = 0x6fff_4c01;
/// List of address-significant symbols for safe ICF.
pub const SHT_LLVM_ADDRSIG: u32 = 0x6fff_4c03;
/// LLVM Dependent Library Specifiers.
pub const SHT_LLVM_DEPENDENT_LIBRARIES: u32 = 0x6fff_4c04;
/// Symbol partition specification.
pub const SHT_LLVM_SYMPART: u32 = 0x6fff_4c05;
/// ELF header for loadable partition.
pub const SHT_LLVM_PART_EHDR: u32 = 0x6fff_4c06;
/// Phdrs for loadable partition.
pub const SHT_LLVM_PART_PHDR: u32 = 0x6fff_4c07;
/// LLVM Basic Block Address Map (old version kept for backward-compatibility).
pub const SHT_LLVM_BB_ADDR_MAP_V0: u32 = 0x6fff_4c08;
/// LLVM Call Graph Profile.
pub const SHT_LLVM_CALL_GRAPH_PROFILE: u32 = 0x6fff_4c09;
/// LLVM Basic Block Address Map.
pub const SHT_LLVM_BB_ADDR_MAP: u32 = 0x6fff_4c0a;
/// LLVM device offloading data.
pub const SHT_LLVM_OFFLOADING: u32 = 0x6fff_4c0b;
/// .llvm.lto for fat LTO.
pub const SHT_LLVM_LTO: u32 = 0x6fff_4c0c;

/// GNU object attributes.
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6fff_fff5;
/// GNU-style hash table.
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
/// Prelink library list.
pub const SHT_GNU_LIBLIST: u32 = 0x6fff_fff7;
/// Checksum for DSO content.
pub const SHT_CHECKSUM: u32 = 0x6fff_fff8;

pub const SHT_SUNW_MOVE: u32 = 0x6fff_fffa;
pub const SHT_SUNW_COMDAT: u32 = 0x6fff_fffb;
pub const SHT_SUNW_SYMINFO: u32 = 0x6fff_fffc;
/// Version definition section.
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
/// Version needs section.
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
/// Version symbol table.
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

// Section Header Flag Bits

/// The section contains data that should be writable during process execution.
pub const SHF_WRITE: u32 = 0x1;
/// The section occupies memory during execution.
pub const SHF_ALLOC: u32 = 0x2;
/// The section contains executable machine instructions.
pub const SHF_EXECINSTR: u32 = 0x4;
/// The section might be merged.
pub const SHF_MERGE: u32 = 0x10;
/// The section contains null-terminated strings.
pub const SHF_STRINGS: u32 = 0x20;
/// sh_info contains SHT index.
pub const SHF_INFO_LINK: u32 = 0x40;
/// Preserve order after combining.
pub const SHF_LINK_ORDER: u32 = 0x80;
/// Non-standard OS specific handling required.
pub const SHF_OS_NONCONFORMING: u32 = 0x100;
/// The section is a member of a group.
pub const SHF_GROUP: u32 = 0x200;
/// The section holds thread-local data.
pub const SHF_TLS: u32 = 0x400;
/// The bytes of the section are compressed.
pub const SHF_COMPRESSED: u32 = 0x800;
/// This section is excluded from the final executable or shared library.
pub const SHF_EXCLUDE: u32 = 0x8000_0000;
/// The section contains OS-specific data.
pub const SHF_MASKOS: u32 = 0x0ff0_0000;
/// Processor-specific.
pub const SHF_MASKPROC: u32 = 0xf000_0000;

// Special section index values (stored as 16-bit value)

/// Undefined, missing, or irrelevant section.
pub const SHN_UNDEF: u16 = 0x0000;
/// Lower bound on range of reserved indexes.
pub const SHN_LORESERVE: u16 = 0xff00;
/// Lower bound for processor-specific semantics.
pub const SHN_LOPROC: u16 = 0xff00;
/// Upper bound for processor-specific semantics.
pub const SHN_HIPROC: u16 = 0xff1f;
/// Lowest operating system-specific index.
pub const SHN_LOOS: u16 = 0xff20;
/// Highest operating system-specific index.
pub const SHN_HIOS: u16 = 0xff3f;
/// Symbols defined relative to this section are absolute, not affected by relocation.
pub const SHN_ABS: u16 = 0xfff1;
/// Common symbols, such as Fortran COMMON or unallocated C external vars.
pub const SHN_COMMON: u16 = 0xfff2;
/// Marks that the index is >= SHN_LORESERVE.
pub const SHN_XINDEX: u16 = 0xffff;
/// Upper bound on range of reserved indexes.
pub const SHN_HIRESERVE: u16 = 0xffff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_names_have_correct_values() {
        assert_eq!(DOT_BSS, ".bss");
        assert_eq!(DOT_TEXT, ".text");
        assert_eq!(DOT_DATA, ".data");
        assert_eq!(DOT_RODATA, ".rodata");
        assert_eq!(DOT_SYMTAB, ".symtab");
        assert_eq!(DOT_STRTAB, ".strtab");
        assert_eq!(DOT_SHSTRTAB, ".shstrtab");
        assert_eq!(DOT_DYNAMIC, ".dynamic");
        assert_eq!(DOT_DYNSYM, ".dynsym");
        assert_eq!(DOT_DYNSTR, ".dynstr");
        assert_eq!(DOT_PLT, ".plt");
        assert_eq!(DOT_GOT, ".got");
        assert_eq!(DOT_INIT, ".init");
        assert_eq!(DOT_FINI, ".fini");
        assert_eq!(DOT_INTERP, ".interp");
        assert_eq!(DOT_NOTE, ".note");
        assert_eq!(DOT_HASH, ".hash");
        assert_eq!(DOT_DEBUG, ".debug");
        assert_eq!(DOT_LINE, ".line");
        assert_eq!(DOT_COMMENT, ".comment");
        assert_eq!(DOT_DATA1, ".data1");
        assert_eq!(DOT_RODATA1, ".rodata1");
        assert_eq!(DOT_TBSS, ".tbss");
        assert_eq!(DOT_TDATA, ".tdata");
        assert_eq!(DOT_TDATA1, ".tdata1");
    }

    #[test]
    fn sht_standard_types() {
        assert_eq!(SHT_NULL, 0);
        assert_eq!(SHT_PROGBITS, 1);
        assert_eq!(SHT_SYMTAB, 2);
        assert_eq!(SHT_STRTAB, 3);
        assert_eq!(SHT_RELA, 4);
        assert_eq!(SHT_HASH, 5);
        assert_eq!(SHT_DYNAMIC, 6);
        assert_eq!(SHT_NOTE, 7);
        assert_eq!(SHT_NOBITS, 8);
        assert_eq!(SHT_REL, 9);
        assert_eq!(SHT_SHLIB, 10);
        assert_eq!(SHT_DYNSYM, 11);
        assert_eq!(SHT_INIT_ARRAY, 14);
        assert_eq!(SHT_FINI_ARRAY, 15);
        assert_eq!(SHT_PREINIT_ARRAY, 16);
        assert_eq!(SHT_GROUP, 17);
        assert_eq!(SHT_SYMTAB_SHNDX, 18);
        assert_eq!(SHT_RELR, 19);
    }

    #[test]
    fn sht_android_types() {
        assert_eq!(SHT_ANDROID_REL, 0x60000001);
        assert_eq!(SHT_ANDROID_RELA, 0x60000002);
        assert_eq!(SHT_ANDROID_RELR, 0x6fffff00);
    }

    #[test]
    fn sht_llvm_types_sequential() {
        assert_eq!(SHT_LLVM_ODRTAB, 0x6fff4c00);
        assert_eq!(SHT_LLVM_LINKER_OPTIONS, SHT_LLVM_ODRTAB + 1);
        assert_eq!(SHT_LLVM_ADDRSIG, SHT_LLVM_ODRTAB + 3);
        assert_eq!(SHT_LLVM_DEPENDENT_LIBRARIES, SHT_LLVM_ODRTAB + 4);
        assert_eq!(SHT_LLVM_SYMPART, SHT_LLVM_ODRTAB + 5);
        assert_eq!(SHT_LLVM_PART_EHDR, SHT_LLVM_ODRTAB + 6);
        assert_eq!(SHT_LLVM_PART_PHDR, SHT_LLVM_ODRTAB + 7);
        assert_eq!(SHT_LLVM_BB_ADDR_MAP_V0, SHT_LLVM_ODRTAB + 8);
        assert_eq!(SHT_LLVM_CALL_GRAPH_PROFILE, SHT_LLVM_ODRTAB + 9);
        assert_eq!(SHT_LLVM_BB_ADDR_MAP, SHT_LLVM_ODRTAB + 10);
        assert_eq!(SHT_LLVM_OFFLOADING, SHT_LLVM_ODRTAB + 11);
        assert_eq!(SHT_LLVM_LTO, SHT_LLVM_ODRTAB + 12);
    }

    #[test]
    fn sht_gnu_types() {
        assert_eq!(SHT_GNU_ATTRIBUTES, 0x6ffffff5);
        assert_eq!(SHT_GNU_HASH, 0x6ffffff6);
        assert_eq!(SHT_GNU_LIBLIST, 0x6ffffff7);
        assert_eq!(SHT_CHECKSUM, 0x6ffffff8);
        assert_eq!(SHT_SUNW_MOVE, 0x6ffffffa);
        assert_eq!(SHT_SUNW_COMDAT, 0x6ffffffb);
        assert_eq!(SHT_SUNW_SYMINFO, 0x6ffffffc);
        assert_eq!(SHT_GNU_VERDEF, 0x6ffffffd);
        assert_eq!(SHT_GNU_VERNEED, 0x6ffffffe);
        assert_eq!(SHT_GNU_VERSYM, 0x6fffffff);
    }

    #[test]
    fn shf_flag_bits() {
        assert_eq!(SHF_WRITE, 0x1);
        assert_eq!(SHF_ALLOC, 0x2);
        assert_eq!(SHF_EXECINSTR, 0x4);
        assert_eq!(SHF_MERGE, 0x10);
        assert_eq!(SHF_STRINGS, 0x20);
        assert_eq!(SHF_INFO_LINK, 0x40);
        assert_eq!(SHF_LINK_ORDER, 0x80);
        assert_eq!(SHF_OS_NONCONFORMING, 0x100);
        assert_eq!(SHF_GROUP, 0x200);
        assert_eq!(SHF_TLS, 0x400);
        assert_eq!(SHF_COMPRESSED, 0x800);
        assert_eq!(SHF_EXCLUDE, 0x80000000);
    }

    #[test]
    fn shf_masks() {
        assert_eq!(SHF_MASKOS, 0x0ff00000);
        assert_eq!(SHF_MASKPROC, 0xf0000000);
    }

    #[test]
    fn shf_maskos_and_maskproc_do_not_overlap() {
        assert_eq!(SHF_MASKOS & SHF_MASKPROC, 0);
    }

    #[test]
    fn shf_basic_flags_are_disjoint() {
        assert_eq!(SHF_WRITE & SHF_ALLOC, 0);
        assert_eq!(SHF_WRITE & SHF_EXECINSTR, 0);
        assert_eq!(SHF_ALLOC & SHF_EXECINSTR, 0);
    }

    #[test]
    fn shn_special_indices() {
        assert_eq!(SHN_UNDEF, 0x0000);
        assert_eq!(SHN_LORESERVE, 0xff00);
        assert_eq!(SHN_LOPROC, 0xff00);
        assert_eq!(SHN_HIPROC, 0xff1f);
        assert_eq!(SHN_LOOS, 0xff20);
        assert_eq!(SHN_HIOS, 0xff3f);
        assert_eq!(SHN_ABS, 0xfff1);
        assert_eq!(SHN_COMMON, 0xfff2);
        assert_eq!(SHN_XINDEX, 0xffff);
        assert_eq!(SHN_HIRESERVE, 0xffff);
    }

    #[test]
    fn shn_loreserve_equals_loproc() {
        assert_eq!(SHN_LORESERVE, SHN_LOPROC);
    }

    #[test]
    fn shn_xindex_equals_hireserve() {
        assert_eq!(SHN_XINDEX, SHN_HIRESERVE);
    }

    #[test]
    fn shn_proc_range_within_reserved() {
        assert!(SHN_LOPROC >= SHN_LORESERVE);
        assert!(SHN_HIPROC <= SHN_HIRESERVE);
    }

    #[test]
    fn shn_os_range_within_reserved() {
        assert!(SHN_LOOS >= SHN_LORESERVE);
        assert!(SHN_HIOS <= SHN_HIRESERVE);
    }
}
