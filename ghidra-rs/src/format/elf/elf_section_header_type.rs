//! Port of `ghidra.app.util.bin.format.elf.ElfSectionHeaderType`.
//!
//! An extensible name+value+description registry for ELF section header (`sh_type`) values --
//! the [`ElfProgramHeaderType`](super::elf_program_header_type::ElfProgramHeaderType) sibling for
//! sections instead of segments. See [`elf_dynamic_type`](super::elf_dynamic_type)'s module docs
//! for the shared shape rationale (plain value type, no shared singleton, seam-trait bridge);
//! this module repeats the same choices for `sh_type`.
//!
//! # Two faithfully-reproduced Java quirks
//!
//! Unlike its two siblings ([`ElfDynamicType`](super::elf_dynamic_type::ElfDynamicType) and
//! [`ElfProgramHeaderType`](super::elf_program_header_type::ElfProgramHeaderType), both of which
//! guard their constructor against a negative `value` with an `IllegalArgumentException`), Java's
//! `ElfSectionHeaderType(int, String, String)` constructor (`ElfSectionHeaderType.java:141-145`)
//! has **no** such guard -- it stores whatever `value` it is given, including a negative one.
//! This port reproduces that asymmetry exactly: [`ElfSectionHeaderType::new`] never panics on a
//! negative `value`, while `ElfDynamicType::new`/`ElfProgramHeaderType::new` do. See
//! `new_accepts_negative_value_unlike_its_siblings` below for a test proving it.
//!
//! `ElfSectionHeaderType.getEnumDataType` (`ElfSectionHeaderType.java:151-163`) also reproduces
//! (rather than "fixes") an apparent copy-paste bug: it names the enum it builds
//! `"Elf32_PHType"`/`"Elf64_PHType"` -- the exact same name `ElfProgramHeaderType.getEnumDataType`
//! uses for *program* headers -- rather than something section-header-specific like
//! `"Elf32_SHType"`. See `get_enum_data_type_reuses_program_header_type_name` below.

use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::format::elf::elf_section_header_constants::{
    SHT_ANDROID_REL, SHT_ANDROID_RELA, SHT_CHECKSUM, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY,
    SHT_GNU_ATTRIBUTES, SHT_GNU_HASH, SHT_GNU_LIBLIST, SHT_GNU_VERDEF, SHT_GNU_VERNEED,
    SHT_GNU_VERSYM, SHT_GROUP, SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_NOTE, SHT_NULL,
    SHT_PREINIT_ARRAY, SHT_PROGBITS, SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB, SHT_SUNW_COMDAT,
    SHT_SUNW_MOVE, SHT_SUNW_SYMINFO, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;
use crate::util::exception::DuplicateNameException;

/// A single ELF section header type: `SHT_NULL`, `SHT_PROGBITS`, etc.
///
/// Port of `ghidra.app.util.bin.format.elf.ElfSectionHeaderType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSectionHeaderType {
    /// `ElfSectionHeaderType.value` -- the `sh_type` value this type represents.
    pub value: i32,
    /// `ElfSectionHeaderType.name` -- the type's symbolic name, e.g. `"SHT_SYMTAB"`.
    pub name: String,
    /// `ElfSectionHeaderType.description` -- a short human-readable description.
    pub description: String,
}

impl ElfSectionHeaderType {
    /// `new ElfSectionHeaderType(int, String, String)`.
    ///
    /// Unlike [`ElfDynamicType::new`](super::elf_dynamic_type::ElfDynamicType::new) and
    /// [`ElfProgramHeaderType::new`](super::elf_program_header_type::ElfProgramHeaderType::new),
    /// this does **not** validate `value >= 0` -- see the [module docs](self).
    pub fn new(value: i32, name: impl Into<String>, description: impl Into<String>) -> Self {
        ElfSectionHeaderType { value, name: name.into(), description: description.into() }
    }
}

impl std::fmt::Display for ElfSectionHeaderType {
    /// `ElfSectionHeaderType.toString()`: `NAME(0xHHHHHHHH)`, zero-padded to 8 hex digits.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value as u32)
    }
}

/// Bridges the real [`ElfSectionHeaderType`] into the pre-existing (empty marker)
/// [`crate::format::seam_stubs::ElfSectionHeaderType`] placeholder trait, so a value constructed
/// here can be used anywhere that trait is without any change to the not-yet-migrated call sites
/// that depend on it.
impl crate::format::seam_stubs::ElfSectionHeaderType for ElfSectionHeaderType {}

/// `ElfSectionHeaderType.addSectionHeaderType(ElfSectionHeaderType, Map<Integer,
/// ElfSectionHeaderType>)`.
///
/// Registers `ty` into `section_header_type_map`, keyed by its `value`. Fails if
/// `section_header_type_map` already has an entry with the same `value` *or* an entry whose
/// `name` matches case-insensitively -- both checks are real Java behavior
/// (`ElfSectionHeaderType.java:120-135`).
///
/// # Errors
/// Returns [`DuplicateNameException`] on either conflict, without modifying
/// `section_header_type_map`.
pub fn add_section_header_type(
    ty: ElfSectionHeaderType,
    section_header_type_map: &mut HashMap<i32, ElfSectionHeaderType>,
) -> Result<(), DuplicateNameException> {
    if let Some(conflict) = section_header_type_map.get(&ty.value) {
        return Err(DuplicateNameException::with_message(format!(
            "ElfSectionHeaderType conflict during initialization ({} / {}), value=0x{:x}",
            ty.name, conflict.name, ty.value
        )));
    }
    for existing in section_header_type_map.values() {
        if ty.name.eq_ignore_ascii_case(&existing.name) {
            return Err(DuplicateNameException::with_message(format!(
                "ElfSectionHeaderType conflict during initialization, name={}",
                ty.name
            )));
        }
    }
    section_header_type_map.insert(ty.value, ty);
    Ok(())
}

/// `ElfSectionHeaderType.addDefaultTypes(Map<Integer, ElfSectionHeaderType>)` -- merges every
/// well-known default type into `section_header_type_map`. Unlike [`add_section_header_type`]
/// this never fails: Java's `Map.putAll` silently overwrites any pre-existing entry with the
/// same key.
pub fn add_default_types(section_header_type_map: &mut HashMap<i32, ElfSectionHeaderType>) {
    for ty in DEFAULT_TYPES.values() {
        section_header_type_map.insert(ty.value, ty.clone());
    }
}

/// `ElfSectionHeaderType.getEnumDataType(boolean, String, Map<Integer, ElfSectionHeaderType>)`.
///
/// Builds an `EnumDataType` with one entry per `(name, value)` pair in
/// `section_header_type_map`. **Faithfully reproduces** the Java method's apparent copy-paste
/// bug: the enum is named `"Elf32_PHType"`/`"Elf64_PHType"` -- the *program*-header name -- not
/// anything section-header-specific. See the [module docs](self).
pub fn get_enum_data_type(
    is32_bit: bool,
    type_suffix: Option<&str>,
    section_header_type_map: &HashMap<i32, ElfSectionHeaderType>,
) -> EnumDataType {
    let size = if is32_bit { 4 } else { 8 };
    // `ElfSectionHeaderType.java:154`: literally "Elf32_PHType"/"Elf64_PHType", copy-pasted from
    // `ElfProgramHeaderType.getEnumDataType` and never updated for the section-header type.
    let mut name = if is32_bit { "Elf32_PHType" } else { "Elf64_PHType" }.to_string();
    if let Some(suffix) = type_suffix {
        name.push_str(suffix);
    }
    let category = CategoryPath::parse("/ELF").expect("\"/ELF\" is a valid category path");
    let mut sh_type_enum = EnumDataType::new_in_category(category, name, size);
    for ty in section_header_type_map.values() {
        sh_type_enum.add(&ty.name, ty.value as i64);
    }
    sh_type_enum
}

/// Declares one free function per well-known `ElfSectionHeaderType` (mirroring a Java `public
/// static final ElfSectionHeaderType SHT_*` field) plus the `build_default_types` helper that
/// registers every one of them, in declaration order, into a fresh map.
macro_rules! default_section_header_types {
    ($($fn_name:ident => ($value:expr, $name:expr, $desc:expr)),+ $(,)?) => {
        $(
            #[doc = concat!("`ElfSectionHeaderType.", $name, "`: ", $desc, ".")]
            pub fn $fn_name() -> ElfSectionHeaderType {
                ElfSectionHeaderType::new($value, $name, $desc)
            }
        )+

        fn build_default_types() -> HashMap<i32, ElfSectionHeaderType> {
            let mut map = HashMap::new();
            $(
                add_section_header_type($fn_name(), &mut map).unwrap_or_else(|e| {
                    panic!("ElfSectionHeaderType initialization error: {e}")
                });
            )+
            map
        }
    };
}

default_section_header_types! {
    sht_null => (SHT_NULL as i32, "SHT_NULL", "Inactive section header"),
    sht_progbits => (SHT_PROGBITS as i32, "SHT_PROGBITS", "Program defined section"),
    sht_symtab => (SHT_SYMTAB as i32, "SHT_SYMTAB", "Symbol table for link editing and dynamic linking"),
    sht_strtab => (SHT_STRTAB as i32, "SHT_STRTAB", "String table"),
    sht_rela => (SHT_RELA as i32, "SHT_RELA", "Relocation entries with explicit addends"),
    sht_hash => (SHT_HASH as i32, "SHT_HASH", "Symbol hash table for dynamic linking"),
    sht_dynamic => (SHT_DYNAMIC as i32, "SHT_DYNAMIC", "Dynamic linking information"),
    sht_note => (SHT_NOTE as i32, "SHT_NOTE", "Section holds information that marks the file"),
    sht_nobits => (SHT_NOBITS as i32, "SHT_NOBITS", "Section contains no bytes"),
    sht_rel => (SHT_REL as i32, "SHT_REL", "Relocation entries w/o explicit addends"),
    sht_shlib => (SHT_SHLIB as i32, "SHT_SHLIB", ""),
    sht_dynsym => (SHT_DYNSYM as i32, "SHT_DYNSYM", "Symbol table for dynamic linking"),
    sht_init_array => (SHT_INIT_ARRAY as i32, "SHT_INIT_ARRAY", "Array of initializer functions"),
    sht_fini_array => (SHT_FINI_ARRAY as i32, "SHT_FINI_ARRAY", "Array of finalizer functions"),
    sht_preinit_array => (SHT_PREINIT_ARRAY as i32, "SHT_PREINIT_ARRAY", "Array of pre-initializer functions"),
    sht_group => (SHT_GROUP as i32, "SHT_GROUP", "Section group"),
    sht_symtab_shndx => (SHT_SYMTAB_SHNDX as i32, "SHT_SYMTAB_SHNDX", "Extended section indeces"),
    // OS-specific range: 0x60000000 - 0x6fffffff
    sht_android_rel => (SHT_ANDROID_REL as i32, "SHT_ANDROID_REL", "Android relocation entries w/o explicit addends"),
    sht_android_rela => (SHT_ANDROID_RELA as i32, "SHT_ANDROID_RELA", "Android relocation entries with explicit addends"),
    sht_gnu_attributes => (SHT_GNU_ATTRIBUTES as i32, "SHT_GNU_ATTRIBUTES", "Object attributes"),
    sht_gnu_hash => (SHT_GNU_HASH as i32, "SHT_GNU_HASH", "GNU-style hash table"),
    sht_gnu_liblist => (SHT_GNU_LIBLIST as i32, "SHT_GNU_LIBLIST", "Prelink library list"),
    sht_checksum => (SHT_CHECKSUM as i32, "SHT_CHECKSUM", "Checksum for DSO content"),
    sht_sunw_move => (SHT_SUNW_MOVE as i32, "SHT_SUNW_move", ""),
    sht_sunw_comdat => (SHT_SUNW_COMDAT as i32, "SHT_SUNW_COMDAT", ""),
    sht_sunw_syminfo => (SHT_SUNW_SYMINFO as i32, "SHT_SUNW_syminfo", ""),
    sht_gnu_verdef => (SHT_GNU_VERDEF as i32, "SHT_GNU_verdef", "Version definition section"),
    sht_gnu_verneed => (SHT_GNU_VERNEED as i32, "SHT_GNU_verneed", "Version needs section"),
    sht_gnu_versym => (SHT_GNU_VERSYM as i32, "SHT_GNU_versym", "Version symbol table"),
}

static DEFAULT_TYPES: Lazy<HashMap<i32, ElfSectionHeaderType>> = Lazy::new(build_default_types);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    #[test]
    fn well_known_type_has_expected_fields() {
        let t = sht_symtab();
        assert_eq!(t.value, 2);
        assert_eq!(t.name, "SHT_SYMTAB");
        assert_eq!(t.description, "Symbol table for link editing and dynamic linking");
    }

    #[test]
    fn display_matches_java_tostring_zero_padded_hex() {
        assert_eq!(sht_null().to_string(), "SHT_NULL(0x00000000)");
        assert_eq!(sht_symtab().to_string(), "SHT_SYMTAB(0x00000002)");
        assert_eq!(sht_gnu_versym().to_string(), "SHT_GNU_versym(0x6fffffff)");
    }

    #[test]
    fn new_accepts_negative_value_unlike_its_siblings() {
        // ElfSectionHeaderType.java:141-145 has no `value < 0` guard, unlike
        // ElfDynamicType.java:274-279 and ElfProgramHeaderType.java:101-106. Constructing with a
        // negative value must NOT panic here, even though the analogous call would panic for
        // ElfDynamicType::new/ElfProgramHeaderType::new.
        let ty = ElfSectionHeaderType::new(-1, "SHT_BOGUS", "");
        assert_eq!(ty.value, -1);
    }

    #[test]
    fn add_section_header_type_rejects_value_conflict() {
        let mut map = HashMap::new();
        add_section_header_type(sht_symtab(), &mut map).unwrap();
        let err = add_section_header_type(
            ElfSectionHeaderType::new(2, "SHT_SOMETHING_ELSE", ""),
            &mut map,
        )
        .unwrap_err();
        assert!(err.to_string().contains("SHT_SYMTAB"));
        assert!(err.to_string().contains("SHT_SOMETHING_ELSE"));
        assert_eq!(map.get(&2).unwrap().name, "SHT_SYMTAB");
    }

    #[test]
    fn add_section_header_type_rejects_case_insensitive_name_conflict() {
        let mut map = HashMap::new();
        add_section_header_type(sht_symtab(), &mut map).unwrap();
        let err =
            add_section_header_type(ElfSectionHeaderType::new(99, "sht_symtab", ""), &mut map)
                .unwrap_err();
        assert!(err.to_string().contains("name=sht_symtab"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn add_default_types_populates_well_known_entries() {
        let mut map = HashMap::new();
        add_default_types(&mut map);
        assert_eq!(map.get(&0).unwrap().name, "SHT_NULL");
        assert_eq!(map.len(), 29);
    }

    #[test]
    fn get_enum_data_type_reuses_program_header_type_name() {
        // Faithfully reproduces ElfSectionHeaderType.java:154's copy-paste bug: the *section*
        // header enum comes out named identically to the *program* header enum.
        let mut map = HashMap::new();
        add_default_types(&mut map);

        let enum_32 = get_enum_data_type(true, None, &map);
        assert_eq!(enum_32.get_name(), "Elf32_PHType");
        assert_eq!(enum_32.get_length(), 4);
        assert_eq!(enum_32.get_value_for_name("SHT_SYMTAB"), Some(2));

        let enum_64_suffixed = get_enum_data_type(false, Some("_MyExt"), &map);
        assert_eq!(enum_64_suffixed.get_name(), "Elf64_PHType_MyExt");
        assert_eq!(enum_64_suffixed.get_length(), 8);
    }

    #[test]
    fn seam_trait_marker_is_implemented() {
        let _: Box<dyn crate::format::seam_stubs::ElfSectionHeaderType> = Box::new(sht_symtab());
    }
}
