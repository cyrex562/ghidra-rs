//! Port of `ghidra.app.util.bin.format.elf.ElfDynamicType`.
//!
//! An extensible name+value+description registry for ELF `.dynamic` section tag (`d_tag`)
//! values. Java models each well-known tag as a `public static final ElfDynamicType` field,
//! shares a single mutable default-instance map (`defaultElfDynamicTypeMap`) populated as a side
//! effect of those field initializers, and lets `ElfLoadAdapter`/`ElfExtension` subclasses declare
//! additional `static ElfDynamicType` fields of their own that get merged into a per-image type
//! map via reflection (`Class.getDeclaredFields()`).
//!
//! # Shape
//!
//! [`ElfDynamicType`] is ported as a plain (`Clone`, `PartialEq`, `Eq`) value type rather than a
//! class hierarchy: Java never subclasses it, only ever *instantiates* it with different
//! `value`/`name`/`description`/`valueType` tuples. Each Java `public static final ElfDynamicType
//! DT_*` field becomes a same-named lowercase free function (e.g. `DT_NULL` -> [`dt_null`]) that
//! constructs a fresh, equal instance on demand -- there is no shared singleton, since nothing in
//! this port needs referential identity for these values (`PartialEq`/`Eq` compare by field,
//! which is what every real use site actually cares about).
//!
//! Reflection-based extension-type discovery has no Rust equivalent; an extension port is
//! expected to build its own `Vec`/slice of [`ElfDynamicType`] values and register them
//! explicitly (mirrors the same departure already documented on
//! [`ElfLoadAdapter::add_dynamic_types`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::add_dynamic_types)).
//!
//! # Relationship to the pre-existing seam stub
//!
//! [`crate::format::seam_stubs::ElfDynamicType`] is an earlier placeholder trait (`value`/`name`
//! only) that [`ElfDynamic`](crate::format::elf::elf_dynamic::ElfDynamic) and
//! [`ElfLoadAdapter`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter) depend on via
//! `Box<dyn ElfDynamicType>` / `HashMap<i32, Box<dyn ElfDynamicType>>`. This module is the real
//! port of the Java class; [`ElfDynamicType`] implements that seam trait below so a value here can
//! be boxed straight into those existing call sites without any change to them.

use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::util::exception::DuplicateNameException;

/// `ElfDynamicType.ElfDynamicValueType` -- how a dynamic entry's `d_val`/`d_ptr` union should be
/// interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfDynamicValueType {
    /// `VALUE` -- a plain integer value.
    Value,
    /// `ADDRESS` -- an address within the image.
    Address,
    /// `STRING` -- an offset into the dynamic string table.
    String,
}

/// A single ELF dynamic tag type: `DT_NULL`, `DT_NEEDED`, etc.
///
/// Port of `ghidra.app.util.bin.format.elf.ElfDynamicType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfDynamicType {
    /// `ElfDynamicType.value` -- the `d_tag` value this type represents. Always non-negative;
    /// see [`ElfDynamicType::new`].
    pub value: i32,
    /// `ElfDynamicType.name` -- the type's symbolic name, e.g. `"DT_SYMTAB"`.
    pub name: String,
    /// `ElfDynamicType.description` -- a short human-readable description.
    pub description: String,
    /// `ElfDynamicType.valueType` -- how `d_val`/`d_ptr` should be interpreted for this tag.
    pub value_type: ElfDynamicValueType,
}

impl ElfDynamicType {
    /// `new ElfDynamicType(int, String, String, ElfDynamicValueType)`.
    ///
    /// # Panics
    /// Panics (standing in for Java's `IllegalArgumentException`) if `value` is negative.
    pub fn new(
        value: i32,
        name: impl Into<String>,
        description: impl Into<String>,
        value_type: ElfDynamicValueType,
    ) -> Self {
        if value < 0 {
            panic!("ElfDynamicType value out of range: 0x{:x}", value as u32);
        }
        ElfDynamicType { value, name: name.into(), description: description.into(), value_type }
    }
}

impl std::fmt::Display for ElfDynamicType {
    /// `ElfDynamicType.toString()`: `NAME(0xHHHHHHHH)`, zero-padded to 8 hex digits.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value as u32)
    }
}

/// Bridges the real [`ElfDynamicType`] into the pre-existing
/// [`crate::format::seam_stubs::ElfDynamicType`] placeholder trait, so a value constructed here
/// can be used anywhere that trait is (e.g. `Box<dyn seam_stubs::ElfDynamicType>`) without any
/// change to the not-yet-migrated call sites that depend on it.
impl crate::format::seam_stubs::ElfDynamicType for ElfDynamicType {
    fn value(&self) -> i32 {
        self.value
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

/// `ElfDynamicType.addDynamicType(ElfDynamicType, Map<Integer, ElfDynamicType>)`.
///
/// Registers `ty` into `dynamic_type_map`, keyed by its `value`. Fails if `dynamic_type_map`
/// already has an entry with the same `value` *or* an entry whose `name` matches
/// case-insensitively -- both checks are real Java behavior (`ElfDynamicType.java:252-267`), so
/// e.g. registering `"dt_null"` after `"DT_NULL"` is already present fails even though the two
/// differ only in case.
///
/// # Errors
/// Returns [`DuplicateNameException`] on either conflict, without modifying `dynamic_type_map`.
pub fn add_dynamic_type(
    ty: ElfDynamicType,
    dynamic_type_map: &mut HashMap<i32, ElfDynamicType>,
) -> Result<(), DuplicateNameException> {
    if let Some(conflict) = dynamic_type_map.get(&ty.value) {
        return Err(DuplicateNameException::with_message(format!(
            "ElfDynamicType conflict during initialization ({} / {}), value=0x{:x}",
            ty.name, conflict.name, ty.value
        )));
    }
    for existing in dynamic_type_map.values() {
        if ty.name.eq_ignore_ascii_case(&existing.name) {
            return Err(DuplicateNameException::with_message(format!(
                "ElfDynamicType conflict during initialization, name={}",
                ty.name
            )));
        }
    }
    dynamic_type_map.insert(ty.value, ty);
    Ok(())
}

/// `ElfDynamicType.addDefaultTypes(Map<Integer, ElfDynamicType>)` -- merges every well-known
/// default type into `dynamic_type_map`. Unlike [`add_dynamic_type`] this never fails: Java's
/// `Map.putAll` silently overwrites any pre-existing entry with the same key.
pub fn add_default_types(dynamic_type_map: &mut HashMap<i32, ElfDynamicType>) {
    for ty in DEFAULT_TYPES.values() {
        dynamic_type_map.insert(ty.value, ty.clone());
    }
}

// DT_FLAGS flag bits (see DF_ constants for flag definitions).
/// `$ORIGIN` processing required.
pub const DF_ORIGIN: u32 = 0x1;
/// Symbolic symbol resolution required.
pub const DF_SYMBOLIC: u32 = 0x2;
/// Text relocations exist.
pub const DF_TEXTREL: u32 = 0x4;
/// Non-lazy binding required.
pub const DF_BIND_NOW: u32 = 0x8;
/// Object uses static TLS scheme.
pub const DF_STATIC_TLS: u32 = 0x10;

// DT_FLAGS_1 flag bits (see DF_1_ constants for flag definitions).
pub const DF_1_NOW: u32 = 0x1;
pub const DF_1_GLOBAL: u32 = 0x2;
pub const DF_1_GROUP: u32 = 0x4;
pub const DF_1_NODELETE: u32 = 0x8;
pub const DF_1_LOADFLTR: u32 = 0x10;
pub const DF_1_INITFIRST: u32 = 0x20;
pub const DF_1_NOOPEN: u32 = 0x40;
pub const DF_1_ORIGIN: u32 = 0x80;
pub const DF_1_DIRECT: u32 = 0x100;
pub const DF_1_INTERPOSE: u32 = 0x400;
pub const DF_1_NODEFLIB: u32 = 0x800;

/// Declares one free function per well-known `ElfDynamicType` (mirroring a Java `public static
/// final ElfDynamicType DT_*` field) plus the `build_default_types` helper that registers every
/// one of them, in declaration order, into a fresh map -- exactly mirroring the side effect Java
/// gets for free from running each field initializer during static class init.
macro_rules! default_dynamic_types {
    ($($fn_name:ident => ($value:expr, $name:expr, $desc:expr, $vt:expr)),+ $(,)?) => {
        $(
            #[doc = concat!("`ElfDynamicType.", $name, "`: ", $desc, ".")]
            pub fn $fn_name() -> ElfDynamicType {
                ElfDynamicType::new($value, $name, $desc, $vt)
            }
        )+

        fn build_default_types() -> HashMap<i32, ElfDynamicType> {
            let mut map = HashMap::new();
            $(
                add_dynamic_type($fn_name(), &mut map).unwrap_or_else(|e| {
                    // Mirrors `addDefaultDynamicType` wrapping `DuplicateNameException` in an
                    // unchecked `RuntimeException` during static initialization.
                    panic!("ElfDynamicType initialization error: {e}")
                });
            )+
            map
        }
    };
}

default_dynamic_types! {
    dt_null => (0, "DT_NULL", "Marks end of dynamic section", ElfDynamicValueType::Value),
    dt_needed => (1, "DT_NEEDED", "Name of needed library", ElfDynamicValueType::String),
    dt_pltrelsz => (2, "DT_PLTRELSZ", "Size in bytes of PLT relocs", ElfDynamicValueType::Value),
    dt_pltgot => (3, "DT_PLTGOT", "Processor defined value", ElfDynamicValueType::Address),
    dt_hash => (4, "DT_HASH", "Address of symbol hash table", ElfDynamicValueType::Address),
    dt_strtab => (5, "DT_STRTAB", "Address of string table", ElfDynamicValueType::Address),
    dt_symtab => (6, "DT_SYMTAB", "Address of symbol table", ElfDynamicValueType::Address),
    dt_rela => (7, "DT_RELA", "Address of Rela relocs", ElfDynamicValueType::Address),
    dt_relasz => (8, "DT_RELASZ", "Total size of Rela relocs", ElfDynamicValueType::Value),
    dt_relaent => (9, "DT_RELAENT", "Size of one Rela reloc", ElfDynamicValueType::Value),
    dt_strsz => (10, "DT_STRSZ", "Size of string table", ElfDynamicValueType::Value),
    dt_syment => (11, "DT_SYMENT", "Size of one symbol table entry", ElfDynamicValueType::Value),
    dt_init => (12, "DT_INIT", "Address of init function", ElfDynamicValueType::Address),
    dt_fini => (13, "DT_FINI", "Address of termination function", ElfDynamicValueType::Address),
    dt_soname => (14, "DT_SONAME", "Name of shared object (string ref)", ElfDynamicValueType::String),
    dt_rpath => (15, "DT_RPATH", "Library search path", ElfDynamicValueType::String),
    dt_symbolic => (16, "DT_SYMBOLIC", "Start symbol search here", ElfDynamicValueType::Value),
    dt_rel => (17, "DT_REL", "Address of Rel relocs", ElfDynamicValueType::Address),
    dt_relsz => (18, "DT_RELSZ", "Total size of Rel relocs", ElfDynamicValueType::Value),
    dt_relent => (19, "DT_RELENT", "Size of one Rel reloc", ElfDynamicValueType::Value),
    dt_pltrel => (20, "DT_PLTREL", "Type of reloc in PLT", ElfDynamicValueType::Value),
    dt_debug => (21, "DT_DEBUG", "For debugging (unspecified)", ElfDynamicValueType::Value),
    dt_textrel => (22, "DT_TEXTREL", "Reloc might modify .text", ElfDynamicValueType::Value),
    dt_jmprel => (23, "DT_JMPREL", "Address of PLT relocs", ElfDynamicValueType::Address),
    dt_bind_now => (24, "DT_BIND_NOW", "Process relocations of object", ElfDynamicValueType::Value),
    dt_init_array => (25, "DT_INIT_ARRAY", "Address of array with addresses of init fct", ElfDynamicValueType::Address),
    dt_fini_array => (26, "DT_FINI_ARRAY", "Address of array with addresses of fini fct", ElfDynamicValueType::Address),
    dt_init_arraysz => (27, "DT_INIT_ARRAYSZ", "Size in bytes of DT_INIT_ARRAY", ElfDynamicValueType::Value),
    dt_fini_arraysz => (28, "DT_FINI_ARRAYSZ", "Size in bytes of DT_FINI_ARRAY", ElfDynamicValueType::Value),
    dt_runpath => (29, "DT_RUNPATH", "Library search path (string ref)", ElfDynamicValueType::String),
    dt_flags => (30, "DT_FLAGS", "Flags for the object being loaded", ElfDynamicValueType::Value),
    // Experimental RELR relocation support.
    dt_relrsz => (35, "DT_RELRSZ", "Total size of Relr relocs", ElfDynamicValueType::Value),
    dt_relr => (36, "DT_RELR", "Address of Relr relocs", ElfDynamicValueType::Address),
    dt_relrent => (37, "DT_RELRENT", "Size of Relr relocation entry", ElfDynamicValueType::Value),
    // glibc and BSD disagree on DT_ENCODING (32); Java leaves it commented out and uses 32/33 for
    // DT_PREINIT_ARRAY/DT_PREINIT_ARRAYSZ instead. Reproduced here for the same reason.
    dt_preinit_array => (32, "DT_PREINIT_ARRAY", "Array with addresses of preinit fct", ElfDynamicValueType::Address),
    dt_preinit_arraysz => (33, "DT_PREINIT_ARRAYSZ", "Size in bytes of DT_PREINIT_ARRAY", ElfDynamicValueType::Value),
    // OS-specific range: 0x6000000d - 0x6ffff000
    dt_android_rel => (0x6000000F, "DT_ANDROID_REL", "Address of Rel relocs", ElfDynamicValueType::Address),
    dt_android_relsz => (0x60000010, "DT_ANDROID_RELSZ", "Total size of Rel relocs", ElfDynamicValueType::Value),
    dt_android_rela => (0x60000011, "DT_ANDROID_RELA", "Address of Rela relocs", ElfDynamicValueType::Address),
    dt_android_relasz => (0x60000012, "DT_ANDROID_RELASZ", "Total size of Rela relocs", ElfDynamicValueType::Value),
    dt_android_relr => (0x6FFFE000, "DT_ANDROID_RELR", "Address of Relr relocs", ElfDynamicValueType::Address),
    dt_android_relrsz => (0x6FFFE001, "DT_ANDROID_RELRSZ", "Total size of Relr relocs", ElfDynamicValueType::Value),
    dt_android_relrent => (0x6FFFE003, "DT_ANDROID_RELRENT", "Size of Relr relocation entry", ElfDynamicValueType::Value),
    // Value Range (??): 0x6ffffd00 - 0x6ffffdff
    dt_gnu_prelinked => (0x6ffffdf5, "DT_GNU_PRELINKED", "Prelinking timestamp", ElfDynamicValueType::Value),
    dt_gnu_conflictsz => (0x6ffffdf6, "DT_GNU_CONFLICTSZ", "Size of conflict section", ElfDynamicValueType::Value),
    dt_gnu_liblistsz => (0x6ffffdf7, "DT_GNU_LIBLISTSZ", "Size of library list", ElfDynamicValueType::Value),
    dt_checksum => (0x6ffffdf8, "DT_CHECKSUM", "", ElfDynamicValueType::Value),
    dt_pltpadsz => (0x6ffffdf9, "DT_PLTPADSZ", "", ElfDynamicValueType::Value),
    dt_moveent => (0x6ffffdfa, "DT_MOVEENT", "", ElfDynamicValueType::Value),
    dt_movesz => (0x6ffffdfb, "DT_MOVESZ", "", ElfDynamicValueType::Value),
    dt_feature_1 => (0x6ffffdfc, "DT_FEATURE_1", "", ElfDynamicValueType::Value),
    dt_posflag_1 => (0x6ffffdfd, "DT_POSFLAG_1", "", ElfDynamicValueType::Value),
    dt_syminsz => (0x6ffffdfe, "DT_SYMINSZ", "", ElfDynamicValueType::Value),
    dt_syminent => (0x6ffffdff, "DT_SYMINENT", "", ElfDynamicValueType::Value),
    // Address Range (??): 0x6ffffe00 - 0x6ffffeff
    dt_gnu_xhash => (0x6ffffef4, "DT_GNU_XHASH", "GNU-style extended hash table", ElfDynamicValueType::Address),
    dt_gnu_hash => (0x6ffffef5, "DT_GNU_HASH", "GNU-style hash table", ElfDynamicValueType::Address),
    dt_tlsdesc_plt => (0x6ffffef6, "DT_TLSDESC_PLT", "", ElfDynamicValueType::Value),
    dt_tlsdesc_got => (0x6ffffef7, "DT_TLSDESC_GOT", "", ElfDynamicValueType::Value),
    dt_gnu_conflict => (0x6ffffef8, "DT_GNU_CONFLICT", "Start of conflict section", ElfDynamicValueType::Address),
    dt_gnu_liblist => (0x6ffffef9, "DT_GNU_LIBLIST", "Library list", ElfDynamicValueType::Value),
    dt_config => (0x6ffffefa, "DT_CONFIG", "Configuration information", ElfDynamicValueType::Value),
    dt_depaudit => (0x6ffffefb, "DT_DEPAUDIT", "Dependency auditing", ElfDynamicValueType::Value),
    dt_audit => (0x6ffffefc, "DT_AUDIT", "Object auditing", ElfDynamicValueType::Value),
    dt_pltpad => (0x6ffffefd, "DT_PLTPAD", "PLT padding", ElfDynamicValueType::Value),
    dt_movetab => (0x6ffffefe, "DT_MOVETAB", "Move table", ElfDynamicValueType::Address),
    dt_syminfo => (0x6ffffeff, "DT_SYMINFO", "Syminfo table", ElfDynamicValueType::Address),
    dt_versym => (0x6ffffff0, "DT_VERSYM", "Address of symbol version table", ElfDynamicValueType::Address),
    dt_relacount => (0x6ffffff9, "DT_RELACOUNT", "", ElfDynamicValueType::Value),
    dt_relcount => (0x6ffffffa, "DT_RELCOUNT", "", ElfDynamicValueType::Value),
    // see DF_1_ constants for flag definitions
    dt_flags_1 => (0x6ffffffb, "DT_FLAGS_1", "State flags", ElfDynamicValueType::Value),
    dt_verdef => (0x6ffffffc, "DT_VERDEF", "Address of version definition table", ElfDynamicValueType::Address),
    dt_verdefnum => (0x6ffffffd, "DT_VERDEFNUM", "Number of version definitions", ElfDynamicValueType::Value),
    dt_verneed => (0x6ffffffe, "DT_VERNEED", "Address of table with needed versions", ElfDynamicValueType::Address),
    dt_verneednum => (0x6fffffff, "DT_VERNEEDNUM", "Number of needed versions", ElfDynamicValueType::Value),
    // Processor-specific range: 0x70000000 - 0x7fffffff
    dt_auxiliary => (0x7ffffffd, "DT_AUXILIARY", "Shared object to load before self", ElfDynamicValueType::Value),
    dt_filter => (0x7fffffff, "DT_FILTER", "Shared object to get values from", ElfDynamicValueType::Value),
}

static DEFAULT_TYPES: Lazy<HashMap<i32, ElfDynamicType>> = Lazy::new(build_default_types);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_type_has_expected_fields() {
        let t = dt_symtab();
        assert_eq!(t.value, 6);
        assert_eq!(t.name, "DT_SYMTAB");
        assert_eq!(t.description, "Address of symbol table");
        assert_eq!(t.value_type, ElfDynamicValueType::Address);
    }

    #[test]
    fn display_matches_java_tostring_zero_padded_hex() {
        // NAME + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")"
        assert_eq!(dt_null().to_string(), "DT_NULL(0x00000000)");
        assert_eq!(dt_symtab().to_string(), "DT_SYMTAB(0x00000006)");
        assert_eq!(dt_filter().to_string(), "DT_FILTER(0x7fffffff)");
        // Android range values are already 8 hex digits; padding is a no-op, not truncation.
        assert_eq!(dt_android_rel().to_string(), "DT_ANDROID_REL(0x6000000f)");
    }

    #[test]
    fn new_panics_on_negative_value() {
        // Mirrors `ElfDynamicType(int, ...)` throwing `IllegalArgumentException` for value < 0
        // (ElfDynamicType.java:276-279).
        let result = std::panic::catch_unwind(|| ElfDynamicType::new(-1, "DT_BOGUS", "", ElfDynamicValueType::Value));
        assert!(result.is_err());
    }

    #[test]
    fn add_dynamic_type_rejects_value_conflict() {
        let mut map = HashMap::new();
        add_dynamic_type(dt_null(), &mut map).unwrap();
        let err = add_dynamic_type(
            ElfDynamicType::new(0, "DT_SOMETHING_ELSE", "", ElfDynamicValueType::Value),
            &mut map,
        )
        .unwrap_err();
        assert!(err.to_string().contains("DT_NULL"));
        assert!(err.to_string().contains("DT_SOMETHING_ELSE"));
        // The conflicting insert must not have happened.
        assert_eq!(map.get(&0).unwrap().name, "DT_NULL");
    }

    #[test]
    fn add_dynamic_type_rejects_case_insensitive_name_conflict() {
        // ElfDynamicType.java:260-265 compares names with `equalsIgnoreCase`, so a name that
        // differs only in case from an already-registered type is still rejected even though its
        // *value* is unique.
        let mut map = HashMap::new();
        add_dynamic_type(dt_null(), &mut map).unwrap();
        let err =
            add_dynamic_type(ElfDynamicType::new(99, "dt_null", "", ElfDynamicValueType::Value), &mut map)
                .unwrap_err();
        assert!(err.to_string().contains("name=dt_null"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn add_default_types_populates_well_known_entries() {
        let mut map = HashMap::new();
        add_default_types(&mut map);
        assert_eq!(map.get(&6).unwrap().name, "DT_SYMTAB");
        assert_eq!(map.get(&0x7fffffff).unwrap().name, "DT_FILTER");
        assert_eq!(map.get(&0x6000000F).unwrap().name, "DT_ANDROID_REL");
    }

    #[test]
    fn add_default_types_overwrites_without_erroring() {
        // Map.putAll semantics: unlike add_dynamic_type, a pre-existing conflicting entry is
        // silently replaced rather than rejected.
        let mut map = HashMap::new();
        add_dynamic_type(ElfDynamicType::new(0, "CUSTOM", "custom", ElfDynamicValueType::Value), &mut map)
            .unwrap();
        add_default_types(&mut map);
        assert_eq!(map.get(&0).unwrap().name, "DT_NULL");
    }

    #[test]
    fn default_types_registry_has_no_internal_conflicts() {
        // Exercises `build_default_types`/`DEFAULT_TYPES` in full: if two of the ~50 well-known
        // entries ever collided on value or case-insensitive name, this would already have
        // panicked during `Lazy` initialization. Forcing the lazy here (rather than relying on an
        // earlier test to have done so) keeps this test meaningful in isolation.
        assert!(DEFAULT_TYPES.len() > 50);
    }

    #[test]
    fn seam_trait_bridge_exposes_value_and_name() {
        let boxed: Box<dyn crate::format::seam_stubs::ElfDynamicType> = Box::new(dt_hash());
        assert_eq!(boxed.value(), 4);
        assert_eq!(boxed.name(), "DT_HASH");
    }

    #[test]
    fn df_flag_bits_are_disjoint() {
        assert_eq!(DF_ORIGIN & DF_SYMBOLIC, 0);
        assert_eq!(DF_TEXTREL & DF_BIND_NOW, 0);
    }
}
