//! Port of `ghidra.app.util.bin.format.elf.ElfProgramHeaderType`.
//!
//! An extensible name+value+description registry for ELF program header (`p_type`) values --
//! the [`ElfSectionHeaderType`](super::elf_section_header_type::ElfSectionHeaderType) sibling for
//! segments instead of sections. See [`elf_dynamic_type`](super::elf_dynamic_type)'s module docs
//! for the shared shape rationale (plain value type, no shared singleton, seam-trait bridge);
//! this module repeats the same choices for `p_type`.

use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::format::elf::elf_program_header_constants::{
    PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE, PT_NULL,
    PT_PHDR, PT_SHLIB, PT_TLS,
};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;
use crate::util::exception::DuplicateNameException;

/// A single ELF program header (segment) type: `PT_NULL`, `PT_LOAD`, etc.
///
/// Port of `ghidra.app.util.bin.format.elf.ElfProgramHeaderType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfProgramHeaderType {
    /// `ElfProgramHeaderType.value` -- the `p_type` value this type represents. Always
    /// non-negative; see [`ElfProgramHeaderType::new`].
    pub value: i32,
    /// `ElfProgramHeaderType.name` -- the type's symbolic name, e.g. `"PT_LOAD"`.
    pub name: String,
    /// `ElfProgramHeaderType.description` -- a short human-readable description.
    pub description: String,
}

impl ElfProgramHeaderType {
    /// `new ElfProgramHeaderType(int, String, String)`.
    ///
    /// # Panics
    /// Panics (standing in for Java's `IllegalArgumentException`) if `value` is negative.
    pub fn new(value: i32, name: impl Into<String>, description: impl Into<String>) -> Self {
        if value < 0 {
            panic!("ElfProgramHeaderType value out of range: 0x{:x}", value as u32);
        }
        ElfProgramHeaderType { value, name: name.into(), description: description.into() }
    }
}

impl std::fmt::Display for ElfProgramHeaderType {
    /// `ElfProgramHeaderType.toString()`: `NAME(0xHHHHHHHH)`, zero-padded to 8 hex digits.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value as u32)
    }
}

/// Bridges the real [`ElfProgramHeaderType`] into the pre-existing (empty marker)
/// [`crate::format::seam_stubs::ElfProgramHeaderType`] placeholder trait, so a value constructed
/// here can be used anywhere that trait is without any change to the not-yet-migrated call sites
/// that depend on it.
impl crate::format::seam_stubs::ElfProgramHeaderType for ElfProgramHeaderType {}

/// `ElfProgramHeaderType.addProgramHeaderType(ElfProgramHeaderType, Map<Integer,
/// ElfProgramHeaderType>)`.
///
/// Registers `ty` into `program_header_type_map`, keyed by its `value`. Fails if
/// `program_header_type_map` already has an entry with the same `value` *or* an entry whose
/// `name` matches case-insensitively -- both checks are real Java behavior
/// (`ElfProgramHeaderType.java:81-93`).
///
/// # Errors
/// Returns [`DuplicateNameException`] on either conflict, without modifying
/// `program_header_type_map`.
pub fn add_program_header_type(
    ty: ElfProgramHeaderType,
    program_header_type_map: &mut HashMap<i32, ElfProgramHeaderType>,
) -> Result<(), DuplicateNameException> {
    if let Some(conflict) = program_header_type_map.get(&ty.value) {
        return Err(DuplicateNameException::with_message(format!(
            "ElfProgramHeaderType conflict during initialization ({} / {}), value=0x{:x}",
            ty.name, conflict.name, ty.value
        )));
    }
    for existing in program_header_type_map.values() {
        if ty.name.eq_ignore_ascii_case(&existing.name) {
            return Err(DuplicateNameException::with_message(format!(
                "ElfProgramHeaderType conflict during initialization, name={}",
                ty.name
            )));
        }
    }
    program_header_type_map.insert(ty.value, ty);
    Ok(())
}

/// `ElfProgramHeaderType.addDefaultTypes(Map<Integer, ElfProgramHeaderType>)` -- merges every
/// well-known default type into `program_header_type_map`. Unlike [`add_program_header_type`]
/// this never fails: Java's `Map.putAll` silently overwrites any pre-existing entry with the
/// same key.
pub fn add_default_types(program_header_type_map: &mut HashMap<i32, ElfProgramHeaderType>) {
    for ty in DEFAULT_TYPES.values() {
        program_header_type_map.insert(ty.value, ty.clone());
    }
}

/// `ElfProgramHeaderType.getEnumDataType(boolean, String, Map<Integer, ElfProgramHeaderType>)`.
///
/// Builds an `EnumDataType` named `"Elf32_PHType"`/`"Elf64_PHType"` (plus `type_suffix`, if any)
/// with one entry per `(name, value)` pair in `program_header_type_map`.
pub fn get_enum_data_type(
    is32_bit: bool,
    type_suffix: Option<&str>,
    program_header_type_map: &HashMap<i32, ElfProgramHeaderType>,
) -> EnumDataType {
    let size = if is32_bit { 4 } else { 8 };
    let mut name = if is32_bit { "Elf32_PHType" } else { "Elf64_PHType" }.to_string();
    if let Some(suffix) = type_suffix {
        name.push_str(suffix);
    }
    let category = CategoryPath::parse("/ELF").expect("\"/ELF\" is a valid category path");
    let mut ph_type_enum = EnumDataType::new_in_category(category, name, size);
    for ty in program_header_type_map.values() {
        ph_type_enum.add(&ty.name, ty.value as i64);
    }
    ph_type_enum
}

/// Declares one free function per well-known `ElfProgramHeaderType` (mirroring a Java `public
/// static final ElfProgramHeaderType PT_*` field) plus the `build_default_types` helper that
/// registers every one of them, in declaration order, into a fresh map.
macro_rules! default_program_header_types {
    ($($fn_name:ident => ($value:expr, $name:expr, $desc:expr)),+ $(,)?) => {
        $(
            #[doc = concat!("`ElfProgramHeaderType.", $name, "`: ", $desc, ".")]
            pub fn $fn_name() -> ElfProgramHeaderType {
                ElfProgramHeaderType::new($value, $name, $desc)
            }
        )+

        fn build_default_types() -> HashMap<i32, ElfProgramHeaderType> {
            let mut map = HashMap::new();
            $(
                add_program_header_type($fn_name(), &mut map).unwrap_or_else(|e| {
                    panic!("ElfProgramHeaderType initialization error: {e}")
                });
            )+
            map
        }
    };
}

default_program_header_types! {
    pt_null => (PT_NULL as i32, "PT_NULL", "Unused/Undefined segment"),
    pt_load => (PT_LOAD as i32, "PT_LOAD", "Loadable segment"),
    pt_dynamic => (PT_DYNAMIC as i32, "PT_DYNAMIC", "Dynamic linking information"),
    pt_interp => (PT_INTERP as i32, "PT_INTERP", "Interpreter path name"),
    pt_note => (PT_NOTE as i32, "PT_NOTE", "Auxiliary information location"),
    pt_shlib => (PT_SHLIB as i32, "PT_SHLIB", ""),
    pt_phdr => (PT_PHDR as i32, "PT_PHDR", "Program header table"),
    pt_tls => (PT_TLS as i32, "PT_TLS", "Thread-Local Storage template"),
    // OS-specific range: 0x60000000 - 0x6fffffff
    pt_gnu_eh_frame => (PT_GNU_EH_FRAME as i32, "PT_GNU_EH_FRAME", "GCC .eh_frame_hdr segment"),
    pt_gnu_stack => (PT_GNU_STACK as i32, "PT_GNU_STACK", "Indicates stack executability"),
    pt_gnu_relro => (PT_GNU_RELRO as i32, "PT_GNU_RELRO", "Specifies segments which may be read-only post-relocation"),
}

static DEFAULT_TYPES: Lazy<HashMap<i32, ElfProgramHeaderType>> = Lazy::new(build_default_types);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    #[test]
    fn well_known_type_has_expected_fields() {
        let t = pt_load();
        assert_eq!(t.value, 1);
        assert_eq!(t.name, "PT_LOAD");
        assert_eq!(t.description, "Loadable segment");
    }

    #[test]
    fn display_matches_java_tostring_zero_padded_hex() {
        assert_eq!(pt_null().to_string(), "PT_NULL(0x00000000)");
        assert_eq!(pt_load().to_string(), "PT_LOAD(0x00000001)");
        assert_eq!(pt_gnu_eh_frame().to_string(), "PT_GNU_EH_FRAME(0x6474e550)");
    }

    #[test]
    fn new_panics_on_negative_value() {
        // Mirrors `ElfProgramHeaderType(int, ...)` throwing `IllegalArgumentException` for
        // value < 0 (ElfProgramHeaderType.java:102-105).
        let result = std::panic::catch_unwind(|| ElfProgramHeaderType::new(-1, "PT_BOGUS", ""));
        assert!(result.is_err());
    }

    #[test]
    fn add_program_header_type_rejects_value_conflict() {
        let mut map = HashMap::new();
        add_program_header_type(pt_load(), &mut map).unwrap();
        let err =
            add_program_header_type(ElfProgramHeaderType::new(1, "PT_SOMETHING_ELSE", ""), &mut map)
                .unwrap_err();
        assert!(err.to_string().contains("PT_LOAD"));
        assert!(err.to_string().contains("PT_SOMETHING_ELSE"));
        assert_eq!(map.get(&1).unwrap().name, "PT_LOAD");
    }

    #[test]
    fn add_program_header_type_rejects_case_insensitive_name_conflict() {
        let mut map = HashMap::new();
        add_program_header_type(pt_load(), &mut map).unwrap();
        let err = add_program_header_type(ElfProgramHeaderType::new(99, "pt_load", ""), &mut map)
            .unwrap_err();
        assert!(err.to_string().contains("name=pt_load"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn add_default_types_populates_well_known_entries() {
        let mut map = HashMap::new();
        add_default_types(&mut map);
        assert_eq!(map.get(&0).unwrap().name, "PT_NULL");
        assert_eq!(map.get(&(PT_GNU_RELRO as i32)).unwrap().name, "PT_GNU_RELRO");
        assert_eq!(map.len(), 11);
    }

    #[test]
    fn get_enum_data_type_uses_expected_name_and_entries() {
        let mut map = HashMap::new();
        add_default_types(&mut map);

        let enum_32 = get_enum_data_type(true, None, &map);
        assert_eq!(enum_32.get_name(), "Elf32_PHType");
        assert_eq!(enum_32.get_length(), 4);
        assert_eq!(enum_32.get_value_for_name("PT_LOAD"), Some(1));

        let enum_64_suffixed = get_enum_data_type(false, Some("_MyExt"), &map);
        assert_eq!(enum_64_suffixed.get_name(), "Elf64_PHType_MyExt");
        assert_eq!(enum_64_suffixed.get_length(), 8);
    }

    #[test]
    fn seam_trait_marker_is_implemented() {
        let _: Box<dyn crate::format::seam_stubs::ElfProgramHeaderType> = Box::new(pt_load());
    }
}
