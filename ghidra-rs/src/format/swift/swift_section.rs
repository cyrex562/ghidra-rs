/// A Swift binary section, which can have different names depending on the platform.
///
/// Each variant carries the set of names by which that section is known across
/// macOS/MachO, Linux/ELF, and Windows/COFF object formats.
///
/// See <https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/Swift.def>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwiftSection {
    BlockFieldmd,
    BlockAssocty,
    BlockBuiltin,
    BlockCapture,
    BlockTyperef,
    BlockReflstr,
    BlockConform,
    BlockProtocs,
    BlockAcfuncs,
    BlockMpenum,
    BlockTypes,
    BlockEntry,
    BlockSwiftast,
}

impl SwiftSection {
    /// Returns the platform-specific names for this section.
    pub fn section_names(self) -> &'static [&'static str] {
        match self {
            Self::BlockFieldmd  => &["__swift5_fieldmd", "swift5_fieldmd", ".sw5flmd"],
            Self::BlockAssocty  => &["__swift5_assocty", "swift5_assocty", ".sw5asty"],
            Self::BlockBuiltin  => &["__swift5_builtin", "swift5_builtin", ".sw5bltn"],
            Self::BlockCapture  => &["__swift5_capture", "swift5_capture", ".sw5cptr"],
            Self::BlockTyperef  => &["__swift5_typeref", "swift5_typeref", ".sw5tyrf"],
            Self::BlockReflstr  => &["__swift5_reflstr", "swift5_reflstr", ".sw5rfst"],
            Self::BlockConform  => &["__swift5_proto", "swift5_protocol_conformances", ".sw5prtc"],
            Self::BlockProtocs  => &["__swift5_protos", "swift5_protocols", ".sw5prt"],
            Self::BlockAcfuncs  => &["__swift5_acfuncs", "swift5_accessible_functions", ".sw5acfn"],
            Self::BlockMpenum   => &["__swift5_mpenum", "swift5_mpenum", ".sw5mpen"],
            Self::BlockTypes    => &["__swift5_types", "__swift5_types2", "swift5_type_metadata", ".sw5tymd"],
            Self::BlockEntry    => &["__swift5_entry", "swift5_entry", ".sw5entr"],
            Self::BlockSwiftast => &["__swift_ast", ".swift_ast", "swiftast"],
        }
    }

    /// Returns all known `SwiftSection` variants.
    pub fn all() -> &'static [SwiftSection] {
        &[
            Self::BlockFieldmd,
            Self::BlockAssocty,
            Self::BlockBuiltin,
            Self::BlockCapture,
            Self::BlockTyperef,
            Self::BlockReflstr,
            Self::BlockConform,
            Self::BlockProtocs,
            Self::BlockAcfuncs,
            Self::BlockMpenum,
            Self::BlockTypes,
            Self::BlockEntry,
            Self::BlockSwiftast,
        ]
    }

    /// Returns the `SwiftSection` whose name list contains `name`, or `None`.
    pub fn from_name(name: &str) -> Option<SwiftSection> {
        Self::all().iter().copied().find(|s| s.section_names().contains(&name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_fieldmd_names() {
        assert_eq!(
            SwiftSection::BlockFieldmd.section_names(),
            &["__swift5_fieldmd", "swift5_fieldmd", ".sw5flmd"]
        );
    }

    #[test]
    fn block_types_has_four_names() {
        let names = SwiftSection::BlockTypes.section_names();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&"__swift5_types"));
        assert!(names.contains(&"__swift5_types2"));
        assert!(names.contains(&"swift5_type_metadata"));
        assert!(names.contains(&".sw5tymd"));
    }

    #[test]
    fn all_variants_covered() {
        assert_eq!(SwiftSection::all().len(), 13);
    }

    #[test]
    fn from_name_finds_macho_name() {
        assert_eq!(SwiftSection::from_name("__swift5_proto"), Some(SwiftSection::BlockConform));
    }

    #[test]
    fn from_name_finds_elf_name() {
        assert_eq!(SwiftSection::from_name("swift5_protocols"), Some(SwiftSection::BlockProtocs));
    }

    #[test]
    fn from_name_finds_coff_name() {
        assert_eq!(SwiftSection::from_name(".sw5acfn"), Some(SwiftSection::BlockAcfuncs));
    }

    #[test]
    fn from_name_returns_none_for_unknown() {
        assert_eq!(SwiftSection::from_name("__no_such_section"), None);
    }

    #[test]
    fn from_name_swiftast_variants() {
        assert_eq!(SwiftSection::from_name("__swift_ast"), Some(SwiftSection::BlockSwiftast));
        assert_eq!(SwiftSection::from_name(".swift_ast"), Some(SwiftSection::BlockSwiftast));
        assert_eq!(SwiftSection::from_name("swiftast"), Some(SwiftSection::BlockSwiftast));
    }

    #[test]
    fn section_names_are_nonempty() {
        for section in SwiftSection::all() {
            assert!(!section.section_names().is_empty(), "{section:?} has no names");
        }
    }

    #[test]
    fn all_names_unique_across_variants() {
        let mut seen = std::collections::HashSet::new();
        for section in SwiftSection::all() {
            for name in section.section_names() {
                assert!(seen.insert(*name), "duplicate section name: {name}");
            }
        }
    }
}
