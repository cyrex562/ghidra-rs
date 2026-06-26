/// Common DWARF section identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DWARFSectionId {
    DebugInfo,
    DebugTypes,
    DebugAbbrev,
    DebugArranges,
    DebugLine,
    /// DWARF v5+
    DebugLineStr,
    DebugFrame,
    DebugLoc,
    /// DWARF v5+
    DebugLoclists,
    DebugStr,
    /// DWARF v5+
    DebugStrOffsets,
    DebugRanges,
    /// DWARF v5+
    DebugRnglists,
    DebugPubnames,
    DebugPubtypes,
    DebugMacinfo,
    /// DWARF v5+
    DebugMacro,
    DebugAddr,
}

/// The minimum set of section names required for a valid DWARF binary.
pub const MINIMAL_DWARF_SECTIONS: [&str; 2] = [
    DWARFSectionId::DebugInfo.section_name(),
    DWARFSectionId::DebugAbbrev.section_name(),
];

impl DWARFSectionId {
    /// Returns the ELF section name string for this DWARF section.
    pub const fn section_name(self) -> &'static str {
        match self {
            Self::DebugInfo => "debug_info",
            Self::DebugTypes => "debug_types",
            Self::DebugAbbrev => "debug_abbrev",
            Self::DebugArranges => "debug_arranges",
            Self::DebugLine => "debug_line",
            Self::DebugLineStr => "debug_line_str",
            Self::DebugFrame => "debug_frame",
            Self::DebugLoc => "debug_loc",
            Self::DebugLoclists => "debug_loclists",
            Self::DebugStr => "debug_str",
            Self::DebugStrOffsets => "debug_str_offsets",
            Self::DebugRanges => "debug_ranges",
            Self::DebugRnglists => "debug_rnglists",
            Self::DebugPubnames => "debug_pubnames",
            Self::DebugPubtypes => "debug_pubtypes",
            Self::DebugMacinfo => "debug_macinfo",
            Self::DebugMacro => "debug_macro",
            Self::DebugAddr => "debug_addr",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_names_match_java_source() {
        assert_eq!(DWARFSectionId::DebugInfo.section_name(), "debug_info");
        assert_eq!(DWARFSectionId::DebugTypes.section_name(), "debug_types");
        assert_eq!(DWARFSectionId::DebugAbbrev.section_name(), "debug_abbrev");
        assert_eq!(DWARFSectionId::DebugArranges.section_name(), "debug_arranges");
        assert_eq!(DWARFSectionId::DebugLine.section_name(), "debug_line");
        assert_eq!(DWARFSectionId::DebugLineStr.section_name(), "debug_line_str");
        assert_eq!(DWARFSectionId::DebugFrame.section_name(), "debug_frame");
        assert_eq!(DWARFSectionId::DebugLoc.section_name(), "debug_loc");
        assert_eq!(DWARFSectionId::DebugLoclists.section_name(), "debug_loclists");
        assert_eq!(DWARFSectionId::DebugStr.section_name(), "debug_str");
        assert_eq!(DWARFSectionId::DebugStrOffsets.section_name(), "debug_str_offsets");
        assert_eq!(DWARFSectionId::DebugRanges.section_name(), "debug_ranges");
        assert_eq!(DWARFSectionId::DebugRnglists.section_name(), "debug_rnglists");
        assert_eq!(DWARFSectionId::DebugPubnames.section_name(), "debug_pubnames");
        assert_eq!(DWARFSectionId::DebugPubtypes.section_name(), "debug_pubtypes");
        assert_eq!(DWARFSectionId::DebugMacinfo.section_name(), "debug_macinfo");
        assert_eq!(DWARFSectionId::DebugMacro.section_name(), "debug_macro");
        assert_eq!(DWARFSectionId::DebugAddr.section_name(), "debug_addr");
    }

    #[test]
    fn minimal_dwarf_sections_contains_info_and_abbrev() {
        assert_eq!(MINIMAL_DWARF_SECTIONS[0], "debug_info");
        assert_eq!(MINIMAL_DWARF_SECTIONS[1], "debug_abbrev");
        assert_eq!(MINIMAL_DWARF_SECTIONS.len(), 2);
    }

    #[test]
    fn minimal_sections_match_enum_section_names() {
        assert_eq!(MINIMAL_DWARF_SECTIONS[0], DWARFSectionId::DebugInfo.section_name());
        assert_eq!(MINIMAL_DWARF_SECTIONS[1], DWARFSectionId::DebugAbbrev.section_name());
    }

    #[test]
    fn all_variants_have_distinct_section_names() {
        let all = [
            DWARFSectionId::DebugInfo,
            DWARFSectionId::DebugTypes,
            DWARFSectionId::DebugAbbrev,
            DWARFSectionId::DebugArranges,
            DWARFSectionId::DebugLine,
            DWARFSectionId::DebugLineStr,
            DWARFSectionId::DebugFrame,
            DWARFSectionId::DebugLoc,
            DWARFSectionId::DebugLoclists,
            DWARFSectionId::DebugStr,
            DWARFSectionId::DebugStrOffsets,
            DWARFSectionId::DebugRanges,
            DWARFSectionId::DebugRnglists,
            DWARFSectionId::DebugPubnames,
            DWARFSectionId::DebugPubtypes,
            DWARFSectionId::DebugMacinfo,
            DWARFSectionId::DebugMacro,
            DWARFSectionId::DebugAddr,
        ];
        let names: std::collections::HashSet<&str> = all.iter().map(|v| v.section_name()).collect();
        assert_eq!(names.len(), all.len(), "all section names must be distinct");
    }
}
