//! Port of `ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroEndFile`.

use crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::{
    DWARFMacroInfoEntry, DWARFMacroInfoEntryBase,
};

/// Represents the end of an included source file.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroEndFile`, which `extends
/// DWARFMacroInfoEntry` with a copy constructor and an overridden `toString()` that simply
/// returns `super.toString()` verbatim (a no-op override). This port instead composes a
/// `base: DWARFMacroInfoEntryBase` field (this crate's "composition over inheritance"
/// convention) and relies on [`DWARFMacroInfoEntry::to_string`]'s own default implementation,
/// which already does exactly what the Java override does -- so no override is written here
/// either.
pub struct DWARFMacroEndFile {
    base: DWARFMacroInfoEntryBase,
}

impl DWARFMacroEndFile {
    /// Mirrors `DWARFMacroEndFile(DWARFMacroInfoEntry other)`.
    pub fn new(other: DWARFMacroInfoEntryBase) -> Self {
        DWARFMacroEndFile { base: other }
    }
}

impl DWARFMacroInfoEntry for DWARFMacroEndFile {
    fn base(&self) -> &DWARFMacroInfoEntryBase {
        &self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::dwarf::r#macro::dwarf_macro_header::DWARFMacroHeader;
    use crate::format::dwarf::r#macro::dwarf_macro_opcode::DWARFMacroOpcode;
    use crate::format::seam_stubs::DWARFCompilationUnit;
    use std::sync::Arc;

    struct MockCu;
    impl DWARFCompilationUnit for MockCu {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
    }

    fn test_header() -> Arc<DWARFMacroHeader> {
        Arc::new(DWARFMacroHeader::new(
            0, // start_offset
            5, // version
            0, // flags
            0, // debug_line_offset
            4, // int_size
            1, // entries_start_offset
            Some(Arc::new(MockCu) as Arc<dyn DWARFCompilationUnit>),
            None, // line
            DWARFMacroOpcode::default_opcode_operand_map(),
        ))
    }

    #[test]
    fn wraps_generic_entry_and_exposes_its_base() {
        let header = test_header();
        let generic = DWARFMacroInfoEntryBase::new(DWARFMacroOpcode::DwMacroEndFile, header);

        let end_file = DWARFMacroEndFile::new(generic);

        assert_eq!(end_file.base().opcode, Some(DWARFMacroOpcode::DwMacroEndFile));
        assert!(end_file.base().operand_values.is_empty());
    }

    #[test]
    fn to_string_matches_the_inherited_base_display_with_no_operands() {
        // Java's override is a no-op (`return super.toString();`); this proves the Rust port,
        // which relies on the trait's default rather than writing a redundant override, produces
        // the exact same string as calling `to_display_string()` on the base directly.
        let header = test_header();
        let generic = DWARFMacroInfoEntryBase::new(DWARFMacroOpcode::DwMacroEndFile, header);
        let expected = generic.to_display_string();

        let end_file = DWARFMacroEndFile::new(generic);
        assert_eq!(DWARFMacroInfoEntry::to_string(&end_file), expected);
        assert_eq!(DWARFMacroInfoEntry::to_string(&end_file), "endfile");
    }

    #[test]
    fn read_from_reader_produces_a_specialized_end_file_entry() {
        // DW_MACRO_end_file (0x4) has no operands, so the entry is just its one opcode byte.
        let mut reader = BinaryReader::from_bytes(vec![0x04], true);
        let header = test_header();

        let entry = DWARFMacroInfoEntryBase::read(&mut reader, header)
            .unwrap()
            .expect("DW_MACRO_end_file is not the unit terminator");

        assert_eq!(entry.base().opcode, Some(DWARFMacroOpcode::DwMacroEndFile));
        assert_eq!(DWARFMacroInfoEntry::to_string(entry.as_ref()), "endfile");
    }
}
