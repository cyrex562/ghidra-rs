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
    use crate::filesystem::ghidra::g_binary_reader::GByteStore;
    use crate::format::dwarf::r#macro::dwarf_macro_header::DWARFMacroHeader;
    use crate::format::dwarf::r#macro::dwarf_macro_opcode::DWARFMacroOpcode;
    use crate::format::seam_stubs::DWARFCompilationUnit;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl crate::app::util::bin::binary_reader::BinaryReader for TestReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(
            &self,
            new_index: u64,
        ) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

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
        let mut reader = TestReader::new(vec![0x04]);
        let header = test_header();

        let entry = DWARFMacroInfoEntryBase::read(&mut reader, header)
            .unwrap()
            .expect("DW_MACRO_end_file is not the unit terminator");

        assert_eq!(entry.base().opcode, Some(DWARFMacroOpcode::DwMacroEndFile));
        assert_eq!(DWARFMacroInfoEntry::to_string(entry.as_ref()), "endfile");
    }
}
