//! Port of `ghidra.app.util.bin.format.dwarf.DWARFAbbreviation`.
//!
//! This struct represents the 'schema' for a DWARF DIE record. A raw DWARF DIE record specifies
//! its abbreviation code (pointing to an instance of this type), and the corresponding
//! `DWARFAbbreviation` instance has the information about how the raw DIE is laid out.
//!
//! # Departures from the Java class
//!
//! * `DIEContainer` isn't ported yet (it sits on the far side of the `DebugInfoEntry` /
//!   `DWARFCompilationUnit` / `DWARFAbbreviation` cycle), so [`DWARFAbbreviation::read`] and
//!   [`DWARFAbbreviation::read_abbreviations`] take a
//!   [`&dyn DIEContainer`](crate::format::seam_stubs::DIEContainer) from
//!   [`crate::format::seam_stubs`] to keep the parameter list. Java's own methods never actually
//!   use the parameter either -- it is threaded through for signature parity only.
//! * `DWARFTag` isn't ported yet either (same cycle); `tag` is resolved through the stub's
//!   `DWARFTag::of` the same way the Java constructor resolves it via `DWARFTag.of(tagId)`, and
//!   `get_tag_name` renders through the stub's `DWARFTag::name`.

use std::collections::HashMap;
use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_attribute_id::{AttrDef, DWARFAttributeId};
use crate::format::dwarf::dwarf_children::DWARFChildren;
use crate::format::seam_stubs::{DIEContainer, DWARFTag};
use crate::util::msg::Msg;

const EOL: i32 = 0;

/// This struct represents the 'schema' for a DWARF DIE record.
///
/// A raw DWARF DIE record specifies its abbreviation code (pointing to an instance of this
/// struct) and the corresponding `DWARFAbbreviation` instance has the information about how the
/// raw DIE is laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFAbbreviation {
    abbreviation_code: i32,
    tag: DWARFTag,
    tag_id: i32,
    has_children: bool,
    attributes: Vec<AttrDef>,
}

impl DWARFAbbreviation {
    /// Mirrors the public `DWARFAbbreviation(int, int, boolean, AttrDef[])` constructor.
    pub fn new(
        abbreviation_code: i32,
        tag_id: i32,
        has_children: bool,
        attributes: Vec<AttrDef>,
    ) -> Self {
        DWARFAbbreviation {
            abbreviation_code,
            tag: DWARFTag::of(tag_id),
            tag_id,
            has_children,
            attributes,
        }
    }

    /// Reads a [`DWARFAbbreviation`] from `reader`. Returns `Ok(None)` if the stream was at an
    /// end-of-list marker. Mirrors the static `DWARFAbbreviation.read(BinaryReader,
    /// DIEContainer)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        die_container: &dyn DIEContainer,
    ) -> io::Result<Option<DWARFAbbreviation>> {
        let _ = die_container;

        let ac = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
        if ac == EOL {
            return Ok(None);
        }
        let tag_id = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
        let has_children = reader.read_next_byte()?;

        // Read each attribute specification until EOL marker value
        let mut tmp_attr_specs = Vec::new();
        while let Some(attr_spec) = AttrDef::read(reader)? {
            warn_if_mismatched_forms(&attr_spec);
            tmp_attr_specs.push(attr_spec);
        }

        Ok(Some(DWARFAbbreviation::new(
            ac,
            tag_id,
            has_children as u32 == DWARFChildren::Yes.value(),
            tmp_attr_specs,
        )))
    }

    /// Reads a list of [`DWARFAbbreviation`]s, stopping when the end-of-list marker is
    /// encountered. Mirrors the static `DWARFAbbreviation.readAbbreviations(BinaryReader,
    /// DIEContainer)`.
    pub fn read_abbreviations(
        reader: &mut dyn BinaryReader,
        die_container: &dyn DIEContainer,
    ) -> io::Result<HashMap<i32, DWARFAbbreviation>> {
        let mut result = HashMap::new();
        while let Some(abbrev) = DWARFAbbreviation::read(reader, die_container)? {
            result.insert(abbrev.get_abbreviation_code(), abbrev);
        }
        Ok(result)
    }

    /// Get the abbreviation code. Mirrors `DWARFAbbreviation.getAbbreviationCode()`.
    pub fn get_abbreviation_code(&self) -> i32 {
        self.abbreviation_code
    }

    /// Get the tag value. Mirrors `DWARFAbbreviation.getTag()`.
    pub fn get_tag(&self) -> DWARFTag {
        self.tag
    }

    /// Mirrors `DWARFAbbreviation.getTagName()`.
    pub fn get_tag_name(&self) -> String {
        self.tag.name(self.tag_id)
    }

    /// Checks to see if this abbreviation has any DIE children. Mirrors
    /// `DWARFAbbreviation.hasChildren()`.
    pub fn has_children(&self) -> bool {
        self.has_children
    }

    /// Return a live list of the attributes. Mirrors `DWARFAbbreviation.getAttributes()`.
    pub fn get_attributes(&self) -> &[AttrDef] {
        &self.attributes
    }

    /// Return number of attribute values. Mirrors `DWARFAbbreviation.getAttributeCount()`.
    pub fn get_attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Get the attribute at the given index. Mirrors `DWARFAbbreviation.getAttributeAt(int)`,
    /// which throws `ArrayIndexOutOfBoundsException` for an out-of-range index; this returns
    /// [`None`] instead.
    pub fn get_attribute_at(&self, index: usize) -> Option<AttrDef> {
        self.attributes.get(index).copied()
    }

    /// Get the attribute with the given attribute key. Mirrors
    /// `DWARFAbbreviation.findAttribute(DWARFAttributeId)`.
    pub fn find_attribute(&self, attribute_id: DWARFAttributeId) -> Option<AttrDef> {
        self.attributes.iter().find(|spec| spec.get_attribute_id() == Some(attribute_id)).copied()
    }
}

impl fmt::Display for DWARFAbbreviation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}:{}", self.abbreviation_code, self.get_tag_name())
    }
}

/// Mirrors the private static `DWARFAbbreviation.warnIfMismatchedForms(DWARFAttributeId.AttrDef)`.
fn warn_if_mismatched_forms(attr_spec: &AttrDef) {
    let form_classes = attr_spec.get_attribute_form().get_form_classes();
    let Some(attr_id) = attr_spec.get_attribute_id() else {
        return;
    };
    let id_classes = attr_id.get_attribute_class();
    if form_classes.is_empty() || id_classes.is_empty() {
        return;
    }
    let intersects = form_classes.iter().any(|class| id_classes.contains(class));
    if !intersects {
        Msg::warn(
            "DWARFAbbreviation",
            &format!("Mismatched DWARF Attribute and Form: {:?}", attr_spec),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(length).unwrap_or(usize::MAX);
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0 }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
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
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index })
        }
    }

    struct MockDIEContainer;
    impl DIEContainer for MockDIEContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }
    }

    const DW_TAG_SUBPROGRAM: i32 = 0x2e;

    #[test]
    fn read_returns_none_at_eol_marker() {
        let mut reader = TestReader::new(vec![0x00]);
        let container = MockDIEContainer;
        assert_eq!(DWARFAbbreviation::read(&mut reader, &container).unwrap(), None);
    }

    #[test]
    fn read_decodes_a_simple_abbreviation() {
        // Abbrev code 1, tag DW_TAG_subprogram (0x2e), has_children=1 (DW_CHILDREN_yes),
        // DW_AT_name (0x3) / DW_FORM_string (0x8), then the attrspec EOL marker (0x0, 0x0).
        let mut reader =
            TestReader::new(vec![0x01, 0x2e, 0x01, 0x03, 0x08, 0x00, 0x00]);
        let container = MockDIEContainer;
        let abbrev = DWARFAbbreviation::read(&mut reader, &container).unwrap().unwrap();

        assert_eq!(abbrev.get_abbreviation_code(), 1);
        assert_eq!(abbrev.get_tag().get_id(), DW_TAG_SUBPROGRAM);
        assert!(abbrev.has_children());
        assert_eq!(abbrev.get_attribute_count(), 1);
        assert_eq!(
            abbrev.get_attribute_at(0).unwrap().get_attribute_id(),
            Some(DWARFAttributeId::DwAtName)
        );
        assert_eq!(reader.get_pointer_index(), 7);
    }

    #[test]
    fn read_abbreviations_collects_until_the_list_terminator() {
        // Two abbreviations (codes 1 and 2, both DW_TAG_subprogram/no children/no attrs), then
        // the list-terminating EOL marker (an abbrev code of 0).
        let mut reader =
            TestReader::new(vec![0x01, 0x2e, 0x00, 0x00, 0x00, 0x02, 0x2e, 0x00, 0x00, 0x00, 0x00]);
        let container = MockDIEContainer;
        let map = DWARFAbbreviation::read_abbreviations(&mut reader, &container).unwrap();

        assert_eq!(map.len(), 2);
        assert!(!map[&1].has_children());
        assert!(!map[&2].has_children());
    }

    #[test]
    fn find_attribute_locates_by_id_and_reports_missing() {
        let abbrev = DWARFAbbreviation::new(
            1,
            DW_TAG_SUBPROGRAM,
            false,
            vec![AttrDef::new(Some(DWARFAttributeId::DwAtName), 0x3, DWARFForm::DwFormString, 0)],
        );

        assert!(abbrev.find_attribute(DWARFAttributeId::DwAtName).is_some());
        assert!(abbrev.find_attribute(DWARFAttributeId::DwAtByteSize).is_none());
    }

    #[test]
    fn display_matches_java_formatted_string() {
        let abbrev = DWARFAbbreviation::new(0x1a, DW_TAG_SUBPROGRAM, false, Vec::new());
        // Java: "%x:%s".formatted(abbreviationCode, getTagName()); the DWARFTag stub renders an
        // unresolved tag name via its `name(int)` fallback format.
        assert_eq!(abbrev.to_string(), format!("1a:{}", abbrev.get_tag_name()));
    }
}
