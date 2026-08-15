//! Port of `ghidra.app.util.bin.format.dwarf.DebugInfoEntry`.
//!
//! # Departures from the Java class
//!
//! * `DWARFCompilationUnit`, `DIEContainer`, `DWARFAbbreviation`, `DWARFTag` and
//!   `DWARFMissingAttributeValue` aren't ported yet, so they come from
//!   [`crate::format::seam_stubs`]. `DebugInfoEntry` sits on a dependency cycle with all of them
//!   (a container owns DIEs and every DIE reaches back through its compilation unit to that
//!   container), which the stubs break. The compilation unit and abbreviation are shared by many
//!   DIEs, so they are held as [`Arc`]s where Java holds plain references.
//! * Java lazily caches each deserialized attribute value in a mutable `DWARFAttributeValue[]`
//!   read through a non-mutating getter. Here each slot is a [`OnceLock`], which gives the same
//!   read-through-`&self` caching. One consequence: where Java returns a fresh
//!   `DWARFMissingAttributeValue` on every failed read (and retries the read next time), this
//!   caches the failure marker in the slot.
//! * Java's null-valued fields become [`Option`]s (`abbreviation`) and its null returns become
//!   `None` (`get_tag`, `get_parent`, `find_attribute`). Java methods that would raise
//!   `NullPointerException` on a terminator DIE, or when a stubbed collaborator is absent, return
//!   an empty/`None`/zero result instead: `get_attribute_count` (0), `get_children` (empty),
//!   `get_attribute`/`get_attribute_def` (`None`), `get_depth` (-1).
//! * `equals`/`hashCode` hash the compilation unit, which doesn't override Java's identity
//!   `equals`; [`PartialEq`] and [`Hash`] here compare/hash the `Arc`'s address to match.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{Arc, OnceLock};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_attribute::DWARFAttribute;
use crate::format::dwarf::attribs::dwarf_attribute_id::{AttrDef, DWARFAttributeId};
use crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue;
use crate::format::dwarf::attribs::dwarf_form_context::DWARFFormContext;
use crate::format::seam_stubs::{
    DIEContainer, DWARFAbbreviation, DWARFCompilationUnit, DWARFMissingAttributeValue,
    DWARFProgram, DWARFTag,
};

/// A DWARF Debug Info Entry is a collection of
/// [attributes](crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue) in a
/// hierarchical structure (see [`Self::get_parent`], [`Self::get_children`]).
///
/// This is a lower-level type; `DIEAggregate` should be used instead in most cases when examining
/// information from the DWARF system.
pub struct DebugInfoEntry {
    compilation_unit: Arc<dyn DWARFCompilationUnit>,
    abbreviation: Option<Arc<DWARFAbbreviation>>,
    /// Lazily deserialized attribute values, one slot per entry of `attr_offsets`.
    attributes: Vec<OnceLock<Box<dyn DWARFAttributeValue>>>,
    /// Offset (from `offset`) of each attribute value.
    attr_offsets: Vec<i32>,
    offset: u64,
    die_index: i32,
}

impl DebugInfoEntry {
    /// Read a DIE record from `reader`, positioned at the start of the record. Mirrors the static
    /// `DebugInfoEntry.read(BinaryReader, DWARFCompilationUnit, int)`.
    pub fn read(
        reader: &mut dyn BinaryReader,
        cu: Arc<dyn DWARFCompilationUnit>,
        die_index: i32,
    ) -> io::Result<DebugInfoEntry> {
        let offset = reader.get_pointer_index();
        let ac = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;

        // Check for terminator DIE
        if ac == 0 {
            return Ok(DebugInfoEntry::terminator(cu, offset));
        }

        let abbreviation = cu.get_abbreviation(ac).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Abbreviation code {} not found in compunit {} at 0x{:x}",
                    ac,
                    cu.get_unit_number(),
                    cu.get_start_offset()
                ),
            )
        })?;

        let mut attr_offsets = Vec::with_capacity(abbreviation.get_attribute_count());

        // Read in all of the attribute values based on the attribute specification
        let mut current_attr_offset = (reader.get_pointer_index() - offset) as i64;
        for attribute_spec in abbreviation.get_attributes() {
            attr_offsets.push(current_attr_offset as i32);

            let mut context =
                DWARFFormContext::with_comp_unit_int_size(&mut *reader, &*cu, attribute_spec);
            let attr_size = attribute_spec.get_attribute_form().get_size(&mut context)?;
            if attr_size < 0 || attr_size > i32::MAX as i64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid attribute value size",
                ));
            }

            current_attr_offset += attr_size;

            // manually set stream position because some attributes don't read from the stream to
            // determine size
            reader.set_pointer_index(offset + current_attr_offset as u64);
        }

        Ok(DebugInfoEntry::new(cu, offset, die_index, Some(abbreviation), attr_offsets))
    }

    /// Creates a DIE. Mirrors the public `DebugInfoEntry(DWARFCompilationUnit, long, int,
    /// DWARFAbbreviation, int[])` constructor.
    pub fn new(
        cu: Arc<dyn DWARFCompilationUnit>,
        offset: u64,
        die_index: i32,
        abbreviation: Option<Arc<DWARFAbbreviation>>,
        attr_offsets: Vec<i32>,
    ) -> DebugInfoEntry {
        let attributes = attr_offsets.iter().map(|_| OnceLock::new()).collect();
        DebugInfoEntry { compilation_unit: cu, abbreviation, attributes, attr_offsets, offset, die_index }
    }

    /// Creates a terminator DIE (no abbreviation, no attributes). Mirrors the private
    /// `DebugInfoEntry(DWARFCompilationUnit, long)` constructor.
    pub fn terminator(cu: Arc<dyn DWARFCompilationUnit>, offset: u64) -> DebugInfoEntry {
        DebugInfoEntry::new(cu, offset, -1, None, Vec::new())
    }

    /// Returns the index of this DIE in the entire dwarf program. Mirrors
    /// `DebugInfoEntry.getIndex()`.
    pub fn get_index(&self) -> i32 {
        self.die_index
    }

    /// Return the child DIEs. Mirrors `DebugInfoEntry.getChildren()`.
    pub fn get_children(&self) -> Vec<&DebugInfoEntry> {
        match self.get_container() {
            Some(container) => container.get_children_of(self.die_index),
            None => Vec::new(),
        }
    }

    /// Return the children that are of a specific DWARF type. Mirrors the
    /// `DebugInfoEntry.getChildren(DWARFTag)` overload.
    pub fn get_children_with_tag(&self, child_tag: DWARFTag) -> Vec<&DebugInfoEntry> {
        self.get_children().into_iter().filter(|child| child.get_tag() == Some(child_tag)).collect()
    }

    /// Get the parent DIE of this DIE, or `None` if this DIE is the root of the compilation unit.
    /// Mirrors `DebugInfoEntry.getParent()`.
    pub fn get_parent(&self) -> Option<&DebugInfoEntry> {
        self.get_container().and_then(|container| container.get_parent_of(self.die_index))
    }

    /// Get the offset of this DIE from the beginning of the debug_info section. Mirrors
    /// `DebugInfoEntry.getOffset()`.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// Get the [`DWARFTag`] of this DIE, or `None` (Java's `null`) for a terminator DIE. Mirrors
    /// `DebugInfoEntry.getTag()`.
    pub fn get_tag(&self) -> Option<DWARFTag> {
        self.abbreviation.as_ref().map(|abbr| abbr.get_tag())
    }

    /// Returns the number of attributes in this DIE. Mirrors
    /// `DebugInfoEntry.getAttributeCount()`, which raises a `NullPointerException` for a
    /// terminator DIE where this returns 0.
    pub fn get_attribute_count(&self) -> usize {
        self.attr_offsets.len()
    }

    /// Returns the indexed attribute value, deserializing (and caching) it on first access.
    /// Mirrors `DebugInfoEntry.getAttributeValue(int)`, including its substitution of a
    /// `DWARFMissingAttributeValue` when the read fails.
    ///
    /// # Panics
    ///
    /// If `attrib_index` is out of range, matching Java's `ArrayIndexOutOfBoundsException`.
    pub fn get_attribute_value(&self, attrib_index: usize) -> &dyn DWARFAttributeValue {
        let slot = &self.attributes[attrib_index];
        if slot.get().is_none() {
            let value = self
                .read_attribute_value(attrib_index)
                .unwrap_or_else(|_| Box::new(DWARFMissingAttributeValue));
            // Ignore an Err: it can only mean another reader won the race and already filled the
            // slot, in which case that value is just as good as this one.
            let _ = slot.set(value);
        }
        slot.get().expect("slot was just filled").as_ref()
    }

    /// Deserializes one attribute value from the compilation unit's `.debug_info` reader, which is
    /// the body of Java's `getAttributeValue` `try` block.
    fn read_attribute_value(&self, attrib_index: usize) -> io::Result<Box<dyn DWARFAttributeValue>> {
        let container = self.get_container().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "DIE has no DIEContainer")
        })?;
        let def = self.get_attribute_def(attrib_index).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DIE has no attribute definition")
        })?;
        let mut reader = container
            .get_reader_for_comp_unit(&*self.compilation_unit)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "DIEContainer has no .debug_info reader")
            })?
            .clone_at(self.offset + self.attr_offsets[attrib_index] as u64);

        let mut context = DWARFFormContext::with_comp_unit_int_size(
            &mut *reader,
            &*self.compilation_unit,
            &def,
        );
        def.get_attribute_form().read_value(&mut context)
    }

    /// Overwrites the cached value of an attribute. Mirrors the "for testing"
    /// `DebugInfoEntry.setAttributeValue(int, DWARFAttributeValue)`; unlike Java's, this needs
    /// `&mut self` because it replaces an already-populated cache slot.
    pub fn set_attribute_value(&mut self, index: usize, attr_val: Box<dyn DWARFAttributeValue>) {
        let slot = OnceLock::new();
        let _ = slot.set(attr_val);
        self.attributes[index] = slot;
    }

    /// Searches the attributes for a specific attribute, by id. Mirrors
    /// `DebugInfoEntry.findAttribute(DWARFAttributeId)`.
    pub fn find_attribute(&self, attr_id: DWARFAttributeId) -> Option<DWARFAttribute<'_>> {
        let abbreviation = self.abbreviation.as_ref()?;
        abbreviation
            .get_attributes()
            .iter()
            .position(|attr_def| attr_def.get_attribute_id() == Some(attr_id))
            .map(|i| {
                DWARFAttribute::new(self, abbreviation.get_attributes()[i], self.get_attribute_value(i))
            })
    }

    /// The specified [`DWARFAttribute`], by index. Mirrors `DebugInfoEntry.getAttribute(int)`,
    /// which raises a `NullPointerException` for a terminator DIE.
    pub fn get_attribute(&self, index: usize) -> Option<DWARFAttribute<'_>> {
        let def = self.get_attribute_def(index)?;
        Some(DWARFAttribute::new(self, def, self.get_attribute_value(index)))
    }

    /// The [`AttrDef`] of the specified attribute, by index. Mirrors
    /// `DebugInfoEntry.getAttributeDef(int)`.
    pub fn get_attribute_def(&self, index: usize) -> Option<AttrDef> {
        self.abbreviation.as_ref()?.get_attribute_at(index)
    }

    /// Get the abbreviation (schema) of this DIE. Mirrors `DebugInfoEntry.getAbbreviation()`.
    pub fn get_abbreviation(&self) -> Option<&Arc<DWARFAbbreviation>> {
        self.abbreviation.as_ref()
    }

    /// Check to see if the DIE is a terminator. Mirrors `DebugInfoEntry.isTerminator()`.
    pub fn is_terminator(&self) -> bool {
        self.abbreviation.is_none()
    }

    /// Mirrors `DebugInfoEntry.getCompilationUnit()`.
    pub fn get_compilation_unit(&self) -> &dyn DWARFCompilationUnit {
        &*self.compilation_unit
    }

    /// Mirrors `DebugInfoEntry.getContainer()`.
    pub fn get_container(&self) -> Option<&dyn DIEContainer> {
        self.compilation_unit.get_die_container()
    }

    /// Mirrors `DebugInfoEntry.getProgram()`.
    pub fn get_program(&self) -> Option<&dyn DWARFProgram> {
        self.compilation_unit.get_program()
    }

    /// Mirrors `DebugInfoEntry.getDepth()`, where the root DIE of a compilation unit is depth 0.
    pub fn get_depth(&self) -> i32 {
        match self.get_container() {
            Some(container) => container.get_parent_depth(self.die_index),
            None => -1,
        }
    }

    /// Mirrors `DebugInfoEntry.getPositionInParent(Predicate<DWARFTag>)`, returning -1 when this
    /// DIE has no parent. The filter is handed each preceding sibling's tag, which is `None` for a
    /// terminator DIE.
    pub fn get_position_in_parent(&self, dw_tag_filter: &dyn Fn(Option<DWARFTag>) -> bool) -> i32 {
        match self.get_container() {
            Some(container) => container.get_position_in_parent(self, dw_tag_filter),
            None => -1,
        }
    }
}

impl fmt::Debug for DebugInfoEntry {
    /// Neither the compilation unit nor the deserialized attribute values are `Debug`, so this
    /// reports the identifying state ([`PartialEq`]'s fields) plus the schema.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugInfoEntry")
            .field("offset", &self.offset)
            .field("die_index", &self.die_index)
            .field("abbreviation", &self.abbreviation)
            .field("attr_offsets", &self.attr_offsets)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DebugInfoEntry {
    /// Mirrors `DebugInfoEntry.equals(Object)`. `DWARFCompilationUnit` doesn't override Java's
    /// identity `equals`, so the compilation units are compared by address.
    fn eq(&self, other: &Self) -> bool {
        std::ptr::addr_eq(
            Arc::as_ptr(&self.compilation_unit),
            Arc::as_ptr(&other.compilation_unit),
        ) && self.die_index == other.die_index
            && self.offset == other.offset
    }
}

impl Eq for DebugInfoEntry {}

impl Hash for DebugInfoEntry {
    /// Mirrors `DebugInfoEntry.hashCode()`: `Objects.hash(compilationUnit, dieIndex, offset)`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.compilation_unit) as *const () as usize).hash(state);
        self.die_index.hash(state);
        self.offset.hash(state);
    }
}

impl fmt::Display for DebugInfoEntry {
    /// Mirrors `DebugInfoEntry.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = self.get_tag();
        let tag_num = tag.map(|tag| tag.get_id()).unwrap_or(0);
        let abbr_num =
            self.abbreviation.as_ref().map(|abbr| abbr.get_abbreviation_code()).unwrap_or(0);
        let child_count =
            self.get_container().map(|container| container.get_child_count(self.die_index)).unwrap_or(0);
        let tag_str = match tag {
            Some(tag) => tag.to_string(),
            None => "null".to_string(),
        };

        writeln!(
            f,
            "<{}><{:x}>: {} [abbrev {}, tag {}, index {}, children {}]",
            self.get_depth(),
            self.offset,
            tag_str,
            abbr_num,
            tag_num,
            self.die_index,
            child_count
        )?;

        if self.is_terminator() {
            return Ok(());
        }

        for i in 0..self.attributes.len() {
            if let Some(attr) = self.get_attribute(i) {
                writeln!(f, "\t\t{attr}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
    use crate::format::seam_stubs::{DWARFNumericAttribute, DWARFStringAttribute};
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
            self.0.get(index as usize).copied().ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
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
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader { provider: Rc::new(RefCell::new(VecProvider(data))), current_index: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
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
            Box::new(MockReader { provider: Rc::clone(&self.provider), current_index: new_index })
        }
    }

    /// Models only what `DebugInfoEntry` asks of a container: a `.debug_info` byte image it hands
    /// out fresh readers over, plus a fixed parent/child topology.
    struct MockContainer {
        debug_info: Vec<u8>,
        children: Vec<DebugInfoEntry>,
        depth: i32,
    }

    impl DIEContainer for MockContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }
        fn get_reader_for_comp_unit(&self, _cu: &dyn DWARFCompilationUnit) -> Option<Box<dyn BinaryReader>> {
            Some(Box::new(MockReader::new(self.debug_info.clone())))
        }
        fn get_children_of(&self, _die_index: i32) -> Vec<&DebugInfoEntry> {
            self.children.iter().collect()
        }
        fn get_child_count(&self, _die_index: i32) -> i32 {
            self.children.len() as i32
        }
        fn get_parent_depth(&self, _die_index: i32) -> i32 {
            self.depth
        }
    }

    struct MockCompUnit {
        abbreviation: Option<Arc<DWARFAbbreviation>>,
        container: Option<MockContainer>,
    }

    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
        }
        fn get_pointer_size(&self) -> i8 {
            8
        }
        fn get_abbreviation(&self, ac: i32) -> Option<Arc<DWARFAbbreviation>> {
            self.abbreviation.as_ref().filter(|abbr| abbr.get_abbreviation_code() == ac).map(Arc::clone)
        }
        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            self.container.as_ref().map(|c| c as &dyn DIEContainer)
        }
        fn get_unit_number(&self) -> i32 {
            7
        }
        fn get_start_offset(&self) -> u64 {
            0x100
        }
    }

    const DW_TAG_SUBPROGRAM: i32 = 0x2e;
    const DW_TAG_VARIABLE: i32 = 0x34;

    /// A DIE record for an abbreviation of `DW_AT_name` (DW_FORM_string) + `DW_AT_byte_size`
    /// (DW_FORM_data1): abbrev code 1, then "hi\0", then 42.
    fn die_bytes() -> Vec<u8> {
        vec![0x01, b'h', b'i', 0x00, 42]
    }

    fn subprogram_abbrev() -> Arc<DWARFAbbreviation> {
        Arc::new(DWARFAbbreviation::new(
            1,
            DW_TAG_SUBPROGRAM,
            true,
            vec![
                AttrDef::new(Some(DWARFAttributeId::DwAtName), 0x3, DWARFForm::DwFormString, 0),
                AttrDef::new(Some(DWARFAttributeId::DwAtByteSize), 0xb, DWARFForm::DwFormData1, 0),
            ],
        ))
    }

    fn comp_unit(container: Option<MockContainer>) -> Arc<dyn DWARFCompilationUnit> {
        Arc::new(MockCompUnit { abbreviation: Some(subprogram_abbrev()), container })
    }

    fn read_die(die_index: i32, depth: i32) -> DebugInfoEntry {
        let cu = comp_unit(Some(MockContainer {
            debug_info: die_bytes(),
            children: Vec::new(),
            depth,
        }));
        let mut reader = MockReader::new(die_bytes());
        DebugInfoEntry::read(&mut reader, cu, die_index).expect("DIE should read")
    }

    #[test]
    fn read_records_the_offsets_of_each_attribute_and_leaves_the_reader_past_the_record() {
        let cu = comp_unit(None);
        let mut reader = MockReader::new(die_bytes());

        let die = DebugInfoEntry::read(&mut reader, cu, 5).expect("DIE should read");

        assert_eq!(die.get_offset(), 0);
        assert_eq!(die.get_index(), 5);
        assert!(!die.is_terminator());
        assert_eq!(die.get_tag(), Some(DWARFTag::of(DW_TAG_SUBPROGRAM)));
        assert_eq!(die.get_attribute_count(), 2);
        // 1 byte of abbreviation code, then a 3-byte "hi\0", then a 1-byte data1.
        assert_eq!(die.attr_offsets, vec![1, 4]);
        assert_eq!(reader.get_pointer_index(), 5);
    }

    #[test]
    fn read_returns_a_terminator_for_abbreviation_code_zero() {
        let cu = comp_unit(None);
        let mut reader = MockReader::new(vec![0x00, 0xff]);

        let die = DebugInfoEntry::read(&mut reader, cu, 5).expect("terminator should read");

        assert!(die.is_terminator());
        assert_eq!(die.get_tag(), None);
        // Java's private terminator constructor forces the index to -1, ignoring dieIndex.
        assert_eq!(die.get_index(), -1);
        assert_eq!(die.get_attribute_count(), 0);
        assert_eq!(reader.get_pointer_index(), 1);
    }

    #[test]
    fn read_rejects_an_unknown_abbreviation_code() {
        let cu = comp_unit(None);
        let mut reader = MockReader::new(vec![0x09]);

        let err = DebugInfoEntry::read(&mut reader, cu, 0).expect_err("abbrev 9 is not defined");

        assert_eq!(
            err.to_string(),
            "Abbreviation code 9 not found in compunit 7 at 0x100"
        );
    }

    #[test]
    fn attribute_values_are_deserialized_on_demand_from_their_recorded_offsets() {
        let die = read_die(0, 0);

        let name = die.get_attribute_value(0);
        let name = name.as_any().downcast_ref::<DWARFStringAttribute>().expect("DW_FORM_string");
        assert_eq!(name.value, "hi");

        let byte_size = die.get_attribute_value(1);
        let byte_size =
            byte_size.as_any().downcast_ref::<DWARFNumericAttribute>().expect("DW_FORM_data1");
        assert_eq!(byte_size.value, 42);
    }

    #[test]
    fn get_attribute_value_yields_a_missing_value_when_the_read_fails() {
        // No container => no .debug_info reader to deserialize from.
        let cu = comp_unit(None);
        let mut reader = MockReader::new(die_bytes());
        let die = DebugInfoEntry::read(&mut reader, cu, 0).expect("DIE should read");

        let value = die.get_attribute_value(0);

        assert!(value.as_any().downcast_ref::<DWARFMissingAttributeValue>().is_some());
        assert_eq!(value.get_value_string(die.get_compilation_unit(), &die.get_attribute_def(0).unwrap()), "<missing>");
    }

    #[test]
    fn find_attribute_matches_by_id_and_carries_the_matching_value() {
        let die = read_die(0, 0);

        let name = die.find_attribute(DWARFAttributeId::DwAtName).expect("DW_AT_name is present");
        assert_eq!(name.get_attribute_name(), "DW_AT_name");
        assert_eq!(name.get_attribute_form(), DWARFForm::DwFormString);
        assert_eq!(name.get_value_string(), "\"hi\"");

        assert!(die.find_attribute(DWARFAttributeId::DwAtLowPc).is_none());
    }

    #[test]
    fn set_attribute_value_replaces_the_cached_value() {
        let mut die = read_die(0, 0);
        assert_eq!(die.get_attribute_value(1).get_value_string(die.get_compilation_unit(), &die.get_attribute_def(1).unwrap()), "42");

        die.set_attribute_value(1, Box::new(DWARFNumericAttribute::new(99)));

        let replaced = die.get_attribute_value(1);
        let replaced = replaced.as_any().downcast_ref::<DWARFNumericAttribute>().unwrap();
        assert_eq!(replaced.value, 99);
    }

    #[test]
    fn children_come_from_the_container_and_can_be_filtered_by_tag() {
        let leaf_cu = comp_unit(None);
        let subprogram_child = DebugInfoEntry::new(
            Arc::clone(&leaf_cu),
            0x20,
            1,
            Some(subprogram_abbrev()),
            Vec::new(),
        );
        let variable_child = DebugInfoEntry::new(
            Arc::clone(&leaf_cu),
            0x30,
            2,
            Some(Arc::new(DWARFAbbreviation::new(2, DW_TAG_VARIABLE, false, Vec::new()))),
            Vec::new(),
        );
        let cu = comp_unit(Some(MockContainer {
            debug_info: die_bytes(),
            children: vec![subprogram_child, variable_child],
            depth: 0,
        }));
        let mut reader = MockReader::new(die_bytes());
        let die = DebugInfoEntry::read(&mut reader, cu, 0).expect("DIE should read");

        assert_eq!(die.get_children().len(), 2);

        let variables = die.get_children_with_tag(DWARFTag::of(DW_TAG_VARIABLE));
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].get_offset(), 0x30);
    }

    #[test]
    fn equality_ignores_everything_but_the_comp_unit_identity_index_and_offset() {
        let cu = comp_unit(None);
        let other_cu = comp_unit(None);

        let die = DebugInfoEntry::new(Arc::clone(&cu), 0x10, 3, Some(subprogram_abbrev()), vec![1]);
        let same = DebugInfoEntry::new(Arc::clone(&cu), 0x10, 3, None, Vec::new());
        let other_index = DebugInfoEntry::new(Arc::clone(&cu), 0x10, 4, None, Vec::new());
        let other_unit = DebugInfoEntry::new(other_cu, 0x10, 3, None, Vec::new());

        assert_eq!(die, same);
        assert_ne!(die, other_index);
        assert_ne!(die, other_unit);
    }

    #[test]
    fn display_mirrors_the_java_to_string_layout() {
        let die = read_die(5, 1);

        assert_eq!(
            die.to_string(),
            "<1><0>: DW_TAG_0x2e [abbrev 1, tag 46, index 5, children 0]\n\
             \t\tDW_AT_name : DW_FORM_string = \"hi\"\n\
             \t\tDW_AT_byte_size : DW_FORM_data1 = 42\n"
        );
    }

    #[test]
    fn display_of_a_terminator_stops_after_the_header_line() {
        let cu = comp_unit(None);
        let die = DebugInfoEntry::terminator(cu, 0x40);

        assert_eq!(
            die.to_string(),
            "<-1><40>: null [abbrev 0, tag 0, index -1, children 0]\n"
        );
    }
}
