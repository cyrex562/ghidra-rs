//! Port of `ghidra.app.util.bin.format.dwarf.DIEAggregate`.
//!
//! # Departures from the Java class
//!
//! * The fragments are `&DebugInfoEntry` borrows rather than owned values: in Java the
//!   `DIEContainer` owns every DIE and an aggregate just points at a few of them. That gives the
//!   struct a lifetime parameter, `DIEAggregate<'a>`, where `'a` is the container's DIE storage.
//! * `DWARFCompilationUnit`, `DIEContainer`, `DWARFProgram`, `DWARFTag`, `DWARFRangeList` and the
//!   `DWARFAttributeValue` implementations aren't ported yet, so they come from
//!   [`crate::format::seam_stubs`]. `DIEAggregate` sits on a dependency cycle with all of them
//!   (the container hands out aggregates, and every aggregate reaches back through its DIEs'
//!   compilation unit to that container), which the stubs break.
//! * Java's `getValue(Class<T>)`-style lookups become turbofished generic methods
//!   ([`DIEAggregate::find_value`], [`DIEAggregate::find_attribute_in_children`]) that downcast
//!   through [`DWARFAttributeValue::as_any`] instead of taking a `Class` token.
//! * Java's null returns become `None`: `get_tag`, `get_parent`, `get_decl_parent`,
//!   `find_ancestor`, `get_ref`, `get_source_file`, `get_abstract_instance`, ... In particular
//!   `getString(attrId, defaultValue)` becomes [`DIEAggregate::get_string`], which returns
//!   `Option<String>`; the only in-repo caller (`getName()`) passes a null default, and other
//!   callers can spell the default with `unwrap_or`.
//! * `parseInt`/`parseUnsignedLong`/`parseDataMemberOffset` throw both `IOException` and
//!   `DWARFExpressionException` in Java; here both are folded into [`io::Error`] (Java's
//!   `DWARFException` is itself an `IOException`).

use std::fmt;
use std::io;

use crate::format::dwarf::attribs::dwarf_attribute::DWARFAttribute;
use crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId;
use crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::dwarf::debug_info_entry::DebugInfoEntry;
use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::dwarf::dwarf_location_list::DWARFLocationList;
use crate::format::dwarf::dwarf_range::DWARFRange;
use crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator;
use crate::format::seam_stubs::{
    DIEContainer, DWARFBlobAttribute, DWARFBooleanAttribute, DWARFCompilationUnit, DWARFLocation,
    DWARFNumericAttribute, DWARFProgram, DWARFRangeList, DWARFStringAttribute, DWARFTag,
};
use crate::util::msg::Msg;

/// Sanity check upper limit on how many DIE records can be in an aggregate.
const MAX_FRAGMENT_COUNT: usize = 20;

/// `DW_TAG_formal_parameter`, the child tag `getFunctionParamList()` collects.
const DW_TAG_FORMAL_PARAMETER: i32 = 0x5;

/// Groups related [`DebugInfoEntry`] records together in a single view for querying attribute
/// values.
///
/// Information about program elements is written into `.debug_info` as partial snapshots of the
/// element, with later follow-up records that more fully specify the program element. (For
/// instance, a declaration-only DIE that introduces the name of a structure type will be found at
/// the beginning of a compilation unit, followed later by a DIE that specifies the contents of the
/// structure type.) A `DIEAggregate` groups those records so a fully specified view of the program
/// element can be presented.
///
/// The fragments are ordered 'head'-most first, followed by earlier less specified DIEs, ending
/// with the first 'decl' DIE:
///
/// ```text
/// [0] - head
/// [1] - specification
/// [2] - decl
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DIEAggregate<'a> {
    fragments: Vec<&'a DebugInfoEntry>,
}

impl<'a> DIEAggregate<'a> {
    /// Creates a `DIEAggregate` starting from a 'head' [`DebugInfoEntry`], following
    /// `DW_AT_abstract_origin` and `DW_AT_specification` attributes to find the previous DIEs.
    /// Mirrors `DIEAggregate.createFromHead(DebugInfoEntry)`.
    pub fn create_from_head(die: &'a DebugInfoEntry) -> DIEAggregate<'a> {
        // Build the list of fragments assuming we are starting at the topmost fragment (ie.
        // forward references only). The fragments are in reversed order (ie. more primitive DIEs
        // are at the front of the list) while querying for additional abstract_origin values, to
        // ensure that we retrieve what would normally be the overridden value.
        let mut result = DIEAggregate { fragments: vec![die] };

        // Keep querying for abstract_origin DIEs as long as we haven't seen them yet, and add
        // them to the fragment list.
        while result.get_fragment_count() < MAX_FRAGMENT_COUNT {
            let Some(tmp) = result.get_ref_die(DWARFAttributeId::DwAtAbstractOrigin) else {
                break;
            };
            if result.has_offset(tmp.get_offset()) {
                break;
            }
            result.add_fragment(tmp);
        }

        // Look for 1 spec DIE and add it.
        if let Some(tmp) = result.get_ref_die(DWARFAttributeId::DwAtSpecification) {
            result.add_fragment(tmp);
        }
        result.flip_fragments();
        result
    }

    /// Creates a new `DIEAggregate` from the fragments of `source`, skipping the head fragment,
    /// or `None` if `source` only has that one fragment.
    ///
    /// Used when a DIEA is composed of a head DIE with a different TAG type than the rest of the
    /// DIEs (ie. a `dw_tag_call_site` -> `dw_tag_sub` DIEA). Mirrors
    /// `DIEAggregate.createSkipHead(DIEAggregate)`.
    pub fn create_skip_head(source: &DIEAggregate<'a>) -> Option<DIEAggregate<'a>> {
        if source.fragments.len() == 1 {
            return None;
        }
        Some(DIEAggregate { fragments: source.fragments[1..].to_vec() })
    }

    /// Creates a `DIEAggregate` from a single DIE, without following any links. Mainly useful
    /// early in the compilation unit's bootstrapping process. Mirrors
    /// `DIEAggregate.createSingle(DebugInfoEntry)`.
    pub fn create_single(die: &'a DebugInfoEntry) -> DIEAggregate<'a> {
        DIEAggregate { fragments: vec![die] }
    }

    /// Adds a newly found fragment to the front of the fragment list, which is reversed from how
    /// it needs to be when this DIEA is being used; [`Self::flip_fragments`] puts it right at the
    /// end of the build phase. Mirrors the private `DIEAggregate.addFragment(DebugInfoEntry)`.
    fn add_fragment(&mut self, new_die: &'a DebugInfoEntry) {
        self.fragments.insert(0, new_die);
    }

    fn flip_fragments(&mut self) {
        self.fragments.reverse();
    }

    pub fn get_fragment_count(&self) -> usize {
        self.fragments.len()
    }

    pub fn get_offset(&self) -> u64 {
        self.get_head_fragment().get_offset()
    }

    pub fn get_offsets(&self) -> Vec<u64> {
        self.fragments.iter().map(|frag| frag.get_offset()).collect()
    }

    /// Returns true if any of the DIEs that make up this aggregate have the specified offset.
    /// Mirrors `DIEAggregate.hasOffset(long)`.
    pub fn has_offset(&self, offset: u64) -> bool {
        self.fragments.iter().any(|frag| frag.get_offset() == offset)
    }

    pub fn get_decl_offset(&self) -> u64 {
        self.get_last_fragment().get_offset()
    }

    /// [`Self::get_offset`] as a hex string. Mirrors `DIEAggregate.getHexOffset()`.
    pub fn get_hex_offset(&self) -> String {
        format!("{:x}", self.get_head_fragment().get_offset())
    }

    /// The head fragment's tag, or `None` (Java's `null`) for a terminator DIE. Mirrors
    /// `DIEAggregate.getTag()`.
    pub fn get_tag(&self) -> Option<DWARFTag> {
        self.get_head_fragment().get_tag()
    }

    pub fn get_compilation_unit(&self) -> &'a dyn DWARFCompilationUnit {
        self.get_head_fragment().get_compilation_unit()
    }

    /// Mirrors `DIEAggregate.getProgram()`. The real method never returns `null`; the `Option`
    /// only exists because the stubbed compilation unit may not model a program.
    pub fn get_program(&self) -> Option<&'a dyn DWARFProgram> {
        self.get_head_fragment().get_program()
    }

    /// The program's single [`DIEContainer`]. Mirrors `DIEAggregate.getDIEContainer()`; as with
    /// [`Self::get_program`], the `Option` is an artifact of the stubbed collaborators.
    pub fn get_die_container(&self) -> Option<&'a dyn DIEContainer> {
        self.get_head_fragment().get_container()
    }

    /// The last DIE fragment, ie. the decl DIE. Mirrors `DIEAggregate.getLastFragment()`.
    pub fn get_last_fragment(&self) -> &'a DebugInfoEntry {
        self.fragments[self.fragments.len() - 1]
    }

    /// The first DIE fragment, ie. the spec or abstract_origin DIE. Mirrors
    /// `DIEAggregate.getHeadFragment()`.
    pub fn get_head_fragment(&self) -> &'a DebugInfoEntry {
        self.fragments[0]
    }

    /// Mirrors `DIEAggregate.getDeclParent()`.
    pub fn get_decl_parent(&self) -> Option<DIEAggregate<'a>> {
        let decl_parent = self.get_last_fragment().get_parent()?;
        Some(self.get_die_container()?.get_aggregate(decl_parent))
    }

    /// Mirrors `DIEAggregate.getParent()`.
    pub fn get_parent(&self) -> Option<DIEAggregate<'a>> {
        let parent = self.get_head_fragment().get_parent()?;
        Some(self.get_die_container()?.get_aggregate(parent))
    }

    /// The first ancestor (parent, grandparent, etc) that matches the specified DIE tag type, or
    /// `None` if not found. Mirrors `DIEAggregate.findAncestor(DWARFTag)`.
    pub fn find_ancestor(&self, ancestor_type: DWARFTag) -> Option<DIEAggregate<'a>> {
        let mut parent = self.get_parent();
        while let Some(p) = parent {
            if p.get_tag() == Some(ancestor_type) {
                return Some(p);
            }
            parent = p.get_parent();
        }
        None
    }

    /// The depth of the head fragment, ie. the distance between the DIE and the root DIE of the
    /// owning compilation unit (the root DIE is depth 0). Mirrors `DIEAggregate.getDepth()`.
    pub fn get_depth(&self) -> i32 {
        self.get_head_fragment().get_depth()
    }

    /// An attribute value present in this aggregate, or in any of its direct children carrying
    /// `child_tag`. Mirrors `DIEAggregate.findAttributeInChildren(DWARFAttributeId, DWARFTag,
    /// Class<T>)`, with the `Class` token replaced by a turbofished type parameter.
    pub fn find_attribute_in_children<T: DWARFAttributeValue + 'static>(
        &self,
        attr_id: DWARFAttributeId,
        child_tag: DWARFTag,
    ) -> Option<&'a T> {
        if let Some(attribute_value) = self.find_value::<T>(attr_id) {
            return Some(attribute_value);
        }
        let container = self.get_die_container()?;
        for child_die in self.get_children(child_tag) {
            let child_diea = container.get_aggregate(child_die);
            if let Some(attribute_value) = child_diea.find_value::<T>(attr_id) {
                return Some(attribute_value);
            }
        }
        None
    }

    /// The matching attribute, by id, or `None` if not found. Attributes are searched for in each
    /// fragment, starting with the 'head' fragment and progressing toward the 'decl' fragment.
    /// Mirrors `DIEAggregate.findAttribute(DWARFAttributeId)`.
    pub fn find_attribute(&self, attr_id: DWARFAttributeId) -> Option<DWARFAttribute<'a>> {
        self.fragments.iter().find_map(|die| die.find_attribute(attr_id))
    }

    /// The value of the matching attribute, downcast to a specific implementation, or `None` if
    /// the attribute does not exist or is a different type. Mirrors
    /// `DIEAggregate.findValue(DWARFAttributeId, Class<T>)`.
    pub fn find_value<T: DWARFAttributeValue + 'static>(
        &self,
        attr_id: DWARFAttributeId,
    ) -> Option<&'a T> {
        self.find_attribute(attr_id)?.get_value_typed::<T>()
    }

    /// The value of the matching attribute, or `None` if not found. Mirrors
    /// `DIEAggregate.findValue(DWARFAttributeId)`.
    pub fn find_value_any(&self, attr_id: DWARFAttributeId) -> Option<&'a dyn DWARFAttributeValue> {
        Some(self.find_attribute(attr_id)?.get_value())
    }

    /// The value of the requested attribute, or `default_value` if the attribute is missing or is
    /// not numeric. Mirrors `DIEAggregate.getLong(DWARFAttributeId, long)`.
    pub fn get_long(&self, attr_id: DWARFAttributeId, default_value: i64) -> i64 {
        self.find_value::<DWARFNumericAttribute>(attr_id)
            .map_or(default_value, DWARFNumericAttribute::get_value)
    }

    /// The boolean value of the requested attribute, or `default_value` if the attribute is
    /// missing or not the correct type. Mirrors `DIEAggregate.getBool(DWARFAttributeId, boolean)`.
    pub fn get_bool(&self, attr_id: DWARFAttributeId, default_value: bool) -> bool {
        self.find_value::<DWARFBooleanAttribute>(attr_id)
            .map_or(default_value, DWARFBooleanAttribute::get_value)
    }

    /// The string value of the requested attribute, or `None` if the attribute is missing or not
    /// the correct type. Mirrors `DIEAggregate.getString(DWARFAttributeId, String)` with a null
    /// default; callers wanting a different default can use `unwrap_or`.
    pub fn get_string(&self, attr_id: DWARFAttributeId) -> Option<String> {
        let attr = self.find_attribute(attr_id)?;
        let sval = attr.get_value_typed::<DWARFStringAttribute>()?;
        Some(sval.get_value(attr.get_die().get_compilation_unit()))
    }

    /// The string value of the `DW_AT_name` attribute, or `None` if it is missing. Mirrors
    /// `DIEAggregate.getName()`.
    pub fn get_name(&self) -> Option<String> {
        self.get_string(DWARFAttributeId::DwAtName)
    }

    /// The unsigned value of the requested attribute, or `default_value` if the attribute is
    /// missing. The 'unsigned'ness refers to how the binary value is read from the dwarf
    /// information (ie. a value with the high bit set is not treated as signed). Mirrors
    /// `DIEAggregate.getUnsignedLong(DWARFAttributeId, long)`.
    pub fn get_unsigned_long(&self, attr_id: DWARFAttributeId, default_value: i64) -> i64 {
        self.find_value::<DWARFNumericAttribute>(attr_id)
            .map_or(default_value, DWARFNumericAttribute::get_unsigned_value)
    }

    /// Mirrors the private `DIEAggregate.getRefDIE(DWARFAttributeId)`, which logs and swallows a
    /// bad reference.
    fn get_ref_die(&self, attr_id: DWARFAttributeId) -> Option<&'a DebugInfoEntry> {
        let found_attr = self.find_attribute(attr_id)?;
        let val = found_attr.get_value_typed::<DWARFNumericAttribute>()?;
        let container = self.get_die_container()?;

        match container.get_die(
            found_attr.get_attribute_form(),
            val.get_unsigned_value(),
            found_attr.get_die().get_compilation_unit(),
        ) {
            Ok(die) => die,
            Err(_) => {
                Msg::warn(
                    "DIEAggregate",
                    &format!(
                        "Invalid reference from DIE 0x{:x} to 0x{:x} ({})",
                        found_attr.get_die().get_offset(),
                        val.get_unsigned_value(),
                        found_attr.get_attribute_form().name()
                    ),
                );
                Msg::debug("DIEAggregate", &self.to_string());
                None
            }
        }
    }

    /// The aggregate pointed to by the requested attribute, or `None` if the attribute does not
    /// exist. Mirrors `DIEAggregate.getRef(DWARFAttributeId)`.
    pub fn get_ref(&self, attr_id: DWARFAttributeId) -> Option<DIEAggregate<'a>> {
        let die = self.get_ref_die(attr_id)?;
        Some(self.get_die_container()?.get_aggregate(die))
    }

    /// The DIEA pointed to by a `DW_AT_containing_type` attribute, or `None` if not present.
    /// Mirrors `DIEAggregate.getContainingTypeRef()`.
    pub fn get_containing_type_ref(&self) -> Option<DIEAggregate<'a>> {
        self.get_ref(DWARFAttributeId::DwAtContainingType)
    }

    /// Mirrors `DIEAggregate.getTypeRef()`.
    pub fn get_type_ref(&self) -> Option<DIEAggregate<'a>> {
        self.get_ref(DWARFAttributeId::DwAtType)
    }

    /// The name of the source file this item was declared in (`DW_AT_decl_file`), or `None` if
    /// the info is not available. Mirrors `DIEAggregate.getSourceFile()`.
    pub fn get_source_file(&self) -> Option<String> {
        let attr_info = self.find_attribute(DWARFAttributeId::DwAtDeclFile)?;
        let attr = attr_info.get_value_typed::<DWARFNumericAttribute>()?;
        let file_num = attr.get_unsigned_int_exact().ok()?;
        let line = attr_info.get_die().get_compilation_unit().get_line()?;
        let file = line.get_file(file_num).ok()?;
        Some(file.get_name().to_string())
    }

    /// The children of the head fragment that are of a specific DWARF type. Mirrors
    /// `DIEAggregate.getChildren(DWARFTag)`.
    pub fn get_children(&self, child_tag: DWARFTag) -> Vec<&'a DebugInfoEntry> {
        self.get_head_fragment().get_children_with_tag(child_tag)
    }

    /// Mirrors `DIEAggregate.hasAttribute(DWARFAttributeId)`.
    pub fn has_attribute(&self, attr_id: DWARFAttributeId) -> bool {
        self.find_attribute(attr_id).is_some()
    }

    /// An aggregate that only contains the information present in the "abstract instance" (and
    /// lower) DIEs, or `None` if this DIEA was not split into a concrete and abstract portion.
    /// Mirrors `DIEAggregate.getAbstractInstance()`.
    pub fn get_abstract_instance(&self) -> Option<DIEAggregate<'a>> {
        let ao_attr = self.find_attribute(DWARFAttributeId::DwAtAbstractOrigin)?;
        let ao_index = self
            .fragments
            .iter()
            .position(|frag| std::ptr::eq(*frag, ao_attr.get_die()))
            // findAttribute only ever returns an attribute of one of these fragments, which is
            // Java's `throw new IllegalArgumentException("Should not get here")`.
            .expect("the attribute's DIE is one of this aggregate's fragments");
        Some(DIEAggregate { fragments: self.fragments[ao_index + 1..].to_vec() })
    }

    /// The signed integer value of the requested attribute after resolving any DWARF expression
    /// opcodes, or `default_value` if the attribute is not present. Mirrors
    /// `DIEAggregate.parseInt(DWARFAttributeId, int)`.
    pub fn parse_int(&self, attr_id: DWARFAttributeId, default_value: i32) -> io::Result<i32> {
        let Some(attr) = self.find_value_any(attr_id) else {
            return Ok(default_value);
        };

        if let Some(dnum) = attr.as_any().downcast_ref::<DWARFNumericAttribute>() {
            assert_valid_int(dnum.get_value())
        } else if let Some(dblob) = attr.as_any().downcast_ref::<DWARFBlobAttribute>() {
            assert_valid_int(self.eval_expr(self.head_compilation_unit_arc(), dblob)?)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not integer attribute: {}", self.attr_value_string(attr_id)),
            ))
        }
    }

    /// The unsigned value of the requested attribute after resolving any DWARF expression
    /// opcodes, or `default_value` if the attribute is not present. Mirrors
    /// `DIEAggregate.parseUnsignedLong(DWARFAttributeId, long)`.
    pub fn parse_unsigned_long(
        &self,
        attr_id: DWARFAttributeId,
        default_value: i64,
    ) -> io::Result<i64> {
        let Some(attr) = self.find_attribute(attr_id) else {
            return Ok(default_value);
        };

        if let Some(dnum) = attr.get_value_typed::<DWARFNumericAttribute>() {
            Ok(dnum.get_unsigned_value())
        } else if let Some(dblob) = attr.get_value_typed::<DWARFBlobAttribute>() {
            // Unlike parseInt/parseDataMemberOffset, Java evaluates this expression against the
            // attribute's own DIE's compilation unit rather than the head fragment's.
            self.eval_expr(attr.get_die().get_compilation_unit_arc(), dblob)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not integer attribute: {}", self.attr_value_string(attr_id)),
            ))
        }
    }

    /// The unsigned integer value of the requested attribute after resolving any DWARF expression
    /// opcodes, or `default_value` if the attribute is not present. Mirrors
    /// `DIEAggregate.parseDataMemberOffset(DWARFAttributeId, int)`.
    pub fn parse_data_member_offset(
        &self,
        attr_id: DWARFAttributeId,
        default_value: i32,
    ) -> io::Result<i32> {
        let Some(attr) = self.find_attribute(attr_id) else {
            return Ok(default_value);
        };

        if let Some(dnum) = attr.get_value_typed::<DWARFNumericAttribute>() {
            dnum.get_unsigned_int_exact()
        } else if let Some(dblob) = attr.get_value_typed::<DWARFBlobAttribute>() {
            // DW_AT_data_member_location expects the address of the containing object to be on
            // the stack before evaluation starts. We don't have that so we fake it with zero.
            assert_valid_uint(self.eval_expr(self.head_compilation_unit_arc(), dblob)?)
        } else {
            Err(dwarf_error(format!(
                "DWARF attribute form not valid for data member offset: {}",
                attr.get_attribute_form().name()
            )))
        }
    }

    /// Evaluates a location-expression blob with a single zero argument pre-pushed on the stack
    /// and pops the result, the body shared by the three `parseXyz` methods.
    fn eval_expr(
        &self,
        cu: std::sync::Arc<dyn DWARFCompilationUnit>,
        dblob: &DWARFBlobAttribute,
    ) -> io::Result<i64> {
        let mut evaluator = DWARFExpressionEvaluator::new(cu);
        evaluator
            .evaluate_bytes_with_args(dblob.get_bytes(), &[0])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        evaluator.pop_long().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The shared handle to the head fragment's compilation unit, which
    /// [`DWARFExpressionEvaluator::new`] takes by value.
    fn head_compilation_unit_arc(&self) -> std::sync::Arc<dyn DWARFCompilationUnit> {
        self.get_head_fragment().get_compilation_unit_arc()
    }

    /// Renders an attribute value the way Java's `"%s".formatted(attr)` does in the "not an
    /// integer attribute" error messages.
    fn attr_value_string(&self, attr_id: DWARFAttributeId) -> String {
        self.find_attribute(attr_id).map_or_else(|| "null".to_string(), |attr| attr.to_string())
    }

    /// Parses a location attribute value, which can be a single expression that is valid for any
    /// PC, or a list of expressions that are tied to specific ranges. Never null, possibly empty.
    /// Mirrors `DIEAggregate.getLocationList(DWARFAttributeId)`.
    pub fn get_location_list(&self, attr_id: DWARFAttributeId) -> io::Result<DWARFLocationList> {
        self.get_die_container()
            .ok_or_else(|| dwarf_error("DIE has no DIEContainer"))?
            .get_location_list(self, attr_id)
    }

    /// Parses a location attribute value and returns the location that covers the specified pc,
    /// or `None` if none does. Mirrors `DIEAggregate.getLocation(DWARFAttributeId, long)`.
    pub fn get_location(
        &self,
        attr_id: DWARFAttributeId,
        pc: u64,
    ) -> io::Result<Option<DWARFLocation>> {
        let loc_list = self.get_location_list(attr_id)?;
        Ok(loc_list.get_location_containing(pc).cloned())
    }

    /// True if this DIE has a `DW_AT_declaration` attribute and does NOT have a matching inbound
    /// `DW_AT_specification` reference. Mirrors `DIEAggregate.isDanglingDeclaration()`.
    pub fn is_dangling_declaration(&self) -> bool {
        self.is_partial_declaration() && self.fragments.len() == 1
    }

    /// True if this DIE has a `DW_AT_declaration` attribute. Mirrors
    /// `DIEAggregate.isPartialDeclaration()`.
    pub fn is_partial_declaration(&self) -> bool {
        self.has_attribute(DWARFAttributeId::DwAtDeclaration)
    }

    /// Parses a range list. Mirrors `DIEAggregate.getRangeList(DWARFAttributeId)`.
    pub fn get_range_list(&self, attr_id: DWARFAttributeId) -> io::Result<DWARFRangeList> {
        self.get_die_container()
            .ok_or_else(|| dwarf_error("DIE has no DIEContainer"))?
            .get_range_list(self, attr_id)
    }

    /// The range specified by the `DW_AT_low_pc`..`DW_AT_high_pc` attribute values, or
    /// [`DWARFRange::EMPTY`] if the low_pc is not present (or is tombstoned). Mirrors
    /// `DIEAggregate.getPCRange()`.
    pub fn get_pc_range(&self) -> DWARFRange {
        let Some(low_pc) = self.find_attribute(DWARFAttributeId::DwAtLowPc) else {
            return DWARFRange::EMPTY;
        };
        let Some(low_pc_attr_val) = low_pc.get_value_typed::<DWARFNumericAttribute>() else {
            return DWARFRange::EMPTY;
        };
        let Some(container) = self.get_die_container() else {
            return DWARFRange::EMPTY;
        };

        let raw_low_pc = low_pc_attr_val.get_unsigned_value();
        let Ok(low_pc_offset) =
            container.get_address(low_pc.get_attribute_form(), raw_low_pc, self.get_compilation_unit())
        else {
            // Java catches the IOException and falls through to the empty range.
            return DWARFRange::EMPTY;
        };

        if low_pc_offset == 0 && self.get_program().is_some_and(DWARFProgram::is_addr0_tombstone) {
            return DWARFRange::EMPTY;
        }

        let mut high_pc_offset = low_pc_offset;
        if let Some(high_pc) = self.find_attribute(DWARFAttributeId::DwAtHighPc) {
            if let Some(high_pc_attr_val) = high_pc.get_value_typed::<DWARFNumericAttribute>() {
                high_pc_offset = if high_pc.get_attribute_form() == DWARFForm::DwFormAddr {
                    high_pc_attr_val.get_unsigned_value()
                } else {
                    // Anything but DW_FORM_addr is a length relative to low_pc.
                    low_pc_offset.wrapping_add(high_pc_attr_val.get_unsigned_value())
                };
            }
        }
        DWARFRange::new(low_pc_offset as u64, high_pc_offset as u64)
    }

    /// A function's parameter list, taking care to ensure that the params are well ordered (to
    /// avoid issues with concrete instance param ordering). Mirrors
    /// `DIEAggregate.getFunctionParamList()`.
    pub fn get_function_param_list(&self) -> Vec<DIEAggregate<'a>> {
        let Some(container) = self.get_die_container() else {
            return Vec::new();
        };

        // Build list of params, as seen by the function's DIEA.
        let mut params: Vec<DIEAggregate<'a>> = self
            .get_children(DWARFTag::of(DW_TAG_FORMAL_PARAMETER))
            .into_iter()
            .map(|param_die| container.get_aggregate(param_die))
            .collect();

        // Since the function might be defined using abstract and concrete parts, and the param
        // ordering of the concrete part can be inconsistent, re-order the params according to the
        // abstract instance's params. Extra concrete params are appended at the end.
        if let Some(abstract_diea) = self.get_abstract_instance() {
            let mut new_params = Vec::with_capacity(params.len());
            for param_die in abstract_diea.get_children(DWARFTag::of(DW_TAG_FORMAL_PARAMETER)) {
                match find_die_in_list(&params, param_die) {
                    Some(index) => new_params.push(params.remove(index)),
                    // Add the generic (abstract) definition of the param to the list.
                    None => new_params.push(container.get_aggregate(param_die)),
                }
            }
            new_params.append(&mut params);
            params = new_params;
        }

        params
    }
}

/// Mirrors the private static `DIEAggregate.findDIEInList(List<DIEAggregate>, DebugInfoEntry)`,
/// returning `None` where Java returns -1.
fn find_die_in_list(dieas: &[DIEAggregate<'_>], die: &DebugInfoEntry) -> Option<usize> {
    dieas.iter().position(|diea| diea.has_offset(die.get_offset()))
}

/// Mirrors the private `DIEAggregate.assertValidInt(long)`.
fn assert_valid_int(l: i64) -> io::Result<i32> {
    if l < i32::MIN as i64 || l > i32::MAX as i64 {
        return Err(dwarf_error(format!("Value out of allowed range: {l}")));
    }
    Ok(l as i32)
}

/// Mirrors the private `DIEAggregate.assertValidUInt(long)`.
fn assert_valid_uint(l: i64) -> io::Result<i32> {
    if l < 0 || l > i32::MAX as i64 {
        return Err(dwarf_error(format!("Value out of allowed range: {l}")));
    }
    Ok(l as i32)
}

/// Wraps a [`DWARFException`] (an `IOException` subclass in Java) as an [`io::Error`].
fn dwarf_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, DWARFException::with_message(message))
}

impl fmt::Display for DIEAggregate<'_> {
    /// Mirrors `DIEAggregate.toString()`, typo in the header line included.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DIEAgregrate of: ")?;
        for die in &self.fragments {
            write!(f, "DIE [0x{:x}], ", die.get_offset())?;
        }
        writeln!(f)?;
        for die in &self.fragments {
            write!(f, "{die}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::dwarf::attribs::dwarf_attribute_id::AttrDef;
    use crate::format::dwarf::dwarf_abbreviation::DWARFAbbreviation;
    use crate::format::dwarf::line::dwarf_file::DWARFFile;
    use crate::format::dwarf::line::dwarf_line::DWARFLine;
    use crate::format::seam_stubs::DWARFImportSummary;
    use std::sync::{Arc, OnceLock};

    pub(crate) const DW_TAG_SUBPROGRAM: i32 = 0x2e;
    pub(crate) const DW_TAG_VARIABLE: i32 = 0x34;

    /// A container that owns a set of DIEs plus a parent/child topology keyed by DIE index, and
    /// resolves references by DIE offset. Models only what `DIEAggregate` asks of a
    /// `DIEContainer`.
    #[derive(Default)]
    pub(crate) struct MockContainer {
        /// Every DIE reachable through this container.
        pub(crate) dies: Vec<DebugInfoEntry>,
        /// `(child index, parent index)` pairs.
        pub(crate) parents: Vec<(i32, i32)>,
        /// `(parent index, child index)` pairs.
        pub(crate) children: Vec<(i32, i32)>,
        pub(crate) location_list: Option<DWARFLocationList>,
        pub(crate) range_list: Option<DWARFRangeList>,
    }

    impl MockContainer {
        pub(crate) fn die_at(&self, die_index: i32) -> &DebugInfoEntry {
            self.dies
                .iter()
                .find(|die| die.get_index() == die_index)
                .unwrap_or_else(|| panic!("no DIE with index {die_index}"))
        }
    }

    impl DIEContainer for MockContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }

        fn get_die(
            &self,
            _form: DWARFForm,
            raw_offset: i64,
            _cu: &dyn DWARFCompilationUnit,
        ) -> io::Result<Option<&DebugInfoEntry>> {
            Ok(self.dies.iter().find(|die| die.get_offset() == raw_offset as u64))
        }

        fn get_parent_of(&self, die_index: i32) -> Option<&DebugInfoEntry> {
            let parent_index =
                self.parents.iter().find(|(child, _)| *child == die_index).map(|(_, p)| *p)?;
            Some(self.die_at(parent_index))
        }

        fn get_children_of(&self, die_index: i32) -> Vec<&DebugInfoEntry> {
            self.children
                .iter()
                .filter(|(parent, _)| *parent == die_index)
                .map(|(_, child)| self.die_at(*child))
                .collect()
        }

        fn get_child_count(&self, die_index: i32) -> i32 {
            self.get_children_of(die_index).len() as i32
        }

        /// The raw value of a `DW_FORM_addr` low_pc already is the address.
        fn get_address(
            &self,
            _form: DWARFForm,
            value: i64,
            _cu: &dyn DWARFCompilationUnit,
        ) -> io::Result<i64> {
            Ok(value)
        }

        fn get_location_list(
            &self,
            _diea: &DIEAggregate<'_>,
            _attr_id: DWARFAttributeId,
        ) -> io::Result<DWARFLocationList> {
            Ok(self.location_list.clone().unwrap_or_else(|| DWARFLocationList::new(Vec::new())))
        }

        fn get_range_list(
            &self,
            _diea: &DIEAggregate<'_>,
            _attr_id: DWARFAttributeId,
        ) -> io::Result<DWARFRangeList> {
            Ok(self.range_list.clone().unwrap_or_default())
        }
    }

    /// A compilation unit that owns its line table, its program and the container of its DIEs.
    /// The container goes in a [`OnceLock`] because the DIEs it holds need this compilation unit
    /// to exist first -- Java's object graph is cyclic here.
    #[derive(Default)]
    pub(crate) struct MockCompUnit {
        pub(crate) line: Option<DWARFLine>,
        pub(crate) program: Option<Arc<dyn DWARFProgram>>,
        pub(crate) container: OnceLock<MockContainer>,
    }

    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
        }

        fn get_line(&self) -> Option<&DWARFLine> {
            self.line.as_ref()
        }

        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            self.container.get().map(|c| c as &dyn DIEContainer)
        }

        fn get_program(&self) -> Option<&dyn DWARFProgram> {
            self.program.as_deref()
        }
    }

    /// A program that reports address 0 as a tombstone.
    pub(crate) struct TombstoneProgram;

    impl DWARFProgram for TombstoneProgram {
        fn is_addr0_tombstone(&self) -> bool {
            true
        }
        fn get_import_summary(&self) -> &DWARFImportSummary {
            unimplemented!("not used by DIEAggregate")
        }
    }

    /// A line table whose (pre-DWARF5, 1-based) file index 1 resolves to `name`.
    pub(crate) fn line_table_with_file(name: &str) -> DWARFLine {
        DWARFLine::with_files(4, vec![DWARFFile::new(name)])
    }

    pub(crate) fn comp_unit() -> Arc<MockCompUnit> {
        Arc::new(MockCompUnit::default())
    }

    pub(crate) fn comp_unit_with_line(name: &str) -> Arc<MockCompUnit> {
        Arc::new(MockCompUnit { line: Some(line_table_with_file(name)), ..MockCompUnit::default() })
    }

    /// Closes the compilation unit <-> container cycle. Must be called once, after every DIE the
    /// container holds has been built against `cu`.
    pub(crate) fn install(cu: &Arc<MockCompUnit>, container: MockContainer) {
        assert!(cu.container.set(container).is_ok(), "container installed twice");
    }

    /// Builds a DIE whose attribute values are injected directly (no `.debug_info` bytes to
    /// deserialize), so a test can state just the attributes it cares about.
    pub(crate) fn die(
        cu: &Arc<MockCompUnit>,
        offset: u64,
        die_index: i32,
        tag: i32,
        attrs: Vec<(DWARFAttributeId, DWARFForm, Box<dyn DWARFAttributeValue>)>,
    ) -> DebugInfoEntry {
        let defs: Vec<AttrDef> = attrs
            .iter()
            .map(|(id, form, _)| AttrDef::new(Some(*id), id.get_id(), *form, 0))
            .collect();
        let abbrev = Arc::new(DWARFAbbreviation::new(1, tag, true, defs));
        let mut die = DebugInfoEntry::new(
            Arc::clone(cu) as Arc<dyn DWARFCompilationUnit>,
            offset,
            die_index,
            Some(abbrev),
            (0..attrs.len() as i32).collect(),
        );
        for (i, (_, _, value)) in attrs.into_iter().enumerate() {
            die.set_attribute_value(i, value);
        }
        die
    }

    pub(crate) fn num(value: i64) -> Box<dyn DWARFAttributeValue> {
        Box::new(DWARFNumericAttribute::new(value))
    }

    pub(crate) fn string(value: &str) -> Box<dyn DWARFAttributeValue> {
        Box::new(DWARFStringAttribute::new(value))
    }

    pub(crate) fn flag(value: bool) -> Box<dyn DWARFAttributeValue> {
        Box::new(DWARFBooleanAttribute::new(value))
    }

    #[test]
    fn create_single_holds_exactly_the_one_die() {
        let cu = comp_unit();
        let d = die(&cu, 0x10, 0, DW_TAG_SUBPROGRAM, vec![]);

        let diea = DIEAggregate::create_single(&d);

        assert_eq!(diea.get_fragment_count(), 1);
        assert_eq!(diea.get_offset(), 0x10);
        assert_eq!(diea.get_decl_offset(), 0x10);
        assert_eq!(diea.get_hex_offset(), "10");
        assert_eq!(diea.get_offsets(), vec![0x10]);
        assert!(diea.has_offset(0x10));
        assert!(!diea.has_offset(0x11));
        assert_eq!(diea.get_tag(), Some(DWARFTag::of(DW_TAG_SUBPROGRAM)));
    }

    /// head(0x10) --DW_AT_abstract_origin--> spec(0x20) --DW_AT_specification--> decl(0x30).
    fn abstract_origin_chain() -> Arc<MockCompUnit> {
        let cu = comp_unit();
        let head = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtAbstractOrigin, DWARFForm::DwFormRef4, num(0x20))],
        );
        let spec = die(
            &cu,
            0x20,
            1,
            DW_TAG_SUBPROGRAM,
            vec![
                (DWARFAttributeId::DwAtSpecification, DWARFForm::DwFormRef4, num(0x30)),
                (DWARFAttributeId::DwAtDeclaration, DWARFForm::DwFormFlag, flag(true)),
            ],
        );
        let decl = die(
            &cu,
            0x30,
            2,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtName, DWARFForm::DwFormString, string("myfunc"))],
        );
        install(&cu, MockContainer { dies: vec![head, spec, decl], ..MockContainer::default() });
        cu
    }

    #[test]
    fn create_from_head_follows_abstract_origin_then_specification_and_reverses_the_list() {
        let cu = abstract_origin_chain();
        let container = cu.container.get().unwrap();

        let diea = DIEAggregate::create_from_head(container.die_at(0));

        // [0] head, [1] the abstract_origin DIE, [2] the DIE its DW_AT_specification points at.
        assert_eq!(diea.get_offsets(), vec![0x10, 0x20, 0x30]);
        assert_eq!(diea.get_offset(), 0x10);
        assert_eq!(diea.get_decl_offset(), 0x30);
        // Attribute lookup walks head -> decl, so the name on the decl fragment is visible.
        assert_eq!(diea.get_name(), Some("myfunc".to_string()));
        // DW_AT_declaration is present, but this aggregate has more than one fragment.
        assert!(diea.is_partial_declaration());
        assert!(!diea.is_dangling_declaration());
    }

    #[test]
    fn create_from_head_stops_on_a_self_referential_abstract_origin() {
        // A DIE whose DW_AT_abstract_origin points at itself would otherwise loop forever.
        let cu = comp_unit();
        let looper = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtAbstractOrigin, DWARFForm::DwFormRef4, num(0x10))],
        );
        install(&cu, MockContainer { dies: vec![looper], ..MockContainer::default() });

        let diea = DIEAggregate::create_from_head(cu.container.get().unwrap().die_at(0));

        assert_eq!(diea.get_fragment_count(), 1);
    }

    #[test]
    fn skip_head_drops_the_first_fragment_and_is_none_for_a_single_die() {
        let cu = abstract_origin_chain();
        let head = cu.container.get().unwrap().die_at(0);
        let diea = DIEAggregate::create_from_head(head);

        let skipped = DIEAggregate::create_skip_head(&diea).expect("3 fragments -> 2");
        assert_eq!(skipped.get_offsets(), vec![0x20, 0x30]);
        // The skipped-head aggregate is a partial declaration standing on its own fragments.
        assert!(skipped.is_partial_declaration());

        assert!(DIEAggregate::create_skip_head(&DIEAggregate::create_single(head)).is_none());
    }

    #[test]
    fn abstract_instance_keeps_only_the_fragments_below_the_abstract_origin_die() {
        let cu = abstract_origin_chain();
        let head = cu.container.get().unwrap().die_at(0);
        let diea = DIEAggregate::create_from_head(head);

        let abstract_instance =
            diea.get_abstract_instance().expect("head has DW_AT_abstract_origin");
        assert_eq!(abstract_instance.get_offsets(), vec![0x20, 0x30]);

        // No DW_AT_abstract_origin anywhere in the aggregate => not split.
        let plain = comp_unit();
        let d = die(&plain, 0x10, 0, DW_TAG_SUBPROGRAM, vec![]);
        assert!(DIEAggregate::create_single(&d).get_abstract_instance().is_none());
    }

    #[test]
    fn dangling_declaration_is_a_lone_fragment_with_dw_at_declaration() {
        let cu = comp_unit();
        let d = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtDeclaration, DWARFForm::DwFormFlag, flag(true))],
        );

        let diea = DIEAggregate::create_single(&d);

        assert!(diea.is_partial_declaration());
        assert!(diea.is_dangling_declaration());
    }

    #[test]
    fn typed_attribute_lookups_fall_back_to_the_default_when_the_type_does_not_match() {
        let cu = comp_unit();
        let d = die(
            &cu,
            0x10,
            0,
            DW_TAG_VARIABLE,
            vec![
                (DWARFAttributeId::DwAtByteSize, DWARFForm::DwFormData1, num(42)),
                (DWARFAttributeId::DwAtName, DWARFForm::DwFormString, string("x")),
                (DWARFAttributeId::DwAtExternal, DWARFForm::DwFormFlag, flag(true)),
            ],
        );
        let diea = DIEAggregate::create_single(&d);

        assert_eq!(diea.get_long(DWARFAttributeId::DwAtByteSize, -1), 42);
        assert_eq!(diea.get_unsigned_long(DWARFAttributeId::DwAtByteSize, -1), 42);
        assert_eq!(diea.get_name(), Some("x".to_string()));
        assert!(diea.get_bool(DWARFAttributeId::DwAtExternal, false));
        assert!(diea.has_attribute(DWARFAttributeId::DwAtName));

        // Missing attribute -> the supplied default.
        assert_eq!(diea.get_long(DWARFAttributeId::DwAtLowPc, -7), -7);
        assert!(!diea.get_bool(DWARFAttributeId::DwAtDeclaration, false));
        assert_eq!(diea.get_string(DWARFAttributeId::DwAtProducer), None);
        assert!(!diea.has_attribute(DWARFAttributeId::DwAtLowPc));

        // Present, but the wrong value type -> also the default.
        assert_eq!(diea.get_long(DWARFAttributeId::DwAtName, -7), -7);
        assert_eq!(diea.get_string(DWARFAttributeId::DwAtByteSize), None);
    }

    #[test]
    fn parse_methods_reject_values_outside_the_32_bit_range() {
        let cu = comp_unit();
        let d = die(
            &cu,
            0x10,
            0,
            DW_TAG_VARIABLE,
            vec![
                (DWARFAttributeId::DwAtByteSize, DWARFForm::DwFormData1, num(42)),
                (DWARFAttributeId::DwAtBitSize, DWARFForm::DwFormData8, num(0x1_0000_0000)),
                (DWARFAttributeId::DwAtName, DWARFForm::DwFormString, string("x")),
            ],
        );
        let diea = DIEAggregate::create_single(&d);

        assert_eq!(diea.parse_int(DWARFAttributeId::DwAtByteSize, -1).unwrap(), 42);
        // Missing attribute -> the default, not an error.
        assert_eq!(diea.parse_int(DWARFAttributeId::DwAtLowPc, -1).unwrap(), -1);
        assert_eq!(
            diea.parse_int(DWARFAttributeId::DwAtBitSize, -1).unwrap_err().to_string(),
            "Value out of allowed range: 4294967296"
        );
        // A string attribute is not an integer attribute.
        assert!(diea.parse_int(DWARFAttributeId::DwAtName, -1).is_err());

        // parseUnsignedLong is a long, so the same value is fine there...
        assert_eq!(
            diea.parse_unsigned_long(DWARFAttributeId::DwAtBitSize, -1).unwrap(),
            0x1_0000_0000
        );
        // ...but parseDataMemberOffset is an int again.
        assert_eq!(diea.parse_data_member_offset(DWARFAttributeId::DwAtByteSize, -1).unwrap(), 42);
        assert!(diea.parse_data_member_offset(DWARFAttributeId::DwAtBitSize, -1).is_err());
    }

    #[test]
    fn pc_range_treats_a_non_addr_high_pc_as_a_length() {
        let cu = comp_unit();
        // DW_FORM_data8 high_pc is a *length* past low_pc.
        let length_form = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![
                (DWARFAttributeId::DwAtLowPc, DWARFForm::DwFormAddr, num(0x1000)),
                (DWARFAttributeId::DwAtHighPc, DWARFForm::DwFormData8, num(0x20)),
            ],
        );
        // DW_FORM_addr high_pc is an absolute address.
        let addr_form = die(
            &cu,
            0x20,
            1,
            DW_TAG_SUBPROGRAM,
            vec![
                (DWARFAttributeId::DwAtLowPc, DWARFForm::DwFormAddr, num(0x1000)),
                (DWARFAttributeId::DwAtHighPc, DWARFForm::DwFormAddr, num(0x1234)),
            ],
        );
        // No high_pc: the range collapses to low_pc..low_pc.
        let low_only = die(
            &cu,
            0x30,
            2,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtLowPc, DWARFForm::DwFormAddr, num(0x1000))],
        );
        // No low_pc at all.
        let neither = die(&cu, 0x40, 3, DW_TAG_SUBPROGRAM, vec![]);
        install(
            &cu,
            MockContainer {
                dies: vec![length_form, addr_form, low_only, neither],
                ..MockContainer::default()
            },
        );
        let container = cu.container.get().unwrap();

        let pc_range =
            |index| DIEAggregate::create_single(container.die_at(index)).get_pc_range();
        assert_eq!(pc_range(0), DWARFRange::new(0x1000, 0x1020));
        assert_eq!(pc_range(1), DWARFRange::new(0x1000, 0x1234));
        assert_eq!(pc_range(2), DWARFRange::new(0x1000, 0x1000));
        assert_eq!(pc_range(3), DWARFRange::EMPTY);
    }

    #[test]
    fn pc_range_of_a_tombstoned_zero_low_pc_is_empty() {
        let cu = Arc::new(MockCompUnit {
            program: Some(Arc::new(TombstoneProgram)),
            ..MockCompUnit::default()
        });
        let d = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![
                (DWARFAttributeId::DwAtLowPc, DWARFForm::DwFormAddr, num(0)),
                (DWARFAttributeId::DwAtHighPc, DWARFForm::DwFormData8, num(0x20)),
            ],
        );
        install(&cu, MockContainer { dies: vec![d], ..MockContainer::default() });

        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        assert_eq!(diea.get_pc_range(), DWARFRange::EMPTY);
    }

    #[test]
    fn source_file_resolves_decl_file_through_the_compilation_units_line_table() {
        let cu = comp_unit_with_line("foo.c");
        let found = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtDeclFile, DWARFForm::DwFormData1, num(1))],
        );
        // File index 2 isn't in the (1-based, pre-DWARF5) table of one file.
        let missing = die(
            &cu,
            0x20,
            1,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtDeclFile, DWARFForm::DwFormData1, num(2))],
        );
        let no_attr = die(&cu, 0x30, 2, DW_TAG_SUBPROGRAM, vec![]);
        install(
            &cu,
            MockContainer { dies: vec![found, missing, no_attr], ..MockContainer::default() },
        );
        let container = cu.container.get().unwrap();

        let source_file =
            |index| DIEAggregate::create_single(container.die_at(index)).get_source_file();
        assert_eq!(source_file(0), Some("foo.c".to_string()));
        assert_eq!(source_file(1), None);
        assert_eq!(source_file(2), None);
    }

    /// A subprogram (index 0) with two children: a formal parameter (index 1) carrying
    /// `DW_AT_decl_line`, and a variable (index 2).
    pub(crate) fn family() -> Arc<MockCompUnit> {
        let cu = comp_unit();
        let parent = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtName, DWARFForm::DwFormString, string("parent"))],
        );
        let param = die(
            &cu,
            0x20,
            1,
            DW_TAG_FORMAL_PARAMETER,
            vec![(DWARFAttributeId::DwAtDeclLine, DWARFForm::DwFormData1, num(7))],
        );
        let variable = die(&cu, 0x30, 2, DW_TAG_VARIABLE, vec![]);
        install(
            &cu,
            MockContainer {
                dies: vec![parent, param, variable],
                parents: vec![(1, 0), (2, 0)],
                children: vec![(0, 1), (0, 2)],
                ..MockContainer::default()
            },
        );
        cu
    }

    #[test]
    fn children_are_filtered_by_tag_and_parents_resolve_through_the_container() {
        let cu = family();
        let container = cu.container.get().unwrap();
        let diea = DIEAggregate::create_single(container.die_at(1));

        let parent = diea.get_parent().expect("child DIE 1 has parent DIE 0");
        assert_eq!(parent.get_offset(), 0x10);
        assert_eq!(parent.get_name(), Some("parent".to_string()));
        // A single-fragment aggregate's decl parent is its parent.
        assert_eq!(diea.get_decl_parent().map(|p| p.get_offset()), Some(0x10));
        assert!(parent.get_parent().is_none());

        assert_eq!(parent.get_children(DWARFTag::of(DW_TAG_FORMAL_PARAMETER)).len(), 1);
        assert_eq!(parent.get_children(DWARFTag::of(DW_TAG_VARIABLE)).len(), 1);
        assert_eq!(parent.get_children(DWARFTag::of(0x99)).len(), 0);

        // findAncestor walks up until the tag matches, and stops at the root.
        assert_eq!(
            diea.find_ancestor(DWARFTag::of(DW_TAG_SUBPROGRAM)).map(|a| a.get_offset()),
            Some(0x10)
        );
        assert!(diea.find_ancestor(DWARFTag::of(DW_TAG_VARIABLE)).is_none());
    }

    #[test]
    fn attribute_in_children_falls_back_to_the_children_of_the_matching_tag() {
        let cu = family();
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        // DW_AT_decl_line is on the formal-parameter child, not on the subprogram itself.
        let decl_line = diea
            .find_attribute_in_children::<DWARFNumericAttribute>(
                DWARFAttributeId::DwAtDeclLine,
                DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
            )
            .expect("the formal parameter child carries DW_AT_decl_line");
        assert_eq!(decl_line.get_unsigned_value(), 7);

        // ...and the variable child doesn't have it.
        assert!(diea
            .find_attribute_in_children::<DWARFNumericAttribute>(
                DWARFAttributeId::DwAtDeclLine,
                DWARFTag::of(DW_TAG_VARIABLE),
            )
            .is_none());
    }

    #[test]
    fn function_param_list_collects_the_formal_parameter_children() {
        let cu = family();
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        let params = diea.get_function_param_list();

        assert_eq!(params.len(), 1);
        assert_eq!(params[0].get_offset(), 0x20);
    }

    #[test]
    fn location_list_and_range_list_come_from_the_container() {
        let cu = comp_unit();
        let d = die(&cu, 0x10, 0, DW_TAG_SUBPROGRAM, vec![]);
        install(
            &cu,
            MockContainer {
                dies: vec![d],
                location_list: Some(DWARFLocationList::new(vec![DWARFLocation::from_bounds(
                    0x1000,
                    0x1010,
                    vec![0x9c],
                )])),
                range_list: Some(DWARFRangeList::new(vec![DWARFRange::new(0x1000, 0x1010)])),
                ..MockContainer::default()
            },
        );
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        assert!(!diea.get_location_list(DWARFAttributeId::DwAtLocation).unwrap().is_empty());
        assert_eq!(
            diea.get_location(DWARFAttributeId::DwAtLocation, 0x1008).unwrap(),
            Some(DWARFLocation::from_bounds(0x1000, 0x1010, vec![0x9c]))
        );
        // No location covers this pc.
        assert_eq!(diea.get_location(DWARFAttributeId::DwAtLocation, 0x2000).unwrap(), None);

        let ranges = diea.get_range_list(DWARFAttributeId::DwAtRanges).unwrap();
        assert_eq!(ranges.get(0), Some(&DWARFRange::new(0x1000, 0x1010)));
    }

    #[test]
    fn ref_attributes_resolve_through_the_container_by_offset() {
        let cu = comp_unit();
        let source = die(
            &cu,
            0x10,
            0,
            DW_TAG_VARIABLE,
            vec![
                (DWARFAttributeId::DwAtType, DWARFForm::DwFormRef4, num(0x20)),
                (DWARFAttributeId::DwAtContainingType, DWARFForm::DwFormRef4, num(0x20)),
            ],
        );
        let target = die(
            &cu,
            0x20,
            1,
            DW_TAG_SUBPROGRAM,
            vec![(DWARFAttributeId::DwAtName, DWARFForm::DwFormString, string("int"))],
        );
        install(&cu, MockContainer { dies: vec![source, target], ..MockContainer::default() });
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        assert_eq!(diea.get_type_ref().and_then(|r| r.get_name()), Some("int".to_string()));
        assert_eq!(diea.get_containing_type_ref().map(|r| r.get_offset()), Some(0x20));
        // No DW_AT_specification on this DIE.
        assert!(diea.get_ref(DWARFAttributeId::DwAtSpecification).is_none());
    }

    #[test]
    fn display_lists_every_fragment_offset_then_dumps_each_die() {
        let cu = comp_unit();
        let d = die(&cu, 0x10, 0, DW_TAG_SUBPROGRAM, vec![]);
        let diea = DIEAggregate::create_single(&d);

        assert_eq!(diea.to_string(), format!("DIEAgregrate of: DIE [0x10], \n{d}"));
    }

    #[test]
    fn equality_compares_the_fragment_lists() {
        let cu = comp_unit();
        let d = die(&cu, 0x10, 0, DW_TAG_SUBPROGRAM, vec![]);
        let other = die(&cu, 0x20, 1, DW_TAG_SUBPROGRAM, vec![]);

        assert_eq!(DIEAggregate::create_single(&d), DIEAggregate::create_single(&d));
        assert_ne!(DIEAggregate::create_single(&d), DIEAggregate::create_single(&other));
    }
}

