//! Port of `ghidra.app.util.bin.format.dwarf.DWARFUtil`.
//!
//! The Java class holds only `public static` helpers (no instance fields, no instance methods),
//! so per this crate's shape rules it ports to a plain module of free functions and constants --
//! there is no `struct DWARFUtil`.
//!
//! # What isn't ported
//!
//! `toString(Class<?>, int)`, `toString(Class<?>, long)`, and
//! `getStaticFinalFieldWithValue(Class<?>, long)` use Java reflection (`Class.getDeclaredFields`,
//! `Field.getLong`) to find the symbolic name of a numeric DWARF constant by scanning a class's
//! `public static final` fields -- a pre-`enum`-era trick with no Rust equivalent (Rust has no
//! runtime reflection over `impl` blocks/associated consts). The eight in-repo callers
//! (`DWARFEncoding`, `DWARFEndianity`, `DWARFImportSummary`, `DWARFLocationListEntry`,
//! `DWARFRangeListEntry`, `DWARFUnitHeader`, `DWARFLineNumberExtendedOpcodes`,
//! `DWARFLineNumberStandardOpcodes`) are all themselves still `TODO` in `PORT_MANIFEST.tsv`, so
//! nothing currently in this crate calls the omitted surface.

use std::io;
use std::sync::Arc;

use regex::Regex;

use crate::app::cmd::comments::AppendCommentCmd;
use crate::format::dwarf::debug_info_entry::DebugInfoEntry;
use crate::format::dwarf::die_aggregate::DIEAggregate;
use crate::format::seam_stubs::{DWARFNumericAttribute, DWARFTag};
use crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId;
use crate::framework::cmd::Command;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::address::{Address, AddressSpaceType};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::function::THIS_PARAM_NAME;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::Varnode;

/// Raw DWARF tag ids referenced by this module (mirrors the statically-imported
/// `DWARFTag.DW_TAG_*` constants in the Java source). See [`DWARFTag`]'s own doc comment for why
/// this crate's `DWARFTag` stub only stores a raw id rather than a named enum variant.
const DW_TAG_MEMBER: i32 = 0xd;
const DW_TAG_POINTER_TYPE: i32 = 0xf;
const DW_TAG_TYPEDEF: i32 = 0x16;
const DW_TAG_INHERITANCE: i32 = 0x1c;
const DW_TAG_SUBPROGRAM: i32 = 0x2e;

/// A dummy zero-sized receiver used purely to invoke [`DataTypeUtilities`]'s default methods, per
/// that trait's own documented convention (see e.g. `category_db.rs`'s identical `Utils`).
struct Utils;
impl DataTypeUtilities for Utils {}

/// Java's `String.hashCode()`: `s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]` over UTF-16 code
/// units. Used by [`get_struct_layout_fingerprint`] to reproduce
/// `List<String>.hashCode()` exactly.
fn java_string_hash_code(s: &str) -> i32 {
    let mut hash: i32 = 0;
    for unit in s.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(unit as i32);
    }
    hash
}

/// Java's `AbstractList.hashCode()`: `hashCode = 1; for (E e : this) hashCode = 31*hashCode +
/// (e==null ? 0 : e.hashCode())`, specialized to a list of (non-null) `String`s.
fn java_list_hash_code(items: &[String]) -> i32 {
    let mut hash: i32 = 1;
    for item in items {
        hash = hash.wrapping_mul(31).wrapping_add(java_string_hash_code(item));
    }
    hash
}

/// A lightweight attempt to get nesting (ie. namespaces and such) information from gnu mangled
/// name strings.
///
/// For example, `"_ZN19class1_inline_funcs3fooEv"` -> `["class1_inline_funcs", "foo"]`.
///
/// Port of `DWARFUtil.parseMangledNestings(String)`.
pub fn parse_mangled_nestings(s: &str) -> Vec<String> {
    let mut results = Vec::new();

    let re = Regex::new(r"^(?:.*_Z)?N([0-9]+.*)$").unwrap();
    let Some(caps) = re.captures(s) else {
        return results;
    };
    let Some(group) = caps.get(1) else {
        return results;
    };

    let chars: Vec<char> = group.as_str().chars().collect();
    let mut cp = 0usize;
    while cp < chars.len() {
        let start = cp;
        while cp < chars.len() && chars[cp].is_ascii_digit() {
            cp += 1;
        }
        if start == cp {
            break;
        }
        let Ok(len) = chars[start..cp].iter().collect::<String>().parse::<usize>() else {
            break;
        };
        if cp + len <= chars.len() {
            results.push(chars[cp..cp + len].iter().collect());
        }
        cp += len;
    }
    results
}

/// Try to find gnu mangled name nesting info in a DIE's children's linkage strings.
///
/// Returns a list of nesting names, ending with what should be the DIE parameter's name.
///
/// Port of `DWARFUtil.findLinkageNameInChildren(DebugInfoEntry)`.
pub fn find_linkage_name_in_children(die: &DebugInfoEntry) -> Vec<String> {
    for child_die in die.get_children_with_tag(DWARFTag::of(DW_TAG_SUBPROGRAM)) {
        let Some(container) = die.get_container() else {
            continue;
        };
        let child_diea = container.get_aggregate(child_die);
        let linkage = child_diea
            .get_string(DWARFAttributeId::DwAtLinkageName)
            .or_else(|| child_diea.get_string(DWARFAttributeId::DwAtMipsLinkageName));

        if let Some(linkage) = linkage {
            let mut nestings = parse_mangled_nestings(&linkage);
            if !nestings.is_empty() {
                nestings.pop();
                return nestings;
            }
        }
    }
    Vec::new()
}

/// Determines if a name is a C++ style templated name. If so, returns just the base portion of
/// the name. The name must have a start and end angle bracket: `<` and `>`.
///
/// `operator<()` and `operator<<()` are handled so their angle brackets don't trigger the
/// template start/end angle bracket incorrectly.
///
/// Port of `DWARFUtil.getTemplateBaseName(String)`.
pub fn get_template_base_name(name: &str) -> Option<String> {
    const OPERATOR_LT_STR: &str = "operator<";
    const OPERATOR_LSHIFT_STR: &str = "operator<<";

    let search_start = if name.starts_with(OPERATOR_LSHIFT_STR) {
        OPERATOR_LSHIFT_STR.len()
    } else if name.starts_with(OPERATOR_LT_STR) {
        OPERATOR_LT_STR.len()
    } else {
        0
    };

    let start_of_template = name[search_start..].find('<').map(|i| i + search_start);
    match start_of_template {
        Some(start) if start > 0 && name.contains('>') => Some(name[..start].trim().to_string()),
        _ => None,
    }
}

/// Creates a name for anon types based on their position in their parent's child list.
///
/// Port of `DWARFUtil.getAnonNameForMeFromParentContext(DIEAggregate)`.
///
/// # Panics
/// Mirrors the Java method's `RuntimeException` when `diea` cannot be found in its own parent's
/// list of children -- a should-never-happen internal-consistency failure, not a normal error
/// path.
pub fn get_anon_name_for_me_from_parent_context(diea: &DIEAggregate) -> Option<String> {
    let parent = diea.get_head_fragment().get_parent()?;

    let mut type_def_count = 0i32;
    for child_die in parent.get_children() {
        let Some(container) = diea.get_die_container() else {
            continue;
        };
        let child_diea = container.get_aggregate(child_die);
        if diea.get_offset() == child_diea.get_offset() {
            let tag = child_diea.get_tag().expect("DWARFUtil: DIE has no tag");
            return Some(format!("anon_{}_{}", tag.get_container_type_name(), type_def_count));
        }
        if child_diea.get_tag().map(|t| t.is_named_type()).unwrap_or(false) {
            type_def_count += 1;
        }
    }
    panic!(
        "Could not find child in parent's list of children: child:\n{}\nparent:\n{}",
        diea, parent
    );
}

/// Creates a name for anon types based on the names of sibling entries that are using the anon
/// type (example: `"anon_struct_for_field1_field2"`). Falls back to
/// [`get_anon_name_for_me_from_parent_context`] if no siblings found.
///
/// Port of `DWARFUtil.getAnonNameForMeFromParentContext2(DIEAggregate)`.
pub fn get_anon_name_for_me_from_parent_context2(diea: &DIEAggregate) -> Option<String> {
    let parent = diea.get_head_fragment().get_parent()?;

    let mut users: Vec<String> = Vec::new();
    for child_die in parent.get_children() {
        let Some(container) = diea.get_die_container() else {
            continue;
        };
        let child_diea = container.get_aggregate(child_die);
        let child_name = child_diea.get_name();
        let type_ref = child_diea.get_type_ref();
        if let (Some(type_ref), Some(child_name)) = (type_ref, child_name) {
            if type_ref.get_offset() == diea.get_offset() {
                users.push(child_name);
            }
        }
    }
    users.sort();
    if users.is_empty() {
        return get_anon_name_for_me_from_parent_context(diea);
    }

    let tag = diea.get_tag().expect("DWARFUtil: DIE has no tag");
    Some(format!("anon_{}_for_{}", tag.get_container_type_name(), users.join("_")))
}

/// Creates a fingerprint of the layout of an (anonymous) structure using its size, number of
/// members, and the hashcode of the member field names.
///
/// Returns a formatted string, example `"80_5_73dc6de9"` (80 bytes, 5 fields, hex hash of field
/// names).
///
/// Port of `DWARFUtil.getStructLayoutFingerprint(DIEAggregate)`.
pub fn get_struct_layout_fingerprint(diea: &DIEAggregate) -> String {
    let struct_size = diea.get_unsigned_long(DWARFAttributeId::DwAtByteSize, 0);
    let mut member_count = 0i32;
    let mut member_names: Vec<String> = Vec::new();

    for child_entry in diea.get_head_fragment().get_children() {
        let tag = child_entry.get_tag();
        if tag != Some(DWARFTag::of(DW_TAG_MEMBER)) && tag != Some(DWARFTag::of(DW_TAG_INHERITANCE)) {
            continue;
        }
        let Some(container) = diea.get_die_container() else {
            continue;
        };
        let child_diea = container.get_aggregate(child_entry);
        if child_diea.has_attribute(DWARFAttributeId::DwAtExternal) {
            continue;
        }
        member_count += 1;

        let member_offset = child_diea
            .parse_data_member_offset(DWARFAttributeId::DwAtDataMemberLocation, 0)
            .unwrap_or(0);
        let member_name = child_diea
            .get_name()
            .unwrap_or_else(|| format!("UNNAMED_MEMBER_{member_count}"));
        member_names.push(format!("{:04x}_{}", member_offset, member_name));
    }

    member_names.sort();
    format!(
        "{}_{}_{:08x}",
        struct_size,
        member_count,
        java_list_hash_code(&member_names) as u32
    )
}

/// Append a string to a [`DataType`]'s description.
///
/// Port of `DWARFUtil.appendDescription(DataType, String, String)`.
pub fn append_description(dt: &mut dyn DataType, description: Option<&str>, sep: &str) {
    let Some(description) = description.filter(|d| !d.is_empty()) else {
        return;
    };
    let mut prev = dt.get_description();
    if !prev.is_empty() {
        prev.push_str(sep);
    }
    prev.push_str(description);
    let _ = dt.set_description(&prev);
}

/// Append a string to a description of a field in a structure.
///
/// The crate's [`DataTypeComponent`](crate::program::model::data::data_type_component::DataTypeComponent)
/// models `setComment` as a pure `&self -> Box<dyn DataTypeComponent>` update rather than an
/// in-place mutation (see that trait's own docs), so unlike the Java `void` method, this returns
/// the updated component when a description was actually appended -- `None` when `description`
/// was empty/`None`, mirroring Java's no-op in that case.
///
/// Port of `DWARFUtil.appendDescription(DataTypeComponent, String, String)`.
pub fn append_description_to_component(
    dtc: &dyn crate::program::model::data::data_type_component::DataTypeComponent,
    description: Option<&str>,
    sep: &str,
) -> Option<Box<dyn crate::program::model::data::data_type_component::DataTypeComponent>> {
    let description = description.filter(|d| !d.is_empty())?;
    let mut prev = dtc.get_comment().unwrap_or_default();
    if !prev.is_empty() {
        prev.push_str(sep);
    }
    prev.push_str(description);
    Some(dtc.set_comment(Some(prev)))
}

/// Port of the private `DWARFUtil`/`AppendCommentCmd.getCodeUnit`-style lookup, shared by
/// [`append_comment`] here and by [`AppendCommentCmd`]'s own (independent, matching Java's actual
/// code duplication) copy of the same logic.
///
/// Port of `DWARFUtil.getCodeUnitForComment(Program, Address)`.
pub fn get_code_unit_for_comment(
    program: &mut (dyn Program + 'static),
    address: &Address,
) -> Option<Arc<dyn CodeUnit>> {
    let listing = program.get_listing()?;
    let cu = listing.get_code_unit_containing(address)?;
    let cu_addr = cu.get_min_address();
    if let Some(data) = cu.as_data() {
        if *address != cu_addr {
            let offset = address.subtract(&cu_addr) as i32;
            let primitive = data.get_primitive_at(offset)?;
            return Some(Arc::from(primitive as Box<dyn CodeUnit>));
        }
    }
    Some(cu)
}

/// Port of `DWARFUtil.appendComment(Program, Address, CommentType, String, String, String)`.
pub fn append_comment(
    program: &mut (dyn Program + 'static),
    address: Address,
    comment_type: CommentType,
    prefix: Option<&str>,
    comment: Option<&str>,
    sep: &str,
) {
    let Some(comment) = comment.filter(|c| !c.trim().is_empty()) else {
        return;
    };

    if let Some(cu) = get_code_unit_for_comment(program, &address) {
        if let Some(existing_comment) = cu.get_comment(comment_type) {
            if existing_comment.contains(comment) {
                // don't add same comment twice
                return;
            }
        }
    }

    let mut cmd = AppendCommentCmd::new(
        address,
        comment_type,
        format!("{}{}", prefix.unwrap_or(""), comment),
        sep,
    );
    cmd.apply_to(program);
}

/// Port of `DWARFUtil.isThisParam(DIEAggregate)`.
///
/// # Panics
/// Mirrors Java's `NullPointerException` when `paramDIEA` has no parent (a `DW_TAG_formal_parameter`
/// is always expected to have an enclosing subprogram DIE).
pub fn is_this_param(param_diea: &DIEAggregate) -> bool {
    // DWARF has multiple ways of indicating a DW_TAG_formal_parameter is the "this" parameter,
    // and different versions of different toolchains can express this differently. We check the
    // most common method (param named "this" or marked artificial) first, and then check the
    // object_pointer property of the parent function.
    let param_name = param_diea.get_name();
    if param_diea.get_bool(DWARFAttributeId::DwAtArtificial, false)
        || param_name.as_deref() == Some(THIS_PARAM_NAME)
    {
        return true;
    }

    let func_diea = param_diea
        .get_parent()
        .expect("DWARFUtil.isThisParam: paramDIEA has no parent (mirrors Java NPE)");
    if let Some(dnum) = func_diea.find_value::<DWARFNumericAttribute>(DWARFAttributeId::DwAtObjectPointer)
    {
        if param_diea.has_offset(dnum.get_unsigned_value() as u64) {
            return true;
        }
    }

    // If the variable is not named, check to see if the parent of the function is a
    // struct/class, and the parameter points to it.
    let class_diea = func_diea.get_parent();
    if param_name.is_none() {
        if let Some(class_diea) = &class_diea {
            if class_diea.get_tag().map(|t| t.is_structure_type()).unwrap_or(false) {
                return is_pointer_to(class_diea, param_diea.get_type_ref().as_ref());
            }
        }
    }

    false
}

/// Port of `DWARFUtil.isPointerTo(DIEAggregate, DIEAggregate)`.
pub fn is_pointer_to(target_diea: &DIEAggregate, test_diea: Option<&DIEAggregate>) -> bool {
    let Some(test_diea) = test_diea else {
        return false;
    };
    test_diea.get_tag() == Some(DWARFTag::of(DW_TAG_POINTER_TYPE))
        && test_diea.get_type_ref().map(|t| t.get_offset()) == Some(target_diea.get_offset())
}

/// Port of `DWARFUtil.isPointerDataType(DIEAggregate)`.
///
/// # Panics
/// Mirrors Java's `NullPointerException` if a `DW_TAG_typedef` has no type reference.
pub fn is_pointer_data_type(diea: &DIEAggregate) -> bool {
    let mut current = diea.clone();
    while current.get_tag() == Some(DWARFTag::of(DW_TAG_TYPEDEF)) {
        current = current
            .get_type_ref()
            .expect("DWARFUtil.isPointerDataType: typedef has no type ref (mirrors Java NPE)");
    }
    current.get_tag() == Some(DWARFTag::of(DW_TAG_POINTER_TYPE))
}

/// Returns a file that has been referenced in the specified [`Language`]'s ldefs description via
/// an `<external_name tool="name" name="value"/>` entry.
///
/// Port of `DWARFUtil.getLanguageExternalFile(Language, String)`.
pub fn get_language_external_file(lang: &dyn Language, name: &str) -> io::Result<Option<ResourceFile>> {
    let Some(filename) = get_language_external_name_value(lang, name)? else {
        return Ok(None);
    };
    let dir = get_language_definition_directory(lang)?;
    Ok(Some(dir.join(&filename)))
}

/// Returns the base directory of a language definition.
///
/// Port of `DWARFUtil.getLanguageDefinitionDirectory(Language)`.
pub fn get_language_definition_directory(lang: &dyn Language) -> io::Result<ResourceFile> {
    let lang_desc = lang.get_language_description();
    let sld = lang_desc.as_sleigh().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Not a Sleigh Language: {}", lang.get_language_id()))
    })?;
    let defs_file = sld
        .get_defs_file()
        .expect("DWARFUtil.getLanguageDefinitionDirectory: SleighLanguageDescription has no .defs file (mirrors Java NPE)");
    Ok(defs_file
        .get_parent_file()
        .expect("DWARFUtil.getLanguageDefinitionDirectory: .defs file has no parent (mirrors Java NPE)"))
}

/// Returns a value specified in a [`Language`] definition via an
/// `<external_name tool="name" name="value"/>` entry.
///
/// Port of `DWARFUtil.getLanguageExternalNameValue(Language, String)`.
pub fn get_language_external_name_value(lang: &dyn Language, name: &str) -> io::Result<Option<String>> {
    let lang_desc = lang.get_language_description();
    if lang_desc.as_sleigh().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a Sleigh Language: {}", lang.get_language_id()),
        ));
    }

    let values = lang_desc.get_external_names(name);
    let Some(values) = values.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Multiple external name values for {} found in language {}",
                name,
                lang.get_language_id()
            ),
        ));
    }
    Ok(Some(values[0].clone()))
}

/// Packs `original` using its default packing if doing so produces a byte-for-byte identical
/// layout (same length, same component offsets/lengths/bitfield-ness). Used to shrink an
/// explicitly-laid-out structure down to a packed equivalent without silently changing its
/// layout.
///
/// Port of `DWARFUtil.packCompositeIfPossible(Composite, DataTypeManager)`.
pub fn pack_composite_if_possible(original: &mut dyn Composite, dtm: &dyn DataTypeManager) {
    if original.is_zero_length() || original.get_num_defined_components() == 0 {
        // don't try to pack empty structs, this would throw off conflict-handler logic. also
        // don't pack sized structs with no fields because when packed down to 0 bytes they cause
        // errors when used as a param type.
        return;
    }

    let mut copy_dt = original.clone_data_type(dtm);
    let Some(copy) = copy_dt.as_composite_mut() else {
        return;
    };
    copy.set_to_default_packing();
    if copy.get_length() != original.get_length() {
        // so far, typically because trailing zero-len flex array caused toolchain to bump struct
        // size to next alignment value in a way that doesn't mesh with ghidra's logic.
        return;
    }

    let pre_comps = original.get_defined_components();
    let post_comps = copy.get_defined_components();
    if pre_comps.len() != post_comps.len() {
        return;
    }
    for (pre_dtc, post_dtc) in pre_comps.iter().zip(post_comps.iter()) {
        if pre_dtc.get_offset() != post_dtc.get_offset()
            || pre_dtc.get_length() != post_dtc.get_length()
            || pre_dtc.is_bit_field_component() != post_dtc.is_bit_field_component()
        {
            return;
        }
        if pre_dtc.is_bit_field_component() {
            let pre_data_type = pre_dtc.get_data_type();
            let post_data_type = post_dtc.get_data_type();
            let (Some(pre_bf), Some(post_bf)) =
                (pre_data_type.as_bit_field_data_type(), post_data_type.as_bit_field_data_type())
            else {
                return;
            };
            if pre_bf.get_bit_offset() != post_bf.get_bit_offset()
                || pre_bf.get_bit_size() != post_bf.get_bit_size()
            {
                return;
            }
        }
    }

    original.set_to_default_packing();
}

/// Port of `DWARFUtil.convertRegisterListToVarnodeStorage(List<Register>, int)`.
///
/// # Panics
/// Mirrors Java's unchecked `AddressOutOfBoundsException` if a big-endian register's address
/// cannot be advanced by its unused byte count.
pub fn convert_register_list_to_varnode_storage(
    registers: &[Register],
    mut data_type_size: i32,
) -> Vec<Varnode> {
    let mut results = Vec::with_capacity(registers.len());
    for reg in registers {
        let reg_size = reg.minimum_byte_size();
        let bytes_used = data_type_size.min(reg_size);
        let mut addr = reg.address().clone();
        if reg.is_big_endian() && bytes_used < reg_size {
            addr = addr
                .add((reg_size - bytes_used) as i64)
                .expect("DWARFUtil.convertRegisterListToVarnodeStorage: address overflow");
        }
        results.push(Varnode::new(addr, bytes_used));
        data_type_size -= bytes_used;
    }
    results
}

/// Port of `DWARFUtil.isEmptyArray(DataType)`.
pub fn is_empty_array(dt: &dyn DataType) -> bool {
    dt.as_array().map(|array| array.get_num_elements() == 0).unwrap_or(false)
}

/// Port of `DWARFUtil.isVoid(DataType)`.
pub fn is_void(dt: &dyn DataType) -> bool {
    crate::program::seam_stubs::is_void_data_type(Some(dt))
}

/// Port of `DWARFUtil.isZeroByteDataType(DataType)`.
pub fn is_zero_byte_data_type(dt: &dyn DataType) -> bool {
    if is_void(dt) {
        return true;
    }
    if !dt.is_zero_length() {
        if let Some(array) = dt.as_array() {
            return Utils.get_array_base_data_type(array).is_zero_length();
        }
    }
    dt.is_zero_length()
}

/// Port of `DWARFUtil.isStackVarnode(Varnode)`.
pub fn is_stack_varnode(varnode: Option<&Varnode>) -> bool {
    varnode.is_some_and(|v| v.get_address().space().space_type() == AddressSpaceType::Stack)
}

/// Port of `DWARFUtil.isConstVarnode(Varnode)`.
pub fn is_const_varnode(varnode: Option<&Varnode>) -> bool {
    varnode.is_some_and(|v| v.get_address().space().space_type() == AddressSpaceType::Constant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mangled_nestings_splits_class_and_method() {
        let result = parse_mangled_nestings("_ZN19class1_inline_funcs3fooEv");
        assert_eq!(result, vec!["class1_inline_funcs".to_string(), "foo".to_string()]);
    }

    #[test]
    fn parse_mangled_nestings_returns_empty_for_non_matching_string() {
        assert!(parse_mangled_nestings("not_mangled").is_empty());
    }

    #[test]
    fn get_template_base_name_extracts_base() {
        assert_eq!(get_template_base_name("vector<int>"), Some("vector".to_string()));
    }

    #[test]
    fn get_template_base_name_none_when_no_brackets() {
        assert_eq!(get_template_base_name("plain_name"), None);
    }

    #[test]
    fn get_template_base_name_handles_operator_lshift() {
        // "operator<<" itself must not be mistaken for the start of a template.
        assert_eq!(get_template_base_name("operator<<"), None);
    }

    #[test]
    fn get_template_base_name_handles_operator_lt_with_real_template() {
        assert_eq!(
            get_template_base_name("operator<<Foo<int>>"),
            Some("operator<<Foo".to_string())
        );
    }

    #[test]
    fn java_string_hash_code_matches_known_values() {
        // Cross-checked against real java.lang.String.hashCode() output.
        assert_eq!(java_string_hash_code(""), 0);
        assert_eq!(java_string_hash_code("a"), 97);
        assert_eq!(java_string_hash_code("hello"), 99162322);
    }

    #[test]
    fn java_list_hash_code_matches_known_values() {
        // Cross-checked against real java.util.AbstractList.hashCode() output for
        // List.of("a", "b").
        assert_eq!(java_list_hash_code(&["a".to_string(), "b".to_string()]), 4066);
        assert_eq!(java_list_hash_code(&[]), 1);
    }

    #[test]
    fn is_void_and_is_empty_array_default_false_for_plain_data_type() {
        struct PlainDataType;
        impl DataType for PlainDataType {}
        assert!(!is_void(&PlainDataType));
        assert!(!is_empty_array(&PlainDataType));
    }

    #[test]
    fn is_stack_and_const_varnode_are_false_for_none() {
        assert!(!is_stack_varnode(None));
        assert!(!is_const_varnode(None));
    }

    #[test]
    fn is_stack_varnode_true_for_stack_address() {
        use crate::program::model::address::AddressSpace;
        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1);
        let addr = Address::new(stack_space, 0x10);
        let varnode = Varnode::new(addr, 4);
        assert!(is_stack_varnode(Some(&varnode)));
        assert!(!is_const_varnode(Some(&varnode)));
    }

    #[test]
    fn is_const_varnode_true_for_constant_address() {
        use crate::program::model::address::AddressSpace;
        let const_space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 2);
        let addr = Address::new(const_space, 5);
        let varnode = Varnode::new(addr, 4);
        assert!(is_const_varnode(Some(&varnode)));
        assert!(!is_stack_varnode(Some(&varnode)));
    }
}
