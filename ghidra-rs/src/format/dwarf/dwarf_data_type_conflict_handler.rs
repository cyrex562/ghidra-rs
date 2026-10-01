//! Port of `ghidra.app.util.bin.format.dwarf.DWARFDataTypeConflictHandler`.

use std::collections::HashSet;
use std::rc::Rc;

use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_conflict_handler::{ConflictResult, DataTypeConflictHandler};
use crate::program::model::data::function_definition::FunctionDefinition;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::union::Union;

/// This conflict handler attempts to match conflicting composite data types (structure or
/// union) when they have compatible data layouts. (Data types that are exactly equiv will not be
/// subjected to conflict handling and will never reach here.)
///
/// A default/empty sized structure, or structures with the same size are candidates for
/// matching. Structures that have a subset of the other's field definition are candidates for
/// matching.
///
/// When a candidate data type is matched with an existing data type, this conflict handler
/// specifies that the new data type is either discarded and replaced by the existing data type
/// ([`ConflictResult::UseExisting`]) or used to overwrite the existing data type
/// ([`ConflictResult::ReplaceExisting`]). Otherwise the new data type is kept, but renamed with
/// a `.conflictNNNN` suffix to make it unique ([`ConflictResult::RenameAndAdd`]).
///
/// NOTE: structures with alignment (instead of being statically laid out) are not treated
/// specially and will not match other aligned or non-aligned structures.
///
/// Port of `ghidra.app.util.bin.format.dwarf.DWARFDataTypeConflictHandler`; the Java singleton
/// `INSTANCE` is [`DWARFDataTypeConflictHandler::INSTANCE`].
///
/// Java tracks visited (existing, added) pairs by `System.identityHashCode`. Here a pair is keyed
/// by [`DataType::identity_key`], and every data type handle the comparison obtains (component,
/// typedef base, pointee, ...) is kept alive until the comparison finishes, so a dropped handle's
/// address can never be reused by a later handle and mistaken for an already-visited pair.
pub struct DWARFDataTypeConflictHandler {
    _private: (),
}

impl DWARFDataTypeConflictHandler {
    /// The singleton instance (`DWARFDataTypeConflictHandler.INSTANCE`).
    pub const INSTANCE: &'static DWARFDataTypeConflictHandler = &INSTANCE;

    /// `isSizeCompatible(Composite, Composite)`: true if `src` can overwrite the `target`
    /// composite based on size.
    fn is_size_compatible(src: &dyn Composite, target: &dyn Composite) -> bool {
        target.is_not_yet_defined() || src.get_length() == target.get_length()
    }

    /// `isCompositeDefault(Composite)`: whether the composite is either empty or has no defined
    /// components.
    fn is_composite_default(composite: &dyn Composite) -> bool {
        composite.is_not_yet_defined() || composite.get_num_defined_components() == 0
    }
}

static INSTANCE: DWARFDataTypeConflictHandler = DWARFDataTypeConflictHandler { _private: () };

/// The state of one `resolveConflict` call: Java's `visitedDataTypes` set, plus the handles that
/// keep every compared data type alive (see [`DWARFDataTypeConflictHandler`]).
struct Comparison {
    visited: HashSet<(usize, usize)>,
    held: Vec<Rc<dyn DataType>>,
}

impl Comparison {
    fn new() -> Self {
        Comparison { visited: HashSet::new(), held: Vec::new() }
    }

    /// Keeps `dt` alive for the rest of the comparison.
    fn hold(&mut self, dt: Box<dyn DataType>) -> Rc<dyn DataType> {
        let dt: Rc<dyn DataType> = Rc::from(dt);
        self.held.push(dt.clone());
        dt
    }

    /// `addVisited(DataType, DataType, Set<Long>)`: false if the pair was already visited.
    fn add_visited(&mut self, data_type1: &dyn DataType, data_type2: &dyn DataType) -> bool {
        self.visited.insert((data_type1.identity_key(), data_type2.identity_key()))
    }

    /// `isCompositePart(Composite, Composite, Set<Long>)`.
    fn is_composite_part(&mut self, full: &dyn Composite, part: &dyn Composite) -> bool {
        if let (Some(full), Some(part)) = (full.as_structure(), part.as_structure()) {
            self.is_structure_part(full, part)
        } else if let (Some(full), Some(part)) = (full.as_union(), part.as_union()) {
            self.is_union_part(full, part)
        } else {
            false
        }
    }

    /// `isUnionPart(Union, Union, Set<Long>)`: true if `part` is a subset of (or equal to)
    /// `full`.
    ///
    /// Each component of the candidate partial union must be present in the 'full' union and
    /// must be 'equiv'. Order of components is ignored, except for unnamed components, which
    /// receive a default name created using their ordinal position.
    fn is_union_part(&mut self, full: &dyn Union, part: &dyn Union) -> bool {
        if full.get_length() < part.get_length() {
            return false;
        }
        let full_components: Vec<(Option<String>, Box<dyn DataTypeComponent>)> = full
            .get_defined_components()
            .into_iter()
            .map(|dtc| (component_name(dtc.as_ref()), dtc))
            .collect();
        for dtc in part.get_defined_components() {
            let name = component_name(dtc.as_ref());
            // Java fills a HashMap by name, so the last component with a name wins.
            let Some((_, full_dtc)) = full_components.iter().rev().find(|(n, _)| *n == name) else {
                return false;
            };
            let part_dt = self.hold(dtc.get_data_type());
            let full_dt = self.hold(full_dtc.get_data_type());
            if self.do_relaxed_compare(part_dt.as_ref(), full_dt.as_ref()) == ConflictResult::RenameAndAdd {
                return false;
            }
        }
        true
    }

    /// `isStructurePart(Structure, Structure, Set<Long>)`: true if `part` is a partial
    /// definition of `full`.
    ///
    /// Each defined component in the candidate partial structure must be present in the 'full'
    /// structure and must be equiv. The order and sparseness of the candidate partial structure
    /// is not important, only that all of its defined components are present in the full
    /// structure.
    fn is_structure_part(&mut self, full: &dyn Structure, part: &dyn Structure) -> bool {
        // Both structures should be equal in length
        if full.get_length() != part.get_length() {
            return false;
        }
        for part_dtc in part.get_defined_components() {
            let part_dt = self.hold(part_dtc.get_data_type());
            if part_dt.is_zero_length() {
                // don't try to match zero length fields, so skip
                continue;
            }
            let full_dtc_at = if part_dt.as_bit_field_data_type().is_some() {
                get_bitfield_by_offsets(full, part_dtc.as_ref())
            } else {
                get_best_matching_dtc(full, part_dtc.as_ref())
            };
            let Some(full_dtc_at) = full_dtc_at else {
                return false;
            };
            if full_dtc_at.get_offset() != part_dtc.get_offset()
                || full_dtc_at.get_field_name() != part_dtc.get_field_name()
            {
                return false;
            }
            if !self.is_member_field_partially_compatible(full_dtc_at.as_ref(), part_dtc.as_ref()) {
                return false;
            }
        }
        true
    }

    /// `isMemberFieldPartiallyCompatible(DataTypeComponent, DataTypeComponent, Set<Long>)`.
    fn is_member_field_partially_compatible(
        &mut self,
        full_dtc: &dyn DataTypeComponent,
        part_dtc: &dyn DataTypeComponent,
    ) -> bool {
        let part_dt = self.hold(part_dtc.get_data_type());
        let full_dt = self.hold(full_dtc.get_data_type());
        match self.do_relaxed_compare(part_dt.as_ref(), full_dt.as_ref()) {
            // The data type of the field in the 'full' structure is completely different than
            // the field in the 'part' structure, therefore the candidate 'part' structure is not
            // a partial definition of the full struct
            ConflictResult::RenameAndAdd => false,
            // The field from the 'full' struct is the same or better than the field from the
            // 'part' structure if the components are size compatible. This is an intentionally
            // fuzzy match to allow structures with fields that are generally the same at a
            // binary level to match (e.g. the same structure defined in 2 separate compile units
            // with slightly different types for the field).
            ConflictResult::ReplaceExisting => full_dtc.get_length() >= part_dtc.get_length(),
            // the data type of the field in the 'full' structure is the same as or a better
            // version of the field in the 'part' structure.
            ConflictResult::UseExisting => true,
        }
    }

    /// `doStrictCompare(DataType, DataType, Set<Long>)`: compares its parameters; the contents
    /// of these data types (contents of structs, pointers, arrays) are compared with relaxed
    /// typedef checking.
    fn do_strict_compare(&mut self, added_data_type: &dyn DataType, existing_data_type: &dyn DataType) -> ConflictResult {
        if added_data_type.identity_key() == existing_data_type.identity_key()
            || !self.add_visited(existing_data_type, added_data_type)
        {
            return ConflictResult::UseExisting;
        }

        if let (Some(existing_composite), Some(added_composite)) =
            (existing_data_type.as_composite(), added_data_type.as_composite())
        {
            // Check to see if we are adding a default/empty data type
            if DWARFDataTypeConflictHandler::is_composite_default(added_composite)
                && DWARFDataTypeConflictHandler::is_size_compatible(existing_composite, added_composite)
            {
                return ConflictResult::UseExisting;
            }
            // Check to see if the existing type is a default/empty data type
            if DWARFDataTypeConflictHandler::is_composite_default(existing_composite)
                && DWARFDataTypeConflictHandler::is_size_compatible(added_composite, existing_composite)
            {
                return ConflictResult::ReplaceExisting;
            }
            // Check to see if the added type is part of the existing type first to generate
            // more USE_EXISTINGS when possible.
            if self.is_composite_part(existing_composite, added_composite) {
                return ConflictResult::UseExisting;
            }
            // Check to see if the existing type is a part of the added type
            if self.is_composite_part(added_composite, existing_composite) {
                return ConflictResult::ReplaceExisting;
            }
            return ConflictResult::RenameAndAdd;
        }

        if let (Some(existing_typedef), Some(added_typedef)) =
            (existing_data_type.as_typedef(), added_data_type.as_typedef())
        {
            let added_base = self.hold(added_typedef.get_base_data_type());
            let existing_base = self.hold(existing_typedef.get_base_data_type());
            return self.do_relaxed_compare(added_base.as_ref(), existing_base.as_ref());
        }

        if let (Some(existing_array), Some(added_array)) =
            (existing_data_type.as_array(), added_data_type.as_array())
        {
            if added_array.get_num_elements() != existing_array.get_num_elements()
                || added_array.get_element_length() != existing_array.get_element_length()
            {
                return ConflictResult::RenameAndAdd;
            }
            let added_element = self.hold(added_array.get_data_type());
            let existing_element = self.hold(existing_array.get_data_type());
            return self.do_relaxed_compare(added_element.as_ref(), existing_element.as_ref());
        }

        if let (Some(existing_pointer), Some(added_pointer)) =
            (existing_data_type.as_pointer(), added_data_type.as_pointer())
        {
            // Java's getDataType() is null for a pointer to nothing; two such pointers compare
            // as the same (null == null), one against a typed pointer does not.
            return match (added_pointer.get_data_type(), existing_pointer.get_data_type()) {
                (None, None) => ConflictResult::UseExisting,
                (Some(added), Some(existing)) => {
                    let added = self.hold(added);
                    let existing = self.hold(existing);
                    self.do_relaxed_compare(added.as_ref(), existing.as_ref())
                }
                _ => ConflictResult::RenameAndAdd,
            };
        }

        if let (Some(existing_func), Some(added_func)) =
            (existing_data_type.as_function_definition(), added_data_type.as_function_definition())
        {
            return self.compare_func_def(added_func, existing_func);
        }

        if let (Some(existing_bf), Some(added_bf)) =
            (existing_data_type.as_bit_field_data_type(), added_data_type.as_bit_field_data_type())
        {
            if existing_bf.get_declared_bit_size() != added_bf.get_declared_bit_size() {
                return ConflictResult::RenameAndAdd;
            }
            return if existing_bf
                .get_primitive_base_data_type()
                .is_equivalent(added_bf.get_primitive_base_data_type().as_ref())
            {
                ConflictResult::UseExisting
            } else {
                ConflictResult::RenameAndAdd
            };
        }

        if existing_data_type.is_equivalent(added_data_type) {
            return ConflictResult::UseExisting;
        }

        ConflictResult::RenameAndAdd
    }

    /// `compareFuncDef(FunctionDefinition, FunctionDefinition, Set<Long>)`.
    fn compare_func_def(&mut self, added_func: &dyn FunctionDefinition, existing_func: &dyn FunctionDefinition) -> ConflictResult {
        let added_return = self.hold(added_func.get_return_type());
        let existing_return = self.hold(existing_func.get_return_type());
        if self.do_relaxed_compare(added_return.as_ref(), existing_return.as_ref()) == ConflictResult::RenameAndAdd {
            return ConflictResult::RenameAndAdd;
        }
        let added_args = added_func.get_arguments();
        let existing_args = existing_func.get_arguments();
        if added_args.len() != existing_args.len() {
            return ConflictResult::RenameAndAdd;
        }
        for (added_param, existing_param) in added_args.iter().zip(existing_args.iter()) {
            let added = self.hold(added_param.get_data_type());
            let existing = self.hold(existing_param.get_data_type());
            if self.do_relaxed_compare(added.as_ref(), existing.as_ref()) == ConflictResult::RenameAndAdd {
                return ConflictResult::RenameAndAdd;
            }
        }
        ConflictResult::UseExisting
    }

    /// `doRelaxedCompare(DataType, DataType, Set<Long>)`: skips typedefs (possibly
    /// asymmetrically) to compare the types they hide. This is useful when comparing types that
    /// were embedded in differently compiled files, where you might end up with a raw basetype in
    /// one file and a typedef to a basetype in another file.
    fn do_relaxed_compare(&mut self, added_data_type: &dyn DataType, existing_data_type: &dyn DataType) -> ConflictResult {
        if let Some(typedef) = added_data_type.as_typedef() {
            let base = self.hold(typedef.get_base_data_type());
            return self.do_relaxed_compare(base.as_ref(), existing_data_type);
        }
        if let Some(typedef) = existing_data_type.as_typedef() {
            let base = self.hold(typedef.get_base_data_type());
            return self.do_relaxed_compare(added_data_type, base.as_ref());
        }
        self.do_strict_compare(added_data_type, existing_data_type)
    }
}

/// A component's field name, or its default field name when unnamed (Java's
/// `getFieldName() == null ? getDefaultFieldName() : getFieldName()`).
fn component_name(dtc: &dyn DataTypeComponent) -> Option<String> {
    dtc.get_field_name().or_else(|| dtc.get_default_field_name())
}

/// `getBestMatchingDTC(Structure, DataTypeComponent)`: the non-zero-length component of
/// `structure` starting at `match_criteria`'s offset.
fn get_best_matching_dtc(
    structure: &dyn Structure,
    match_criteria: &dyn DataTypeComponent,
) -> Option<Box<dyn DataTypeComponent>> {
    structure
        .get_components_containing(match_criteria.get_offset())
        .into_iter()
        .find(|dtc| dtc.get_offset() == match_criteria.get_offset() && !dtc.get_data_type().is_zero_length())
}

/// `getBitfieldByOffsets(Structure, DataTypeComponent)`: the bitfield component of `full` at the
/// same byte offset, bit offset and bit size as `part_dtc`'s bitfield.
fn get_bitfield_by_offsets(full: &dyn Structure, part_dtc: &dyn DataTypeComponent) -> Option<Box<dyn DataTypeComponent>> {
    let part_dt = part_dtc.get_data_type();
    let part_bf = part_dt.as_bit_field_data_type()?;
    let first = full.get_component_containing(part_dtc.get_offset())?;
    let full_num_comp = full.get_num_components();
    for full_ordinal in first.get_ordinal()..full_num_comp {
        let full_dtc = Structure::get_component(full, full_ordinal).ok()?;
        let full_dt = full_dtc.get_data_type();
        let Some(full_bf) = full_dt.as_bit_field_data_type() else {
            break;
        };
        if full_dtc.get_offset() > part_dtc.get_offset() {
            break;
        }
        if full_dtc.get_offset() == part_dtc.get_offset()
            && full_bf.get_bit_offset() == part_bf.get_bit_offset()
            && full_bf.get_bit_size() == part_bf.get_bit_size()
        {
            return Some(full_dtc);
        }
    }
    None
}

impl DataTypeConflictHandler for DWARFDataTypeConflictHandler {
    fn resolve_conflict(&self, added_data_type: &dyn DataType, existing_data_type: &dyn DataType) -> ConflictResult {
        Comparison::new().do_strict_compare(added_data_type, existing_data_type)
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        DWARFDataTypeConflictHandler::INSTANCE
    }
}

#[cfg(test)]
mod tests {
    //! Expected results are the `ConflictResult`s Java's `DWARFConflictHandlerTest` asserts
    //! (via `DataTypeManager.addDataType`) for each pair of existing/added data types.
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::char_data_type::CharDataType;
    use crate::program::model::data::enum_::Enum;
    use crate::program::model::data::enum_data_type::EnumDataType;
    use crate::program::model::data::integer_data_type::IntegerDataType;
    use crate::program::model::data::pointer_data_type::PointerDataType;
    use crate::program::model::data::structure_data_type::StructureDataType;
    use crate::program::model::data::typedef_data_type::TypedefDataType;
    use crate::program::model::data::union_data_type::UnionDataType;
    use ConflictResult::*;

    fn root() -> CategoryPath {
        CategoryPath::new(ROOT.clone(), &["conflict_test"]).unwrap()
    }

    fn add(c: &mut dyn Composite, dt: Box<dyn DataType>, len: i32, name: Option<&str>) {
        c.add_with_length_and_name(dt, len, name.map(str::to_string), None).unwrap();
    }

    fn char_dt() -> Box<dyn DataType> {
        Box::new(CharDataType::new(None))
    }

    fn int_dt() -> Box<dyn DataType> {
        Box::new(IntegerDataType::new(None))
    }

    fn create_populated() -> StructureDataType {
        let mut s = StructureDataType::new_in_category(root(), "struct1", 0);
        add(&mut s, char_dt(), 1, Some("char1"));
        add(&mut s, char_dt(), 1, Some("char2"));
        s
    }

    fn create_populated2() -> StructureDataType {
        let mut s = StructureDataType::new_in_category(root(), "struct1", 0);
        for name in ["blah1", "blah2", "blah3", "blah4"] {
            add(&mut s, char_dt(), 1, Some(name));
        }
        s
    }

    fn create_populated2_partial() -> StructureDataType {
        let mut s = create_populated2();
        Structure::clear_component(&mut s, 2).unwrap();
        Structure::clear_component(&mut s, 1).unwrap();
        s
    }

    fn create_stub(size: i32) -> StructureDataType {
        StructureDataType::new_in_category(root(), "struct1", size)
    }

    fn union_of(fields: &[(&str, bool)]) -> UnionDataType {
        let mut u = UnionDataType::new_in_category(root(), "union1");
        for (name, is_char) in fields {
            if *is_char {
                add(&mut u, char_dt(), 1, Some(name));
            } else {
                add(&mut u, int_dt(), 4, Some(name));
            }
        }
        u
    }

    fn resolve(existing: &dyn DataType, added: &dyn DataType) -> ConflictResult {
        DWARFDataTypeConflictHandler::INSTANCE.resolve_conflict(added, existing)
    }

    #[test]
    fn add_empty_struct_resolves_to_populated_struct() {
        assert_eq!(resolve(&create_populated(), &create_stub(0)), UseExisting);
    }

    #[test]
    fn add_populated_struct_overwrites_stub() {
        assert_eq!(resolve(&create_stub(0), &create_populated()), ReplaceExisting);
    }

    #[test]
    fn add_populated_struct_overwrites_same_sized_stub() {
        let populated = create_populated();
        assert_eq!(resolve(&create_stub(populated.get_length()), &populated), ReplaceExisting);
    }

    #[test]
    fn add_stub_struct_uses_same_sized_populated() {
        let populated = create_populated();
        assert_eq!(resolve(&populated, &create_stub(populated.get_length())), UseExisting);
    }

    #[test]
    fn add_stub_struct_creates_conflict() {
        let populated = create_populated();
        assert_eq!(resolve(&populated, &create_stub(populated.get_length() + 1)), RenameAndAdd);
    }

    #[test]
    fn add_partial_struct_resolves_to_populated_struct() {
        assert_eq!(resolve(&create_populated2(), &create_populated2_partial()), UseExisting);
    }

    #[test]
    fn add_populated_struct_overwrites_partial_struct() {
        assert_eq!(resolve(&create_populated2_partial(), &create_populated2()), ReplaceExisting);
    }

    #[test]
    fn add_stub_union_resolves_to_populated() {
        let populated = union_of(&[("blah1", true), ("blah2", false)]);
        assert_eq!(resolve(&populated, &union_of(&[])), UseExisting);
    }

    #[test]
    fn add_populated_union_overwrites_stub() {
        let populated = union_of(&[("blah1", true), ("blah2", false)]);
        assert_eq!(resolve(&union_of(&[]), &populated), ReplaceExisting);
    }

    #[test]
    fn add_populated_union_overwrites_partial() {
        let populated = union_of(&[("blah1", true), ("blah2", false), ("blah3", false)]);
        let partial = union_of(&[("blah1", true)]);
        assert_eq!(resolve(&partial, &populated), ReplaceExisting);
    }

    #[test]
    fn add_conflict_union() {
        let populated = union_of(&[("blah1", true), ("blah2", false), ("blah3", false)]);
        let populated2 = union_of(&[("blahA", true)]);
        assert_eq!(resolve(&populated, &populated2), RenameAndAdd);
    }

    #[test]
    fn add_partial_union_with_stub_struct_resolves_to_existing() {
        let s1a = create_populated();
        let len = s1a.get_length();
        let mut populated = union_of(&[("blah1", true)]);
        add(&mut populated, Box::new(s1a), len, Some("blah2"));
        add(&mut populated, Box::new(create_populated()), len, None);

        let s1b = create_stub(0);
        let len = s1b.get_length();
        let mut partial = UnionDataType::new_in_category(root(), "union1");
        add(&mut partial, Box::new(s1b), len, Some("blah2"));

        assert_eq!(resolve(&populated, &partial), UseExisting);
    }

    #[test]
    fn typedef_to_stub_uses_existing_typedef_to_populated_structure() {
        let populated_td = TypedefDataType::new(root(), "typedef1", Box::new(create_populated()) as Box<dyn DataType>).unwrap();
        let stub_td = TypedefDataType::new(root(), "typedef1", Box::new(create_stub(0)) as Box<dyn DataType>).unwrap();
        assert_eq!(resolve(&populated_td, &stub_td), UseExisting);
        // and the other way round, the populated typedef replaces the stub one
        assert_eq!(resolve(&stub_td, &populated_td), ReplaceExisting);
    }

    #[test]
    fn typedef_conflict_to_conflict_struct() {
        let td1a = TypedefDataType::new(root(), "typedef1", Box::new(create_populated()) as Box<dyn DataType>).unwrap();
        let td1b = TypedefDataType::new(root(), "typedef1", Box::new(create_populated2()) as Box<dyn DataType>).unwrap();
        assert_eq!(resolve(&td1a, &td1b), RenameAndAdd);
    }

    #[test]
    fn pointers_compare_their_pointees_relaxed() {
        let to_stub = PointerDataType::to(Box::new(create_stub(0)) as Box<dyn DataType>, 4).unwrap();
        let to_populated = PointerDataType::to(Box::new(create_populated()) as Box<dyn DataType>, 4).unwrap();
        assert_eq!(resolve(&to_populated, &to_stub), UseExisting);
        assert_eq!(resolve(&to_stub, &to_populated), ReplaceExisting);
    }

    #[test]
    fn non_composite_conflict_renames_unless_equivalent() {
        // testResolveDataTypeNonStructConflict: an enum that gained a value is a conflict
        let e = EnumDataType::new_in_category(root(), "Enum", 2);
        let mut e2 = EnumDataType::new_in_category(root(), "Enum", 2);
        Enum::add(&mut e2, "xyz", 1);
        assert_eq!(resolve(&e, &e2), RenameAndAdd);
        assert_eq!(resolve(&e, &EnumDataType::new_in_category(root(), "Enum", 2)), UseExisting);
    }

    #[test]
    fn identical_data_type_uses_existing() {
        let s = create_populated2();
        assert_eq!(resolve(&s, &s), UseExisting);
    }

    #[test]
    fn handler_contract() {
        let s = create_populated();
        assert!(!DWARFDataTypeConflictHandler::INSTANCE.should_update(&s, &s));
        assert!(std::ptr::addr_eq(
            DWARFDataTypeConflictHandler::INSTANCE.get_subsequent_handler(),
            DWARFDataTypeConflictHandler::INSTANCE
        ));
    }
}
