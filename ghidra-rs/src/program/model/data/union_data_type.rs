//! Port of `ghidra.program.model.data.UnionDataType`, mirroring
//! [`StructureDataType`](super::structure_data_type::StructureDataType)'s "promoted to a trait
//! because it was selected as a dependency-cycle cut-point" precedent.
//!
//! The Java class is a concrete, in-memory (non-database-backed) `Union` implementation:
//! `UnionDataType extends CompositeDataTypeImpl implements UnionInternal`. Both
//! [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) and
//! [`UnionInternal`](super::union_internal::UnionInternal) (which itself pulls in
//! [`Union`](super::union::Union), [`Composite`](super::composite::Composite) and
//! [`DataType`](super::data_type::DataType)) are already real, richly-defaulted ported traits, so
//! -- exactly like [`StructureDataType`](super::structure_data_type::StructureDataType) -- this
//! trait only adds what genuinely differs about *this* concrete class.
//!
//! A `Union` has no offset-based layout: every component is anchored at byte offset 0 (its
//! `createComponent` calls always pass `offset = 0`), and the union's own length is simply the
//! largest of its components' (possibly bitfield-adjusted) lengths, aligned up when packing is
//! enabled. This makes the component-management surface below meaningfully **simpler** than
//! [`StructureDataType`]'s: there is no offset bookkeeping, no undefined filler synthesis, no
//! binary search over offsets, and the defined-component list's index always equals a component's
//! ordinal (insert/delete keep the two in lockstep), so `components()[ordinal]` is always the
//! direct answer to `getComponent(ordinal)` -- no `compare_component_to_ordinal` binary search is
//! needed the way [`StructureDataType`] needs one.
//!
//! ## Porting progress (2026-09, incremental)
//!
//! This is being built up in the same incremental, build+test-gated fashion
//! [`StructureDataType`] was. So far this covers: the private-field accessors, the small
//! `getLength`/`isZeroLength`/`hasLanguageDependantLength`/`getRepresentation`/
//! `getDefaultLabelPrefix` deltas, the read-only component-query surface
//! (`getNumComponents`/`getNumDefinedComponents`/`getComponent`/`getComponents`/
//! `getDefinedComponents`), and `DataTypeUtilities.checkAncestry`. Still to come in later
//! commits: `getAlignment`/`repack`, `add`/`insert`/`addBitField`/`insertBitField`, and
//! `delete`/`delete(Set)`/`isEquivalent`/`replaceWith`. Do not flip `UnionDataType.java`'s
//! `PORT_MANIFEST.tsv` row to `DONE` until all of that lands (and even then, see the eventual
//! final module doc's own "explicitly not yet ported" list for `dataTypeAlignmentChanged`-family
//! methods and `copy`/`clone`, which mirror [`StructureDataType`]'s identical omissions).

use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::union_internal::UnionInternal;
use crate::program::model::mem::MemBuffer;
use crate::docking::settings::settings::Settings;

/// Port of the relevant cases of `DataTypeUtilities.isSecondPartOfFirst(DataType, DataType)`, used
/// by [`union_data_type_check_ancestry`]. A near-duplicate of
/// [`structure_data_type::is_part_of_data_type_by_ref`](super::structure_data_type), which exists
/// separately in each module rather than being shared (it is a small private helper, not part of
/// either module's public surface) -- see that sibling's own doc comment for the identical
/// `Array`-case caveat (conservatively treated as "not part of").
fn is_part_of_data_type_by_ref(data_type: &dyn DataType, target: &dyn DataType) -> bool {
    if data_type.is_pointer() || target.is_pointer() {
        return false;
    }
    if data_type.get_data_type_path() == target.get_data_type_path() {
        return true;
    }
    if data_type.is_typedef() {
        return match data_type.typedef_base_data_type() {
            Some(inner) => is_part_of_data_type_by_ref(inner.as_ref(), target),
            None => false,
        };
    }
    match data_type.as_composite() {
        Some(composite) => composite
            .get_defined_components()
            .into_iter()
            .any(|dtc| is_part_of_data_type_by_ref(dtc.get_data_type().as_ref(), target)),
        None => false,
    }
}

/// Basic (in-memory, non-database-backed) implementation of the union data type.
///
/// Port of `ghidra.program.model.data.UnionDataType`. See the module-level documentation for what
/// was ported, defaulted, and intentionally omitted (a work in progress; see the "porting
/// progress" note there).
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
pub trait UnionDataType: UnionInternal + CompositeDataTypeImpl {
    /// Backing storage for the private `unionLength` field.
    fn stored_union_length(&self) -> i32;

    /// Mutator for the private `unionLength` field's backing storage.
    fn set_stored_union_length(&mut self, length: i32);

    /// Backing storage for the private `unionAlignment` field.
    fn stored_union_alignment(&self) -> i32;

    /// Mutator for the private `unionAlignment` field's backing storage.
    fn set_stored_union_alignment(&mut self, alignment: i32);

    /// Backing storage for the private `components` field (`List<DataTypeComponentImpl>`).
    fn components(&self) -> &Vec<DataTypeComponentImpl>;

    /// Mutator for the private `components` field's backing storage.
    fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl>;

    /// Port of `UnionDataType.isZeroLength()`. Exposed under a distinct name since
    /// [`DataType::is_zero_length`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn union_data_type_is_zero_length(&self) -> bool {
        self.stored_union_length() == 0
    }

    /// Port of `UnionDataType.getLength()`: a zero-length union reports a length of 1 since a
    /// defined data unit cannot have zero length. Exposed under a distinct name since
    /// [`DataType::get_length`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn length(&self) -> i32 {
        let len = self.stored_union_length();
        if len == 0 {
            1
        } else {
            len
        }
    }

    /// Port of `UnionDataType.hasLanguageDependantLength()`: always `true` ("Assume any component
    /// may have a language-dependent length"). Exposed under a distinct name since
    /// [`CompositeDataTypeImpl::composite_impl_has_language_dependant_length`] is required
    /// (abstract in Java too) with no default of its own; a concrete implementation should
    /// delegate its answer to this.
    fn union_data_type_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnionDataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since [`DataType::get_representation`] already provides a (placeholder)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        if self.composite_impl_is_not_yet_defined() {
            "<Empty-Union>".to_string()
        } else {
            String::new()
        }
    }

    /// Port of `UnionDataType.getDefaultLabelPrefix()`. Exposed under a distinct name since
    /// [`DataType::get_default_label_prefix`] already provides a (placeholder, `None`) default. A
    /// concrete `impl DataType for ...` should delegate to this.
    fn default_label_prefix(&self) -> Option<String> {
        Some(format!("UNION_{}", self.get_name()))
    }

    /// Port of `UnionDataType.getNumComponents()`. Exposed under a distinct name since
    /// [`Composite::get_num_components`](crate::program::model::data::composite::Composite::get_num_components)
    /// already provides a (placeholder) default. A concrete `impl Composite for ...` should
    /// delegate to this.
    fn union_data_type_get_num_components(&self) -> i32 {
        self.components().len() as i32
    }

    /// Port of `UnionDataType.getNumDefinedComponents()`: identical to
    /// [`union_data_type_get_num_components`] in Java too (a union has no undefined filler
    /// components). Exposed under a distinct name since
    /// [`Composite::get_num_defined_components`](crate::program::model::data::composite::Composite::get_num_defined_components)
    /// already provides a (placeholder) default.
    fn union_data_type_get_num_defined_components(&self) -> i32 {
        self.union_data_type_get_num_components()
    }

    /// Port of `UnionDataType.getComponent(int)`: direct indexing, since a union's component list
    /// index always equals its ordinal (unlike [`StructureDataType`](super::structure_data_type::StructureDataType),
    /// no undefined filler synthesis or offset search is needed). Exposed under a distinct name
    /// since [`Composite::get_component`](crate::program::model::data::composite::Composite::get_component)
    /// already provides a (placeholder) default.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn union_data_type_get_component(&self, ordinal: i32) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal as usize >= self.components().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        Ok(self.components()[ordinal as usize].snapshot())
    }

    /// Port of `UnionDataType.getComponents()`/`getDefinedComponents()` (identical bodies in
    /// Java: `getDefinedComponents() { return getComponents(); }`). Exposed under a distinct name
    /// since [`Composite::get_components`](crate::program::model::data::composite::Composite::get_components)/
    /// [`Composite::get_defined_components`](crate::program::model::data::composite::Composite::get_defined_components)
    /// already provide (placeholder) defaults. A concrete `impl Composite for ...` should
    /// delegate both `get_components`/`get_defined_components` to this single method.
    fn union_data_type_get_components(&self) -> Vec<DataTypeComponentImpl> {
        self.components().iter().map(|dtc| dtc.snapshot()).collect()
    }

    /// Port of `DataTypeUtilities.checkAncestry(DataType, DataType)`, called as
    /// `checkAncestry(this, componentDataType)` throughout this trait's `add`/`insert`/
    /// `insertBitField`/`replaceWith` methods. Rejects `component_data_type` if adding it to this
    /// union would create a cyclic composite.
    ///
    /// # Errors
    /// Returns `Err` if `component_data_type` has this union within it (mirrors
    /// `DataTypeDependencyException`).
    fn union_data_type_check_ancestry(&self, component_data_type: &dyn DataType) -> Result<(), String>
    where
        Self: Sized,
    {
        if is_part_of_data_type_by_ref(component_data_type, self) {
            return Err(format!(
                "DataTypeDependencyException: Data type {} has {} within it.",
                component_data_type.get_display_name(),
                self.get_display_name()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::packing_type::PackingType;

    /// Minimal mock proving object-safety and exercising real behavior, mirroring
    /// `StructureDataType`'s own `MockStructureDataType` test fixture.
    struct MockUnionDataType {
        name: String,
        union_length: i32,
        union_alignment: i32,
        packing_type: PackingType,
        components: Vec<DataTypeComponentImpl>,
    }

    impl DataType for MockUnionDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn as_composite(&self) -> Option<&dyn Composite> {
            Some(self)
        }
        fn get_length(&self) -> i32 {
            UnionDataType::length(self)
        }
        fn is_union(&self) -> bool {
            true
        }
    }

    impl Composite for MockUnionDataType {
        fn get_num_components(&self) -> i32 {
            self.components.len() as i32
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|dtc| Box::new(dtc.snapshot()) as Box<dyn DataTypeComponent>)
                .collect()
        }
    }

    impl CompositeInternal for MockUnionDataType {
        fn get_stored_packing_value(&self) -> i32 {
            if self.packing_type == PackingType::Disabled {
                crate::program::model::data::composite_internal::NO_PACKING
            } else {
                crate::program::model::data::composite_internal::DEFAULT_PACKING
            }
        }
    }

    impl crate::program::model::data::union::Union for MockUnionDataType {
        fn clone_union(&self, _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn crate::program::model::data::union::Union> {
            unimplemented!("not exercised by these tests")
        }
        fn insert_bit_field(
            &mut self,
            _ordinal: i32,
            _base_data_type: Box<dyn DataType>,
            _bit_size: i32,
            _component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            // Wired up to the real `union_data_type_insert_bit_field` port in a later commit.
            Err("not yet ported".to_string())
        }
    }

    impl UnionInternal for MockUnionDataType {}

    impl CompositeDataTypeImpl for MockUnionDataType {
        fn stored_description(&self) -> String {
            String::new()
        }
        fn set_stored_description(&mut self, _description: String) {}
        fn stored_minimum_alignment_value(&self) -> i32 {
            0
        }
        fn set_stored_minimum_alignment_value(&mut self, _minimum_alignment: i32) {}
        fn stored_packing_value(&self) -> i32 {
            if self.packing_type == PackingType::Disabled {
                crate::program::model::data::composite_internal::NO_PACKING
            } else {
                crate::program::model::data::composite_internal::DEFAULT_PACKING
            }
        }
        fn set_stored_packing_value_raw(&mut self, packing: i32) {
            self.packing_type = if packing < crate::program::model::data::composite_internal::DEFAULT_PACKING {
                PackingType::Disabled
            } else if packing == crate::program::model::data::composite_internal::DEFAULT_PACKING {
                PackingType::Default
            } else {
                PackingType::Explicit
            };
        }
        fn set_stored_name(&mut self, name: String) {
            self.name = name;
        }
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            UnionDataType::union_data_type_has_language_dependant_length(self)
        }
        fn repack_with_notify(&mut self, _notify: bool) -> bool {
            // Wired up to the real `union_data_type_repack` port in a later commit.
            false
        }
        fn composite_impl_alignment(&self) -> i32 {
            // Wired up to the real `union_data_type_alignment` port in a later commit.
            1
        }
        fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {
            for dtc in self.components() {
                consumer(dtc);
            }
        }
        fn composite_impl_add_with_length_and_name(
            &mut self,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            // Wired up to the real `union_data_type_add` port in a later commit.
            Err("not yet ported".to_string())
        }
        fn composite_impl_insert_with_length_and_name(
            &mut self,
            _ordinal: i32,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            // Wired up to the real `union_data_type_insert` port in a later commit.
            Err("not yet ported".to_string())
        }
        fn composite_impl_validate_data_type(
            &self,
            data_type: Box<dyn DataType>,
        ) -> Result<Box<dyn DataType>, String> {
            Ok(data_type)
        }
        fn composite_impl_update_bit_field_data_type(
            &mut self,
            _bitfield_component: Box<dyn DataTypeComponent>,
            _old_dt: &dyn DataType,
            _new_dt: Option<&dyn DataType>,
        ) -> Result<bool, String> {
            Ok(false)
        }
    }

    impl UnionDataType for MockUnionDataType {
        fn stored_union_length(&self) -> i32 {
            self.union_length
        }
        fn set_stored_union_length(&mut self, length: i32) {
            self.union_length = length;
        }
        fn stored_union_alignment(&self) -> i32 {
            self.union_alignment
        }
        fn set_stored_union_alignment(&mut self, alignment: i32) {
            self.union_alignment = alignment;
        }
        fn components(&self) -> &Vec<DataTypeComponentImpl> {
            &self.components
        }
        fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl> {
            &mut self.components
        }
    }

    fn sample() -> MockUnionDataType {
        MockUnionDataType {
            name: "MyUnion".to_string(),
            union_length: 0,
            union_alignment: 0,
            packing_type: PackingType::Disabled,
            components: Vec::new(),
        }
    }

    fn byte_data_type(name: &str, length: i32) -> Box<dyn DataType> {
        struct SimpleDataType {
            name: String,
            length: i32,
        }
        impl DataType for SimpleDataType {
            fn get_name(&self) -> String {
                self.name.clone()
            }
            fn get_length(&self) -> i32 {
                self.length
            }
        }
        Box::new(SimpleDataType {
            name: name.to_string(),
            length,
        })
    }

    #[test]
    fn usable_as_trait_object() {
        let u = sample();
        let dyn_union: &dyn UnionDataType = &u;
        assert!(dyn_union.union_data_type_is_zero_length());
        assert_eq!(dyn_union.length(), 1);
    }

    #[test]
    fn zero_length_union_reports_length_one_and_empty_representation() {
        let u = sample();
        assert!(u.union_data_type_is_zero_length());
        assert_eq!(u.length(), 1);
        assert_eq!(u.representation(&MockBuf, &MockSettings, 0), "<Empty-Union>");
    }

    #[test]
    fn defined_union_reports_stored_length_and_blank_representation() {
        let mut u = sample();
        u.set_stored_union_length(4);
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 0, 0, None, None));
        assert!(!u.union_data_type_is_zero_length());
        assert_eq!(u.length(), 4);
        assert_eq!(u.representation(&MockBuf, &MockSettings, 4), "");
    }

    #[test]
    fn has_language_dependant_length_is_always_true() {
        let u = sample();
        assert!(u.union_data_type_has_language_dependant_length());
    }

    #[test]
    fn default_label_prefix_uses_union_prefixed_name() {
        let u = sample();
        assert_eq!(u.default_label_prefix(), Some("UNION_MyUnion".to_string()));
    }

    #[test]
    fn get_component_rejects_out_of_bounds_ordinal() {
        let u = sample();
        assert!(u.union_data_type_get_component(0).is_err());
    }

    #[test]
    fn get_component_and_get_components_reflect_manually_seeded_state() {
        let mut u = sample();
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("byte", 1), None, 1, 0, 0, None, None));
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 1, 0, None, None));

        assert_eq!(u.union_data_type_get_num_components(), 2);
        assert_eq!(u.union_data_type_get_num_defined_components(), 2);

        let c0 = u.union_data_type_get_component(0).unwrap();
        assert_eq!(c0.get_data_type_name(), "byte");
        assert_eq!(c0.get_offset(), 0);

        let all = u.union_data_type_get_components();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].get_data_type_name(), "dword");
    }

    #[test]
    fn check_ancestry_rejects_cyclic_component() {
        let u = sample();
        let dyn_self: &dyn DataType = &u as &dyn DataType;
        assert!(is_part_of_data_type_by_ref(dyn_self, dyn_self));
        let result = u.union_data_type_check_ancestry(dyn_self);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DataTypeDependencyException"));
    }

    #[test]
    fn check_ancestry_accepts_non_cyclic_component() {
        let u = sample();
        let dt = byte_data_type("byte", 1);
        assert!(u.union_data_type_check_ancestry(dt.as_ref()).is_ok());
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}
}
