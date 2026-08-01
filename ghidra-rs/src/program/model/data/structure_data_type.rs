//! Port of `ghidra.program.model.data.StructureDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is a concrete, in-memory (non-database-backed) `Structure` implementation:
//! `StructureDataType extends CompositeDataTypeImpl implements StructureInternal`. Both
//! [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) and
//! [`StructureInternal`](super::structure_internal::StructureInternal) (which itself pulls in
//! [`Structure`](super::structure::Structure), [`Composite`](super::composite::Composite) and
//! [`DataType`](super::data_type::DataType)) are already real, richly-defaulted ported traits, so
//! -- mirroring the precedent set by
//! [`StructureDb`](crate::program::database::data::structure_db::StructureDb) for the sibling
//! database-backed implementation `StructureDB` -- this trait only adds what genuinely differs
//! about *this* concrete class; every public method it overrides that already belongs to one of
//! those ancestor contracts is intentionally not repeated here:
//!   - The entire component-manipulation surface (`getComponent`, `insertAtOffset`, `add`,
//!     `insert`, `delete`(s), `deleteAtOffset`, `clearAtOffset`, `clearComponent`, `replace`,
//!     `replaceAtOffset`, `addBitField`, `insertBitField(At)`, `getDefinedComponents`,
//!     `getComponents`, `getNumComponents`, `getNumDefinedComponents`, `deleteAll`,
//!     `growStructure`, `setLength`, `getDefinedComponentAtOrAfterOffset`,
//!     `getComponentContaining`, `getComponentsContaining`, `getDataTypeAt`) already exists,
//!     method-for-method, as a (placeholder-default) [`Structure`](super::structure::Structure) or
//!     [`Composite`](super::composite::Composite) trait method.
//!   - `forEachDefinedComponent` and `repack(boolean)` already exist as required
//!     [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) methods
//!     (`for_each_defined_component`, `repack_with_notify`).
//!   - `getAlignment()` already exists as the required
//!     [`CompositeDataTypeImpl::composite_impl_alignment`](super::composite_data_type_impl::CompositeDataTypeImpl::composite_impl_alignment).
//!     Its real Java body calls `AlignedStructureInspector.packComponents(this)` for the
//!     packing-enabled case, a helper class that is not yet ported; rather than adding a
//!     placeholder stub for a method this trait does not otherwise need, that computation is left
//!     to whatever concrete type eventually backs `composite_impl_alignment` (which already has no
//!     default for the same reason -- it is `abstract` in `CompositeDataTypeImpl` too).
//!   - `isEquivalent`, `dataTypeSizeChanged`, `dataTypeAlignmentChanged`, `dataTypeDeleted`,
//!     `dataTypeReplaced`, and `replaceWith` already exist as (placeholder-default)
//!     [`DataType`](super::data_type::DataType) methods of the same name/shape.
//!   - `copy(DataTypeManager)`/`clone(DataTypeManager)` are covariant-return overrides of
//!     [`DataType::copy_data_type`]/[`DataType::clone_data_type`], which already return the
//!     necessary `Box<dyn DataType>` (a concrete `StructureDataType` impl already narrows to a
//!     `Structure` internally; the trait-object return type is unchanged).
//!   - The five public constructors have no trait-method equivalent (traits cannot return `Self`
//!     as a sized, constructible value); a concrete implementation supplies its own `new`.
//!
//! What *is* new here is a handful of methods whose real Java bodies are small, self-contained,
//! and differ from the generic default already sitting on an ancestor trait (so Rust requires a
//! distinct name to avoid an ambiguous override, per the `composite_impl_*`/`structure_db_*`
//! naming precedent already used by sibling traits):
//!   - [`structure_data_type_is_zero_length`](StructureDataType::structure_data_type_is_zero_length) /
//!     [`length`](StructureDataType::length), which need the private `structLength` field --
//!     exposed via the required [`stored_struct_length`](StructureDataType::stored_struct_length)/
//!     [`set_stored_struct_length`](StructureDataType::set_stored_struct_length) accessors,
//!     mirroring [`CompositeDataTypeImpl`]'s `stored_description`-style convention for private
//!     field storage.
//!   - [`structure_data_type_has_language_dependant_length`](StructureDataType::structure_data_type_has_language_dependant_length), which
//!     answers the required `CompositeDataTypeImpl::composite_impl_has_language_dependant_length`
//!     with real logic (`isPackingEnabled()`) needing no new state.
//!   - [`representation`](StructureDataType::representation), which returns
//!     `"<Empty-Structure>"` when not yet defined instead of [`DataType::get_representation`]'s
//!     empty-string default, built on the already-real
//!     [`CompositeDataTypeImpl::composite_impl_is_not_yet_defined`].
//!   - [`default_label_prefix`](StructureDataType::default_label_prefix), which returns the
//!     structure's own name instead of [`DataType::get_default_label_prefix`]'s `None` default.

use crate::docking::settings::settings::Settings;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::seam_stubs::MemBuffer;

/// Basic (in-memory, non-database-backed) implementation of the structure data type.
///
/// Port of `ghidra.program.model.data.StructureDataType`. See the module-level documentation for
/// what was ported, defaulted, and intentionally omitted.
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
pub trait StructureDataType: StructureInternal + CompositeDataTypeImpl {
    /// Backing storage for the private `structLength` field.
    fn stored_struct_length(&self) -> i32;

    /// Mutator for the private `structLength` field's backing storage.
    fn set_stored_struct_length(&mut self, length: i32);

    /// Port of `StructureDataType.isZeroLength()`. Exposed under a distinct name since
    /// [`DataType::is_zero_length`](crate::program::model::data::data_type::DataType::is_zero_length)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn structure_data_type_is_zero_length(&self) -> bool {
        self.stored_struct_length() == 0
    }

    /// Port of `StructureDataType.getLength()`: a zero-length structure reports a length of 1
    /// since a defined data unit cannot have zero length. Exposed under a distinct name since
    /// [`DataType::get_length`](crate::program::model::data::data_type::DataType::get_length)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn length(&self) -> i32 {
        let len = self.stored_struct_length();
        if len == 0 {
            1
        } else {
            len
        }
    }

    /// Port of `StructureDataType.hasLanguageDependantLength()`. Exposed under a distinct name
    /// since
    /// [`CompositeDataTypeImpl::composite_impl_has_language_dependant_length`](CompositeDataTypeImpl::composite_impl_has_language_dependant_length)
    /// is required (abstract in Java too) with no default of its own; a concrete implementation
    /// should delegate its answer to this.
    fn structure_data_type_has_language_dependant_length(&self) -> bool {
        self.is_packing_enabled()
    }

    /// Port of `StructureDataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since
    /// [`DataType::get_representation`](crate::program::model::data::data_type::DataType::get_representation)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        if self.composite_impl_is_not_yet_defined() {
            "<Empty-Structure>".to_string()
        } else {
            String::new()
        }
    }

    /// Port of `StructureDataType.getDefaultLabelPrefix()`. Exposed under a distinct name since
    /// [`DataType::get_default_label_prefix`](crate::program::model::data::data_type::DataType::get_default_label_prefix)
    /// already provides a (placeholder, `None`) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn default_label_prefix(&self) -> Option<String> {
        Some(self.get_name())
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
    use std::cell::Cell;

    /// Minimal mock proving object-safety and exercising real (non-trivially-true) behavior: a
    /// structure's zero-length/length/representation/label-prefix all track its stored length and
    /// name, and `has_language_dependant_length` tracks its packing state -- exactly the Java
    /// semantics this trait ports.
    struct MockStructureDataType {
        name: String,
        struct_length: Cell<i32>,
        num_components: Cell<i32>,
        packing_type: PackingType,
    }

    impl DataType for MockStructureDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl Composite for MockStructureDataType {
        fn get_num_components(&self) -> i32 {
            self.num_components.get()
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
    }

    impl CompositeInternal for MockStructureDataType {}

    impl crate::program::model::data::structure::Structure for MockStructureDataType {}

    impl StructureInternal for MockStructureDataType {}

    impl CompositeDataTypeImpl for MockStructureDataType {
        fn stored_description(&self) -> String {
            String::new()
        }
        fn set_stored_description(&mut self, _description: String) {}
        fn stored_minimum_alignment_value(&self) -> i32 {
            0
        }
        fn set_stored_minimum_alignment_value(&mut self, _minimum_alignment: i32) {}
        fn stored_packing_value(&self) -> i32 {
            0
        }
        fn set_stored_packing_value_raw(&mut self, _packing: i32) {}
        fn set_stored_name(&mut self, name: String) {
            self.name = name;
        }
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            StructureDataType::structure_data_type_has_language_dependant_length(self)
        }
        fn repack_with_notify(&mut self, _notify: bool) -> bool {
            false
        }
        fn composite_impl_alignment(&self) -> i32 {
            1
        }
        fn for_each_defined_component(&self, _consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {}
        fn composite_impl_add_with_length_and_name(
            &mut self,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not needed for this smoke test".to_string())
        }
        fn composite_impl_insert_with_length_and_name(
            &mut self,
            _ordinal: i32,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not needed for this smoke test".to_string())
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

    impl StructureDataType for MockStructureDataType {
        fn stored_struct_length(&self) -> i32 {
            self.struct_length.get()
        }
        fn set_stored_struct_length(&mut self, length: i32) {
            self.struct_length.set(length);
        }
    }

    fn sample() -> MockStructureDataType {
        MockStructureDataType {
            name: "MyStruct".to_string(),
            struct_length: Cell::new(0),
            num_components: Cell::new(0),
            packing_type: PackingType::Disabled,
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let s = sample();
        let dyn_struct: &dyn StructureDataType = &s;
        assert!(dyn_struct.structure_data_type_is_zero_length());
        assert_eq!(dyn_struct.length(), 1);
    }

    #[test]
    fn zero_length_structure_reports_length_one_and_empty_representation() {
        let s = sample();
        assert!(s.structure_data_type_is_zero_length());
        assert_eq!(s.length(), 1);
        assert_eq!(
            s.representation(&MockBuf, &MockSettings, 0),
            "<Empty-Structure>"
        );
    }

    #[test]
    fn defined_structure_reports_stored_length_and_blank_representation() {
        let mut s = sample();
        s.set_stored_struct_length(8);
        s.num_components.set(1);
        assert!(!s.structure_data_type_is_zero_length());
        assert_eq!(s.length(), 8);
        assert_eq!(s.representation(&MockBuf, &MockSettings, 8), "");
    }

    #[test]
    fn has_language_dependant_length_tracks_packing() {
        let mut s = sample();
        assert!(!s.structure_data_type_has_language_dependant_length());
        s.packing_type = PackingType::Default;
        assert!(s.structure_data_type_has_language_dependant_length());
    }

    #[test]
    fn default_label_prefix_uses_name() {
        let s = sample();
        assert_eq!(s.default_label_prefix(), Some("MyStruct".to_string()));
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}
}
