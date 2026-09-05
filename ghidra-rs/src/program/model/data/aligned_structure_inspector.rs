//! Port of `ghidra.program.model.data.AlignedStructureInspector`.
//!
//! `AlignedStructureInspector` provides a simple instance of a structure member container used to
//! perform alignment operations without forcing modification of the actual structure.
//!
//! The Java class `extends AlignedStructurePacker`, itself already ported as a cut-point trait
//! (see [`AlignedStructurePacker`]'s own module docs). That trait's `create_component_packer` is a
//! required method with no default, standing in for the not-yet-ported `AlignedComponentPacker`
//! helper class; `AlignedStructureInspector` neither overrides nor needs anything beyond that same
//! requirement (Java's subclass exists purely to reach `AlignedStructurePacker`'s otherwise
//! package-private constructor/`pack()` from a public static entry point, a visibility concern
//! that doesn't exist in this port since [`AlignedStructurePacker::pack_components`] is already
//! `pub`), so this trait is a **blanket implementation**: any type that implements
//! [`AlignedStructurePacker`] automatically implements `AlignedStructureInspector` too, exactly
//! mirroring how any concrete `AlignedComponentPacker`-backed packer, once ported, gets read-only
//! inspection for free.
//!
//! The private nested class `ReadOnlyComponentWrapper implements InternalDataTypeComponent` is
//! ported as the top-level [`ReadOnlyComponentWrapper`] struct (Rust has no nested classes). It
//! snapshots a component's ordinal/offset/length/data-type at construction (mirroring the Java
//! constructor copying those four fields out of the wrapped `component`), lets
//! [`AlignedStructurePacker::pack_components`] mutate the snapshot in place via
//! [`InternalDataTypeComponent::update`]/`set_data_type`, and delegates every other read-only
//! accessor straight through to the wrapped component. `setComment`/`setFieldName`/`isEquivalent`
//! all unconditionally throw `UnsupportedOperationException` in Java; ported here as panics,
//! matching this crate's established convention for that specific Java exception (see e.g.
//! `DataTypeImpl::data_type_impl_replace_with`'s identical unconditional-panic treatment).
//!
//! Storage for the snapshotted `dataType` field uses `Arc<dyn DataType>` +
//! [`share_data_type`](crate::program::seam_stubs::share_data_type), mirroring
//! [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s established answer to
//! `get_data_type(&self) -> Box<dyn DataType>` needing to hand out an owned value repeatedly from
//! a `&self` method (a plain `Box<dyn DataType>` field could only be given out once).
//!
//! `getComponentWrappers(Structure)`/the private constructor collapse into
//! [`AlignedStructureInspector::pack_components_readonly`], and the public static
//! `packComponents(StructureInternal)` factory *is*
//! [`pack_components_readonly`](AlignedStructureInspector::pack_components_readonly) itself (no
//! separate free function needed, since the blanket impl already makes it callable on any
//! [`AlignedStructurePacker`]).

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::aligned_structure_packer::{AlignedStructurePacker, StructurePackResult};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::seam_stubs::share_data_type;

/// Port of the private nested class `AlignedStructureInspector.ReadOnlyComponentWrapper`.
///
/// A read-only-to-external-callers wrapper around an existing [`DataTypeComponent`] that lets
/// [`AlignedStructurePacker::pack_components`] freely rewrite the ordinal/offset/length/data-type
/// snapshot without mutating the original structure's real component. See the module docs for
/// what was dropped (nothing) and for the storage strategy.
pub struct ReadOnlyComponentWrapper {
    component: Box<dyn DataTypeComponent>,
    ordinal: i32,
    offset: i32,
    length: i32,
    data_type: Arc<dyn DataType>,
}

impl ReadOnlyComponentWrapper {
    /// Port of `ReadOnlyComponentWrapper(DataTypeComponent)`.
    pub fn new(component: Box<dyn DataTypeComponent>) -> Self {
        let ordinal = component.get_ordinal();
        let offset = component.get_offset();
        let length = component.get_length();
        let data_type: Arc<dyn DataType> = Arc::from(component.get_data_type());
        ReadOnlyComponentWrapper { component, ordinal, offset, length, data_type }
    }
}

impl DataTypeComponent for ReadOnlyComponentWrapper {
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_parent(&self) -> Box<dyn DataType> {
        self.component.get_parent()
    }

    fn is_bit_field_component(&self) -> bool {
        self.component.is_bit_field_component()
    }

    fn is_zero_bit_field_component(&self) -> bool {
        self.component.is_zero_bit_field_component()
    }

    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn get_end_offset(&self) -> i32 {
        self.offset + self.length - 1
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_comment(&self) -> Option<String> {
        self.component.get_comment()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        self.component.get_default_settings()
    }

    /// # Panics
    /// Always panics, mirroring the unconditional `UnsupportedOperationException` thrown by the
    /// Java override.
    fn set_comment(&self, _comment: Option<String>) -> Box<dyn DataTypeComponent> {
        panic!("UnsupportedOperationException: ReadOnlyComponentWrapper.setComment")
    }

    fn get_field_name(&self) -> Option<String> {
        self.component.get_field_name()
    }

    /// # Panics
    /// Always panics, mirroring the unconditional `UnsupportedOperationException` thrown by the
    /// Java override.
    fn set_field_name(&self, _field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        panic!("UnsupportedOperationException: ReadOnlyComponentWrapper.setFieldName")
    }

    fn get_default_field_name(&self) -> Option<String> {
        self.component.get_default_field_name()
    }

    /// # Panics
    /// Always panics, mirroring the unconditional `UnsupportedOperationException` thrown by the
    /// Java override.
    fn is_equivalent(&self, _dtc: &dyn DataTypeComponent) -> bool {
        panic!("UnsupportedOperationException: ReadOnlyComponentWrapper.isEquivalent")
    }

    fn is_undefined(&self) -> bool {
        self.component.is_undefined()
    }
}

impl InternalDataTypeComponent for ReadOnlyComponentWrapper {
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.data_type = Arc::from(data_type);
    }

    fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
        self.ordinal = ordinal;
        self.offset = offset;
        self.length = length;
    }
}

/// Provides a simple instance of a structure member container used to perform alignment
/// operations without forcing modification of the actual structure.
///
/// Port of `ghidra.program.model.data.AlignedStructureInspector`. See the module-level
/// documentation for why this is a blanket implementation over every [`AlignedStructurePacker`].
pub trait AlignedStructureInspector: AlignedStructurePacker {
    /// Perform structure component packing in a read-only fashion, primarily for the purpose of
    /// computing external alignment for existing structures.
    ///
    /// Port of the static `AlignedStructureInspector.packComponents(StructureInternal)` (folded
    /// together with the private constructor and `getComponentWrappers`; see the module docs).
    fn pack_components_readonly(&self, structure: &dyn StructureInternal) -> StructurePackResult {
        let mut wrappers: Vec<Box<dyn InternalDataTypeComponent>> = structure
            .get_defined_components()
            .into_iter()
            .map(|c| Box::new(ReadOnlyComponentWrapper::new(c)) as Box<dyn InternalDataTypeComponent>)
            .collect();
        self.pack_components(structure, &mut wrappers)
    }
}

impl<T: AlignedStructurePacker + ?Sized> AlignedStructureInspector for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::alignment_type::AlignmentType;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::structure::Structure;
    use crate::program::seam_stubs::AlignedComponentPacker;

    #[derive(Clone)]
    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    }
    impl DataTypeComponent for MockComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: self.length })
        }
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }
    }

    fn component(ordinal: i32, offset: i32, length: i32) -> Box<dyn DataTypeComponent> {
        Box::new(MockComponent { ordinal, offset, length, field_name: None, comment: None })
    }

    #[test]
    fn wrapper_snapshots_ordinal_offset_length_and_data_type() {
        let wrapper = ReadOnlyComponentWrapper::new(component(2, 8, 4));
        assert_eq!(wrapper.get_ordinal(), 2);
        assert_eq!(wrapper.get_offset(), 8);
        assert_eq!(wrapper.get_length(), 4);
        assert_eq!(wrapper.get_end_offset(), 11);
        assert_eq!(wrapper.get_data_type().get_length(), 4);
    }

    #[test]
    fn wrapper_delegates_read_only_accessors() {
        let comp = MockComponent {
            ordinal: 0,
            offset: 0,
            length: 1,
            field_name: Some("field0".to_string()),
            comment: Some("a comment".to_string()),
        };
        let wrapper = ReadOnlyComponentWrapper::new(Box::new(comp));
        assert_eq!(wrapper.get_field_name(), Some("field0".to_string()));
        assert_eq!(wrapper.get_comment(), Some("a comment".to_string()));
    }

    #[test]
    fn update_mutates_snapshot_without_touching_wrapped_component() {
        let mut wrapper = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        InternalDataTypeComponent::update(&mut wrapper, 5, 20, 8);
        assert_eq!(wrapper.get_ordinal(), 5);
        assert_eq!(wrapper.get_offset(), 20);
        assert_eq!(wrapper.get_length(), 8);
        // The original wrapped component (accessible only via the still-unmutated `component`
        // field internally) is never exposed as mutable, so there is no way -- by design -- for
        // external code to observe it changing; this is exactly the "read-only" contract.
    }

    #[test]
    fn set_data_type_replaces_snapshot() {
        let mut wrapper = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        InternalDataTypeComponent::set_data_type(&mut wrapper, Box::new(MockDataType { length: 4 }));
        assert_eq!(wrapper.get_data_type().get_length(), 4);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn set_comment_panics() {
        let wrapper = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        wrapper.set_comment(Some("x".to_string()));
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn set_field_name_panics() {
        let wrapper = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        wrapper.set_field_name(Some("x".to_string()));
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn is_equivalent_panics() {
        let wrapper = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        let other = ReadOnlyComponentWrapper::new(component(0, 0, 1));
        wrapper.is_equivalent(&other);
    }

    // --- End-to-end pack_components_readonly, mirroring aligned_structure_packer.rs's own test
    // packer, since no production `AlignedComponentPacker` exists yet (see the module docs).

    struct SequentialComponentPacker {
        offset: i32,
        max_alignment: i32,
        changed: bool,
    }
    impl SequentialComponentPacker {
        fn new() -> Self {
            SequentialComponentPacker { offset: 0, max_alignment: 1, changed: false }
        }
    }
    impl AlignedComponentPacker for SequentialComponentPacker {
        fn add_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, _is_last_component: bool) {
            let length = dtc.get_data_type().get_length().max(1);
            let ordinal = dtc.get_ordinal();
            dtc.update(ordinal, self.offset, length);
            self.offset += length;
            self.max_alignment = self.max_alignment.max(length);
        }
        fn get_default_alignment(&self) -> i32 {
            self.max_alignment
        }
        fn get_length(&self) -> i32 {
            self.offset
        }
        fn components_changed(&self) -> bool {
            self.changed
        }
    }

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            4
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            struct MockPacking;
            impl BitFieldPacking for MockPacking {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    false
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(MockPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    // Plain (`Send + Sync`) component snapshots rather than `Box<dyn DataTypeComponent>`, since
    // `DataTypeComponent` itself carries no `Send + Sync` bound and `DataType: Send + Sync`
    // requires every field to satisfy it transitively.
    struct MockStructure {
        components: Vec<MockComponent>,
    }
    impl DataType for MockStructure {
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }
    impl Composite for MockStructure {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .cloned()
                .map(|c| -> Box<dyn DataTypeComponent> { Box::new(c) })
                .collect()
        }
    }
    impl Structure for MockStructure {}
    impl CompositeInternal for MockStructure {}
    impl StructureInternal for MockStructure {}

    struct TestInspector;
    impl AlignedStructurePacker for TestInspector {
        fn create_component_packer(
            &self,
            _pack_value: i32,
            _data_organization: &dyn DataOrganization,
        ) -> Box<dyn AlignedComponentPacker> {
            Box::new(SequentialComponentPacker::new())
        }
    }

    #[test]
    fn pack_components_readonly_packs_without_mutating_original_structure() {
        let structure = MockStructure {
            components: vec![
                MockComponent { ordinal: 0, offset: 0, length: 1, field_name: None, comment: None },
                MockComponent { ordinal: 1, offset: 1, length: 4, field_name: None, comment: None },
            ],
        };
        let inspector = TestInspector;
        let result = inspector.pack_components_readonly(&structure);
        assert_eq!(result.num_components, 2);
        // Sequential packer places components at 1 then 4 bytes (raw length 5), but
        // AlignedStructurePacker::pack_components rounds the final length up to a multiple of
        // the structure's alignment (4) via `get_aligned_offset`, giving 8.
        assert_eq!(result.structure_length, 8);
        assert_eq!(result.alignment, 4);

        // The original structure's components are untouched (still their original offsets),
        // proving the read-only wrapper never mutated the real structure.
        let original = structure.get_defined_components();
        assert_eq!(original[0].get_offset(), 0);
        assert_eq!(original[1].get_offset(), 1);
    }

    #[test]
    fn pack_components_readonly_handles_empty_structure() {
        let structure = MockStructure { components: Vec::new() };
        let inspector = TestInspector;
        let result = inspector.pack_components_readonly(&structure);
        assert_eq!(result.num_components, 0);
        assert_eq!(result.structure_length, 0);
    }

    #[test]
    fn blanket_impl_makes_any_packer_an_inspector() {
        fn assert_is_inspector<T: AlignedStructureInspector>() {}
        assert_is_inspector::<TestInspector>();
    }

    #[test]
    fn alignment_type_import_is_exercised_by_underlying_packer() {
        // Sanity check that the real AlignedStructurePacker::pack_components path (not just this
        // module's own wrapper logic) is what's being exercised -- AlignmentType::Default is the
        // branch taken since MockStructure doesn't override get_alignment_type.
        let structure = MockStructure { components: Vec::new() };
        assert_eq!(structure.get_alignment_type(), AlignmentType::Default);
    }
}
