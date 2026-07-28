//! Port of `ghidra.program.model.data.AlignedStructurePacker`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is a package-private helper with a single public entry point,
//! `packComponents(StructureInternal, List<? extends InternalDataTypeComponent>)`, which
//! constructs a private instance (storing `structure`/`components`/`dataOrganization`) purely to
//! call its own `pack()` immediately afterward. Since no other code ever holds onto an
//! `AlignedStructurePacker` instance, that constructor-then-`pack()` sequence is collapsed here
//! into a single default trait method, [`pack_components`](AlignedStructurePacker::pack_components),
//! taking `structure` and `components` as parameters rather than storing them as fields.
//!
//! `pack()` builds a private `AlignedComponentPacker` to do the actual bitfield/alignment
//! arithmetic. That class is not yet ported (it depends on `BitFieldDataType` and
//! `CompositeAlignmentHelper`, neither of which exist in the crate yet), so it is represented here
//! by a minimal placeholder trait,
//! [`seam_stubs::AlignedComponentPacker`](crate::program::seam_stubs::AlignedComponentPacker),
//! exposing only the four members `pack()` actually calls. Since this trait cannot construct one
//! itself, [`create_component_packer`](AlignedStructurePacker::create_component_packer) is left as
//! a required method so a concrete implementor can supply one (the eventual real
//! `AlignedComponentPacker` port, or a test double).
//!
//! `pack()` also calls the static utility `DataOrganizationImpl.getAlignedOffset(int, int)`.
//! `DataOrganizationImpl` itself is not yet ported, but this one static method has no dependency on
//! any of its unported state, so it is ported faithfully as a free function,
//! [`seam_stubs::get_aligned_offset`](crate::program::seam_stubs::get_aligned_offset), rather than
//! stubbed out.
//!
//! Finally, `pack()` replaces any component whose data type is the `DataType.DEFAULT` sentinel
//! with the `Undefined1DataType.dataType` singleton. Neither sentinel exists as a constructible
//! value in the Rust crate (`DataType::DEFAULT` was omitted when `DataType` was ported, and
//! `Undefined1DataType` was itself promoted to a trait with no singleton field -- see that
//! module's docs), so the DEFAULT check is expressed via
//! [`DataType::is_default_data_type`](crate::program::model::data::data_type::DataType::is_default_data_type)
//! and the replacement reuses the existing
//! [`seam_stubs::undefined_data_type(1)`](crate::program::seam_stubs::undefined_data_type) stand-in
//! (already used elsewhere in the crate for exactly this "opaque undefined byte" role) rather than
//! inventing a new placeholder for the same concept.

use crate::program::model::data::alignment_type::AlignmentType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::seam_stubs::{self, AlignedComponentPacker};

/// Port of `AlignedStructurePacker.StructurePackResult`.
///
/// Provides access to aligned packing results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructurePackResult {
    pub num_components: i32,
    pub structure_length: i32,
    pub alignment: i32,
    pub components_changed: bool,
}

impl StructurePackResult {
    pub fn new(
        num_components: i32,
        structure_length: i32,
        alignment: i32,
        components_changed: bool,
    ) -> Self {
        Self {
            num_components,
            structure_length,
            alignment,
            components_changed,
        }
    }
}

/// Port of `ghidra.program.model.data.AlignedStructurePacker`.
///
/// Provides support for performing aligned packing of Structure components.
///
/// NOTE: We currently have no way of conveying or supporting explicit bitfield component pragmas
/// supported by some compilers (e.g., bit_field_size, bit_field_align, bit_packing).
pub trait AlignedStructurePacker {
    /// Constructs the per-call component packer used to align structure components. Required
    /// since `AlignedComponentPacker` (the Java private helper class) has not been ported yet;
    /// see the module docs.
    fn create_component_packer(
        &self,
        pack_value: i32,
        data_organization: &dyn DataOrganization,
    ) -> Box<dyn AlignedComponentPacker>;

    /// Port of `AlignedStructurePacker.packComponents(StructureInternal, List<? extends
    /// InternalDataTypeComponent>)` (folded together with the private constructor and `pack()`;
    /// see the module docs for why).
    ///
    /// Performs packing on the structure's components. Specified components may be updated to
    /// reflect packing (ordinal, offset, length and bit-field datatypes may be modified). The
    /// caller is responsible for updating structure length and component count based upon the
    /// returned result. Component count should only change if the component list includes
    /// DEFAULT members, which are ignored.
    fn pack_components(
        &self,
        structure: &dyn StructureInternal,
        components: &mut [Box<dyn InternalDataTypeComponent>],
    ) -> StructurePackResult {
        let data_organization = structure.get_data_organization();

        let mut packer =
            self.create_component_packer(structure.get_stored_packing_value(), data_organization.as_ref());

        let mut components_changed = false;
        let component_count = components.len() as i32;

        // Transform improper DEFAULT datatype use to an undefined byte.
        for component in components.iter_mut() {
            if component.get_data_type().is_default_data_type() {
                component.set_data_type(seam_stubs::undefined_data_type(1));
                components_changed = true;
            }
        }

        let last_index = component_count - 1;
        for (index, component) in components.iter_mut().enumerate() {
            let is_last_component = index as i32 == last_index;
            packer.add_component(component.as_mut(), is_last_component);
        }

        let default_alignment = packer.get_default_alignment();
        let mut length = packer.get_length();
        components_changed |= packer.components_changed();

        let mut alignment = default_alignment;
        let alignment_type = structure.get_alignment_type();
        if alignment_type != AlignmentType::Default {
            // Apply minimum alignment if applicable - may be reduced by explicit pack.
            // Simplified logic assumes pack and align values which are a power of 2 (1,2,4,8,16...).
            let min_align = if alignment_type == AlignmentType::Machine {
                data_organization.get_machine_alignment()
            } else {
                structure.get_explicit_minimum_alignment()
            };
            alignment = default_alignment.max(min_align);
        }

        if length != 0 {
            length = seam_stubs::get_aligned_offset(alignment, length);
        }

        StructurePackResult::new(component_count, length, alignment, components_changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;

    struct MarkerDataType {
        is_default: bool,
        length: i32,
    }
    impl DataType for MarkerDataType {
        fn is_default_data_type(&self) -> bool {
            self.is_default
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    #[derive(Default)]
    struct MockComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
        is_default: bool,
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MarkerDataType {
                is_default: self.is_default,
                length: self.length,
            })
        }
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    impl InternalDataTypeComponent for MockComponent {
        fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
            self.is_default = data_type.is_default_data_type();
        }
        fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
            self.ordinal = ordinal;
            self.offset = offset;
            self.length = length;
        }
    }

    /// Sequential, non-bitfield-aware stand-in for the real `AlignedComponentPacker` algorithm:
    /// packs each component immediately after the previous one, aligned to its own length. Good
    /// enough to prove `pack_components` wires structure/component state through correctly without
    /// re-implementing Ghidra's real bitfield packing rules (out of scope for this port).
    struct SequentialComponentPacker {
        next_offset: i32,
        max_length: i32,
    }

    impl AlignedComponentPacker for SequentialComponentPacker {
        fn add_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, _is_last_component: bool) {
            let length = dtc.get_length().max(1);
            self.max_length = self.max_length.max(length);
            let offset = seam_stubs::get_aligned_offset(length, self.next_offset);
            let component_length = dtc.get_length();
            dtc.update(dtc.get_ordinal(), offset, component_length);
            self.next_offset = offset + component_length;
        }
        fn get_default_alignment(&self) -> i32 {
            self.max_length
        }
        fn get_length(&self) -> i32 {
            self.next_offset
        }
        fn components_changed(&self) -> bool {
            false
        }
    }

    struct MockDataOrganization {
        machine_alignment: i32,
    }
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
            2
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
            self.machine_alignment
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
            struct MockBitFieldPacking;
            impl BitFieldPacking for MockBitFieldPacking {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    true
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            vec![]
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockStructure {
        packing_value: i32,
        alignment_type: AlignmentType,
        explicit_min_alignment: i32,
        machine_alignment: i32,
    }

    impl DataType for MockStructure {
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization {
                machine_alignment: self.machine_alignment,
            })
        }
    }
    impl Composite for MockStructure {
        fn get_alignment_type(&self) -> AlignmentType {
            self.alignment_type
        }
        fn get_explicit_minimum_alignment(&self) -> i32 {
            self.explicit_min_alignment
        }
    }
    impl Structure for MockStructure {}
    impl CompositeInternal for MockStructure {
        fn get_stored_packing_value(&self) -> i32 {
            self.packing_value
        }
    }
    impl StructureInternal for MockStructure {}

    fn default_structure() -> MockStructure {
        MockStructure {
            packing_value: 0,
            alignment_type: AlignmentType::Default,
            explicit_min_alignment: 1,
            machine_alignment: 8,
        }
    }

    struct TestPacker;
    impl AlignedStructurePacker for TestPacker {
        fn create_component_packer(
            &self,
            _pack_value: i32,
            _data_organization: &dyn DataOrganization,
        ) -> Box<dyn AlignedComponentPacker> {
            Box::new(SequentialComponentPacker {
                next_offset: 0,
                max_length: 1,
            })
        }
    }

    #[test]
    fn usable_as_trait_object_and_swaps_default_components() {
        let structure = default_structure();
        let mut components: Vec<Box<dyn InternalDataTypeComponent>> = vec![
            Box::new(MockComponent {
                length: 1,
                is_default: true,
                ..Default::default()
            }),
            Box::new(MockComponent {
                ordinal: 1,
                length: 4,
                ..Default::default()
            }),
            Box::new(MockComponent {
                ordinal: 2,
                length: 2,
                ..Default::default()
            }),
        ];

        let packer: &dyn AlignedStructurePacker = &TestPacker;
        let result = packer.pack_components(&structure, &mut components);

        assert_eq!(result.num_components, 3);
        assert_eq!(result.alignment, 4);
        assert_eq!(result.structure_length, 12);
        assert!(result.components_changed);

        // The DEFAULT component was transformed into a concrete "undefined" data type.
        assert!(!components[0].get_data_type().is_default_data_type());
        // Its length is preserved (the packer never resizes it -- see module docs).
        assert_eq!(components[0].get_length(), 1);
        // Packing placed the remaining components at their aligned offsets.
        assert_eq!(components[1].get_offset(), 4);
        assert_eq!(components[2].get_offset(), 8);
    }

    #[test]
    fn machine_alignment_type_uses_data_organization_machine_alignment() {
        let structure = MockStructure {
            alignment_type: AlignmentType::Machine,
            machine_alignment: 16,
            ..default_structure()
        };
        let mut components: Vec<Box<dyn InternalDataTypeComponent>> = vec![Box::new(MockComponent {
            length: 2,
            ..Default::default()
        })];

        let packer = TestPacker;
        let result = packer.pack_components(&structure, &mut components);

        // Default alignment from packing alone would only be 2; machine alignment forces 16.
        assert_eq!(result.alignment, 16);
        assert_eq!(result.structure_length, 16);
        assert!(!result.components_changed);
    }

    #[test]
    fn explicit_alignment_type_uses_structures_explicit_minimum_alignment() {
        let structure = MockStructure {
            alignment_type: AlignmentType::Explicit,
            explicit_min_alignment: 8,
            ..default_structure()
        };
        let mut components: Vec<Box<dyn InternalDataTypeComponent>> = vec![Box::new(MockComponent {
            length: 2,
            ..Default::default()
        })];

        let packer = TestPacker;
        let result = packer.pack_components(&structure, &mut components);

        assert_eq!(result.alignment, 8);
        assert_eq!(result.structure_length, 8);
    }
}
