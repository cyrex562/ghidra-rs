use std::cmp::Ordering;

use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;

/// Port of `CompositeInternal.ALIGN_NAME`.
pub const ALIGN_NAME: &str = "aligned";
/// Port of `CompositeInternal.PACKING_NAME`.
pub const PACKING_NAME: &str = "pack";
/// Port of `CompositeInternal.DISABLED_PACKING_NAME`.
pub const DISABLED_PACKING_NAME: &str = "disabled";
/// Port of `CompositeInternal.DEFAULT_PACKING_NAME`.
pub const DEFAULT_PACKING_NAME: &str = "";

/// Port of `CompositeInternal.DEFAULT_PACKING`.
pub const DEFAULT_PACKING: i32 = 0;
/// Port of `CompositeInternal.NO_PACKING`.
pub const NO_PACKING: i32 = -1;
/// Port of `CompositeInternal.DEFAULT_ALIGNMENT`.
pub const DEFAULT_ALIGNMENT: i32 = 0;
/// Port of `CompositeInternal.MACHINE_ALIGNMENT`.
pub const MACHINE_ALIGNMENT: i32 = -1;

/// Interface for common methods in `Structure` and `Union`.
///
/// Port of `ghidra.program.model.data.CompositeInternal`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
///
/// Every method is given a default so that the existing bare `impl CompositeInternal for
/// MockStructure {}`/`impl CompositeInternal for MockUnion {}` in
/// [`StructureInternal`](super::structure_internal::StructureInternal)'s and
/// [`UnionInternal`](super::union_internal::UnionInternal)'s tests keep compiling unmodified.
/// Concrete implementations (`StructureDB`, `UnionDB`, etc.) will override these with real
/// behavior once they are ported.
///
/// The nested `ComponentComparator`, `OffsetComparator`, and `OrdinalComparator` utility classes
/// are ported below as free functions rather than as trait methods, since they are not part of
/// the Java interface's own instance contract.
pub trait CompositeInternal: Composite {
    /// Gets the current packing value (typically a power of 2). Other special values which may
    /// be returned include [`DEFAULT_PACKING`] and [`NO_PACKING`].
    fn get_stored_packing_value(&self) -> i32 {
        DEFAULT_PACKING
    }

    /// Get the minimum alignment setting for this Composite which contributes to the actual
    /// computed alignment value (see [`Composite::get_alignment`](Composite)). Returns a reserved
    /// value to indicate either [`DEFAULT_ALIGNMENT`] or [`MACHINE_ALIGNMENT`].
    fn get_stored_minimum_alignment(&self) -> i32 {
        DEFAULT_ALIGNMENT
    }
}

/// Port of `CompositeInternal.ComponentComparator`.
///
/// Compares two components based upon their ordinal, for sorting components by ordinal.
pub fn compare_components_by_ordinal(a: &dyn DataTypeComponent, b: &dyn DataTypeComponent) -> Ordering {
    a.get_ordinal().cmp(&b.get_ordinal())
}

/// Port of `CompositeInternal.OffsetComparator`.
///
/// Compares a component against a target offset, following the convention expected by
/// `Arrays.binarySearch(elements, key, comparator)` (i.e. `compare(component, offset)`): a
/// component is considered equal (`Ordering::Equal`) if it contains the offset.
pub fn compare_component_to_offset(dtc: &dyn DataTypeComponent, offset: i32) -> Ordering {
    if offset < dtc.get_offset() {
        Ordering::Greater
    } else if offset > dtc.get_end_offset() {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

/// Port of `CompositeInternal.OrdinalComparator`.
///
/// Compares a component against a target ordinal, following the same `compare(component,
/// ordinal)` convention as [`compare_component_to_offset`]. A component is considered equal if it
/// corresponds to the specified ordinal.
pub fn compare_component_to_ordinal(dtc: &dyn DataTypeComponent, ordinal: i32) -> Ordering {
    dtc.get_ordinal().cmp(&ordinal)
}

/// Dump composite and its components for use in `Object.toString()` representation. Port of
/// `CompositeInternal.toString(Composite)`.
pub fn to_string(composite: &dyn Composite) -> String {
    let mut buffer = String::new();
    buffer.push_str(&composite.get_path_name());
    buffer.push('\n');
    buffer.push_str(&get_alignment_and_packing_string(composite));
    buffer.push('\n');
    buffer.push_str(&format!(
        "{} {} {{\n",
        get_type_name(composite),
        composite.get_display_name()
    ));
    dump_components(composite, &mut buffer, "   ");
    buffer.push_str("}\n");
    let length = if composite.is_zero_length() {
        0
    } else {
        composite.get_length()
    };
    buffer.push_str(&format!(
        "Length: {length} Alignment: {}\n",
        composite.get_alignment()
    ));
    buffer
}

/// Dump all components for use in `Object.toString()` representation. Port of the private
/// `CompositeInternal.dumpComponents`.
///
/// The Java original casts a component's data type to `BitFieldDataType` to append its bit
/// offset; that is expressed here via
/// [`DataTypeComponent::is_bit_field_component`](DataTypeComponent::is_bit_field_component) and
/// [`DataTypeComponent::bit_field_bit_offset`](DataTypeComponent::bit_field_bit_offset), which
/// already stand in for that cast elsewhere in the crate.
fn dump_components(composite: &dyn Composite, buffer: &mut String, pad: &str) {
    for dtc in composite.get_defined_components() {
        buffer.push_str(&format!("{pad}{}", dtc.get_offset()));
        buffer.push_str(&format!("{pad}{}", dtc.get_data_type_name()));
        if dtc.is_bit_field_component() {
            buffer.push_str(&format!("({})", dtc.bit_field_bit_offset()));
        }
        buffer.push_str(&format!("{pad}{}", dtc.get_length()));
        buffer.push_str(&format!("{pad}{}", dtc.get_field_name().unwrap_or_default()));
        buffer.push_str(&format!("{pad}\"{}\"", dtc.get_comment().unwrap_or_default()));
        buffer.push('\n');
    }
}

/// Port of the private `CompositeInternal.getTypeName`.
fn get_type_name(composite: &dyn Composite) -> &'static str {
    if composite.is_structure() {
        "Structure"
    } else if composite.is_union() {
        "Union"
    } else {
        ""
    }
}

/// Port of `CompositeInternal.getAlignmentAndPackingString`.
pub fn get_alignment_and_packing_string(composite: &dyn Composite) -> String {
    let mut buf = get_min_alignment_string(composite);
    if !buf.is_empty() {
        buf.push(' ');
    }
    buf.push_str(&get_packing_string(composite));
    buf
}

/// Port of `CompositeInternal.getMinAlignmentString`.
pub fn get_min_alignment_string(composite: &dyn Composite) -> String {
    if composite.is_default_aligned() {
        return String::new();
    }
    let mut buf = String::from(ALIGN_NAME);
    buf.push('(');
    if composite.is_machine_aligned() {
        buf.push_str("machine:");
        buf.push_str(&composite.get_data_organization().get_machine_alignment().to_string());
    } else {
        buf.push_str(&composite.get_explicit_minimum_alignment().to_string());
    }
    buf.push(')');
    buf
}

/// Port of `CompositeInternal.getPackingString`.
pub fn get_packing_string(composite: &dyn Composite) -> String {
    let mut buf = String::from(PACKING_NAME);
    buf.push('(');
    if composite.is_packing_enabled() {
        if composite.has_explicit_packing_value() {
            buf.push_str(&composite.get_explicit_packing_value().to_string());
        } else {
            buf.push_str(DEFAULT_PACKING_NAME);
        }
    } else {
        buf.push_str(DISABLED_PACKING_NAME);
    }
    buf.push(')');
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::alignment_type::AlignmentType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::packing_type::PackingType;

    struct MockDataTypeComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
    }

    impl DataTypeComponent for MockDataTypeComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_data_type_name(&self) -> String {
            "int".to_string()
        }
        fn get_field_name(&self) -> Option<String> {
            Some(format!("field{}", self.ordinal))
        }
    }

    struct MockStructure {
        packing_type: PackingType,
        components: Vec<MockDataTypeComponent>,
    }

    impl DataType for MockStructure {
        fn is_structure(&self) -> bool {
            true
        }
        fn get_path_name(&self) -> String {
            "/MockStructure".to_string()
        }
        fn get_display_name(&self) -> String {
            "MockStructure".to_string()
        }
    }

    impl Composite for MockStructure {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|c| -> Box<dyn DataTypeComponent> {
                    Box::new(MockDataTypeComponent {
                        ordinal: c.ordinal,
                        offset: c.offset,
                        length: c.length,
                    })
                })
                .collect()
        }

        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
    }

    impl CompositeInternal for MockStructure {}

    #[test]
    fn usable_as_trait_object() {
        let s = MockStructure {
            packing_type: PackingType::Disabled,
            components: vec![],
        };
        let dyn_composite: &dyn CompositeInternal = &s;
        assert_eq!(dyn_composite.get_stored_packing_value(), DEFAULT_PACKING);
        assert_eq!(dyn_composite.get_stored_minimum_alignment(), DEFAULT_ALIGNMENT);
    }

    #[test]
    fn get_packing_string_reflects_packing_type() {
        let mut s = MockStructure {
            packing_type: PackingType::Disabled,
            components: vec![],
        };
        assert_eq!(get_packing_string(&s), "pack(disabled)");

        s.packing_type = PackingType::Default;
        assert_eq!(get_packing_string(&s), "pack()");

        s.packing_type = PackingType::Explicit;
        assert_eq!(get_packing_string(&s), "pack(0)");
    }

    #[test]
    fn get_min_alignment_string_default_is_empty() {
        let s = MockStructure {
            packing_type: PackingType::Disabled,
            components: vec![],
        };
        assert_eq!(get_min_alignment_string(&s), "");
    }

    struct MockBitFieldPacking;
    impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockBitFieldPacking {
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
        fn get_bit_field_packing(
            &self,
        ) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
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

    struct MachineAlignedStructure;
    impl DataType for MachineAlignedStructure {
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }
    impl Composite for MachineAlignedStructure {
        fn get_alignment_type(&self) -> AlignmentType {
            AlignmentType::Machine
        }
    }

    #[test]
    fn get_min_alignment_string_reports_machine_alignment() {
        let s = MachineAlignedStructure;
        assert_eq!(get_min_alignment_string(&s), "aligned(machine:8)");
    }

    #[test]
    fn to_string_dumps_type_name_and_components() {
        let s = MockStructure {
            packing_type: PackingType::Disabled,
            components: vec![MockDataTypeComponent {
                ordinal: 0,
                offset: 0,
                length: 4,
            }],
        };
        let dump = to_string(&s);
        assert!(dump.contains("Structure MockStructure {"));
        assert!(dump.contains("field0"));
        assert!(dump.starts_with("/MockStructure\n"));
    }

    #[test]
    fn comparators_match_java_semantics() {
        let a = MockDataTypeComponent {
            ordinal: 0,
            offset: 0,
            length: 4,
        };
        let b = MockDataTypeComponent {
            ordinal: 1,
            offset: 4,
            length: 4,
        };
        assert_eq!(compare_components_by_ordinal(&a, &b), Ordering::Less);
        assert_eq!(compare_component_to_offset(&a, 0), Ordering::Equal);
        assert_eq!(compare_component_to_offset(&a, 4), Ordering::Less);
        assert_eq!(compare_component_to_offset(&b, 0), Ordering::Greater);
        assert_eq!(compare_component_to_ordinal(&b, 1), Ordering::Equal);
        assert_eq!(compare_component_to_ordinal(&b, 0), Ordering::Greater);
    }
}
