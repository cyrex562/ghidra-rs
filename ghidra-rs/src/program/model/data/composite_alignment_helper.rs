use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::composite_internal::CompositeInternal;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_organization_impl::get_least_common_multiple;
use crate::program::model::data::data_type_component::DataTypeComponent;

/// Port of `ghidra.program.model.data.CompositeAlignmentHelper`.
///
/// A plain (non-`DataType`) static utility class in Java holding the alignment-computation logic
/// shared by packed `Structure`/`Union` layout. Ported here as free functions, matching the
/// Java class's own shape (it has no fields and is never instantiated).
///
/// Port of `CompositeAlignmentHelper.getCompositeAlignmentMultiple(DataOrganization,
/// CompositeInternal)`.
fn get_composite_alignment_multiple(
    data_organization: &DataOrganizationImpl,
    composite: &dyn CompositeInternal,
) -> i32 {
    let mut all_components_lcm = 1;
    let packing_value = composite.get_stored_packing_value();

    for data_type_component in composite.get_defined_components() {
        let imparted_alignment =
            get_packed_alignment(data_organization, packing_value, data_type_component.as_ref());
        if imparted_alignment != 0 {
            all_components_lcm = get_least_common_multiple(all_components_lcm, imparted_alignment);
        }
    }
    all_components_lcm
}

/// Port of `CompositeAlignmentHelper.getPackedAlignment(DataOrganization, int,
/// DataTypeComponent)`.
pub fn get_packed_alignment(
    data_organization: &DataOrganizationImpl,
    packing_value: i32,
    component: &dyn DataTypeComponent,
) -> i32 {
    if component.is_zero_bit_field_component()
        && component.get_parent().is_union()
        && !data_organization.get_bit_field_packing().use_ms_convention()
    {
        // Zero-length bitfields ignored within unions for non-MSVC cases
        return 0;
    }
    let component_dt = component.get_data_type();
    get_packed_alignment_values(component_dt.get_alignment(), packing_value)
}

/// Port of the package-private `CompositeAlignmentHelper.getPackedAlignment(int, int)` overload.
///
/// Named `get_packed_alignment_values` (rather than overloading `get_packed_alignment`) since
/// Rust has no method overloading; the two-`DataTypeComponent`-free `i32` arguments make the
/// distinction unambiguous at call sites.
pub fn get_packed_alignment_values(component_alignment: i32, packing_value: i32) -> i32 {
    if packing_value > 0 && packing_value < component_alignment {
        packing_value
    } else {
        component_alignment
    }
}

/// Port of `CompositeAlignmentHelper.getAlignment(DataOrganization, CompositeInternal)`.
///
/// TODO: goal is to eliminate this method in favor of pack once and remember alignment (ported
/// verbatim from the Java source's own TODO comment).
pub fn get_alignment(
    data_organization: &DataOrganizationImpl,
    composite: &dyn CompositeInternal,
) -> i32 {
    let mut minimum_alignment = composite.get_stored_minimum_alignment();
    if minimum_alignment < crate::program::model::data::composite_internal::DEFAULT_ALIGNMENT {
        minimum_alignment = data_organization.get_machine_alignment();
    }

    if !composite.is_packing_enabled() {
        return if minimum_alignment
            == crate::program::model::data::composite_internal::DEFAULT_ALIGNMENT
        {
            1
        } else {
            minimum_alignment
        };
    }

    let mut lcm = get_composite_alignment_multiple(data_organization, composite);
    if minimum_alignment != crate::program::model::data::composite_internal::DEFAULT_ALIGNMENT
        && lcm % minimum_alignment != 0
    {
        lcm = get_least_common_multiple(lcm, minimum_alignment);
    }
    let absolute_max_alignment = data_organization.get_absolute_max_alignment();
    if absolute_max_alignment == 0 || lcm < absolute_max_alignment {
        lcm
    } else {
        absolute_max_alignment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing_impl::BitFieldPackingImpl;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type::DataType;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization(machine_alignment: i32, absolute_max_alignment: i32, ms_convention: bool) -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(4);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(absolute_max_alignment);
        org.set_machine_alignment(machine_alignment);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        let mut packing = BitFieldPackingImpl::new();
        packing.set_use_ms_convention(ms_convention);
        packing.set_type_alignment_enabled(false);
        org.set_bit_field_packing(packing);
        org
    }

    fn default_organization() -> DataOrganizationImpl {
        mock_data_organization(8, 0, false)
    }

    struct MockDataType {
        alignment: i32,
        is_union: bool,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_length(&self) -> i32 {
            self.alignment
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
        fn is_union(&self) -> bool {
            self.is_union
        }
    }

    struct MockComponent {
        data_type_alignment: i32,
        is_zero_bit_field: bool,
        parent_is_union: bool,
    }

    impl DataTypeComponent for MockComponent {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn get_offset(&self) -> i32 {
            0
        }
        fn get_length(&self) -> i32 {
            self.data_type_alignment
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { alignment: self.data_type_alignment, is_union: false })
        }
        fn get_parent(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { alignment: 1, is_union: self.parent_is_union })
        }
        fn is_zero_bit_field_component(&self) -> bool {
            self.is_zero_bit_field
        }
    }

    struct MockComposite {
        components: Vec<MockComponent>,
        packing_value: i32,
        minimum_alignment: i32,
        packing_enabled: bool,
    }

    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            "mock_composite".to_string()
        }
        fn get_length(&self) -> i32 {
            0
        }
    }

    impl Composite for MockComposite {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|c| -> Box<dyn DataTypeComponent> {
                    Box::new(MockComponent {
                        data_type_alignment: c.data_type_alignment,
                        is_zero_bit_field: c.is_zero_bit_field,
                        parent_is_union: c.parent_is_union,
                    })
                })
                .collect()
        }
        fn is_packing_enabled(&self) -> bool {
            self.packing_enabled
        }
    }

    impl CompositeInternal for MockComposite {
        fn get_stored_packing_value(&self) -> i32 {
            self.packing_value
        }
        fn get_stored_minimum_alignment(&self) -> i32 {
            self.minimum_alignment
        }
    }

    fn component(alignment: i32) -> MockComponent {
        MockComponent { data_type_alignment: alignment, is_zero_bit_field: false, parent_is_union: false }
    }

    #[test]
    fn get_packed_alignment_values_uses_smaller_positive_packing() {
        assert_eq!(get_packed_alignment_values(8, 4), 4);
        assert_eq!(get_packed_alignment_values(8, 0), 8);
        assert_eq!(get_packed_alignment_values(2, 4), 2);
    }

    #[test]
    fn get_packed_alignment_ignores_zero_length_bitfield_in_union_without_ms_convention() {
        let org = default_organization();
        let comp = MockComponent { data_type_alignment: 4, is_zero_bit_field: true, parent_is_union: true };
        assert_eq!(get_packed_alignment(&org, 0, &comp), 0);
    }

    #[test]
    fn get_packed_alignment_honors_zero_length_bitfield_in_union_with_ms_convention() {
        let org = mock_data_organization(8, 0, true);
        let comp = MockComponent { data_type_alignment: 4, is_zero_bit_field: true, parent_is_union: true };
        assert_eq!(get_packed_alignment(&org, 0, &comp), 4);
    }

    #[test]
    fn get_packed_alignment_ignores_zero_length_bitfield_outside_union() {
        let org = default_organization();
        let comp = MockComponent { data_type_alignment: 4, is_zero_bit_field: true, parent_is_union: false };
        // Not a union parent, so the MSVC-exception path doesn't apply; normal alignment used.
        assert_eq!(get_packed_alignment(&org, 0, &comp), 4);
    }

    #[test]
    fn get_alignment_returns_one_when_packing_disabled_and_no_minimum() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(4)],
            packing_value: 0,
            minimum_alignment: 0,
            packing_enabled: false,
        };
        assert_eq!(get_alignment(&org, &composite), 1);
    }

    #[test]
    fn get_alignment_returns_minimum_when_packing_disabled_and_minimum_set() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(4)],
            packing_value: 0,
            minimum_alignment: 16,
            packing_enabled: false,
        };
        assert_eq!(get_alignment(&org, &composite), 16);
    }

    #[test]
    fn get_alignment_uses_machine_alignment_when_minimum_below_default() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![],
            packing_value: 0,
            minimum_alignment: -1,
            packing_enabled: false,
        };
        assert_eq!(get_alignment(&org, &composite), org.get_machine_alignment());
    }

    #[test]
    fn get_alignment_computes_lcm_of_component_alignments_when_packing_enabled() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(4), component(6)],
            packing_value: 0,
            minimum_alignment: 0,
            packing_enabled: true,
        };
        assert_eq!(get_alignment(&org, &composite), 12);
    }

    #[test]
    fn get_alignment_folds_in_minimum_alignment_via_lcm() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(4)],
            packing_value: 0,
            minimum_alignment: 6,
            packing_enabled: true,
        };
        // lcm(4, 6) == 12
        assert_eq!(get_alignment(&org, &composite), 12);
    }

    #[test]
    fn get_alignment_caps_at_absolute_max_alignment() {
        let org = mock_data_organization(8, 4, false);
        let composite = MockComposite {
            components: vec![component(16)],
            packing_value: 0,
            minimum_alignment: 0,
            packing_enabled: true,
        };
        assert_eq!(get_alignment(&org, &composite), 4);
    }

    #[test]
    fn get_alignment_zero_absolute_max_means_uncapped() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(64)],
            packing_value: 0,
            minimum_alignment: 0,
            packing_enabled: true,
        };
        assert_eq!(get_alignment(&org, &composite), 64);
    }

    #[test]
    fn get_alignment_applies_packing_value_cap_to_components() {
        let org = default_organization();
        let composite = MockComposite {
            components: vec![component(16)],
            packing_value: 4,
            minimum_alignment: 0,
            packing_enabled: true,
        };
        assert_eq!(get_alignment(&org, &composite), 4);
    }
}
