use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::isf::{IsfObject, IsfDynamicComponent};

/// Extended ISF dynamic component for SARIF export with variable-length support.
///
/// Mirrors `ExtIsfDynamicComponent` from Ghidra's `sarif.export.data` package.
/// Extends [`IsfDynamicComponent`] with a flag indicating whether the component
/// represents a variable-length array.
pub struct ExtIsfDynamicComponent {
    pub component: IsfDynamicComponent,
    pub is_variable_length: bool,
}

impl ExtIsfDynamicComponent {
    /// Creates a new `ExtIsfDynamicComponent` from a dynamic type.
    ///
    /// Initializes the underlying [`IsfDynamicComponent`] and sets
    /// `is_variable_length` to `true` by default, matching the Java
    /// implementation which initializes this field to `true`.
    ///
    /// # Arguments
    ///
    /// * `dynamic_type` - The Dynamic data type to extract metadata from
    /// * `subtype` - The element type of the array
    /// * `element_cnt` - The number of elements in the array
    pub fn new(
        dynamic_type: &dyn Dynamic,
        subtype: Box<dyn IsfObject>,
        element_cnt: i32,
    ) -> Self {
        Self {
            component: IsfDynamicComponent::new(dynamic_type, subtype, element_cnt),
            is_variable_length: true,
        }
    }
}

impl IsfObject for ExtIsfDynamicComponent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::docking::settings::settings::Settings;
    use crate::program::seam_stubs::MemBuffer;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockDynamic {
        name: String,
        category_path: String,
    }

    impl MockDynamic {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
            }
        }
    }

    impl DataType for MockDynamic {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::parse(&self.category_path).unwrap()
        }
    }

    impl crate::program::model::data::built_in_data_type::BuiltInDataType for MockDynamic {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockDynamic {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, max_length: i32) -> i32 {
            max_length
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            struct ReplacementBaseType;
            impl DataType for ReplacementBaseType {
                fn get_name(&self) -> String {
                    "replacement".to_string()
                }

                fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
                    use crate::program::model::data::category_path::CategoryPath;
                    CategoryPath::parse("/").unwrap()
                }
            }
            Box::new(ReplacementBaseType)
        }
    }

    struct MockSubtype;
    impl IsfObject for MockSubtype {}

    #[test]
    fn new_creates_component_with_variable_length_true() {
        let dyn_type = MockDynamic::new("DynArray", "/Category");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 10);

        assert!(ext_component.is_variable_length);
        assert_eq!(ext_component.component.kind, "array");
        assert_eq!(ext_component.component.count, Some(10));
    }

    #[test]
    fn variable_length_initialized_to_true() {
        let dyn_type = MockDynamic::new("Array", "/");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 5);

        assert_eq!(ext_component.is_variable_length, true);
    }

    #[test]
    fn wraps_isf_dynamic_component_correctly() {
        let dyn_type = MockDynamic::new("VarArray", "/Var");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 20);

        assert_eq!(ext_component.component.kind, "array");
        assert_eq!(ext_component.component.count, Some(20));
    }

    #[test]
    fn preserves_element_count_in_wrapped_component() {
        let dyn_type = MockDynamic::new("Array", "/");
        let subtype = Box::new(MockSubtype);
        let element_cnt = 42;

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, element_cnt);

        assert_eq!(ext_component.component.count, Some(element_cnt));
    }

    #[test]
    fn preserves_dynamic_type_metadata() {
        let dyn_type = MockDynamic::new("CustomArray", "/Path/To/Array");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 7);

        assert_eq!(
            ext_component.component.abstract_isf_object.name,
            Some("CustomArray".to_string())
        );
        assert_eq!(
            ext_component.component.abstract_isf_object.location,
            Some("/Path/To/Array".to_string())
        );
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}

        let dyn_type = MockDynamic::new("Array", "/");
        let subtype = Box::new(MockSubtype);
        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 1);

        accepts_isf_object(&ext_component);
    }

    #[test]
    fn zero_element_count_preserves_variable_length() {
        let dyn_type = MockDynamic::new("EmptyArray", "/");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, 0);

        assert!(ext_component.is_variable_length);
        assert_eq!(ext_component.component.count, Some(0));
    }

    #[test]
    fn large_element_count_preserves_variable_length() {
        let dyn_type = MockDynamic::new("LargeArray", "/");
        let subtype = Box::new(MockSubtype);

        let ext_component = ExtIsfDynamicComponent::new(&dyn_type, subtype, i32::MAX);

        assert!(ext_component.is_variable_length);
        assert_eq!(ext_component.component.count, Some(i32::MAX));
    }

    #[test]
    fn multiple_instances_maintain_independent_state() {
        let dyn_type1 = MockDynamic::new("Array1", "/Path1");
        let dyn_type2 = MockDynamic::new("Array2", "/Path2");
        let subtype1 = Box::new(MockSubtype);
        let subtype2 = Box::new(MockSubtype);

        let comp1 = ExtIsfDynamicComponent::new(&dyn_type1, subtype1, 10);
        let comp2 = ExtIsfDynamicComponent::new(&dyn_type2, subtype2, 20);

        assert_eq!(comp1.component.count, Some(10));
        assert_eq!(comp2.component.count, Some(20));
        assert!(comp1.is_variable_length);
        assert!(comp2.is_variable_length);
        assert_eq!(comp1.component.abstract_isf_object.name, Some("Array1".to_string()));
        assert_eq!(comp2.component.abstract_isf_object.name, Some("Array2".to_string()));
    }
}
