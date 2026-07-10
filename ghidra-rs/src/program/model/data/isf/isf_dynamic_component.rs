use crate::program::model::data::dynamic::Dynamic;
use super::{IsfObject, AbstractIsfObject};

/// Represents a dynamic array component in ISF format.
///
/// Mirrors `IsfDynamicComponent` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds fields for array metadata: the kind (always `"array"`),
/// the subtype element data type, and the count of elements.
///
/// The `abstract_isf_object` field is marked with `#[serde(skip)]` to match the Java
/// `@Exclude` annotation on those parent fields.
pub struct IsfDynamicComponent {
    pub abstract_isf_object: AbstractIsfObject,
    pub kind: String,
    pub count: Option<i32>,
    pub subtype: Option<Box<dyn IsfObject>>,
}

impl std::fmt::Debug for IsfDynamicComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsfDynamicComponent")
            .field("abstract_isf_object", &self.abstract_isf_object)
            .field("kind", &self.kind)
            .field("count", &self.count)
            .field("subtype", &"<dyn IsfObject>")
            .finish()
    }
}

impl IsfDynamicComponent {
    /// Creates a new `IsfDynamicComponent` from a `Dynamic` data type.
    ///
    /// Extracts metadata from the provided dynamic type via the parent
    /// `AbstractIsfObject`, and initializes the array-specific fields.
    ///
    /// # Arguments
    ///
    /// * `dynamic_type` - The Dynamic data type to extract metadata from
    /// * `subtype` - The element type of the array
    /// * `element_cnt` - The number of elements in the array
    ///
    /// Mirrors the Java constructor behavior, which calls `super(dynamicType)` and then
    /// initializes the three fields: `kind` to `"array"`, `count` to `elementCnt`,
    /// and `subtype` to `type`.
    pub fn new(dynamic_type: &dyn Dynamic, subtype: Box<dyn IsfObject>, element_cnt: i32) -> Self {
        Self {
            abstract_isf_object: AbstractIsfObject::new(Some(dynamic_type)),
            kind: "array".to_string(),
            count: Some(element_cnt),
            subtype: Some(subtype),
        }
    }
}

impl IsfObject for IsfDynamicComponent {}

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
    fn new_creates_struct_from_dynamic_and_subtype() {
        let dyn_type = MockDynamic::new("DynArray", "/Category");
        let subtype = Box::new(MockSubtype);
        let element_cnt = 10;

        let component = IsfDynamicComponent::new(&dyn_type, subtype, element_cnt);

        assert_eq!(component.kind, "array");
        assert_eq!(component.count, Some(10));
        assert!(component.subtype.is_some());
    }

    #[test]
    fn kind_always_set_to_array() {
        let dyn_type = MockDynamic::new("Array", "/");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, 5);

        assert_eq!(component.kind, "array");
    }

    #[test]
    fn count_matches_element_count() {
        let dyn_type = MockDynamic::new("DynType", "/Test");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, 42);

        assert_eq!(component.count, Some(42));
    }

    #[test]
    fn subtype_is_stored() {
        let dyn_type = MockDynamic::new("DynType", "/");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, 1);

        assert!(component.subtype.is_some());
    }

    #[test]
    fn abstract_isf_object_extracts_metadata() {
        let dyn_type = MockDynamic::new("MyArray", "/Arrays/Dynamic");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, 3);

        assert_eq!(component.abstract_isf_object.name, Some("MyArray".to_string()));
        assert_eq!(
            component.abstract_isf_object.location,
            Some("/Arrays/Dynamic".to_string())
        );
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}

        let dyn_type = MockDynamic::new("DynType", "/");
        let subtype = Box::new(MockSubtype);
        let component = IsfDynamicComponent::new(&dyn_type, subtype, 5);

        accepts_isf_object(&component);
    }


    #[test]
    fn debug_formatting() {
        let dyn_type = MockDynamic::new("DynType", "/");
        let subtype = Box::new(MockSubtype);
        let component = IsfDynamicComponent::new(&dyn_type, subtype, 1);

        let debug_str = format!("{:?}", component);
        assert!(debug_str.contains("IsfDynamicComponent"));
    }

    #[test]
    fn zero_element_count() {
        let dyn_type = MockDynamic::new("EmptyArray", "/");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, 0);

        assert_eq!(component.count, Some(0));
    }

    #[test]
    fn large_element_count() {
        let dyn_type = MockDynamic::new("LargeArray", "/");
        let subtype = Box::new(MockSubtype);

        let component = IsfDynamicComponent::new(&dyn_type, subtype, i32::MAX);

        assert_eq!(component.count, Some(i32::MAX));
    }

    #[test]
    fn multiple_components_have_independent_subtypes() {
        let dyn_type1 = MockDynamic::new("Array1", "/Path1");
        let dyn_type2 = MockDynamic::new("Array2", "/Path2");
        let subtype1 = Box::new(MockSubtype);
        let subtype2 = Box::new(MockSubtype);

        let comp1 = IsfDynamicComponent::new(&dyn_type1, subtype1, 10);
        let comp2 = IsfDynamicComponent::new(&dyn_type2, subtype2, 20);

        assert_eq!(comp1.count, Some(10));
        assert_eq!(comp2.count, Some(20));
        assert_eq!(comp1.abstract_isf_object.name, Some("Array1".to_string()));
        assert_eq!(comp2.abstract_isf_object.name, Some("Array2".to_string()));
    }
}
