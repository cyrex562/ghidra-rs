use crate::program::model::data::data_type_component::DataTypeComponent;
use super::{IsfObject, AbstractIsfObject};

/// Represents a component of a composite data type in ISF format.
///
/// Mirrors `IsfComponent` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds fields for component metadata: the offset within
/// the parent data type and the type of the component.
///
/// Fields marked with a leading undersexcluded comment are conceptually marked as
/// excluded from serialization (matching the Java `@Exclude` annotation) and are
/// retained for internal use only.
pub struct IsfComponent {
    pub abstract_isf_object: AbstractIsfObject,
    pub offset: Option<i32>,
    pub component_type: Option<Box<dyn IsfObject>>,

    // Excluded fields (marked @Exclude in Java)
    pub ordinal: i32,
    pub length: i32,
    pub field_name: Option<String>,
    pub no_field_name: bool,
    pub comment: Option<String>,
}

impl std::fmt::Debug for IsfComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsfComponent")
            .field("abstract_isf_object", &self.abstract_isf_object)
            .field("offset", &self.offset)
            .field("component_type", &"<dyn IsfObject>")
            .field("ordinal", &self.ordinal)
            .field("length", &self.length)
            .field("field_name", &self.field_name)
            .field("no_field_name", &self.no_field_name)
            .field("comment", &self.comment)
            .finish()
    }
}

impl IsfComponent {
    /// Creates a new `IsfComponent` from a `DataTypeComponent` and its type object.
    ///
    /// Extracts metadata from the provided component via the parent
    /// `AbstractIsfObject`, and initializes the component-specific fields.
    ///
    /// # Arguments
    ///
    /// * `component` - The DataTypeComponent to extract metadata from
    /// * `type_obj` - The ISF object representing the component's type
    ///
    /// Mirrors the Java constructor behavior, which calls `super(component.getDataType())`
    /// and then initializes the various fields from the component.
    pub fn new(component: &dyn DataTypeComponent, type_obj: Box<dyn IsfObject>) -> Self {
        let field_name = component.get_field_name();
        let no_field_name = field_name.is_none() || field_name.as_ref().map_or(false, |n| n.is_empty());

        Self {
            abstract_isf_object: AbstractIsfObject::new(Some(&*component.get_data_type())),
            offset: Some(component.get_offset()),
            component_type: Some(type_obj),
            ordinal: component.get_ordinal(),
            length: component.get_length(),
            field_name,
            no_field_name,
            comment: component.get_comment(),
        }
    }
}

impl IsfObject for IsfComponent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::docking::settings::settings::Settings;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockDataType {
        name: String,
        category_path: String,
    }

    impl MockDataType {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
            }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::from_path(&self.category_path)
        }
    }

    struct MockComponent {
        data_type: MockDataType,
        offset: i32,
        ordinal: i32,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    }

    impl MockComponent {
        fn new(name: &str, path: &str) -> Self {
            Self {
                data_type: MockDataType::new(name, path),
                offset: 0,
                ordinal: 0,
                length: 0,
                field_name: None,
                comment: None,
            }
        }

        fn with_offset(mut self, offset: i32) -> Self {
            self.offset = offset;
            self
        }

        fn with_ordinal(mut self, ordinal: i32) -> Self {
            self.ordinal = ordinal;
            self
        }

        fn with_length(mut self, length: i32) -> Self {
            self.length = length;
            self
        }

        fn with_field_name(mut self, field_name: Option<String>) -> Self {
            self.field_name = field_name;
            self
        }

        fn with_comment(mut self, comment: Option<String>) -> Self {
            self.comment = comment;
            self
        }
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType::new(&self.data_type.name, &self.data_type.category_path))
        }

        fn get_offset(&self) -> i32 {
            self.offset
        }

        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }

        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }

        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    struct MockType;
    impl IsfObject for MockType {}

    #[test]
    fn new_creates_struct_from_component_and_type() {
        let comp = MockComponent::new("TestType", "/Category")
            .with_offset(10)
            .with_ordinal(2)
            .with_length(8)
            .with_field_name(Some("my_field".to_string()));
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.offset, Some(10));
        assert_eq!(isf_comp.ordinal, 2);
        assert_eq!(isf_comp.length, 8);
        assert_eq!(isf_comp.field_name, Some("my_field".to_string()));
        assert!(!isf_comp.no_field_name);
    }

    #[test]
    fn no_field_name_true_when_field_name_is_none() {
        let comp = MockComponent::new("TestType", "/Category")
            .with_field_name(None);
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert!(isf_comp.no_field_name);
    }

    #[test]
    fn no_field_name_true_when_field_name_is_empty() {
        let comp = MockComponent::new("TestType", "/Category")
            .with_field_name(Some(String::new()));
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert!(isf_comp.no_field_name);
    }

    #[test]
    fn no_field_name_false_when_field_name_is_set() {
        let comp = MockComponent::new("TestType", "/Category")
            .with_field_name(Some("field_name".to_string()));
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert!(!isf_comp.no_field_name);
    }

    #[test]
    fn comment_is_extracted_from_component() {
        let comp = MockComponent::new("TestType", "/Category")
            .with_comment(Some("test comment".to_string()));
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.comment, Some("test comment".to_string()));
    }

    #[test]
    fn component_type_is_stored() {
        let comp = MockComponent::new("TestType", "/Category");
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert!(isf_comp.component_type.is_some());
    }

    #[test]
    fn abstract_isf_object_extracts_metadata() {
        let comp = MockComponent::new("MyComponent", "/Components/Test");
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.abstract_isf_object.name, Some("MyComponent".to_string()));
        assert_eq!(
            isf_comp.abstract_isf_object.location,
            Some("/Components/Test".to_string())
        );
    }

    #[test]
    fn offset_matches_component_offset() {
        let comp = MockComponent::new("TestType", "/")
            .with_offset(42);
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.offset, Some(42));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}

        let comp = MockComponent::new("TestType", "/");
        let type_obj = Box::new(MockType);
        let isf_comp = IsfComponent::new(&comp, type_obj);

        accepts_isf_object(&isf_comp);
    }

    #[test]
    fn debug_formatting() {
        let comp = MockComponent::new("TestType", "/");
        let type_obj = Box::new(MockType);
        let isf_comp = IsfComponent::new(&comp, type_obj);

        let debug_str = format!("{:?}", isf_comp);
        assert!(debug_str.contains("IsfComponent"));
    }

    #[test]
    fn clone_creates_independent_copy() {
        let comp = MockComponent::new("TestType", "/Path");
        let type_obj = Box::new(MockType);
        let isf_comp1 = IsfComponent::new(&comp, type_obj);
        let isf_comp2 = isf_comp1.clone();

        assert_eq!(isf_comp1.offset, isf_comp2.offset);
        assert_eq!(isf_comp1.ordinal, isf_comp2.ordinal);
        assert_eq!(isf_comp1.field_name, isf_comp2.field_name);
    }

    #[test]
    fn zero_offset() {
        let comp = MockComponent::new("TestType", "/")
            .with_offset(0);
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.offset, Some(0));
    }

    #[test]
    fn large_offset() {
        let comp = MockComponent::new("TestType", "/")
            .with_offset(i32::MAX);
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.offset, Some(i32::MAX));
    }

    #[test]
    fn zero_length() {
        let comp = MockComponent::new("TestType", "/")
            .with_length(0);
        let type_obj = Box::new(MockType);

        let isf_comp = IsfComponent::new(&comp, type_obj);

        assert_eq!(isf_comp.length, 0);
    }

    #[test]
    fn multiple_components_are_independent() {
        let comp1 = MockComponent::new("Type1", "/Path1")
            .with_offset(10)
            .with_ordinal(0)
            .with_field_name(Some("field1".to_string()));
        let comp2 = MockComponent::new("Type2", "/Path2")
            .with_offset(20)
            .with_ordinal(1)
            .with_field_name(Some("field2".to_string()));
        let type_obj1 = Box::new(MockType);
        let type_obj2 = Box::new(MockType);

        let isf_comp1 = IsfComponent::new(&comp1, type_obj1);
        let isf_comp2 = IsfComponent::new(&comp2, type_obj2);

        assert_eq!(isf_comp1.offset, Some(10));
        assert_eq!(isf_comp2.offset, Some(20));
        assert_eq!(isf_comp1.field_name, Some("field1".to_string()));
        assert_eq!(isf_comp2.field_name, Some("field2".to_string()));
    }
}
