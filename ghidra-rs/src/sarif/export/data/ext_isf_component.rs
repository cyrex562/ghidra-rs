use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::isf::{IsfComponent, IsfObject};

/// Extended ISF component for SARIF export, adding bit-field metadata.
///
/// Port of `sarif.export.data.ExtIsfComponent`.
pub struct ExtIsfComponent {
    pub component: IsfComponent,
    pub bit_offset: Option<i32>,
    pub bit_size: Option<i32>,
}

impl std::fmt::Debug for ExtIsfComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtIsfComponent")
            .field("component", &self.component)
            .field("bit_offset", &self.bit_offset)
            .field("bit_size", &self.bit_size)
            .finish()
    }
}

impl ExtIsfComponent {
    /// Creates a new `ExtIsfComponent` from a `DataTypeComponent` and its type object.
    ///
    /// Mirrors `ExtIsfComponent(DataTypeComponent component, IsfObject typeObj)`: constructs the
    /// base [`IsfComponent`] first (Java: `super(component, typeObj)`), then, only when
    /// `component.isBitFieldComponent()`, downcasts `component.getDataType()` to
    /// `BitFieldDataType` and captures its bit offset/size. When the component is not a
    /// bit-field, `bit_offset`/`bit_size` stay `None` -- matching Java, whose `bitOffset`/
    /// `bitSize` fields are simply never assigned (left `null`) in that case.
    pub fn new(component: &dyn DataTypeComponent, type_obj: Box<dyn IsfObject>) -> Self {
        let mut bit_offset = None;
        let mut bit_size = None;

        if component.is_bit_field_component() {
            let data_type = component.get_data_type();
            if let Some(bit_field) = data_type.as_bit_field() {
                bit_offset = Some(bit_field.get_bit_offset());
                bit_size = Some(bit_field.get_bit_size());
            }
        }

        Self { component: IsfComponent::new(component, type_obj), bit_offset, bit_size }
    }
}

impl IsfObject for ExtIsfComponent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::data_type::DataType;
    use crate::program::seam_stubs::BitFieldDataType;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockDataType {
        name: String,
        category_path: String,
    }

    impl MockDataType {
        fn new(name: &str, path: &str) -> Self {
            Self { name: name.to_string(), category_path: path.to_string() }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::parse(&self.category_path).unwrap()
        }
    }

    /// A `MockDataType` that also answers `as_bit_field`, standing in for a real
    /// `BitFieldDataType` instance the way Java's `(BitFieldDataType) component.getDataType()`
    /// cast would find one.
    struct MockBitFieldDataType {
        base: MockDataType,
        bit_offset: i32,
        bit_size: i32,
    }

    impl DataType for MockBitFieldDataType {
        fn get_name(&self) -> String {
            self.base.get_name()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            self.base.get_category_path()
        }

        fn as_bit_field(&self) -> Option<&dyn BitFieldDataType> {
            Some(self)
        }
    }

    impl BitFieldDataType for MockBitFieldDataType {
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType::new(&self.base.name, &self.base.category_path))
        }

        fn get_bit_size(&self) -> i32 {
            self.bit_size
        }

        fn get_bit_offset(&self) -> i32 {
            self.bit_offset
        }
    }

    struct MockComponent {
        data_type_name: String,
        is_bit_field: bool,
        bit_offset: i32,
        bit_size: i32,
    }

    impl MockComponent {
        fn plain(name: &str) -> Self {
            Self { data_type_name: name.to_string(), is_bit_field: false, bit_offset: 0, bit_size: 0 }
        }

        fn bit_field(name: &str, bit_offset: i32, bit_size: i32) -> Self {
            Self { data_type_name: name.to_string(), is_bit_field: true, bit_offset, bit_size }
        }
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            if self.is_bit_field {
                Box::new(MockBitFieldDataType {
                    base: MockDataType::new(&self.data_type_name, "/"),
                    bit_offset: self.bit_offset,
                    bit_size: self.bit_size,
                })
            } else {
                Box::new(MockDataType::new(&self.data_type_name, "/"))
            }
        }

        fn is_bit_field_component(&self) -> bool {
            self.is_bit_field
        }

        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    struct MockType;
    impl IsfObject for MockType {}

    #[test]
    fn non_bit_field_component_leaves_bit_fields_none() {
        let comp = MockComponent::plain("int");
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));

        assert_eq!(ext.bit_offset, None);
        assert_eq!(ext.bit_size, None);
    }

    #[test]
    fn bit_field_component_captures_offset_and_size() {
        let comp = MockComponent::bit_field("int", 3, 5);
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));

        assert_eq!(ext.bit_offset, Some(3));
        assert_eq!(ext.bit_size, Some(5));
    }

    #[test]
    fn wraps_the_base_isf_component() {
        let comp = MockComponent::plain("char");
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));
        assert_eq!(ext.component.abstract_isf_object.name, Some("char".to_string()));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let comp = MockComponent::plain("char");
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));
        accepts_isf_object(&ext);
    }

    #[test]
    fn debug_formatting_does_not_panic() {
        let comp = MockComponent::bit_field("int", 1, 2);
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));
        let s = format!("{:?}", ext);
        assert!(s.contains("ExtIsfComponent"));
    }

    #[test]
    fn zero_bit_offset_and_size_are_still_some() {
        // Ensures the `Option` wrapping tracks "was this a bit field" rather than "was the value
        // truthy" -- Java's boxed `Integer` fields are non-null (0) here, not null.
        let comp = MockComponent::bit_field("int", 0, 0);
        let ext = ExtIsfComponent::new(&comp, Box::new(MockType));
        assert_eq!(ext.bit_offset, Some(0));
        assert_eq!(ext.bit_size, Some(0));
    }
}
