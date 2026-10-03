use crate::program::model::data::composite::Composite;
use crate::program::model::data::isf::{IsfComposite, IsfCompositeWriter, IsfObject};
use crate::sarif::export::data::ExtIsfComponent;
use crate::util::task::TaskMonitor;

/// Extended ISF composite for SARIF export, adding packing/alignment metadata.
///
/// Port of `sarif.export.data.ExtIsfComposite`.
pub struct ExtIsfComposite {
    pub composite: IsfComposite,
    pub packed: String,
    pub explicit_packing_value: Option<i32>,
    pub alignment: String,
    pub explicit_minimum_alignment: Option<i32>,
}

impl std::fmt::Debug for ExtIsfComposite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtIsfComposite")
            .field("composite", &self.composite)
            .field("packed", &self.packed)
            .field("explicit_packing_value", &self.explicit_packing_value)
            .field("alignment", &self.alignment)
            .field("explicit_minimum_alignment", &self.explicit_minimum_alignment)
            .finish()
    }
}

impl ExtIsfComposite {
    /// Creates a new `ExtIsfComposite` from a `Composite` data type.
    ///
    /// Mirrors `ExtIsfComposite(Composite composite, IsfDataTypeWriter writer, TaskMonitor
    /// monitor)`: builds the base [`IsfComposite`] first (Java: `super(composite, writer,
    /// monitor)`), overriding `getComponent` to build [`ExtIsfComponent`]s in place of plain
    /// `IsfComponent`s via
    /// [`IsfComposite::new_with_component_factory`] (see that method's docs for why -- Rust has no
    /// virtual dispatch to override `IsfComposite::new`'s call through), then captures the
    /// composite's packing/alignment metadata.
    pub fn new(
        composite: &dyn Composite,
        writer: &mut dyn IsfCompositeWriter,
        monitor: &dyn TaskMonitor,
    ) -> Self {
        let mut isf_composite = IsfComposite::new_with_component_factory(
            composite,
            writer,
            monitor,
            |component, type_obj| Box::new(ExtIsfComponent::new(component, type_obj)),
        );

        // Java re-derives `name`/`location` here from `composite`, even though the super
        // constructor already set them identically via `AbstractIsfObject`'s own extraction --
        // a redundant but harmless reassignment (same values, computed the same way), faithfully
        // preserved rather than silently dropped.
        isf_composite.abstract_isf_object.name = Some(composite.get_name());
        isf_composite.abstract_isf_object.location = Some(composite.get_category_path().get_path());

        let packed = composite.is_packing_enabled().to_string();
        let epval = composite.get_explicit_packing_value();
        let explicit_packing_value = if epval > 0 { Some(epval) } else { None };
        let alignment = format!("{:x}", composite.get_alignment());
        let maval = composite.get_explicit_minimum_alignment();
        let explicit_minimum_alignment = if maval > 0 { Some(maval) } else { None };

        ExtIsfComposite {
            composite: isf_composite,
            packed,
            explicit_packing_value,
            alignment,
            explicit_minimum_alignment,
        }
    }
}

impl IsfObject for ExtIsfComposite {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::alignment_type::AlignmentType;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::packing_type::PackingType;
    use crate::util::task::DummyMonitor;
    use serde_json::Value as JsonValue;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockComponent {
        data_type_name: String,
        offset: i32,
        ordinal: i32,
        field_name: Option<String>,
    }

    #[derive(Clone)]
    struct MockDataType {
        name: String,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse("/").unwrap()
        }
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { name: self.data_type_name.clone() })
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    struct MockComposite {
        name: String,
        category_path: String,
        is_struct: bool,
        length: i32,
        zero_length: bool,
        packing_type: PackingType,
        explicit_packing_value: i32,
        alignment_type: AlignmentType,
        explicit_minimum_alignment: i32,
        alignment: i32,
        components: Vec<MockComponent>,
    }

    impl Default for MockComposite {
        fn default() -> Self {
            MockComposite {
                name: "MyStruct".to_string(),
                category_path: "/".to_string(),
                is_struct: true,
                length: 8,
                zero_length: false,
                packing_type: PackingType::Disabled,
                explicit_packing_value: 0,
                alignment_type: AlignmentType::Default,
                explicit_minimum_alignment: 0,
                alignment: 1,
                components: Vec::new(),
            }
        }
    }

    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse(&self.category_path).unwrap()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_zero_length(&self) -> bool {
            self.zero_length
        }
        fn is_structure(&self) -> bool {
            self.is_struct
        }
        fn is_union(&self) -> bool {
            !self.is_struct
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
    }

    impl Composite for MockComposite {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|c| {
                    Box::new(MockComponent {
                        data_type_name: c.data_type_name.clone(),
                        offset: c.offset,
                        ordinal: c.ordinal,
                        field_name: c.field_name.clone(),
                    }) as Box<dyn DataTypeComponent>
                })
                .collect()
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
        fn get_explicit_packing_value(&self) -> i32 {
            self.explicit_packing_value
        }
        fn get_alignment_type(&self) -> AlignmentType {
            self.alignment_type
        }
        fn get_explicit_minimum_alignment(&self) -> i32 {
            self.explicit_minimum_alignment
        }
    }

    struct RecordingWriter;
    impl IsfCompositeWriter for RecordingWriter {
        fn get_object_type_declaration(&mut self, component: &dyn DataTypeComponent) -> Box<dyn IsfObject> {
            struct Ty(String);
            impl IsfObject for Ty {}
            Box::new(Ty(component.get_data_type().get_name()))
        }

        fn get_tree(&self, _obj: &dyn IsfObject) -> JsonValue {
            JsonValue::String("rendered".to_string())
        }
    }

    #[test]
    fn packed_reflects_packing_enabled_state() {
        let mut composite = MockComposite::default();
        composite.packing_type = PackingType::Default;
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.packed, "true");

        let composite = MockComposite::default(); // Disabled by default.
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.packed, "false");
    }

    #[test]
    fn explicit_packing_value_is_none_when_zero_or_negative() {
        let composite = MockComposite::default(); // explicit_packing_value defaults to 0.
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.explicit_packing_value, None);
    }

    #[test]
    fn explicit_packing_value_is_some_when_positive() {
        let mut composite = MockComposite::default();
        composite.explicit_packing_value = 4;
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.explicit_packing_value, Some(4));
    }

    #[test]
    fn alignment_is_formatted_as_hex() {
        let mut composite = MockComposite::default();
        composite.alignment = 16; // 0x10
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.alignment, "10");
    }

    #[test]
    fn explicit_minimum_alignment_is_none_when_zero_or_negative() {
        let composite = MockComposite::default();
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.explicit_minimum_alignment, None);
    }

    #[test]
    fn explicit_minimum_alignment_is_some_when_positive() {
        let mut composite = MockComposite::default();
        composite.explicit_minimum_alignment = 8;
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.explicit_minimum_alignment, Some(8));
    }

    #[test]
    fn name_and_location_are_redundantly_but_correctly_set() {
        let mut composite = MockComposite::default();
        composite.name = "Point".to_string();
        composite.category_path = "/Structs".to_string();
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(ext.composite.abstract_isf_object.name, Some("Point".to_string()));
        assert_eq!(ext.composite.abstract_isf_object.location, Some("/Structs".to_string()));
    }

    #[test]
    fn fields_are_built_via_ext_isf_component_not_plain_isf_component() {
        let mut composite = MockComposite::default();
        composite.components = vec![MockComponent {
            data_type_name: "int".to_string(),
            offset: 0,
            ordinal: 0,
            field_name: Some("count".to_string()),
        }];
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        // If `get_component` were used instead of the overridden factory, the field would still
        // be present (both build a `fields` map through the same writer), so what this test
        // really pins down is that the override successfully plugs in without panicking or
        // dropping the field, exercising the `new_with_component_factory` plumbing end to end.
        assert!(ext.composite.fields.contains_key("count"));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let composite = MockComposite::default();
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        accepts_isf_object(&ext);
    }

    #[test]
    fn debug_formatting_does_not_panic() {
        let composite = MockComposite::default();
        let mut writer = RecordingWriter;
        let ext = ExtIsfComposite::new(&composite, &mut writer, &DummyMonitor);
        let s = format!("{:?}", ext);
        assert!(s.contains("ExtIsfComposite"));
    }
}
