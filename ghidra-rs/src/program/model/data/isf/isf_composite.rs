//! Port of `ghidra.program.model.data.ISF.IsfComposite`.

use serde_json::{Map, Value as JsonValue};

use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::{DataTypeComponent, DEFAULT_FIELD_NAME_PREFIX};
use crate::util::task::TaskMonitor;

use super::{AbstractIsfObject, IsfComponent, IsfObject};

/// Seam standing in for the subset of `IsfDataTypeWriter`'s behavior `IsfComposite`'s Java
/// constructor needs: `getObjectTypeDeclaration(DataTypeComponent)` and
/// `getTree(IsfObject)`. The concrete
/// [`IsfDataTypeWriter`](super::isf_data_type_writer::IsfDataTypeWriter) already ported in this
/// crate builds `serde_json::Value` trees directly rather than a graph of [`IsfObject`]s (see
/// that module's own docs on this exact divergence), so it cannot supply this trait's
/// `IsfObject`-based signature without a larger, out-of-scope redesign of that writer; wiring a
/// concrete adapter between the two is left for whichever future port actually needs it.
pub trait IsfCompositeWriter {
    /// Mirrors `IsfDataTypeWriter.getObjectTypeDeclaration(DataTypeComponent)`.
    fn get_object_type_declaration(&mut self, component: &dyn DataTypeComponent) -> Box<dyn IsfObject>;

    /// Mirrors `IsfDataTypeWriter.getTree(IsfObject)`.
    fn get_tree(&self, obj: &dyn IsfObject) -> JsonValue;
}

/// Represents a composite (structure or union) data type in ISF format.
///
/// Mirrors `ghidra.program.model.data.ISF.IsfComposite` from Ghidra's Debugger-isf module. This
/// struct extends [`AbstractIsfObject`] and adds fields for the composite's kind (`"struct"` or
/// `"union"`), size, and a JSON object mapping each defined component's field name to its own
/// ISF-rendered tree -- following the same composition (not inheritance) and `#[derive(Debug)]`-
/// via-manual-impl conventions already established by
/// [`IsfComponent`](super::isf_component::IsfComponent) and
/// [`IsfDynamicComponent`](super::isf_dynamic_component::IsfDynamicComponent) for this exact
/// family of ISF object types.
pub struct IsfComposite {
    pub abstract_isf_object: AbstractIsfObject,
    pub kind: String,
    pub size: i32,
    pub fields: Map<String, JsonValue>,
}

impl std::fmt::Debug for IsfComposite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsfComposite")
            .field("abstract_isf_object", &self.abstract_isf_object)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("fields", &self.fields)
            .finish()
    }
}

impl IsfComposite {
    /// Creates a new `IsfComposite` from a `Composite` data type.
    ///
    /// Mirrors `IsfComposite(Composite composite, IsfDataTypeWriter writer, TaskMonitor monitor)`:
    /// extracts metadata via the parent `AbstractIsfObject`, computes `size`/`kind`, then builds
    /// `fields` by walking `composite.getDefinedComponents()`, stopping early if `monitor` is
    /// cancelled (mid-loop, exactly like Java's `if (monitor.isCancelled()) break;`).
    pub fn new(
        composite: &dyn Composite,
        writer: &mut dyn IsfCompositeWriter,
        monitor: &dyn TaskMonitor,
    ) -> Self {
        let size = if composite.is_zero_length() { 0 } else { composite.get_length() };
        let kind = if composite.is_structure() { "struct" } else { "union" }.to_string();

        let components = composite.get_defined_components();
        let mut fields = Map::new();
        for component in &components {
            if monitor.is_cancelled() {
                break;
            }

            let object_type = writer.get_object_type_declaration(component.as_ref());
            let cobj = Self::get_component(component.as_ref(), object_type);
            let mut key = component.get_field_name();
            if key.is_none() {
                let mut generated =
                    format!("{DEFAULT_FIELD_NAME_PREFIX}_{}", component.get_ordinal());
                if composite.is_structure() {
                    generated.push_str(&format!("_0x{:x}", component.get_offset()));
                }
                key = Some(generated);
            }
            fields.insert(key.expect("just populated above if it was None"), writer.get_tree(&cobj));
        }

        IsfComposite {
            abstract_isf_object: AbstractIsfObject::new(Some(composite as &dyn DataType)),
            kind,
            size,
            fields,
        }
    }

    /// Mirrors the overridable `protected IsfComponent getComponent(DataTypeComponent, IsfObject)`.
    fn get_component(component: &dyn DataTypeComponent, object_type: Box<dyn IsfObject>) -> IsfComponent {
        IsfComponent::new(component, object_type)
    }
}

impl IsfObject for IsfComposite {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::util::task::DummyMonitor;

    struct MockSettings;
    impl Settings for MockSettings {}

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

    struct MockComponent {
        data_type_name: String,
        offset: i32,
        ordinal: i32,
        field_name: Option<String>,
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
        is_struct: bool,
        length: i32,
        zero_length: bool,
        components: Vec<MockComponent>,
    }

    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            CategoryPath::parse("/").unwrap()
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
    }

    struct RecordingWriter;
    impl IsfCompositeWriter for RecordingWriter {
        fn get_object_type_declaration(&mut self, component: &dyn DataTypeComponent) -> Box<dyn IsfObject> {
            Box::new(AbstractIsfObject::new(Some(&*component.get_data_type())))
        }

        fn get_tree(&self, _obj: &dyn IsfObject) -> JsonValue {
            JsonValue::String("rendered".to_string())
        }
    }

    fn struct_with(components: Vec<MockComponent>) -> MockComposite {
        MockComposite {
            name: "MyStruct".to_string(),
            is_struct: true,
            length: 8,
            zero_length: false,
            components,
        }
    }

    #[test]
    fn kind_and_size_reflect_the_composite() {
        let composite = struct_with(vec![]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(isf.kind, "struct");
        assert_eq!(isf.size, 8);
    }

    #[test]
    fn union_kind_is_reported_for_a_union_composite() {
        let mut composite = struct_with(vec![]);
        composite.is_struct = false;
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(isf.kind, "union");
    }

    #[test]
    fn zero_length_composite_reports_size_zero() {
        let mut composite = struct_with(vec![]);
        composite.zero_length = true;
        composite.length = 1; // Java: zero-length composites still report getLength() == 1.
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(isf.size, 0);
    }

    #[test]
    fn fields_are_keyed_by_component_field_name_when_present() {
        let composite = struct_with(vec![MockComponent {
            data_type_name: "int".to_string(),
            offset: 0,
            ordinal: 0,
            field_name: Some("count".to_string()),
        }]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert!(isf.fields.contains_key("count"));
        assert_eq!(isf.fields.len(), 1);
    }

    #[test]
    fn fields_generate_a_default_name_with_offset_suffix_for_structures() {
        let composite = struct_with(vec![MockComponent {
            data_type_name: "int".to_string(),
            offset: 4,
            ordinal: 1,
            field_name: None,
        }]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        let expected_key = format!("{DEFAULT_FIELD_NAME_PREFIX}_1_0x4");
        assert!(isf.fields.contains_key(&expected_key), "fields: {:?}", isf.fields);
    }

    #[test]
    fn fields_generate_a_default_name_without_offset_suffix_for_unions() {
        let mut composite = struct_with(vec![MockComponent {
            data_type_name: "int".to_string(),
            offset: 4,
            ordinal: 2,
            field_name: None,
        }]);
        composite.is_struct = false;
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        let expected_key = format!("{DEFAULT_FIELD_NAME_PREFIX}_2");
        assert!(isf.fields.contains_key(&expected_key), "fields: {:?}", isf.fields);
        // No offset suffix for a union field.
        assert!(!isf.fields.contains_key(&format!("{expected_key}_0x4")));
    }

    #[test]
    fn cancelled_monitor_stops_the_component_loop_early() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(
                &self,
            ) -> Result<(), crate::util::exception::CancelledException> {
                Err(crate::util::exception::CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                -1
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(
                &self,
                _listener: &dyn crate::util::task::CancelledListener,
            ) {
            }
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let composite = struct_with(vec![MockComponent {
            data_type_name: "int".to_string(),
            offset: 0,
            ordinal: 0,
            field_name: Some("count".to_string()),
        }]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &CancelledMonitor);
        assert!(isf.fields.is_empty());
    }

    #[test]
    fn abstract_isf_object_extracts_the_composites_name() {
        let composite = struct_with(vec![]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        assert_eq!(isf.abstract_isf_object.name, Some("MyStruct".to_string()));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let composite = struct_with(vec![]);
        let mut writer = RecordingWriter;
        let isf = IsfComposite::new(&composite, &mut writer, &DummyMonitor);
        accepts_isf_object(&isf);
    }
}
