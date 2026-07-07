use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;

/// Port of `ghidra.program.model.data.InternalDataTypeComponent`.
///
/// Package-internal extension of [`DataTypeComponent`] used by composite data type
/// implementations to mutate a component in place. The Java interface's two `static` helper
/// methods (`toString` and `cleanupFieldName`) are not instance behavior, so they are ported as
/// free functions in this module rather than trait methods.
pub trait InternalDataTypeComponent: DataTypeComponent {
    /// Sets the DataType for this component. Must be used carefully since the component will
    /// not be resized.
    fn set_data_type(&mut self, data_type: Box<dyn DataType>);

    /// Update component ordinal, offset and length during alignment.
    fn update(&mut self, ordinal: i32, offset: i32, length: i32);
}

/// Port of `InternalDataTypeComponent.toString(DataTypeComponent)`.
pub fn to_string(c: &dyn DataTypeComponent) -> String {
    let mut buffer = String::new();
    buffer.push_str(&format!("  {}", c.get_ordinal()));
    buffer.push_str(&format!("  {}", c.get_offset()));
    buffer.push_str(&format!("  {}", c.get_data_type_name()));
    if c.is_bit_field_component() {
        buffer.push_str(&format!("({})", c.bit_field_bit_offset()));
    }
    buffer.push_str(&format!("  {}", c.get_length()));
    buffer.push_str(&format!("  {}", c.get_field_name().unwrap_or_default()));
    buffer.push_str("  ");
    if let Some(cmt) = c.get_comment() {
        buffer.push('"');
        buffer.push_str(&cmt);
        buffer.push('"');
    }
    buffer
}

/// Port of `InternalDataTypeComponent.cleanupFieldName(String)`.
///
/// Modifies a field name to transform whitespace chars to underscores after trimming and
/// checking for an empty string. An empty string is returned as `None` for storage to indicate
/// default name use.
pub fn cleanup_field_name(name: Option<&str>) -> Option<String> {
    let name = name?;
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .chars()
            .map(|ch| if ch.is_whitespace() { '_' } else { ch })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    #[derive(Default)]
    struct MockComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
        data_type_name: String,
        bit_field: bool,
        bit_offset: i32,
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
        fn get_data_type_name(&self) -> String {
            self.data_type_name.clone()
        }
        fn is_bit_field_component(&self) -> bool {
            self.bit_field
        }
        fn bit_field_bit_offset(&self) -> i32 {
            self.bit_offset
        }
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }
    }

    struct MockInternalComponent {
        base: MockComponent,
        data_type: Option<Box<dyn DataType>>,
    }

    impl DataTypeComponent for MockInternalComponent {
        fn get_ordinal(&self) -> i32 {
            self.base.get_ordinal()
        }
        fn get_offset(&self) -> i32 {
            self.base.get_offset()
        }
        fn get_length(&self) -> i32 {
            self.base.get_length()
        }
        fn get_data_type_name(&self) -> String {
            self.base.get_data_type_name()
        }
        fn is_bit_field_component(&self) -> bool {
            self.base.is_bit_field_component()
        }
        fn bit_field_bit_offset(&self) -> i32 {
            self.base.bit_field_bit_offset()
        }
        fn get_field_name(&self) -> Option<String> {
            self.base.get_field_name()
        }
        fn get_comment(&self) -> Option<String> {
            self.base.get_comment()
        }
    }

    impl InternalDataTypeComponent for MockInternalComponent {
        fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
            self.data_type = Some(data_type);
        }
        fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
            self.base.ordinal = ordinal;
            self.base.offset = offset;
            self.base.length = length;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut comp = MockInternalComponent {
            base: MockComponent::default(),
            data_type: None,
        };
        let dyn_comp: &mut dyn InternalDataTypeComponent = &mut comp;
        dyn_comp.set_data_type(Box::new(MockDataType));
        dyn_comp.update(1, 4, 8);

        assert_eq!(dyn_comp.get_ordinal(), 1);
        assert_eq!(dyn_comp.get_offset(), 4);
        assert_eq!(dyn_comp.get_length(), 8);
    }

    #[test]
    fn to_string_formats_component_fields() {
        let comp = MockComponent {
            ordinal: 1,
            offset: 2,
            length: 4,
            data_type_name: "int".to_string(),
            comment: Some("note".to_string()),
            ..Default::default()
        };
        let formatted = to_string(&comp);
        assert_eq!(formatted, "  1  2  int  4    \"note\"");
    }

    #[test]
    fn to_string_marks_bit_field_offset() {
        let comp = MockComponent {
            data_type_name: "uint".to_string(),
            bit_field: true,
            bit_offset: 3,
            length: 1,
            ..Default::default()
        };
        let formatted = to_string(&comp);
        assert!(formatted.contains("uint(3)"));
    }

    #[test]
    fn cleanup_field_name_trims_and_replaces_whitespace() {
        assert_eq!(
            cleanup_field_name(Some("  foo bar  ")),
            Some("foo_bar".to_string())
        );
    }

    #[test]
    fn cleanup_field_name_empty_becomes_none() {
        assert_eq!(cleanup_field_name(Some("   ")), None);
    }

    #[test]
    fn cleanup_field_name_none_stays_none() {
        assert_eq!(cleanup_field_name(None), None);
    }
}
