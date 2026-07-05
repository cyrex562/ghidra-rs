use crate::program::seam_stubs::{DataType, Settings};

/// Port of `ghidra.program.model.data.DataTypeComponent.DEFAULT_FIELD_NAME_PREFIX`.
pub const DEFAULT_FIELD_NAME_PREFIX: &str = "field";

/// Port of `ghidra.program.model.data.DataTypeComponent`.
///
/// `DataTypeComponent`s are holders for the dataTypes that make up composite (Structures and
/// Unions) dataTypes.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that already carried
/// `get_ordinal`/`get_offset`/`get_length`/`get_field_name`/`get_comment`/`is_bit_field_component`,
/// which map directly onto this interface's abstract methods of the same shape. It also carried
/// `get_data_type_name` and `bit_field_bit_offset`, which have no direct counterpart on this
/// interface (they stand in for `getDataType().getName()` and
/// `((BitFieldDataType) getDataType()).getBitOffset()`, used by
/// [`InternalDataTypeComponent`](super::internal_data_type_component::InternalDataTypeComponent)'s
/// `to_string` helper); they are retained here as a superset so existing callers keep compiling.
///
/// Every method (including ones abstract in the Java interface) is given a default so that
/// existing mock/test implementations which relied on the placeholder's blanket defaults are
/// unaffected by this promotion. Concrete implementations (`DataTypeComponentImpl`,
/// `DataTypeComponentDB`, `ReadOnlyDataTypeComponent`) will override these with real behavior
/// once they are ported.
pub trait DataTypeComponent {
    /// Returns the dataType in this component.
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(EmptyDataType)
    }

    /// Returns the dataType that contains this component.
    fn get_parent(&self) -> Box<dyn DataType> {
        Box::new(EmptyDataType)
    }

    /// Determine if the specified component corresponds to a bit-field.
    fn is_bit_field_component(&self) -> bool {
        false
    }

    /// Determine if the specified component corresponds to a zero-length bit-field.
    fn is_zero_bit_field_component(&self) -> bool {
        false
    }

    /// Get the ordinal position within the parent dataType.
    fn get_ordinal(&self) -> i32 {
        0
    }

    /// Get the byte offset of where this component begins relative to the start of the parent
    /// data type.
    fn get_offset(&self) -> i32 {
        0
    }

    /// Get the byte offset of where this component ends relative to the start of the parent
    /// data type.
    fn get_end_offset(&self) -> i32 {
        let length = self.get_length();
        if length <= 0 {
            self.get_offset()
        } else {
            self.get_offset() + length - 1
        }
    }

    /// Get the length of this component in 8-bit bytes. Zero-length components will report a
    /// length of 0 and may overlap other components at the same offset. Similarly, multiple
    /// adjacent bit-field components may appear to overlap at the byte-level.
    fn get_length(&self) -> i32 {
        0
    }

    /// Name of this component's data type. Retained from the placeholder for
    /// [`InternalDataTypeComponent::to_string`](super::internal_data_type_component::to_string);
    /// not part of the Java interface, which exposes the data type itself via [`get_data_type`](Self::get_data_type).
    fn get_data_type_name(&self) -> String {
        String::new()
    }

    /// Bit offset within the containing byte(s); only meaningful when
    /// `is_bit_field_component()` is `true`. Retained from the placeholder; stands in for
    /// `((BitFieldDataType) getDataType()).getBitOffset()` since `BitFieldDataType` is not yet
    /// ported.
    fn bit_field_bit_offset(&self) -> i32 {
        0
    }

    /// Get the comment for this dataTypeComponent, or `None` if one has not been set.
    fn get_comment(&self) -> Option<String> {
        None
    }

    /// Gets the default settings for this data type component.
    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(EmptySettings)
    }

    /// Sets the comment for the component.
    ///
    /// Since a datatype component instance is intended to be immutable, a new component instance
    /// is returned which will reflect the modified component.
    fn set_comment(&self, _comment: Option<String>) -> Box<dyn DataTypeComponent> {
        Box::new(UnsetDataTypeComponent)
    }

    /// Get this component's field name within its parent. If this method returns `None`,
    /// [`get_default_field_name`](Self::get_default_field_name) can be used to obtain a default
    /// generated field name.
    fn get_field_name(&self) -> Option<String> {
        None
    }

    /// Sets the field name. If the field name is empty it will be set to `None`, which is the
    /// default field name.
    ///
    /// Since a datatype component instance is intended to be immutable, a new component instance
    /// is returned which will reflect the modified component.
    fn set_field_name(&self, _field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        Box::new(UnsetDataTypeComponent)
    }

    /// Returns a default field name for this component. Used only if a field name is not set.
    /// Returns `None` for nameless fields such as a zero-length bitfield.
    fn get_default_field_name(&self) -> Option<String> {
        if self.is_zero_bit_field_component() {
            return None;
        }
        let mut name = format!("{}{}", DEFAULT_FIELD_NAME_PREFIX, self.get_ordinal());
        if self.get_parent().is_structure() {
            name.push_str(&format!("_0x{:x}", self.get_offset()));
        }
        Some(name)
    }

    /// Returns true if the given string represents the default field name for this data type
    /// component. This value returned from [`get_default_field_name`](Self::get_default_field_name)
    /// may not be a default name when this method returns true.
    fn is_default_field_name(&self, s: &str) -> bool {
        if self.is_zero_bit_field_component() {
            return false;
        }
        let offset = if self.get_parent().is_structure() {
            format!("_0x{:x}", self.get_offset())
        } else {
            String::new()
        };
        let new_style_name = format!("{}{}{}", DEFAULT_FIELD_NAME_PREFIX, self.get_ordinal(), offset);
        let old_style_name = format!("{}{}", DEFAULT_FIELD_NAME_PREFIX, offset);
        new_style_name == s || old_style_name == s
    }

    /// Returns true if the given dataTypeComponent is equivalent to this dataTypeComponent.
    fn is_equivalent(&self, _dtc: &dyn DataTypeComponent) -> bool {
        false
    }

    /// Returns true if this component is not defined. It is just a placeholder.
    fn is_undefined(&self) -> bool {
        false
    }
}

/// Port of `DataTypeComponent.usesZeroLengthComponent(DataType)`.
///
/// Determine if the specified dataType will be treated as a zero-length component allowing it to
/// possibly overlap the next component.
pub fn uses_zero_length_component(data_type: &dyn DataType) -> bool {
    if !data_type.is_zero_length() {
        return false;
    }
    let substituted = if data_type.is_typedef() {
        data_type.typedef_base_data_type()
    } else {
        None
    };
    let effective: &dyn DataType = substituted.as_deref().unwrap_or(data_type);
    if effective.is_array() {
        return true;
    }
    !effective.is_not_yet_defined()
}

/// Trivial fallback used by this trait's default methods where the Java interface has no
/// meaningful zero-value to fall back on.
struct EmptyDataType;
impl DataType for EmptyDataType {}

/// Trivial fallback used by [`DataTypeComponent::get_default_settings`].
struct EmptySettings;
impl Settings for EmptySettings {}

/// Trivial fallback returned by the default (unimplemented) mutator methods.
struct UnsetDataTypeComponent;
impl DataTypeComponent for UnsetDataTypeComponent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
        zero_bit_field: bool,
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
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }
        fn is_zero_bit_field_component(&self) -> bool {
            self.zero_bit_field
        }
    }

    struct MockStructure;
    impl DataType for MockStructure {
        fn is_structure(&self) -> bool {
            true
        }
    }

    struct MockStructureComponent {
        base: MockComponent,
    }

    impl DataTypeComponent for MockStructureComponent {
        fn get_ordinal(&self) -> i32 {
            self.base.get_ordinal()
        }
        fn get_offset(&self) -> i32 {
            self.base.get_offset()
        }
        fn get_length(&self) -> i32 {
            self.base.get_length()
        }
        fn get_parent(&self) -> Box<dyn DataType> {
            Box::new(MockStructure)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let comp = MockComponent {
            ordinal: 2,
            offset: 4,
            length: 8,
            ..Default::default()
        };
        let dyn_comp: &dyn DataTypeComponent = &comp;

        assert_eq!(dyn_comp.get_ordinal(), 2);
        assert_eq!(dyn_comp.get_offset(), 4);
        assert_eq!(dyn_comp.get_length(), 8);
        assert_eq!(dyn_comp.get_end_offset(), 11);
        assert!(!dyn_comp.is_bit_field_component());
        assert!(!dyn_comp.is_undefined());
    }

    #[test]
    fn default_field_name_without_structure_parent() {
        let comp = MockComponent {
            ordinal: 3,
            offset: 0x10,
            ..Default::default()
        };
        assert_eq!(comp.get_default_field_name(), Some("field3".to_string()));
        assert!(comp.is_default_field_name("field3"));
        assert!(comp.is_default_field_name("field"));
    }

    #[test]
    fn default_field_name_with_structure_parent_includes_offset() {
        let comp = MockStructureComponent {
            base: MockComponent {
                ordinal: 1,
                offset: 0x10,
                ..Default::default()
            },
        };
        assert_eq!(comp.get_default_field_name(), Some("field1_0x10".to_string()));
        assert!(comp.is_default_field_name("field1_0x10"));
        assert!(comp.is_default_field_name("field_0x10"));
    }

    #[test]
    fn zero_bit_field_component_has_no_default_field_name() {
        let comp = MockComponent {
            zero_bit_field: true,
            ..Default::default()
        };
        assert_eq!(comp.get_default_field_name(), None);
        assert!(!comp.is_default_field_name("field0"));
    }

    #[test]
    fn set_comment_and_set_field_name_return_new_component() {
        let comp = MockComponent::default();
        let updated = comp.set_comment(Some("note".to_string()));
        assert!(!updated.is_undefined());
        let renamed = comp.set_field_name(Some("name".to_string()));
        assert!(!renamed.is_undefined());
    }

    struct MockZeroLengthArrayElement;
    impl DataType for MockZeroLengthArrayElement {
        fn is_zero_length(&self) -> bool {
            true
        }
        fn is_typedef(&self) -> bool {
            true
        }
        fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
            struct MockArray;
            impl DataType for MockArray {
                fn is_array(&self) -> bool {
                    true
                }
            }
            Some(Box::new(MockArray))
        }
    }

    #[test]
    fn uses_zero_length_component_true_for_typedef_of_array() {
        assert!(uses_zero_length_component(&MockZeroLengthArrayElement));
    }

    struct MockNonZeroLengthType;
    impl DataType for MockNonZeroLengthType {}

    #[test]
    fn uses_zero_length_component_false_when_not_zero_length() {
        assert!(!uses_zero_length_component(&MockNonZeroLengthType));
    }

    struct MockNotYetDefinedZeroLength;
    impl DataType for MockNotYetDefinedZeroLength {
        fn is_zero_length(&self) -> bool {
            true
        }
        fn is_not_yet_defined(&self) -> bool {
            true
        }
    }

    #[test]
    fn uses_zero_length_component_false_when_not_yet_defined() {
        assert!(!uses_zero_length_component(&MockNotYetDefinedZeroLength));
    }
}
