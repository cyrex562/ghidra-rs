use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::seam_stubs::{MemBuffer, Settings, StringDataInstance};

/// Identifies those data types which, when formed into an array, can be interpreted as a
/// string (e.g. a character array). [`Array`](super) implementations leverage this trait as
/// both a marker and to generate appropriate representations and values for data instances.
///
/// Port of `ghidra.program.model.data.ArrayStringable`.
pub trait ArrayStringable: DataType {
    /// For cases where an array of this type exists, determines if a String value will be
    /// returned.
    fn has_string_value(&self, settings: &dyn Settings) -> bool;

    /// Builds the (not yet ported) `StringDataInstance` used by
    /// [`get_array_string`](Self::get_array_string) to compute the actual string value,
    /// mirroring `new StringDataInstance(this, settings, buf, length, true)` from the Java
    /// default method. Required until `StringDataInstance` itself is ported.
    fn string_data_instance(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Box<dyn StringDataInstance>;

    /// For cases where an array of this type exists, get the array value as a String. When
    /// data corresponds to character data it should generally be expressed as a string. A
    /// `None` value is returned if not supported or memory is uninitialized.
    fn get_array_string(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<String> {
        if self.has_string_value(settings) && buf.is_initialized_memory() {
            return self.string_data_instance(buf, settings, length).get_string_value();
        }
        None
    }

    /// For cases where an array of this type exists, get the appropriate string to use as the
    /// default label prefix for the array.
    fn get_array_default_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String>;

    /// For cases where an array of this type exists, get the appropriate string to use as the
    /// default label prefix, taking into account the fact that there exists a reference to the
    /// data that references `offcut_length` bytes into this type.
    fn get_array_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_length: i32,
    ) -> Option<String>;
}

/// Port of `ArrayStringable.getArrayStringable(DataType)`.
///
/// Get the [`ArrayStringable`] for a specified data type. Not used on an Array data type, but
/// on an Array's element type.
pub fn get_array_stringable(dt: Box<dyn DataType>) -> Option<Box<dyn ArrayStringable>> {
    let base = if dt.is_typedef() {
        dt.typedef_base_data_type().unwrap_or(dt)
    } else {
        dt
    };
    base.into_array_stringable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type_display_options::DEFAULT;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemBuffer {
        initialized: bool,
    }
    impl MemBuffer for MockMemBuffer {
        fn is_initialized_memory(&self) -> bool {
            self.initialized
        }
    }

    struct MockStringDataInstance {
        value: Option<String>,
    }
    impl StringDataInstance for MockStringDataInstance {
        fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String> {
            Ok(value.iter().collect::<String>().into_bytes())
        }

        fn encode_replacement_from_char_representation(
            &self,
            repr: &str,
        ) -> Result<Vec<u8>, String> {
            Ok(repr.as_bytes().to_vec())
        }

        fn get_string_value(&self) -> Option<String> {
            self.value.clone()
        }
    }

    struct MockCharArrayType;
    impl DataType for MockCharArrayType {
        fn get_length(&self) -> i32 {
            1
        }
        fn into_array_stringable(self: Box<Self>) -> Option<Box<dyn ArrayStringable>> {
            Some(self)
        }
    }
    impl ArrayStringable for MockCharArrayType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            true
        }

        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance { value: Some("hello".to_string()) })
        }

        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            Some("STR".to_string())
        }

        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            offcut_length: i32,
        ) -> Option<String> {
            Some(format!("STR_{:x}", offcut_length))
        }
    }

    #[test]
    fn get_array_string_returns_value_when_initialized() {
        let dt = MockCharArrayType;
        let buf = MockMemBuffer { initialized: true };
        assert_eq!(dt.get_array_string(&buf, &MockSettings, 5), Some("hello".to_string()));
    }

    #[test]
    fn get_array_string_none_when_uninitialized() {
        let dt = MockCharArrayType;
        let buf = MockMemBuffer { initialized: false };
        assert_eq!(dt.get_array_string(&buf, &MockSettings, 5), None);
    }

    #[test]
    fn label_prefixes_are_delegated() {
        let dt = MockCharArrayType;
        let buf = MockMemBuffer { initialized: true };
        assert_eq!(
            dt.get_array_default_label_prefix(&buf, &MockSettings, 5, &DEFAULT),
            Some("STR".to_string())
        );
        assert_eq!(
            dt.get_array_default_offcut_label_prefix(&buf, &MockSettings, 5, &DEFAULT, 2),
            Some("STR_2".to_string())
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockCharArrayType;
        let dyn_dt: &dyn ArrayStringable = &dt;
        assert!(dyn_dt.has_string_value(&MockSettings));
        assert_eq!(dyn_dt.get_length(), 1);
    }

    struct MockTypeDef;
    impl DataType for MockTypeDef {
        fn is_typedef(&self) -> bool {
            true
        }
        fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockCharArrayType))
        }
        fn into_array_stringable(self: Box<Self>) -> Option<Box<dyn ArrayStringable>> {
            None
        }
    }

    #[test]
    fn get_array_stringable_resolves_through_typedef() {
        let dt: Box<dyn DataType> = Box::new(MockTypeDef);
        let stringable = get_array_stringable(dt);
        assert!(stringable.is_some());
        assert!(stringable.unwrap().has_string_value(&MockSettings));
    }

    #[test]
    fn get_array_stringable_none_for_non_stringable_type() {
        struct PlainType;
        impl DataType for PlainType {}

        let dt: Box<dyn DataType> = Box::new(PlainType);
        assert!(get_array_stringable(dt).is_none());
    }
}
