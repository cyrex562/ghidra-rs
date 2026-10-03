use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::string_data_instance::StringDataInstance;
use crate::program::model::mem::MemBuffer;

/// Identifies those data types which, when formed into an array, can be interpreted as a
/// string (e.g. a character array). [`Array`](super) implementations leverage this trait as
/// both a marker and to generate appropriate representations and values for data instances.
///
/// Port of `ghidra.program.model.data.ArrayStringable`.
pub trait ArrayStringable: DataType {
    /// For cases where an array of this type exists, determines if a String value will be
    /// returned.
    fn has_string_value(&self, settings: &dyn Settings) -> bool;

    /// For cases where an array of this type exists, get the array value as a String. When
    /// data corresponds to character data it should generally be expressed as a string. A
    /// `None` value is returned if not supported or memory is uninitialized.
    fn get_array_string(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<String> {
        if self.has_string_value(settings) && buf.is_initialized_memory() {
            return StringDataInstance::new_element(self, settings, buf, length, true).get_string_value();
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
    use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};

    /// A one-byte char element type in the default (US-ASCII) charset.
    struct MockCharArrayType;
    impl DataType for MockCharArrayType {
        fn get_length(&self) -> i32 {
            1
        }
        fn is_array_stringable_type(&self) -> bool {
            true
        }
        fn into_array_stringable(self: Box<Self>) -> Option<Box<dyn ArrayStringable>> {
            Some(self)
        }
    }
    impl ArrayStringable for MockCharArrayType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            true
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
    fn get_array_string_reads_a_bounded_null_terminated_string() {
        let dt = MockCharArrayType;
        let buf = mb(false, b"hello\0xy");
        assert_eq!(dt.get_array_string(&buf, &SettingsBuilder::new(), 8), Some("hello".to_string()));
        assert_eq!(dt.get_array_string(&buf, &SettingsBuilder::new(), 3), Some("hel".to_string()));
    }

    #[test]
    fn get_array_string_none_when_uninitialized() {
        let dt = MockCharArrayType;
        let buf = mb(false, &[]);
        assert_eq!(dt.get_array_string(&buf, &SettingsBuilder::new(), 5), None);
    }

    #[test]
    fn label_prefixes_are_delegated() {
        let dt = MockCharArrayType;
        let buf = mb(false, b"x");
        assert_eq!(dt.get_array_default_label_prefix(&buf, &SettingsBuilder::new(), 5, &DEFAULT), Some("STR".to_string()));
        assert_eq!(
            dt.get_array_default_offcut_label_prefix(&buf, &SettingsBuilder::new(), 5, &DEFAULT, 2),
            Some("STR_2".to_string())
        );
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
        assert!(stringable.unwrap().has_string_value(&SettingsBuilder::new()));
    }

    #[test]
    fn get_array_stringable_none_for_non_stringable_type() {
        struct PlainType;
        impl DataType for PlainType {}

        let dt: Box<dyn DataType> = Box::new(PlainType);
        assert!(get_array_stringable(dt).is_none());
    }
}
