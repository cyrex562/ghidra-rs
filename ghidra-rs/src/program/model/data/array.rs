use std::any::{Any, TypeId};

use crate::program::model::data::array_stringable::get_array_stringable;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::seam_stubs::{MemBuffer, Settings};

/// Label prefix used for array data, standing in for `Array.ARRAY_LABEL_PREFIX`.
pub const ARRAY_LABEL_PREFIX: &str = "ARRAY";

/// Placeholder returned as the string representation of an array whose backing memory is
/// uninitialized, standing in for `StringDataInstance.UNKNOWN` (not yet ported).
const STRING_DATA_INSTANCE_UNKNOWN: &str = "??";

/// Unit type whose [`TypeId`] stands in for Java's `Array.class`, used by
/// [`Array::get_array_value_class`] as the sentinel "this datatype yields a nested array"
/// marker in place of a Rust value class.
pub struct ArrayValueClassMarker;

/// Port of `ghidra.program.model.data.Array`.
///
/// The array interface.
pub trait Array: DataType {
    /// Returns the number of elements in the array.
    fn get_num_elements(&self) -> i32;

    /// Returns the length of an element in the array. In the case of a Dynamic base datatype,
    /// this element length will have been explicitly specified at the time of construction. For
    /// a zero-length base type an element length of 1 will be reported with
    /// [`DataType::get_length`] returning the number of elements.
    fn get_element_length(&self) -> i32;

    /// Returns the dataType of the elements in the array.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// Get the appropriate string to use as the label prefix for an array, taking into account
    /// the actual data at the memory location.
    ///
    /// See also [`DataType::get_default_label_prefix`].
    fn get_array_default_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let stringable = get_array_stringable(self.get_data_type());
        let prefix = stringable
            .and_then(|s| s.get_array_default_label_prefix(buf, settings, len, options));
        prefix.or_else(|| self.get_default_label_prefix())
    }

    /// Get the appropriate string to use as the offcut label prefix for an array, taking into
    /// account the actual data at the memory location.
    ///
    /// See also [`DataType::get_default_label_prefix`].
    fn get_array_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_length: i32,
    ) -> Option<String> {
        let stringable = get_array_stringable(self.get_data_type());
        let prefix = stringable.and_then(|s| {
            s.get_array_default_offcut_label_prefix(buf, settings, len, options, offcut_length)
        });
        prefix.or_else(|| self.get_default_label_prefix_for_data(buf, settings, len, options))
    }

    /// Get the representation which corresponds to an array in memory. This will either be a
    /// String for the ArrayStringable case, "??" for uninitialized data, or the empty string if
    /// it is not.
    fn get_array_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        if self.get_num_elements() == 0 {
            return String::new();
        }
        if !buf.is_initialized_memory() {
            return STRING_DATA_INSTANCE_UNKNOWN.to_string();
        }
        let stringable = get_array_stringable(self.get_data_type());
        let value = stringable.and_then(|s| {
            if s.has_string_value(settings) {
                s.string_data_instance(buf, settings, length).get_string_value()
            } else {
                None
            }
        });
        value.unwrap_or_default()
    }

    /// Get the value object which corresponds to an array in memory. This will either be a
    /// String for the ArrayStringable case or `None`.
    fn get_array_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        if !buf.is_at_initialized_memory_address() {
            return None;
        }
        let stringable = get_array_stringable(self.get_data_type());
        stringable
            .and_then(|s| s.get_array_string(buf, settings, length))
            .map(|s| Box::new(s) as Box<dyn Any>)
    }

    /// Get the value Class of a specific arrayDt with settings (see
    /// [`Array::get_array_value_class`]).
    ///
    /// Returns the [`TypeId`] of the value to be returned by the array, or `None` if it can vary
    /// or is unspecified (String or [`ArrayValueClassMarker`] will be returned).
    fn get_array_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let mut dt = self.get_data_type();
        if dt.is_typedef() {
            if let Some(base) = dt.typedef_base_data_type() {
                dt = base;
            }
        }
        if dt.get_value_class(settings).is_some() {
            if let Some(stringable) = dt.into_array_stringable() {
                if stringable.has_string_value(settings) {
                    return Some(TypeId::of::<String>());
                }
                return Some(TypeId::of::<ArrayValueClassMarker>());
            }
            return Some(TypeId::of::<ArrayValueClassMarker>());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockElement;
    impl DataType for MockElement {
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct MockArray;
    impl DataType for MockArray {
        fn is_array(&self) -> bool {
            true
        }
    }
    impl Array for MockArray {
        fn get_num_elements(&self) -> i32 {
            4
        }

        fn get_element_length(&self) -> i32 {
            1
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockElement)
        }
    }

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

    #[test]
    fn usable_as_trait_object() {
        let arr = MockArray;
        let dyn_arr: &dyn Array = &arr;
        assert_eq!(dyn_arr.get_num_elements(), 4);
        assert_eq!(dyn_arr.get_element_length(), 1);
        assert!(dyn_arr.get_data_type().get_length() == 1);
    }

    #[test]
    fn representation_empty_when_no_elements() {
        struct EmptyArray;
        impl DataType for EmptyArray {}
        impl Array for EmptyArray {
            fn get_num_elements(&self) -> i32 {
                0
            }
            fn get_element_length(&self) -> i32 {
                0
            }
            fn get_data_type(&self) -> Box<dyn DataType> {
                Box::new(MockElement)
            }
        }
        let arr = EmptyArray;
        let buf = MockMemBuffer { initialized: true };
        assert_eq!(arr.get_array_representation(&buf, &MockSettings, 4), "");
    }

    #[test]
    fn representation_unknown_when_uninitialized() {
        let arr = MockArray;
        let buf = MockMemBuffer { initialized: false };
        assert_eq!(
            arr.get_array_representation(&buf, &MockSettings, 4),
            "??".to_string()
        );
    }

    #[test]
    fn array_value_none_when_not_at_initialized_address() {
        let arr = MockArray;
        let buf = MockMemBuffer { initialized: true };
        assert!(arr.get_array_value(&buf, &MockSettings, 4).is_none());
    }
}
