use crate::program::database::data::EnumSignedState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::Settings;

/// An enumerated data type: a fixed set of name/value pairs (each with an optional
/// per-entry comment) sharing a signed/unsigned/none state.
///
/// Port of `ghidra.program.model.data.Enum`.
pub trait Enum: DataType {
    /// Get the value for the given name, or `None` if `name` does not exist in this
    /// Enum (mirrors the Java `NoSuchElementException`).
    ///
    /// Named `get_value_for_name` rather than `get_value` (the Java method name) since
    /// [`DataType::get_value`] already claims that name for an unrelated overload
    /// (`DataType.getValue(MemBuffer, Settings, int)`), and Rust traits cannot overload by
    /// parameter list the way Java can.
    fn get_value_for_name(&self, name: &str) -> Option<i64>;

    /// Get the name for the given value, or `None` if no entry has that value.
    ///
    /// Named `get_name_for_value` rather than `get_name` (the Java method name) since
    /// [`DataType::get_name`] already claims that name for an unrelated overload
    /// (`DataType.getName()`).
    fn get_name_for_value(&self, value: i64) -> Option<String>;

    /// Returns all names that map to the given value, or `None` if there is no name
    /// for the given value.
    fn get_names_for_value(&self, value: i64) -> Option<Vec<String>>;

    /// Get the comment for the given name, or the empty string if `name` does not
    /// exist in this enum or if no comment is set.
    fn get_comment(&self, name: &str) -> String;

    /// Get the values of the enum entries, sorted in ascending order.
    fn get_values(&self) -> Vec<i64>;

    /// Get the names of the enum entries, sorted first by value then by name.
    fn get_names(&self) -> Vec<String>;

    /// Get the number of entries in this Enum.
    fn get_count(&self) -> i32;

    /// Add an enum entry.
    fn add(&mut self, name: &str, value: i64);

    /// Add an enum entry with a comment.
    fn add_with_comment(&mut self, name: &str, value: i64, comment: &str);

    /// Remove the enum entry with the given name.
    fn remove(&mut self, name: &str);

    /// Set the description for this Enum.
    fn set_description(&mut self, description: &str);

    /// Get the enum representation of the big-endian value.
    ///
    /// Named `get_enum_representation` rather than `get_representation` (the Java method name)
    /// since [`DataType::get_representation`] already claims that name for an unrelated overload
    /// (`DataType.getRepresentation(MemBuffer, Settings, int)`).
    fn get_enum_representation(
        &self,
        big_int: i128,
        settings: &dyn Settings,
        bit_length: i32,
    ) -> String;

    /// Returns true if this enum has an entry with the given name.
    fn contains_name(&self, name: &str) -> bool;

    /// Returns true if this enum has an entry with the given value.
    fn contains_value(&self, value: i64) -> bool;

    /// Returns true if the enum contains at least one negative value. Internally,
    /// enums have three states: signed, unsigned, and none (can't tell from the
    /// values). If any of the values are negative, the enum is considered signed. If
    /// any of the values are large unsigned values (upper bit set), it is considered
    /// unsigned. This returns true if the enum is signed, and false if it is either
    /// unsigned or none.
    fn is_signed(&self) -> bool;

    /// Returns the signed state.
    fn get_signed_state(&self) -> EnumSignedState;

    /// Returns the maximum value that this enum can represent based on its size and
    /// signedness.
    fn get_max_possible_value(&self) -> i64;

    /// Returns the minimum value that this enum can represent based on its size and
    /// signedness.
    fn get_min_possible_value(&self) -> i64;

    /// Returns the smallest length (size in bytes) this enum can be and still
    /// represent all of its current values. Note that this will only return powers
    /// of 2 (1, 2, 4, or 8).
    fn get_minimum_possible_length(&self) -> i32;

    /// Returns a copy of this enum, associated with the given data type manager.
    fn clone_enum(&self, dtm: &dyn DataTypeManager) -> Box<dyn Enum>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockEnum {
        entries: Vec<(String, i64, String)>,
    }

    impl DataType for MockEnum {}

    impl Enum for MockEnum {
        fn get_value_for_name(&self, name: &str) -> Option<i64> {
            self.entries
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, v, _)| *v)
        }

        fn get_name_for_value(&self, value: i64) -> Option<String> {
            self.entries
                .iter()
                .find(|(_, v, _)| *v == value)
                .map(|(n, _, _)| n.clone())
        }

        fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
            let names: Vec<String> = self
                .entries
                .iter()
                .filter(|(_, v, _)| *v == value)
                .map(|(n, _, _)| n.clone())
                .collect();
            if names.is_empty() {
                None
            } else {
                Some(names)
            }
        }

        fn get_comment(&self, name: &str) -> String {
            self.entries
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, _, c)| c.clone())
                .unwrap_or_default()
        }

        fn get_values(&self) -> Vec<i64> {
            let mut values: Vec<i64> = self.entries.iter().map(|(_, v, _)| *v).collect();
            values.sort_unstable();
            values
        }

        fn get_names(&self) -> Vec<String> {
            let mut names: Vec<(i64, String)> = self
                .entries
                .iter()
                .map(|(n, v, _)| (*v, n.clone()))
                .collect();
            names.sort();
            names.into_iter().map(|(_, n)| n).collect()
        }

        fn get_count(&self) -> i32 {
            self.entries.len() as i32
        }

        fn add(&mut self, name: &str, value: i64) {
            self.add_with_comment(name, value, "");
        }

        fn add_with_comment(&mut self, name: &str, value: i64, comment: &str) {
            self.entries
                .push((name.to_string(), value, comment.to_string()));
        }

        fn remove(&mut self, name: &str) {
            self.entries.retain(|(n, _, _)| n != name);
        }

        fn set_description(&mut self, _description: &str) {}

        fn get_enum_representation(
            &self,
            big_int: i128,
            _settings: &dyn Settings,
            _bit_length: i32,
        ) -> String {
            big_int.to_string()
        }

        fn contains_name(&self, name: &str) -> bool {
            self.entries.iter().any(|(n, _, _)| n == name)
        }

        fn contains_value(&self, value: i64) -> bool {
            self.entries.iter().any(|(_, v, _)| *v == value)
        }

        fn is_signed(&self) -> bool {
            self.entries.iter().any(|(_, v, _)| *v < 0)
        }

        fn get_signed_state(&self) -> EnumSignedState {
            if self.is_signed() {
                EnumSignedState::Signed
            } else {
                EnumSignedState::None
            }
        }

        fn get_max_possible_value(&self) -> i64 {
            i64::MAX
        }

        fn get_min_possible_value(&self) -> i64 {
            i64::MIN
        }

        fn get_minimum_possible_length(&self) -> i32 {
            1
        }

        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
            Box::new(MockEnum {
                entries: self.entries.clone(),
            })
        }
    }

    fn sample() -> MockEnum {
        let mut e = MockEnum { entries: Vec::new() };
        e.add("RED", 0);
        e.add_with_comment("GREEN", 1, "the green one");
        e
    }

    #[test]
    fn usable_as_trait_object() {
        let e = sample();
        let dyn_enum: &dyn Enum = &e;
        assert_eq!(dyn_enum.get_count(), 2);
    }

    #[test]
    fn get_value_and_name_roundtrip() {
        let e = sample();
        assert_eq!(e.get_value_for_name("RED"), Some(0));
        assert_eq!(e.get_value_for_name("MISSING"), None);
        assert_eq!(e.get_name_for_value(1), Some("GREEN".to_string()));
        assert_eq!(e.get_name_for_value(42), None);
    }

    #[test]
    fn comment_defaults_to_empty() {
        let e = sample();
        assert_eq!(e.get_comment("GREEN"), "the green one");
        assert_eq!(e.get_comment("RED"), "");
    }

    #[test]
    fn contains_and_remove() {
        let mut e = sample();
        assert!(e.contains_name("RED"));
        assert!(e.contains_value(1));
        e.remove("RED");
        assert!(!e.contains_name("RED"));
        assert!(!e.contains_value(0));
    }

    #[test]
    fn signed_state_tracks_negative_values() {
        let mut e = sample();
        assert_eq!(e.get_signed_state(), EnumSignedState::None);
        e.add("NEG", -1);
        assert!(e.is_signed());
        assert_eq!(e.get_signed_state(), EnumSignedState::Signed);
    }

    #[test]
    fn clone_enum_produces_independent_copy() {
        let e = sample();
        let dtm = MockDataTypeManager;
        let cloned = e.clone_enum(&dtm);
        assert_eq!(cloned.get_count(), e.get_count());
    }

    #[test]
    fn get_representation_uses_settings() {
        let e = sample();
        let settings = MockSettings;
        assert_eq!(e.get_enum_representation(255, &settings, 8), "255");
    }
}
