use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::program::model::data::enum_::Enum;
use super::{IsfObject, AbstractIsfObject};

/// Represents an enumerated data type in ISF format.
///
/// Mirrors `IsfEnum` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds enum-specific metadata: the size (length in bytes),
/// a base type string (always `"int"`), and a map of constant names to their values.
///
/// The `abstract_isf_object` field is marked with `#[serde(skip)]` to match the Java
/// `@Exclude` annotation on those parent fields.
#[derive(Debug, Clone, Serialize)]
pub struct IsfEnum {
    #[serde(skip)]
    pub abstract_isf_object: AbstractIsfObject,
    pub size: Option<i32>,
    pub base: String,
    pub constants: HashMap<String, i64>,
}

impl IsfEnum {
    /// Creates a new `IsfEnum` from an `Enum` data type.
    ///
    /// Extracts the enum's length as `size`, sets `base` to `"int"`, and populates
    /// `constants` with all enum name-value pairs from the source enum.
    ///
    /// Mirrors the Java constructor behavior, which calls `super(enumm)` and then
    /// initializes the three fields.
    pub fn new(enumm: &dyn Enum) -> Self {
        let abstract_isf_object = AbstractIsfObject::new(Some(enumm));
        let size = enumm.get_length();
        let mut constants = HashMap::new();

        let names = enumm.get_names();
        for name in names {
            if let Some(value) = enumm.get_value_for_name(&name) {
                constants.insert(name, value);
            }
        }

        Self {
            abstract_isf_object,
            size: if size > 0 { Some(size) } else { None },
            base: "int".to_string(),
            constants,
        }
    }
}

impl IsfObject for IsfEnum {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    struct MockEnum {
        name: String,
        category_path: String,
        length: i32,
        names: Vec<String>,
        values: HashMap<String, i64>,
    }

    impl MockEnum {
        fn new(name: &str, path: &str, length: i32) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
                length,
                names: Vec::new(),
                values: HashMap::new(),
            }
        }

        fn add_constant(mut self, name: &str, value: i64) -> Self {
            self.names.push(name.to_string());
            self.values.insert(name.to_string(), value);
            self
        }
    }

    impl DataType for MockEnum {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::parse(&self.category_path).unwrap()
        }
    }

    impl Enum for MockEnum {
        fn get_value_for_name(&self, name: &str) -> Option<i64> {
            self.values.get(name).copied()
        }

        fn get_name_for_value(&self, value: i64) -> Option<String> {
            self.values.iter().find(|(_, v)| **v == value).map(|(k, _)| k.clone())
        }

        fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
            let names: Vec<_> = self
                .values
                .iter()
                .filter(|(_, v)| **v == value)
                .map(|(k, _)| k.clone())
                .collect();
            if names.is_empty() {
                None
            } else {
                Some(names)
            }
        }

        fn get_comment(&self, _name: &str) -> String {
            String::new()
        }

        fn get_values(&self) -> Vec<i64> {
            let mut vals: Vec<_> = self.values.values().copied().collect();
            vals.sort();
            vals.dedup();
            vals
        }

        fn get_names(&self) -> Vec<String> {
            self.names.clone()
        }

        fn get_count(&self) -> i32 {
            self.names.len() as i32
        }

        fn add(&mut self, _name: &str, _value: i64) {}

        fn add_with_comment(&mut self, _name: &str, _value: i64, _comment: &str) {}

        fn remove(&mut self, _name: &str) {}

        fn set_description(&mut self, _description: &str) {}

        fn get_enum_representation(
            &self,
            _big_int: i128,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _bit_length: i32,
        ) -> String {
            String::new()
        }

        fn contains_name(&self, name: &str) -> bool {
            self.values.contains_key(name)
        }

        fn contains_value(&self, value: i64) -> bool {
            self.values.values().any(|&v| v == value)
        }

        fn is_signed(&self) -> bool {
            self.values.values().any(|&v| v < 0)
        }

        fn get_signed_state(&self) -> crate::program::database::data::EnumSignedState {
            crate::program::database::data::EnumSignedState::None
        }

        fn get_max_possible_value(&self) -> i64 {
            i64::MAX
        }

        fn get_min_possible_value(&self) -> i64 {
            i64::MIN
        }

        fn get_minimum_possible_length(&self) -> i32 {
            self.length
        }

        fn clone_enum(&self, _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn Enum> {
            Box::new(Self {
                name: self.name.clone(),
                category_path: self.category_path.clone(),
                length: self.length,
                names: self.names.clone(),
                values: self.values.clone(),
            })
        }
    }

    #[test]
    fn new_creates_struct_from_enum() {
        let enum_data = MockEnum::new("MyEnum", "/Category", 4)
            .add_constant("VALUE_A", 0)
            .add_constant("VALUE_B", 1);
        let isf = IsfEnum::new(&enum_data);
        assert_eq!(isf.size, Some(4));
        assert_eq!(isf.base, "int");
    }

    #[test]
    fn constants_populated_from_enum_names() {
        let enum_data = MockEnum::new("StatusEnum", "/Status", 4)
            .add_constant("READY", 0)
            .add_constant("RUNNING", 1)
            .add_constant("STOPPED", 2);
        let isf = IsfEnum::new(&enum_data);
        assert_eq!(isf.constants.len(), 3);
        assert_eq!(isf.constants.get("READY"), Some(&0));
        assert_eq!(isf.constants.get("RUNNING"), Some(&1));
        assert_eq!(isf.constants.get("STOPPED"), Some(&2));
    }

    #[test]
    fn empty_enum_creates_empty_constants() {
        let enum_data = MockEnum::new("EmptyEnum", "/Empty", 0);
        let isf = IsfEnum::new(&enum_data);
        assert!(isf.constants.is_empty());
        assert_eq!(isf.size, None);
    }

    #[test]
    fn base_inherits_from_abstract_isf_object() {
        let enum_data = MockEnum::new("TestEnum", "/Test/Path", 2)
            .add_constant("A", 10);
        let isf = IsfEnum::new(&enum_data);
        assert_eq!(isf.abstract_isf_object.name, Some("TestEnum".to_string()));
        assert_eq!(isf.abstract_isf_object.location, Some("/Test/Path".to_string()));
    }

    #[test]
    fn base_is_always_int() {
        let enum_data = MockEnum::new("Enum1", "/", 1)
            .add_constant("X", 0);
        let isf = IsfEnum::new(&enum_data);
        assert_eq!(isf.base, "int");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let enum_data = MockEnum::new("Enum", "/", 4);
        let isf = IsfEnum::new(&enum_data);
        accepts_isf_object(&isf);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let enum_data = MockEnum::new("Enum1", "/", 4)
            .add_constant("A", 0);
        let isf1 = IsfEnum::new(&enum_data);
        let isf2 = isf1.clone();
        assert_eq!(isf1.constants, isf2.constants);
        assert_eq!(isf1.size, isf2.size);
    }

    #[test]
    fn debug_formatting() {
        let enum_data = MockEnum::new("E", "/", 4);
        let isf = IsfEnum::new(&enum_data);
        let debug_str = format!("{:?}", isf);
        assert!(debug_str.contains("IsfEnum"));
    }

    #[test]
    fn multiple_enums_have_independent_constants() {
        let e1 = MockEnum::new("E1", "/", 4)
            .add_constant("A", 0)
            .add_constant("B", 1);
        let e2 = MockEnum::new("E2", "/", 4)
            .add_constant("X", 10)
            .add_constant("Y", 20);

        let isf1 = IsfEnum::new(&e1);
        let isf2 = IsfEnum::new(&e2);

        assert_eq!(isf1.constants.len(), 2);
        assert_eq!(isf2.constants.len(), 2);
        assert_eq!(isf1.constants.get("A"), Some(&0));
        assert_eq!(isf2.constants.get("X"), Some(&10));
    }
}
