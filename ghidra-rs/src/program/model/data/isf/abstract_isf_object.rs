use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::data_type::DataType;
use super::{IsfObject, IsfSetting, IsfSettingValue};

/// Base class for ISF data type objects.
///
/// Mirrors `AbstractIsfObject` from Ghidra's Debugger-isf module. This struct holds
/// metadata extracted from a `DataType` (name, location, and settings). The fields are
/// conceptually marked as excluded from serialization (matching the Java `@Exclude`
/// annotation), and are primarily used by subclasses that extend this base type.
///
/// To create an instance, use [`AbstractIsfObject::new`], which extracts the metadata
/// from a provided `DataType`.
#[derive(Debug, Clone)]
pub struct AbstractIsfObject {
    /// The name of the data type.
    pub name: Option<String>,
    /// The category path (location) of the data type.
    pub location: Option<String>,
    /// Settings extracted from the data type's default settings.
    pub settings: Option<Vec<IsfSetting>>,
}

impl AbstractIsfObject {
    /// Creates a new `AbstractIsfObject` from a `DataType`.
    ///
    /// Extracts the name, category path, and settings from the provided `DataType`.
    /// If `dt` is `None`, all fields are initialized to `None`.
    pub fn new(dt: Option<&dyn DataType>) -> Self {
        let mut obj = Self {
            name: None,
            location: None,
            settings: None,
        };

        if let Some(data_type) = dt {
            obj.name = Some(data_type.get_name());
            obj.location = Some(data_type.get_category_path().get_path());
            let default_settings = data_type.get_default_settings();
            obj.process_settings(data_type, &*default_settings);
        }

        obj
    }

    /// Processes and populates the settings list from a `DataType`.
    ///
    /// Iterates through the `DataType`'s settings definitions. For any definition that
    /// has a value in `default_settings`, extracts all setting names and values,
    /// creating an `IsfSetting` for each.
    ///
    /// This mirrors the behavior of the Java `processSettings` method.
    fn process_settings(
        &mut self,
        dt: &dyn DataType,
        default_settings: &dyn crate::docking::settings::settings::Settings,
    ) {
        let settings_definitions = dt.get_settings_definitions();
        for def in settings_definitions {
            if def.has_value(default_settings) {
                let mut settings_vec = Vec::new();
                let names = default_settings.get_names();
                for name in names {
                    if let Some(value) = default_settings.get_value(&name) {
                        let isf_value = if let Some(s) = value.downcast_ref::<String>() {
                            IsfSettingValue::Str(s.clone())
                        } else if let Some(&n) = value.downcast_ref::<i64>() {
                            IsfSettingValue::Long(n)
                        } else {
                            continue;
                        };
                        let setting = IsfSetting::new(name, isf_value);
                        settings_vec.push(setting);
                    }
                }
                self.settings = Some(settings_vec);
            }
        }
    }
}

impl IsfObject for AbstractIsfObject {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType as _;

    struct MockDataType {
        name: String,
        category_path: String,
    }

    impl MockDataType {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
            }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::from_path(&self.category_path)
        }
    }

    #[test]
    fn new_with_none_initializes_all_fields_to_none() {
        let obj = AbstractIsfObject::new(None);
        assert_eq!(obj.name, None);
        assert_eq!(obj.location, None);
        assert_eq!(obj.settings, None);
    }

    #[test]
    fn new_with_data_type_extracts_name() {
        let dt = MockDataType::new("TestType", "/Category");
        let obj = AbstractIsfObject::new(Some(&dt));
        assert_eq!(obj.name, Some("TestType".to_string()));
    }

    #[test]
    fn new_with_data_type_extracts_location() {
        let dt = MockDataType::new("TestType", "/Path/To/Category");
        let obj = AbstractIsfObject::new(Some(&dt));
        assert_eq!(obj.location, Some("/Path/To/Category".to_string()));
    }

    #[test]
    fn new_with_null_name_and_location() {
        let dt = MockDataType::new("", "/");
        let obj = AbstractIsfObject::new(Some(&dt));
        assert_eq!(obj.name, Some(String::new()));
        assert_eq!(obj.location, Some("/".to_string()));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let obj = AbstractIsfObject::new(None);
        accepts_isf_object(&obj);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let dt = MockDataType::new("Type1", "/Path");
        let obj1 = AbstractIsfObject::new(Some(&dt));
        let obj2 = obj1.clone();
        assert_eq!(obj1.name, obj2.name);
        assert_eq!(obj1.location, obj2.location);
    }

    #[test]
    fn debug_formatting() {
        let obj = AbstractIsfObject::new(None);
        let debug_str = format!("{:?}", obj);
        assert!(debug_str.contains("AbstractIsfObject"));
    }
}
