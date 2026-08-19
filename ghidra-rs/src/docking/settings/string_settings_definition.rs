use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::settings::Settings;
use std::collections::HashSet;

/// Interface for SettingsDefinitions that have string values.
///
/// SettingsDefinition objects are used as keys into Settings objects that contain the values
/// using a name-value type storage mechanism.
///
/// Port of `ghidra.docking.settings.StringSettingsDefinition`.
pub trait StringSettingsDefinition: SettingsDefinition {
    /// Gets the value for this SettingsDefinition given a Settings object.
    ///
    /// # Arguments
    /// * `settings` - the set of Settings values for a particular location or None for default value.
    ///
    /// # Returns
    /// The value for this settings object given the context, or None for default value.
    fn get_value(&self, settings: &dyn Settings) -> Option<String>;

    /// Sets the given value into the given settings object using this settingsDefinition as the key.
    ///
    /// # Arguments
    /// * `settings` - the settings object to store the value in.
    /// * `value` - the value to store in the settings object using this settingsDefinition as the key.
    fn set_value(&self, settings: &mut dyn Settings, value: &str);

    /// Get the setting value as a string which corresponds to this definition. A default value
    /// string will be returned if a setting has not been stored.
    ///
    /// Overrides the default from [`SettingsDefinition`] to provide the string value or an empty
    /// string if None.
    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        match self.get_value(settings) {
            Some(val) => Some(val),
            None => Some(String::new()),
        }
    }

    /// Check two settings for equality which correspond to this settings definition.
    ///
    /// Overrides the default from [`SettingsDefinition`] to compare string values.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        self.get_value(settings1) == self.get_value(settings2)
    }

    /// Get suggested setting values.
    ///
    /// # Arguments
    /// * `settings` - settings object
    ///
    /// # Returns
    /// suggested settings or None if none or unsupported
    fn get_suggested_values(&self, settings: &dyn Settings) -> Option<Vec<String>> {
        let _ = settings;
        None
    }

    /// Determine if this settings definition supports suggested values.
    /// See [`get_suggested_values`](Self::get_suggested_values).
    ///
    /// # Returns
    /// true if suggested values are supported, else false.
    fn supports_suggested_values(&self) -> bool {
        false
    }

    /// Add preferred setting values to the specified set as obtained from the specified
    /// settingsOwner.
    ///
    /// # Arguments
    /// * `settings_owner` - settings owner from which a definition may query preferred values.
    /// Supported values are specific to this settings definition. An unsupported settingsOwner
    /// will return false.
    /// * `set` - value set to which values should be added
    ///
    /// # Returns
    /// true if settingsOwner is supported and set updated, else false.
    fn add_preferred_values(
        &self,
        settings_owner: Option<&dyn std::any::Any>,
        set: &mut HashSet<String>,
    ) -> bool {
        let _ = (settings_owner, set);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings {
        string_values: std::cell::RefCell<std::collections::HashMap<String, String>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                string_values: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_string(&self, name: &str) -> Option<String> {
            self.string_values.borrow().get(name).cloned()
        }

        fn set_string(&mut self, name: &str, value: &str) {
            self.string_values.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn is_empty(&self) -> bool {
            self.string_values.borrow().is_empty()
        }
    }

    impl SettingsDefinition for MockSettings {
        fn get_name(&self) -> String {
            "test".to_string()
        }
    }

    struct MockStringSettingsDefinition {
        name: String,
        default_value: Option<String>,
    }

    impl SettingsDefinition for MockStringSettingsDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl StringSettingsDefinition for MockStringSettingsDefinition {
        fn get_value(&self, settings: &dyn Settings) -> Option<String> {
            match settings.get_string(&self.name) {
                Some(val) => Some(val),
                None => self.default_value.clone(),
            }
        }

        fn set_value(&self, settings: &mut dyn Settings, value: &str) {
            settings.set_string(&self.name, value);
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let def = MockStringSettingsDefinition {
            name: "format".to_string(),
            default_value: None,
        };
        let mut settings = MockSettings::new();
        let dyn_def: &dyn StringSettingsDefinition = &def;

        assert_eq!(dyn_def.get_value(&settings), None);

        let mut dyn_settings: &mut dyn Settings = &mut settings;
        dyn_def.set_value(dyn_settings, "hex");

        assert_eq!(dyn_def.get_value(&settings), Some("hex".to_string()));
    }

    #[test]
    fn get_value_string_returns_value_or_empty() {
        let def = MockStringSettingsDefinition {
            name: "label".to_string(),
            default_value: None,
        };
        let mut settings = MockSettings::new();

        assert_eq!(StringSettingsDefinition::get_value_string(&def, &settings), Some(String::new()));

        def.set_value(&mut settings, "test_value");
        assert_eq!(StringSettingsDefinition::get_value_string(&def, &settings), Some("test_value".to_string()));
    }

    #[test]
    fn has_same_value_equal_strings() {
        let def = MockStringSettingsDefinition {
            name: "mode".to_string(),
            default_value: None,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, "active");
        def.set_value(&mut settings2, "active");

        assert!(StringSettingsDefinition::has_same_value(&def, &settings1, &settings2));
    }

    #[test]
    fn has_same_value_different_strings() {
        let def = MockStringSettingsDefinition {
            name: "mode".to_string(),
            default_value: None,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, "active");
        def.set_value(&mut settings2, "inactive");

        assert!(!StringSettingsDefinition::has_same_value(&def, &settings1, &settings2));
    }

    #[test]
    fn has_same_value_both_none() {
        let def = MockStringSettingsDefinition {
            name: "data".to_string(),
            default_value: None,
        };
        let settings1 = MockSettings::new();
        let settings2 = MockSettings::new();

        assert!(StringSettingsDefinition::has_same_value(&def, &settings1, &settings2));
    }

    #[test]
    fn default_value_used_when_unset() {
        let def = MockStringSettingsDefinition {
            name: "option".to_string(),
            default_value: Some("default_val".to_string()),
        };
        let settings = MockSettings::new();

        assert_eq!(def.get_value(&settings), Some("default_val".to_string()));
    }

    #[test]
    fn get_suggested_values_default_none() {
        let def = MockStringSettingsDefinition {
            name: "choice".to_string(),
            default_value: None,
        };
        let settings = MockSettings::new();

        assert_eq!(def.get_suggested_values(&settings), None);
    }

    #[test]
    fn supports_suggested_values_default_false() {
        let def = MockStringSettingsDefinition {
            name: "choice".to_string(),
            default_value: None,
        };

        assert!(!def.supports_suggested_values());
    }

    #[test]
    fn add_preferred_values_default_false() {
        let def = MockStringSettingsDefinition {
            name: "option".to_string(),
            default_value: None,
        };
        let mut set = HashSet::new();

        assert!(!def.add_preferred_values(None, &mut set));
    }
}
