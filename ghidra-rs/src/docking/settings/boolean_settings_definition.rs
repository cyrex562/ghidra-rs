use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::settings::Settings;

/// Interface for SettingsDefinitions that have boolean values.
///
/// SettingsDefinition objects are used as keys into Settings objects that contain the values
/// using a name-value type storage mechanism.
///
/// Port of `ghidra.docking.settings.BooleanSettingsDefinition`.
pub trait BooleanSettingsDefinition: SettingsDefinition {
    /// Gets the value for this SettingsDefinition given a Settings object.
    ///
    /// # Arguments
    /// * `settings` - the set of Settings values for a particular location or None for default value.
    ///
    /// # Returns
    /// The boolean value for this settings object given the context.
    fn get_value(&self, settings: &dyn Settings) -> bool;

    /// Sets the given value into the given settings object using this settingsDefinition as the key.
    ///
    /// # Arguments
    /// * `settings` - the settings object to store the value in.
    /// * `value` - the value to store in the settings object using this settingsDefinition as the key.
    fn set_value(&self, settings: &mut dyn Settings, value: bool);

    /// Check two settings for equality comparing the boolean values.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        self.get_value(settings1) == self.get_value(settings2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings {
        boolean_values: std::cell::RefCell<std::collections::HashMap<String, bool>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                boolean_values: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, _name: &str) -> Option<i64> {
            None
        }

        fn get_string(&self, _name: &str) -> Option<String> {
            None
        }

        fn set_long(&mut self, _name: &str, _value: i64) {}

        fn set_string(&mut self, _name: &str, _value: &str) {}

        fn is_empty(&self) -> bool {
            self.boolean_values.borrow().is_empty()
        }
    }

    struct MockBooleanSettingsDefinition {
        name: String,
        default_value: bool,
    }

    impl SettingsDefinition for MockBooleanSettingsDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl BooleanSettingsDefinition for MockBooleanSettingsDefinition {
        fn get_value(&self, settings: &dyn Settings) -> bool {
            settings
                .get_string(&self.name)
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(self.default_value)
        }

        fn set_value(&self, settings: &mut dyn Settings, value: bool) {
            settings.set_string(&self.name, if value { "true" } else { "false" });
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let def = MockBooleanSettingsDefinition {
            name: "enabled".to_string(),
            default_value: false,
        };
        let mut settings = MockSettings::new();
        let dyn_def: &dyn BooleanSettingsDefinition = &def;

        assert!(!dyn_def.get_value(&settings));

        let mut dyn_settings: &mut dyn Settings = &mut settings;
        dyn_def.set_value(dyn_settings, true);

        assert!(dyn_def.get_value(&settings));
    }

    #[test]
    fn has_same_value_compares_values() {
        let def = MockBooleanSettingsDefinition {
            name: "flag".to_string(),
            default_value: false,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, true);
        def.set_value(&mut settings2, true);

        assert!(BooleanSettingsDefinition::has_same_value(&def, &settings1, &settings2));
    }

    #[test]
    fn has_same_value_detects_differences() {
        let def = MockBooleanSettingsDefinition {
            name: "flag".to_string(),
            default_value: false,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, true);
        def.set_value(&mut settings2, false);

        assert!(!BooleanSettingsDefinition::has_same_value(&def, &settings1, &settings2));
    }

    #[test]
    fn default_value_used_when_unset() {
        let def_true = MockBooleanSettingsDefinition {
            name: "enabled".to_string(),
            default_value: true,
        };
        let def_false = MockBooleanSettingsDefinition {
            name: "enabled".to_string(),
            default_value: false,
        };
        let settings = MockSettings::new();

        assert!(def_true.get_value(&settings));
        assert!(!def_false.get_value(&settings));
    }
}
