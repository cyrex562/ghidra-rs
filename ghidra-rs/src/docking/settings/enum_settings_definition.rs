use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::settings::Settings;

/// Interface for a SettingsDefinition with enumerated values.
///
/// Provides methods to get and set enumerated choice values, with display strings for each choice.
///
/// Port of `ghidra.docking.settings.EnumSettingsDefinition`.
pub trait EnumSettingsDefinition: SettingsDefinition {
    /// Returns the current value for this settings.
    ///
    /// # Arguments
    /// * `settings` - The settings to search
    ///
    /// # Returns
    /// The value for the settings definition
    fn get_choice(&self, settings: &dyn Settings) -> i32;

    /// Sets the given value into the settings object using this definition as a key.
    ///
    /// # Arguments
    /// * `settings` - The settings to store the value in
    /// * `value` - The settings value to be stored
    fn set_choice(&self, settings: &mut dyn Settings, value: i32);

    /// Returns the String for the given enum value.
    ///
    /// # Arguments
    /// * `value` - The value to get a display string for
    /// * `settings` - The instance settings which may affect the results
    ///
    /// # Returns
    /// The display string for the given value
    fn get_display_choice(&self, value: i32, settings: &dyn Settings) -> String;

    /// Gets the list of choices as strings based on the current settings.
    ///
    /// # Arguments
    /// * `settings` - The instance settings
    ///
    /// # Returns
    /// A vector of strings which represent valid choices based on the current settings
    fn get_display_choices(&self, settings: &dyn Settings) -> Vec<String>;

    /// Check two settings for equality by comparing their choice values.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        self.get_choice(settings1) == self.get_choice(settings2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings {
        choice_values: std::cell::RefCell<std::collections::HashMap<String, i32>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                choice_values: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.choice_values
                .borrow()
                .get(name)
                .map(|v| *v as i64)
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.choice_values.borrow_mut().insert(name.to_string(), value as i32);
        }

        fn get_string(&self, _name: &str) -> Option<String> {
            None
        }

        fn set_string(&mut self, _name: &str, _value: &str) {}

        fn is_empty(&self) -> bool {
            self.choice_values.borrow().is_empty()
        }
    }

    struct MockEnumSettingsDefinition {
        name: String,
        default_choice: i32,
        choices: Vec<String>,
    }

    impl SettingsDefinition for MockEnumSettingsDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl EnumSettingsDefinition for MockEnumSettingsDefinition {
        fn get_choice(&self, settings: &dyn Settings) -> i32 {
            settings
                .get_long(&self.name)
                .map(|v| v as i32)
                .unwrap_or(self.default_choice)
        }

        fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
            settings.set_long(&self.name, value as i64);
        }

        fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
            if (value as usize) < self.choices.len() && value >= 0 {
                self.choices[value as usize].clone()
            } else {
                String::new()
            }
        }

        fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
            self.choices.clone()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let def = MockEnumSettingsDefinition {
            name: "format".to_string(),
            default_choice: 0,
            choices: vec!["hex".to_string(), "decimal".to_string(), "binary".to_string()],
        };
        let mut settings = MockSettings::new();
        let dyn_def: &dyn EnumSettingsDefinition = &def;

        assert_eq!(dyn_def.get_choice(&settings), 0);
        assert_eq!(dyn_def.get_display_choice(0, &settings), "hex");
        assert_eq!(dyn_def.get_display_choice(1, &settings), "decimal");
        assert_eq!(dyn_def.get_display_choice(2, &settings), "binary");
    }

    #[test]
    fn set_and_get_choice() {
        let def = MockEnumSettingsDefinition {
            name: "style".to_string(),
            default_choice: 0,
            choices: vec!["bold".to_string(), "italic".to_string()],
        };
        let mut settings = MockSettings::new();
        let dyn_def: &mut dyn EnumSettingsDefinition = &mut (&def as &dyn EnumSettingsDefinition) as *const _ as *mut _;

        def.set_choice(&mut settings, 1);

        assert_eq!(def.get_choice(&settings), 1);
        assert_eq!(def.get_display_choice(1, &settings), "italic");
    }

    #[test]
    fn get_display_choices() {
        let choices = vec!["red".to_string(), "green".to_string(), "blue".to_string()];
        let def = MockEnumSettingsDefinition {
            name: "color".to_string(),
            default_choice: 0,
            choices: choices.clone(),
        };
        let settings = MockSettings::new();
        let dyn_def: &dyn EnumSettingsDefinition = &def;

        let display_choices = dyn_def.get_display_choices(&settings);
        assert_eq!(display_choices, choices);
    }

    #[test]
    fn get_display_choice_with_invalid_value() {
        let def = MockEnumSettingsDefinition {
            name: "option".to_string(),
            default_choice: 0,
            choices: vec!["first".to_string(), "second".to_string()],
        };
        let settings = MockSettings::new();

        assert_eq!(def.get_display_choice(-1, &settings), "");
        assert_eq!(def.get_display_choice(5, &settings), "");
    }

    #[test]
    fn has_same_value_equal_choices() {
        let def = MockEnumSettingsDefinition {
            name: "mode".to_string(),
            default_choice: 0,
            choices: vec!["a".to_string(), "b".to_string()],
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_choice(&mut settings1, 1);
        def.set_choice(&mut settings2, 1);

        assert!(def.has_same_value(&settings1, &settings2));
    }

    #[test]
    fn has_same_value_different_choices() {
        let def = MockEnumSettingsDefinition {
            name: "mode".to_string(),
            default_choice: 0,
            choices: vec!["a".to_string(), "b".to_string()],
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_choice(&mut settings1, 0);
        def.set_choice(&mut settings2, 1);

        assert!(!def.has_same_value(&settings1, &settings2));
    }

    #[test]
    fn default_choice_used_when_unset() {
        let def = MockEnumSettingsDefinition {
            name: "option".to_string(),
            default_choice: 2,
            choices: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        let settings = MockSettings::new();

        assert_eq!(def.get_choice(&settings), 2);
    }

    #[test]
    fn has_same_value_with_unset_and_default() {
        let def = MockEnumSettingsDefinition {
            name: "option".to_string(),
            default_choice: 1,
            choices: vec!["a".to_string(), "b".to_string()],
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_choice(&mut settings2, 1);

        assert!(def.has_same_value(&settings1, &settings2));
    }
}
