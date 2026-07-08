use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::settings::Settings;

/// Interface for SettingsDefinitions that have numeric values.
///
/// SettingsDefinition objects are used as keys into Settings objects that contain the values
/// using a name-value type storage mechanism.
///
/// Port of `ghidra.docking.settings.NumberSettingsDefinition`.
pub trait NumberSettingsDefinition: SettingsDefinition {
    /// Gets the value for this SettingsDefinition given a Settings object.
    ///
    /// # Arguments
    /// * `settings` - the set of Settings values for a particular location or None for default value.
    ///
    /// # Returns
    /// The long value for this settings object given the context.
    fn get_value(&self, settings: &dyn Settings) -> i64;

    /// Sets the given value into the given settings object using this settingsDefinition as the key.
    ///
    /// # Arguments
    /// * `settings` - the settings object to store the value in.
    /// * `value` - the value to store in the settings object using this settingsDefinition as the key.
    fn set_value(&self, settings: &mut dyn Settings, value: i64);

    /// Get the maximum value permitted. The absolute value of the setting may not exceed this value.
    ///
    /// # Returns
    /// Maximum value permitted (as u64 to represent unsigned or large values).
    fn get_max_value(&self) -> u64;

    /// Determine if negative values are permitted.
    ///
    /// # Returns
    /// true if negative values are permitted, else false.
    fn allow_negative_value(&self) -> bool;

    /// Determine if hexadecimal entry/display is preferred due to the nature of the setting
    /// (e.g., mask).
    ///
    /// # Returns
    /// true if hex preferred over decimal, else false.
    fn is_hex_mode_preferred(&self) -> bool {
        false
    }

    /// Get the setting value as a string which corresponds to this definition. A default value
    /// string will be returned if a setting has not been stored.
    ///
    /// Overrides the default from [`SettingsDefinition`] to provide the hex-formatted value.
    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        let value = self.get_value(settings);

        if !self.allow_negative_value() {
            let unsigned_value = value as u64;
            return Some(format!("0x{:x}", unsigned_value));
        }

        if value < 0 {
            let abs_value = (-value) as u64;
            Some(format!("-0x{:x}", abs_value))
        } else {
            Some(format!("0x{:x}", value as u64))
        }
    }

    /// Check two settings for equality comparing the long values.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        self.get_value(settings1) == self.get_value(settings2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings {
        long_values: std::cell::RefCell<std::collections::HashMap<String, i64>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                long_values: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.long_values.borrow().get(name).copied()
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.long_values.borrow_mut().insert(name.to_string(), value);
        }

        fn is_empty(&self) -> bool {
            self.long_values.borrow().is_empty()
        }
    }

    struct MockNumberSettingsDefinition {
        name: String,
        max_value: u64,
        allow_negative: bool,
        hex_preferred: bool,
    }

    impl SettingsDefinition for MockNumberSettingsDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_storage_key(&self) -> String {
            self.name.clone()
        }
    }

    impl NumberSettingsDefinition for MockNumberSettingsDefinition {
        fn get_value(&self, settings: &dyn Settings) -> i64 {
            settings.get_long(&self.name).unwrap_or(0)
        }

        fn set_value(&self, settings: &mut dyn Settings, value: i64) {
            settings.set_long(&self.name, value);
        }

        fn get_max_value(&self) -> u64 {
            self.max_value
        }

        fn allow_negative_value(&self) -> bool {
            self.allow_negative
        }

        fn is_hex_mode_preferred(&self) -> bool {
            self.hex_preferred
        }
    }

    #[test]
    fn unsigned_value_formats_as_hex() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFF,
            allow_negative: false,
            hex_preferred: false,
        };
        let mut settings = MockSettings::new();
        def.set_value(&mut settings, 255);

        assert_eq!(def.get_value_string(&settings), Some("0xff".to_string()));
    }

    #[test]
    fn unsigned_value_handles_large_numbers() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFFFFFFFFFFFFFF,
            allow_negative: false,
            hex_preferred: false,
        };
        let mut settings = MockSettings::new();
        def.set_value(&mut settings, -1);

        assert_eq!(
            def.get_value_string(&settings),
            Some("0xffffffffffffffff".to_string())
        );
    }

    #[test]
    fn signed_positive_value_formats_as_hex() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0x7FFFFFFFFFFFFFFF,
            allow_negative: true,
            hex_preferred: false,
        };
        let mut settings = MockSettings::new();
        def.set_value(&mut settings, 255);

        assert_eq!(def.get_value_string(&settings), Some("0xff".to_string()));
    }

    #[test]
    fn signed_negative_value_formats_with_sign() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0x7FFFFFFFFFFFFFFF,
            allow_negative: true,
            hex_preferred: false,
        };
        let mut settings = MockSettings::new();
        def.set_value(&mut settings, -255);

        assert_eq!(
            def.get_value_string(&settings),
            Some("-0xff".to_string())
        );
    }

    #[test]
    fn signed_negative_one_formats_correctly() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0x7FFFFFFFFFFFFFFF,
            allow_negative: true,
            hex_preferred: false,
        };
        let mut settings = MockSettings::new();
        def.set_value(&mut settings, -1);

        assert_eq!(def.get_value_string(&settings), Some("-0x1".to_string()));
    }

    #[test]
    fn has_same_value_equal_values() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFF,
            allow_negative: false,
            hex_preferred: false,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, 42);
        def.set_value(&mut settings2, 42);

        assert!(def.has_same_value(&settings1, &settings2));
    }

    #[test]
    fn has_same_value_different_values() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFF,
            allow_negative: false,
            hex_preferred: false,
        };
        let mut settings1 = MockSettings::new();
        let mut settings2 = MockSettings::new();

        def.set_value(&mut settings1, 42);
        def.set_value(&mut settings2, 43);

        assert!(!def.has_same_value(&settings1, &settings2));
    }

    #[test]
    fn hex_mode_preference_default_false() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFF,
            allow_negative: false,
            hex_preferred: false,
        };

        assert!(!def.is_hex_mode_preferred());
    }

    #[test]
    fn hex_mode_preference_can_be_true() {
        let def = MockNumberSettingsDefinition {
            name: "value".to_string(),
            max_value: 0xFFFF,
            allow_negative: false,
            hex_preferred: true,
        };

        assert!(def.is_hex_mode_preferred());
    }
}
