use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const PRECISION_DIGITS: &str = "Precision digits";

const CHOICES: &[&str] = &[
    "default", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
];

const DEFAULT_PRECISION: i32 = 3;

/// Maximum precision value supported (ignoring the "default" and "0" choices).
pub const MAX_PRECISION: i32 = CHOICES.len() as i32 - 2;

/// SettingsDefinition to define the number of digits of precision to show. The value is
/// rendered to thousandths, 3 digits of precision, by default.
///
/// Port of `ghidra.docking.settings.FloatingPointPrecisionSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatingPointPrecisionSettingsDefinition;

impl FloatingPointPrecisionSettingsDefinition {
    /// The default definition.
    pub const DEF: FloatingPointPrecisionSettingsDefinition =
        FloatingPointPrecisionSettingsDefinition;

    fn get_choice_value(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return DEFAULT_PRECISION + 1;
        };
        settings
            .get_long(PRECISION_DIGITS)
            .map(|value| value as i32)
            .unwrap_or(DEFAULT_PRECISION + 1)
    }

    /// Returns the number of digits of precision to display based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings or `None` for the default value.
    pub fn get_precision(&self, settings: Option<&dyn Settings>) -> i32 {
        self.get_choice_value(settings) - 1
    }

    /// Sets the number of digits of precision to display.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value.
    /// * `digits` - the number of digits of precision to display.
    pub fn set_precision(&self, settings: &mut dyn Settings, digits: i32) {
        self.set_choice(settings, digits + 1);
    }

    /// Returns the index of `display_choice` within the list of display choices, or -1 if not
    /// found. The `settings` argument is unused, matching the Java source's overload.
    pub fn get_choice_for_display(&self, display_choice: &str, _settings: &dyn Settings) -> i32 {
        CHOICES
            .iter()
            .position(|choice| *choice == display_choice)
            .map(|index| index as i32)
            .unwrap_or(-1)
    }
}

impl EnumSettingsDefinition for FloatingPointPrecisionSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_choice_value(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, value_index: i32) {
        if value_index < 0 {
            settings.clear_setting(PRECISION_DIGITS);
            return;
        }

        let mut value_index = value_index;
        if value_index == 0 {
            value_index = DEFAULT_PRECISION + 1;
        }
        if value_index > MAX_PRECISION + 1 {
            value_index = MAX_PRECISION + 1;
        }
        settings.set_long(PRECISION_DIGITS, value_index as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for FloatingPointPrecisionSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(PRECISION_DIGITS).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.get_precision(Some(settings)).to_string())
    }

    fn get_name(&self) -> String {
        PRECISION_DIGITS.to_string()
    }

    fn get_storage_key(&self) -> String {
        PRECISION_DIGITS.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the number of digits of precision to display".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(PRECISION_DIGITS);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(PRECISION_DIGITS) {
            Some(value) => dest_settings.set_long(PRECISION_DIGITS, value),
            None => dest_settings.clear_setting(PRECISION_DIGITS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockSettings {
        longs: RefCell<HashMap<String, i64>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                longs: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.longs.borrow().get(name).copied()
        }

        fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
            self.longs
                .borrow()
                .get(name)
                .copied()
                .map(|v| Box::new(v) as Box<dyn std::any::Any>)
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.longs.borrow_mut().insert(name.to_string(), value);
        }

        fn clear_setting(&mut self, name: &str) {
            self.longs.borrow_mut().remove(name);
        }

        fn is_empty(&self) -> bool {
            self.longs.borrow().is_empty()
        }
    }

    #[test]
    fn get_precision_returns_default_when_settings_is_none() {
        assert_eq!(
            FloatingPointPrecisionSettingsDefinition::DEF.get_precision(None),
            DEFAULT_PRECISION
        );
    }

    #[test]
    fn get_precision_returns_default_when_unset() {
        let settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        assert_eq!(def.get_precision(Some(&settings)), DEFAULT_PRECISION);
    }

    #[test]
    fn set_precision_then_get_precision_round_trips() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_precision(&mut settings, 5);
        assert_eq!(def.get_precision(Some(&settings)), 5);
    }

    #[test]
    fn set_precision_clamps_to_max() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_precision(&mut settings, MAX_PRECISION + 10);
        assert_eq!(def.get_precision(Some(&settings)), MAX_PRECISION);
    }

    #[test]
    fn set_choice_zero_maps_to_default_precision() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_choice(&mut settings, 0);
        assert_eq!(def.get_precision(Some(&settings)), DEFAULT_PRECISION);
    }

    #[test]
    fn set_choice_negative_clears_setting() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_choice(&mut settings, 5);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "default");
        assert_eq!(def.get_display_choice(1, &settings), "0");
        assert_eq!(def.get_display_choice(11, &settings), "10");
        assert_eq!(def.get_display_choices(&settings).len(), CHOICES.len());
    }

    #[test]
    fn get_choice_for_display_matches_java_overload() {
        let settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        assert_eq!(def.get_choice_for_display("default", &settings), 0);
        assert_eq!(def.get_choice_for_display("3", &settings), 4);
        assert_eq!(def.get_choice_for_display("10", &settings), 11);
        assert_eq!(def.get_choice_for_display("not-a-choice", &settings), -1);
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_precision(&mut settings, 2);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_precision() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        assert_eq!(
            def.get_value_string(&settings),
            Some(DEFAULT_PRECISION.to_string())
        );

        def.set_precision(&mut settings, 7);
        assert_eq!(def.get_value_string(&settings), Some("7".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_precision(&mut settings, 6);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_precision(Some(&settings)), DEFAULT_PRECISION);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_precision(&mut src, 8);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_precision(Some(&dest)), 8);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FloatingPointPrecisionSettingsDefinition::DEF;

        def.set_precision(&mut dest, 4);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = FloatingPointPrecisionSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Precision digits");
        assert_eq!(def.get_storage_key(), "Precision digits");
        assert_eq!(
            def.get_description(),
            "Selects the number of digits of precision to display"
        );
    }

    #[test]
    fn max_precision_matches_java_source() {
        assert_eq!(MAX_PRECISION, 10);
    }
}
