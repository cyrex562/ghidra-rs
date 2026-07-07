use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Choice value for an unpadded display.
pub const UNPADDED_VALUE: i32 = 0;
/// Choice value for a padded display.
pub const PADDED_VALUE: i32 = 1;

const CHOICES: &[&str] = &["unpadded", "padded"];

const PADDED: &str = "padded";

/// The settings definition for setting the padded/unpadded setting.
///
/// Port of `ghidra.program.model.data.PaddingSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingSettingsDefinition;

impl PaddingSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: PaddingSettingsDefinition = PaddingSettingsDefinition;

    /// Checks if the current settings are padded or unpadded.
    ///
    /// # Arguments
    /// * `settings` - the instance settings to check, or `None` for the default value.
    ///
    /// # Returns
    /// `true` if the value is "padded".
    pub fn is_padded(&self, settings: Option<&dyn Settings>) -> bool {
        let Some(settings) = settings else {
            return false;
        };
        let Some(value) = settings.get_long(PADDED) else {
            return false;
        };
        value != UNPADDED_VALUE as i64
    }

    /// Set true if value should display padded out with zero's.
    ///
    /// # Arguments
    /// * `settings` - settings to set padded value
    /// * `is_padded` - true for padding
    pub fn set_padded(&self, settings: &mut dyn Settings, is_padded: bool) {
        let value = if is_padded { PADDED_VALUE } else { UNPADDED_VALUE };
        self.set_choice(settings, value);
    }
}

impl EnumSettingsDefinition for PaddingSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        if self.is_padded(Some(settings)) {
            PADDED_VALUE
        } else {
            UNPADDED_VALUE
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        settings.set_long(PADDED, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for PaddingSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(PADDED).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Padding".to_string()
    }

    fn get_storage_key(&self) -> String {
        PADDED.to_string()
    }

    fn get_description(&self) -> String {
        "Selects if the data is padded or not".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(PADDED);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(PADDED) {
            Some(value) => dest_settings.set_long(PADDED, value),
            None => dest_settings.clear_setting(PADDED),
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
    fn is_padded_returns_false_when_settings_is_none() {
        assert!(!PaddingSettingsDefinition::DEF.is_padded(None));
    }

    #[test]
    fn is_padded_returns_false_when_unset() {
        let settings = MockSettings::new();
        assert!(!PaddingSettingsDefinition::DEF.is_padded(Some(&settings)));
    }

    #[test]
    fn set_padded_then_is_padded_round_trips() {
        let mut settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        def.set_padded(&mut settings, true);
        assert!(def.is_padded(Some(&settings)));

        def.set_padded(&mut settings, false);
        assert!(!def.is_padded(Some(&settings)));
    }

    #[test]
    fn get_choice_reflects_padded_state() {
        let mut settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        assert_eq!(def.get_choice(&settings), UNPADDED_VALUE);

        def.set_padded(&mut settings, true);
        assert_eq!(def.get_choice(&settings), PADDED_VALUE);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(UNPADDED_VALUE, &settings), "unpadded");
        assert_eq!(def.get_display_choice(PADDED_VALUE, &settings), "padded");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["unpadded", "padded"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, PADDED_VALUE);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("unpadded".to_string()));

        def.set_padded(&mut settings, true);
        assert_eq!(def.get_value_string(&settings), Some("padded".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        def.set_padded(&mut settings, true);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert!(!def.is_padded(Some(&settings)));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        def.set_padded(&mut src, true);
        def.copy_setting(&src, &mut dest);

        assert!(def.is_padded(Some(&dest)));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = PaddingSettingsDefinition::DEF;

        def.set_padded(&mut dest, true);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = PaddingSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Padding");
        assert_eq!(def.get_storage_key(), "padded");
        assert_eq!(def.get_description(), "Selects if the data is padded or not");
    }
}
