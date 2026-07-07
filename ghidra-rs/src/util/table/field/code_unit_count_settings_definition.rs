use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const CODE_UNIT_COUNT: &str = "Code-unit count";
const CHOICES: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "8"];

/// The largest code-unit count that may be selected.
pub const MAX_CODE_UNIT_COUNT: i32 = 8;

/// Settings definition for the number of code units to display in a table field.
///
/// Port of `ghidra.util.table.field.CodeUnitCountSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CodeUnitCountSettingsDefinition;

impl CodeUnitCountSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: CodeUnitCountSettingsDefinition = CodeUnitCountSettingsDefinition;

    /// Returns the number of code units to display, based on the current choice.
    pub fn get_count(&self, settings: &dyn Settings) -> i32 {
        self.get_choice(settings) + 1
    }

    /// Sets the number of code units to display.
    ///
    /// A `count` less than 1 clears the setting; a `count` greater than
    /// [`MAX_CODE_UNIT_COUNT`] is clamped to that maximum.
    pub fn set_count(&self, settings: &mut dyn Settings, count: i32) {
        if count < 1 {
            settings.clear_setting(CODE_UNIT_COUNT);
        } else {
            settings.set_long(CODE_UNIT_COUNT, (count.min(MAX_CODE_UNIT_COUNT) - 1) as i64);
        }
    }

    /// Returns the display string for the current choice.
    pub fn get_display_value(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }
}

impl EnumSettingsDefinition for CodeUnitCountSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        match settings.get_long(CODE_UNIT_COUNT) {
            Some(value) if value >= 0 && (value as usize) < CHOICES.len() => value as i32,
            _ => 0,
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        if value < 0 {
            settings.clear_setting(CODE_UNIT_COUNT);
        } else {
            settings.set_long(CODE_UNIT_COUNT, value.min(CHOICES.len() as i32 - 1) as i64);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for CodeUnitCountSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(CODE_UNIT_COUNT).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        CODE_UNIT_COUNT.to_string()
    }

    fn get_storage_key(&self) -> String {
        CODE_UNIT_COUNT.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the number of bytes to display".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(CODE_UNIT_COUNT);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(CODE_UNIT_COUNT) {
            Some(value) => dest_settings.set_long(CODE_UNIT_COUNT, value),
            None => dest_settings.clear_setting(CODE_UNIT_COUNT),
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
    fn default_choice_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(CodeUnitCountSettingsDefinition::DEF.get_choice(&settings), 0);
    }

    #[test]
    fn default_choice_when_out_of_range() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        settings.set_long(CODE_UNIT_COUNT, -1);
        assert_eq!(def.get_choice(&settings), 0);

        settings.set_long(CODE_UNIT_COUNT, 8);
        assert_eq!(def.get_choice(&settings), 0);
    }

    #[test]
    fn set_choice_then_get_choice_round_trips() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut settings, 4);
        assert_eq!(def.get_choice(&settings), 4);
    }

    #[test]
    fn set_choice_clamps_to_last_choice() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut settings, 100);
        assert_eq!(def.get_choice(&settings), CHOICES.len() as i32 - 1);
    }

    #[test]
    fn set_choice_below_zero_clears_setting() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut settings, 3);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_count_is_choice_plus_one() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        assert_eq!(def.get_count(&settings), 1);

        def.set_choice(&mut settings, 3);
        assert_eq!(def.get_count(&settings), 4);
    }

    #[test]
    fn set_count_then_get_count_round_trips() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_count(&mut settings, 5);
        assert_eq!(def.get_count(&settings), 5);
    }

    #[test]
    fn set_count_clamps_to_max_code_unit_count() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_count(&mut settings, 100);
        assert_eq!(def.get_count(&settings), MAX_CODE_UNIT_COUNT);
    }

    #[test]
    fn set_count_below_one_clears_setting() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_count(&mut settings, 3);
        assert!(def.has_value(&settings));

        def.set_count(&mut settings, 0);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_count(&settings), 1);
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("1".to_string()));

        def.set_choice(&mut settings, 5);
        assert_eq!(def.get_value_string(&settings), Some("6".to_string()));
    }

    #[test]
    fn get_display_value_matches_choice() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        assert_eq!(def.get_display_value(&settings), "1");

        def.set_choice(&mut settings, 7);
        assert_eq!(def.get_display_value(&settings), "8");
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "1");
        assert_eq!(def.get_display_choice(7, &settings), "8");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["1", "2", "3", "4", "5", "6", "7", "8"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, 2);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut settings, 6);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_choice(&settings), 0);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut src, 7);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_choice(&dest), 7);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = CodeUnitCountSettingsDefinition::DEF;

        def.set_choice(&mut dest, 3);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = CodeUnitCountSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Code-unit count");
        assert_eq!(def.get_storage_key(), "Code-unit count");
        assert_eq!(def.get_description(), "Selects the number of bytes to display");
    }
}
