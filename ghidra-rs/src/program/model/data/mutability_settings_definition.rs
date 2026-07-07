use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Mutability mode indicating normal (unspecified) mutability.
pub const NORMAL: i32 = 0;
/// Mutability mode indicating volatile data.
pub const VOLATILE: i32 = 1;
/// Mutability mode indicating constant data.
pub const CONSTANT: i32 = 2;
/// Mutability mode indicating writable data.
pub const WRITABLE: i32 = 3;

// NOTE: if these strings change, the XML needs to be changed also...
const CHOICES: &[&str] = &["normal", "volatile", "constant", "writable"];

const MUTABILITY: &str = "mutability";

/// The settings definition for the numeric display format.
///
/// Port of `ghidra.program.model.data.MutabilitySettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutabilitySettingsDefinition;

impl MutabilitySettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: MutabilitySettingsDefinition = MutabilitySettingsDefinition;

    /// Returns the mutability mode based on the current settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings, or `None` for the default value.
    ///
    /// # Returns
    /// The current mutability mode.
    pub fn get_mutability_mode(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return NORMAL;
        };
        let Some(value) = settings.get_long(MUTABILITY) else {
            return NORMAL;
        };
        let mode = value as i32;
        if mode < 0 || mode > WRITABLE {
            NORMAL
        } else {
            mode
        }
    }
}

impl EnumSettingsDefinition for MutabilitySettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_mutability_mode(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        if value < 0 || value > WRITABLE {
            settings.clear_setting(MUTABILITY);
        } else {
            settings.set_long(MUTABILITY, value as i64);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for MutabilitySettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(MUTABILITY).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Mutability".to_string()
    }

    fn get_storage_key(&self) -> String {
        MUTABILITY.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the data mutability".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(MUTABILITY);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(MUTABILITY) {
            Some(value) => dest_settings.set_long(MUTABILITY, value),
            None => dest_settings.clear_setting(MUTABILITY),
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
    fn get_mutability_mode_returns_normal_when_settings_is_none() {
        assert_eq!(
            MutabilitySettingsDefinition::DEF.get_mutability_mode(None),
            NORMAL
        );
    }

    #[test]
    fn get_mutability_mode_returns_normal_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            MutabilitySettingsDefinition::DEF.get_mutability_mode(Some(&settings)),
            NORMAL
        );
    }

    #[test]
    fn get_mutability_mode_returns_normal_when_stored_value_is_invalid() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        settings.set_long(MUTABILITY, -1);
        assert_eq!(def.get_mutability_mode(Some(&settings)), NORMAL);

        settings.set_long(MUTABILITY, (WRITABLE + 1) as i64);
        assert_eq!(def.get_mutability_mode(Some(&settings)), NORMAL);
    }

    #[test]
    fn set_choice_then_get_mutability_mode_round_trips() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        def.set_choice(&mut settings, VOLATILE);
        assert_eq!(def.get_mutability_mode(Some(&settings)), VOLATILE);

        def.set_choice(&mut settings, CONSTANT);
        assert_eq!(def.get_mutability_mode(Some(&settings)), CONSTANT);

        def.set_choice(&mut settings, WRITABLE);
        assert_eq!(def.get_mutability_mode(Some(&settings)), WRITABLE);
    }

    #[test]
    fn set_choice_with_invalid_value_clears_setting() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        def.set_choice(&mut settings, CONSTANT);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));

        def.set_choice(&mut settings, CONSTANT);
        def.set_choice(&mut settings, WRITABLE + 1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(NORMAL, &settings), "normal");
        assert_eq!(def.get_display_choice(VOLATILE, &settings), "volatile");
        assert_eq!(def.get_display_choice(CONSTANT, &settings), "constant");
        assert_eq!(def.get_display_choice(WRITABLE, &settings), "writable");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["normal", "volatile", "constant", "writable"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, VOLATILE);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("normal".to_string()));

        def.set_choice(&mut settings, WRITABLE);
        assert_eq!(def.get_value_string(&settings), Some("writable".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        def.set_choice(&mut settings, CONSTANT);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_mutability_mode(Some(&settings)), NORMAL);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        def.set_choice(&mut src, VOLATILE);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_mutability_mode(Some(&dest)), VOLATILE);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = MutabilitySettingsDefinition::DEF;

        def.set_choice(&mut dest, CONSTANT);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = MutabilitySettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Mutability");
        assert_eq!(def.get_storage_key(), "mutability");
        assert_eq!(def.get_description(), "Selects the data mutability");
    }
}
