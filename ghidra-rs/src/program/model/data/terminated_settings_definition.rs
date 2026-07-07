use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Choice value for an unterminated string.
pub const UNTERMINATED_VALUE: i32 = 0;
/// Choice value for a terminated string.
pub const TERMINATED_VALUE: i32 = 1;

const CHOICES: &[&str] = &["unterminated", "terminated"];

const TERMINATED: &str = "terminated";

/// Settings definition for strings being terminated or unterminated.
///
/// Port of `ghidra.program.model.data.TerminatedSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminatedSettingsDefinition;

impl TerminatedSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: TerminatedSettingsDefinition = TerminatedSettingsDefinition;

    /// Gets the current termination setting from the given settings objects or returns
    /// the default if not in either settings object.
    ///
    /// # Arguments
    /// * `settings` - the instance settings.
    ///
    /// # Returns
    /// The current value for this settings definition.
    pub fn is_terminated(&self, settings: Option<&dyn Settings>) -> bool {
        let Some(settings) = settings else {
            return false;
        };
        let Some(value) = settings.get_long(TERMINATED) else {
            return false;
        };
        value == TERMINATED_VALUE as i64
    }

    pub fn set_terminated(&self, settings: &mut dyn Settings, is_terminated: bool) {
        let value = if is_terminated {
            TERMINATED_VALUE
        } else {
            UNTERMINATED_VALUE
        };
        self.set_choice(settings, value);
    }
}

impl EnumSettingsDefinition for TerminatedSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        if self.is_terminated(Some(settings)) {
            TERMINATED_VALUE
        } else {
            UNTERMINATED_VALUE
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        settings.set_long(TERMINATED, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for TerminatedSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(TERMINATED).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Termination".to_string()
    }

    fn get_storage_key(&self) -> String {
        TERMINATED.to_string()
    }

    fn get_description(&self) -> String {
        "Selects if the string is terminated or unterminated".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(TERMINATED);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(TERMINATED) {
            Some(value) => dest_settings.set_long(TERMINATED, value),
            None => dest_settings.clear_setting(TERMINATED),
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
    fn is_terminated_returns_false_when_settings_is_none() {
        assert!(!TerminatedSettingsDefinition::DEF.is_terminated(None));
    }

    #[test]
    fn is_terminated_returns_false_when_unset() {
        let settings = MockSettings::new();
        assert!(!TerminatedSettingsDefinition::DEF.is_terminated(Some(&settings)));
    }

    #[test]
    fn set_terminated_then_is_terminated_round_trips() {
        let mut settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        def.set_terminated(&mut settings, true);
        assert!(def.is_terminated(Some(&settings)));

        def.set_terminated(&mut settings, false);
        assert!(!def.is_terminated(Some(&settings)));
    }

    #[test]
    fn get_choice_reflects_terminated_state() {
        let mut settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        assert_eq!(def.get_choice(&settings), UNTERMINATED_VALUE);

        def.set_terminated(&mut settings, true);
        assert_eq!(def.get_choice(&settings), TERMINATED_VALUE);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        assert_eq!(
            def.get_display_choice(UNTERMINATED_VALUE, &settings),
            "unterminated"
        );
        assert_eq!(
            def.get_display_choice(TERMINATED_VALUE, &settings),
            "terminated"
        );
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["unterminated", "terminated"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, TERMINATED_VALUE);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        assert_eq!(
            def.get_value_string(&settings),
            Some("unterminated".to_string())
        );

        def.set_terminated(&mut settings, true);
        assert_eq!(
            def.get_value_string(&settings),
            Some("terminated".to_string())
        );
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        def.set_terminated(&mut settings, true);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert!(!def.is_terminated(Some(&settings)));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        def.set_terminated(&mut src, true);
        def.copy_setting(&src, &mut dest);

        assert!(def.is_terminated(Some(&dest)));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = TerminatedSettingsDefinition::DEF;

        def.set_terminated(&mut dest, true);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = TerminatedSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Termination");
        assert_eq!(def.get_storage_key(), "terminated");
        assert_eq!(
            def.get_description(),
            "Selects if the string is terminated or unterminated"
        );
    }
}
