use crate::docking::settings::boolean_settings_definition::BooleanSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const THUNK: &str = "Show thunk";
const NAME: &str = THUNK;
const DESCRIPTION: &str = "On siganls to show the thunk function attribute when present";
const DEFAULT: bool = true;

/// Settings definition for showing the thunk function attribute in tables.
///
/// Port of `ghidra.util.table.field.FunctionThunkSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FunctionThunkSettingsDefinition;

impl FunctionThunkSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: FunctionThunkSettingsDefinition = FunctionThunkSettingsDefinition;
}

impl BooleanSettingsDefinition for FunctionThunkSettingsDefinition {
    fn get_value(&self, settings: &dyn Settings) -> bool {
        match settings.get_string(THUNK) {
            Some(value) => value.eq_ignore_ascii_case("true"),
            None => DEFAULT,
        }
    }

    fn set_value(&self, settings: &mut dyn Settings, value: bool) {
        settings.set_string(THUNK, if value { "true" } else { "false" });
    }
}

impl SettingsDefinition for FunctionThunkSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(THUNK).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.get_value(settings).to_string())
    }

    fn get_name(&self) -> String {
        NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        THUNK.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(THUNK);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_string(THUNK) {
            Some(value) => dest_settings.set_string(THUNK, &value),
            None => dest_settings.clear_setting(THUNK),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockSettings {
        strings: RefCell<HashMap<String, String>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                strings: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_string(&self, name: &str) -> Option<String> {
            self.strings.borrow().get(name).cloned()
        }

        fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
            self.strings
                .borrow()
                .get(name)
                .cloned()
                .map(|v| Box::new(v) as Box<dyn std::any::Any>)
        }

        fn set_string(&mut self, name: &str, value: &str) {
            self.strings.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn clear_setting(&mut self, name: &str) {
            self.strings.borrow_mut().remove(name);
        }

        fn is_empty(&self) -> bool {
            self.strings.borrow().is_empty()
        }
    }

    #[test]
    fn default_value_is_true_when_unset() {
        let settings = MockSettings::new();
        assert!(FunctionThunkSettingsDefinition::DEF.get_value(&settings));
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let mut settings = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        def.set_value(&mut settings, false);
        assert!(!def.get_value(&settings));

        def.set_value(&mut settings, true);
        assert!(def.get_value(&settings));
    }

    #[test]
    fn get_value_string_matches_boolean_value() {
        let mut settings = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        def.set_value(&mut settings, false);
        assert_eq!(def.get_value_string(&settings), Some("false".to_string()));
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_value(&mut settings, true);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        def.set_value(&mut settings, false);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert!(def.get_value(&settings));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        def.set_value(&mut src, false);
        def.copy_setting(&src, &mut dest);

        assert!(!def.get_value(&dest));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FunctionThunkSettingsDefinition::DEF;

        def.set_value(&mut dest, false);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = FunctionThunkSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Show thunk");
        assert_eq!(def.get_storage_key(), "Show thunk");
        assert_eq!(
            def.get_description(),
            "On siganls to show the thunk function attribute when present"
        );
    }
}
