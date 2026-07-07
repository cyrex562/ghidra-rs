use crate::docking::settings::boolean_settings_definition::BooleanSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const DEFAULT: bool = true;
const DESCRIPTION: &str = "Toggles showing namespace when displaying function name";
const SHOW_NAMESPACE: &str = "Show Namespace";

/// Settings definition for showing function namespaces in the BSim Results table.
///
/// Port of `ghidra.features.bsim.gui.search.results.ShowNamespaceSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShowNamespaceSettingsDefinition;

impl ShowNamespaceSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: ShowNamespaceSettingsDefinition = ShowNamespaceSettingsDefinition;
}

impl BooleanSettingsDefinition for ShowNamespaceSettingsDefinition {
    fn get_value(&self, settings: &dyn Settings) -> bool {
        match settings.get_string(SHOW_NAMESPACE) {
            Some(value) => value.eq_ignore_ascii_case("true"),
            None => DEFAULT,
        }
    }

    fn set_value(&self, settings: &mut dyn Settings, value: bool) {
        settings.set_string(SHOW_NAMESPACE, if value { "true" } else { "false" });
    }
}

impl SettingsDefinition for ShowNamespaceSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(SHOW_NAMESPACE).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.get_value(settings).to_string())
    }

    fn get_name(&self) -> String {
        SHOW_NAMESPACE.to_string()
    }

    fn get_storage_key(&self) -> String {
        SHOW_NAMESPACE.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(SHOW_NAMESPACE);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_string(SHOW_NAMESPACE) {
            Some(value) => dest_settings.set_string(SHOW_NAMESPACE, &value),
            None => dest_settings.clear_setting(SHOW_NAMESPACE),
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
        assert!(ShowNamespaceSettingsDefinition::DEF.get_value(&settings));
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let mut settings = MockSettings::new();
        let def = ShowNamespaceSettingsDefinition::DEF;

        def.set_value(&mut settings, false);
        assert!(!def.get_value(&settings));

        def.set_value(&mut settings, true);
        assert!(def.get_value(&settings));
    }

    #[test]
    fn get_value_string_matches_boolean_value() {
        let mut settings = MockSettings::new();
        let def = ShowNamespaceSettingsDefinition::DEF;

        def.set_value(&mut settings, false);
        assert_eq!(def.get_value_string(&settings), Some("false".to_string()));
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = ShowNamespaceSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_value(&mut settings, true);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = ShowNamespaceSettingsDefinition::DEF;

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
        let def = ShowNamespaceSettingsDefinition::DEF;

        def.set_value(&mut src, false);
        def.copy_setting(&src, &mut dest);

        assert!(!def.get_value(&dest));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = ShowNamespaceSettingsDefinition::DEF;

        def.set_value(&mut dest, false);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = ShowNamespaceSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Show Namespace");
        assert_eq!(def.get_storage_key(), "Show Namespace");
        assert_eq!(
            def.get_description(),
            "Toggles showing namespace when displaying function name"
        );
    }
}
