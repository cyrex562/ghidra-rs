use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;

const COMPONENT_OFFSET_SETTING_NAME: &str = "component_offset";
const DESCRIPTION: &str = "Identifies a component offset to be applied to a pointer reference";
const DISPLAY_NAME: &str = "Component Offset";

const DEFAULT: i64 = 0;

/// A [`NumberSettingsDefinition`]/[`TypeDefSettingsDefinition`] which identifies a component
/// offset to be applied to a pointer reference.
///
/// Port of `ghidra.program.model.data.ComponentOffsetSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentOffsetSettingsDefinition;

impl ComponentOffsetSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: ComponentOffsetSettingsDefinition = ComponentOffsetSettingsDefinition;
}

impl NumberSettingsDefinition for ComponentOffsetSettingsDefinition {
    fn get_value(&self, settings: &dyn Settings) -> i64 {
        settings
            .get_long(COMPONENT_OFFSET_SETTING_NAME)
            .unwrap_or(DEFAULT)
    }

    fn set_value(&self, settings: &mut dyn Settings, value: i64) {
        if value == DEFAULT {
            settings.clear_setting(COMPONENT_OFFSET_SETTING_NAME);
        } else {
            settings.set_long(COMPONENT_OFFSET_SETTING_NAME, value);
        }
    }

    fn get_max_value(&self) -> u64 {
        i64::MAX as u64
    }

    fn allow_negative_value(&self) -> bool {
        true
    }

    fn is_hex_mode_preferred(&self) -> bool {
        false
    }
}

impl SettingsDefinition for ComponentOffsetSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        NumberSettingsDefinition::get_value(self, settings) != DEFAULT
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        NumberSettingsDefinition::get_value_string(self, settings)
    }

    fn get_name(&self) -> String {
        DISPLAY_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        COMPONENT_OFFSET_SETTING_NAME.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(COMPONENT_OFFSET_SETTING_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(COMPONENT_OFFSET_SETTING_NAME) {
            Some(value) => dest_settings.set_long(COMPONENT_OFFSET_SETTING_NAME, value),
            None => dest_settings.clear_setting(COMPONENT_OFFSET_SETTING_NAME),
        }
    }

    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        NumberSettingsDefinition::has_same_value(self, settings1, settings2)
    }
}

impl TypeDefSettingsDefinition for ComponentOffsetSettingsDefinition {
    fn get_attribute_specification(&self, settings: &dyn Settings) -> Option<String> {
        if !self.has_value(settings) {
            return None;
        }
        let mut offset = NumberSettingsDefinition::get_value(self, settings);
        let mut sign = "";
        if offset < 0 {
            offset = -offset;
            sign = "-";
        }
        Some(format!("offset({}0x{:x})", sign, offset as u64))
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
    fn get_value_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            ComponentOffsetSettingsDefinition::DEF.get_value(&settings),
            DEFAULT
        );
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut settings, 42);
        assert_eq!(def.get_value(&settings), 42);

        def.set_value(&mut settings, -42);
        assert_eq!(def.get_value(&settings), -42);
    }

    #[test]
    fn set_value_with_default_clears_setting() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut settings, 42);
        assert!(def.has_value(&settings));

        def.set_value(&mut settings, DEFAULT);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_value(&mut settings, 8);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_max_value_allow_negative_and_hex_preference() {
        let def = ComponentOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_max_value(), i64::MAX as u64);
        assert!(def.allow_negative_value());
        assert!(!def.is_hex_mode_preferred());
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = ComponentOffsetSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Component Offset");
        assert_eq!(def.get_storage_key(), "component_offset");
        assert_eq!(
            def.get_description(),
            "Identifies a component offset to be applied to a pointer reference"
        );
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut settings, 8);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut src, 16);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_value(&dest), 16);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut dest, 16);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn get_attribute_specification_returns_none_when_unset() {
        let settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn get_attribute_specification_formats_positive_offset() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut settings, 0x18);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("offset(0x18)".to_string())
        );
    }

    #[test]
    fn get_attribute_specification_formats_negative_offset() {
        let mut settings = MockSettings::new();
        let def = ComponentOffsetSettingsDefinition::DEF;

        def.set_value(&mut settings, -0x18);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("offset(-0x18)".to_string())
        );
    }
}
