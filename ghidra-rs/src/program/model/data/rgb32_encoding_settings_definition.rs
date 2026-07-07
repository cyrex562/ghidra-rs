use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;

/// Enumeration of 32-bit RGB color encoding standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RGB32Encoding {
    /// ARGB 8-8-8-8 encoding (8 bits alpha, 8 bits red, 8 bits green, 8 bits blue)
    ARGB8888,
    /// RGBA 8-8-8-8 encoding (8 bits red, 8 bits green, 8 bits blue, 8 bits alpha)
    RGBA8888,
    /// BGRA 8-8-8-8 encoding (8 bits blue, 8 bits green, 8 bits red, 8 bits alpha)
    BGRA8888,
    /// ABGR 8-8-8-8 encoding (8 bits alpha, 8 bits blue, 8 bits green, 8 bits red)
    ABGR8888,
}

impl RGB32Encoding {
    /// Returns the name of this encoding.
    pub fn name(&self) -> &'static str {
        match self {
            RGB32Encoding::ARGB8888 => "ARGB_8888",
            RGB32Encoding::RGBA8888 => "RGBA_8888",
            RGB32Encoding::BGRA8888 => "BGRA_8888",
            RGB32Encoding::ABGR8888 => "ABGR_8888",
        }
    }

    /// Parses an encoding from its name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ARGB_8888" => Some(RGB32Encoding::ARGB8888),
            "RGBA_8888" => Some(RGB32Encoding::RGBA8888),
            "BGRA_8888" => Some(RGB32Encoding::BGRA8888),
            "ABGR_8888" => Some(RGB32Encoding::ABGR8888),
            _ => None,
        }
    }
}

/// Default encoding: ARGB 8-8-8-8.
pub const DEFAULT_ENCODING: RGB32Encoding = RGB32Encoding::ARGB8888;

const RGB32_ENCODING_SETTINGS_NAME: &str = "rgb32";
const DESCRIPTION: &str = "Specifies a 32-bit RGB Color Encoding";
const DISPLAY_NAME: &str = "RGB32 Encoding";

const CHOICES: &[&str] = &["ARGB_8888", "RGBA_8888", "BGRA_8888", "ABGR_8888"];

/// The typedef settings definition which specifies a 32-bit RGB Color Encoding.
///
/// Port of `ghidra.program.model.data.RGB32EncodingSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RGB32EncodingSettingsDefinition;

impl RGB32EncodingSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: RGB32EncodingSettingsDefinition = RGB32EncodingSettingsDefinition;

    /// Returns the RGB encoding standard based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings, or `None` for the default value.
    ///
    /// # Returns
    /// The RGB encoding standard. The default encoding (ARGB_8888) will be returned
    /// if no setting has been made.
    pub fn get_rgb_encoding(&self, settings: Option<&dyn Settings>) -> RGB32Encoding {
        RGB32Encoding::from_name(&self.get_value_string_for_choice(self.get_choice_internal(settings)))
            .unwrap_or(DEFAULT_ENCODING)
    }

    fn get_choice_internal(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return 0;
        };
        let Some(value) = settings.get_long(RGB32_ENCODING_SETTINGS_NAME) else {
            return 0;
        };
        let choice = value as i32;
        if choice < 0 || choice >= CHOICES.len() as i32 {
            0
        } else {
            choice
        }
    }

    fn get_value_string_for_choice(&self, choice: i32) -> String {
        CHOICES[choice as usize].to_string()
    }

    /// Sets the settings object to the encoding indicated by the specified RGB32Encoding value.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value
    /// * `encoding` - the RGB encoding value to set
    ///
    /// # Panics
    /// Panics if the encoding is not one of the expected enum values.
    pub fn set_rgb_encoding(&self, settings: &mut dyn Settings, encoding: RGB32Encoding) {
        for (i, choice_str) in CHOICES.iter().enumerate() {
            if *choice_str == encoding.name() {
                self.set_choice(settings, i as i32);
                return;
            }
        }
        panic!("Missing RGB Encoding choice: {:?}", encoding);
    }

    /// Returns the display choice string for the current settings.
    ///
    /// # Arguments
    /// * `settings` - the settings to get the display choice from
    ///
    /// # Returns
    /// The display name string for the current choice
    pub fn get_display_choice_string(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }

    /// Sets the settings object to the enum value indicated by the specified choice string.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value
    /// * `choice` - the enum string representing a choice
    pub fn set_display_choice_string(&self, settings: &mut dyn Settings, choice: &str) {
        for (i, choice_str) in CHOICES.iter().enumerate() {
            if *choice_str == choice {
                self.set_choice(settings, i as i32);
                return;
            }
        }
    }
}

impl EnumSettingsDefinition for RGB32EncodingSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_choice_internal(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, choice: i32) {
        if choice > 0 && choice < CHOICES.len() as i32 {
            settings.set_long(RGB32_ENCODING_SETTINGS_NAME, choice as i64);
        } else {
            settings.clear_setting(RGB32_ENCODING_SETTINGS_NAME);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for RGB32EncodingSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(RGB32_ENCODING_SETTINGS_NAME).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.get_value_string_for_choice(self.get_choice(settings)))
    }

    fn get_name(&self) -> String {
        DISPLAY_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        RGB32_ENCODING_SETTINGS_NAME.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(RGB32_ENCODING_SETTINGS_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(RGB32_ENCODING_SETTINGS_NAME) {
            Some(value) => dest_settings.set_long(RGB32_ENCODING_SETTINGS_NAME, value),
            None => dest_settings.clear_setting(RGB32_ENCODING_SETTINGS_NAME),
        }
    }
}

impl TypeDefSettingsDefinition for RGB32EncodingSettingsDefinition {
    fn get_attribute_specification(&self, settings: &dyn Settings) -> Option<String> {
        let choice = self.get_choice(settings);
        if choice != 0 {
            Some(CHOICES[choice as usize].to_string())
        } else {
            None
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
    fn get_rgb_encoding_returns_default_when_settings_is_none() {
        assert_eq!(
            RGB32EncodingSettingsDefinition::DEF.get_rgb_encoding(None),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn get_rgb_encoding_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            RGB32EncodingSettingsDefinition::DEF.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn get_rgb_encoding_returns_default_for_out_of_range_values() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        settings.set_long(RGB32_ENCODING_SETTINGS_NAME, -1);
        assert_eq!(
            def.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );

        settings.set_long(RGB32_ENCODING_SETTINGS_NAME, (CHOICES.len() as i64) + 1);
        assert_eq!(
            def.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn set_choice_then_get_rgb_encoding_round_trips() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 0);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::ARGB8888);

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::RGBA8888);

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::BGRA8888);

        def.set_choice(&mut settings, 3);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::ABGR8888);
    }

    #[test]
    fn set_choice_clears_setting_for_out_of_range_value() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));

        def.set_choice(&mut settings, 1);
        def.set_choice(&mut settings, (CHOICES.len() as i32) + 1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_choice_reflects_set_choice() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_choice(&settings), 0);

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_choice(&settings), 1);

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_choice(&settings), 2);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "ARGB_8888");
        assert_eq!(def.get_display_choice(1, &settings), "RGBA_8888");
        assert_eq!(def.get_display_choice(2, &settings), "BGRA_8888");
        assert_eq!(def.get_display_choice(3, &settings), "ABGR_8888");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["ARGB_8888", "RGBA_8888", "BGRA_8888", "ABGR_8888"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, 1);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("ARGB_8888".to_string()));

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_value_string(&settings), Some("RGBA_8888".to_string()));

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_value_string(&settings), Some("BGRA_8888".to_string()));

        def.set_choice(&mut settings, 3);
        assert_eq!(def.get_value_string(&settings), Some("ABGR_8888".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_rgb_encoding(Some(&settings)), DEFAULT_ENCODING);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut src, 3);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_rgb_encoding(Some(&dest)), RGB32Encoding::ABGR8888);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut dest, 1);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = RGB32EncodingSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "RGB32 Encoding");
        assert_eq!(def.get_storage_key(), "rgb32");
        assert_eq!(def.get_description(), "Specifies a 32-bit RGB Color Encoding");
    }

    #[test]
    fn get_attribute_specification_returns_none_for_default() {
        let settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn get_attribute_specification_returns_choice_for_non_default() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("RGBA_8888".to_string())
        );

        def.set_choice(&mut settings, 2);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("BGRA_8888".to_string())
        );

        def.set_choice(&mut settings, 3);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("ABGR_8888".to_string())
        );
    }

    #[test]
    fn rgb32_encoding_enum_names() {
        assert_eq!(RGB32Encoding::ARGB8888.name(), "ARGB_8888");
        assert_eq!(RGB32Encoding::RGBA8888.name(), "RGBA_8888");
        assert_eq!(RGB32Encoding::BGRA8888.name(), "BGRA_8888");
        assert_eq!(RGB32Encoding::ABGR8888.name(), "ABGR_8888");
    }

    #[test]
    fn rgb32_encoding_from_name() {
        assert_eq!(RGB32Encoding::from_name("ARGB_8888"), Some(RGB32Encoding::ARGB8888));
        assert_eq!(RGB32Encoding::from_name("RGBA_8888"), Some(RGB32Encoding::RGBA8888));
        assert_eq!(RGB32Encoding::from_name("BGRA_8888"), Some(RGB32Encoding::BGRA8888));
        assert_eq!(RGB32Encoding::from_name("ABGR_8888"), Some(RGB32Encoding::ABGR8888));
        assert_eq!(RGB32Encoding::from_name("INVALID"), None);
    }

    #[test]
    fn set_rgb_encoding_then_get_rgb_encoding_round_trips() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_rgb_encoding(&mut settings, RGB32Encoding::ARGB8888);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::ARGB8888);

        def.set_rgb_encoding(&mut settings, RGB32Encoding::RGBA8888);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::RGBA8888);

        def.set_rgb_encoding(&mut settings, RGB32Encoding::BGRA8888);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::BGRA8888);

        def.set_rgb_encoding(&mut settings, RGB32Encoding::ABGR8888);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB32Encoding::ABGR8888);
    }

    #[test]
    fn get_display_choice_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice_string(&settings), "ARGB_8888");

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_display_choice_string(&settings), "RGBA_8888");

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_display_choice_string(&settings), "BGRA_8888");

        def.set_choice(&mut settings, 3);
        assert_eq!(def.get_display_choice_string(&settings), "ABGR_8888");
    }

    #[test]
    fn set_display_choice_string_sets_choice_by_string() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_display_choice_string(&mut settings, "RGBA_8888");
        assert_eq!(def.get_choice(&settings), 1);
        assert_eq!(def.get_display_choice_string(&settings), "RGBA_8888");

        def.set_display_choice_string(&mut settings, "ABGR_8888");
        assert_eq!(def.get_choice(&settings), 3);
        assert_eq!(def.get_display_choice_string(&settings), "ABGR_8888");
    }

    #[test]
    fn set_display_choice_string_does_nothing_for_invalid_string() {
        let mut settings = MockSettings::new();
        let def = RGB32EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        def.set_display_choice_string(&mut settings, "INVALID");
        assert_eq!(def.get_choice(&settings), 1);
    }
}
