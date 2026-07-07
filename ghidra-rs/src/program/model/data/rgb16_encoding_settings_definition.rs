use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;

/// Enumeration of 16-bit RGB color encoding standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RGB16Encoding {
    /// RGB 5-6-5 encoding (5 bits red, 6 bits green, 5 bits blue)
    RGB565,
    /// RGB 5-5-5 encoding (5 bits red, 5 bits green, 5 bits blue)
    RGB555,
    /// ARGB 1-5-5-5 encoding (1 bit alpha, 5 bits red, 5 bits green, 5 bits blue)
    ARGB1555,
}

impl RGB16Encoding {
    /// Returns the name of this encoding.
    pub fn name(&self) -> &'static str {
        match self {
            RGB16Encoding::RGB565 => "RGB_565",
            RGB16Encoding::RGB555 => "RGB_555",
            RGB16Encoding::ARGB1555 => "ARGB_1555",
        }
    }

    /// Parses an encoding from its name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "RGB_565" => Some(RGB16Encoding::RGB565),
            "RGB_555" => Some(RGB16Encoding::RGB555),
            "ARGB_1555" => Some(RGB16Encoding::ARGB1555),
            _ => None,
        }
    }
}

/// Default encoding: RGB 5-6-5.
pub const DEFAULT_ENCODING: RGB16Encoding = RGB16Encoding::RGB565;

const RGB16_ENCODING_SETTINGS_NAME: &str = "rgb16";
const DESCRIPTION: &str = "Specifies a 16-bit RGB Color Encoding";
const DISPLAY_NAME: &str = "RGB16 Encoding";

const CHOICES: &[&str] = &["RGB_565", "RGB_555", "ARGB_1555"];

/// The typedef settings definition which specifies a 16-bit RGB Color Encoding.
///
/// Port of `ghidra.program.model.data.RGB16EncodingSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RGB16EncodingSettingsDefinition;

impl RGB16EncodingSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: RGB16EncodingSettingsDefinition = RGB16EncodingSettingsDefinition;

    /// Returns the RGB encoding standard based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings, or `None` for the default value.
    ///
    /// # Returns
    /// The RGB encoding standard. The default encoding (RGB_565) will be returned
    /// if no setting has been made.
    pub fn get_rgb_encoding(&self, settings: Option<&dyn Settings>) -> RGB16Encoding {
        RGB16Encoding::from_name(&self.get_value_string_for_choice(self.get_choice_internal(settings)))
            .unwrap_or(DEFAULT_ENCODING)
    }

    fn get_choice_internal(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return 0;
        };
        let Some(value) = settings.get_long(RGB16_ENCODING_SETTINGS_NAME) else {
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

    /// Sets the settings object to the encoding indicated by the specified RGB16Encoding value.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value
    /// * `encoding` - the RGB encoding value to set
    ///
    /// # Panics
    /// Panics if the encoding is not one of the expected enum values.
    pub fn set_rgb_encoding(&self, settings: &mut dyn Settings, encoding: RGB16Encoding) {
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

impl EnumSettingsDefinition for RGB16EncodingSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_choice_internal(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, choice: i32) {
        if choice > 0 && choice < CHOICES.len() as i32 {
            settings.set_long(RGB16_ENCODING_SETTINGS_NAME, choice as i64);
        } else {
            settings.clear_setting(RGB16_ENCODING_SETTINGS_NAME);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for RGB16EncodingSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(RGB16_ENCODING_SETTINGS_NAME).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.get_value_string_for_choice(self.get_choice(settings)))
    }

    fn get_name(&self) -> String {
        DISPLAY_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        RGB16_ENCODING_SETTINGS_NAME.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(RGB16_ENCODING_SETTINGS_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(RGB16_ENCODING_SETTINGS_NAME) {
            Some(value) => dest_settings.set_long(RGB16_ENCODING_SETTINGS_NAME, value),
            None => dest_settings.clear_setting(RGB16_ENCODING_SETTINGS_NAME),
        }
    }
}

impl TypeDefSettingsDefinition for RGB16EncodingSettingsDefinition {
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
            RGB16EncodingSettingsDefinition::DEF.get_rgb_encoding(None),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn get_rgb_encoding_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            RGB16EncodingSettingsDefinition::DEF.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn get_rgb_encoding_returns_default_for_out_of_range_values() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        settings.set_long(RGB16_ENCODING_SETTINGS_NAME, -1);
        assert_eq!(
            def.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );

        settings.set_long(RGB16_ENCODING_SETTINGS_NAME, (CHOICES.len() as i64) + 1);
        assert_eq!(
            def.get_rgb_encoding(Some(&settings)),
            DEFAULT_ENCODING
        );
    }

    #[test]
    fn set_choice_then_get_rgb_encoding_round_trips() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 0);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::RGB565);

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::RGB555);

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::ARGB1555);
    }

    #[test]
    fn set_choice_clears_setting_for_out_of_range_value() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

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
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_choice(&settings), 0);

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_choice(&settings), 1);

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_choice(&settings), 2);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "RGB_565");
        assert_eq!(def.get_display_choice(1, &settings), "RGB_555");
        assert_eq!(def.get_display_choice(2, &settings), "ARGB_1555");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["RGB_565", "RGB_555", "ARGB_1555"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, 1);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("RGB_565".to_string()));

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_value_string(&settings), Some("RGB_555".to_string()));

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_value_string(&settings), Some("ARGB_1555".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

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
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_choice(&mut src, 2);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_rgb_encoding(Some(&dest)), RGB16Encoding::ARGB1555);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_choice(&mut dest, 1);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = RGB16EncodingSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "RGB16 Encoding");
        assert_eq!(def.get_storage_key(), "rgb16");
        assert_eq!(def.get_description(), "Specifies a 16-bit RGB Color Encoding");
    }

    #[test]
    fn get_attribute_specification_returns_none_for_default() {
        let settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn get_attribute_specification_returns_choice_for_non_default() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("RGB_555".to_string())
        );

        def.set_choice(&mut settings, 2);
        assert_eq!(
            def.get_attribute_specification(&settings),
            Some("ARGB_1555".to_string())
        );
    }

    #[test]
    fn rgb16_encoding_enum_names() {
        assert_eq!(RGB16Encoding::RGB565.name(), "RGB_565");
        assert_eq!(RGB16Encoding::RGB555.name(), "RGB_555");
        assert_eq!(RGB16Encoding::ARGB1555.name(), "ARGB_1555");
    }

    #[test]
    fn rgb16_encoding_from_name() {
        assert_eq!(RGB16Encoding::from_name("RGB_565"), Some(RGB16Encoding::RGB565));
        assert_eq!(RGB16Encoding::from_name("RGB_555"), Some(RGB16Encoding::RGB555));
        assert_eq!(RGB16Encoding::from_name("ARGB_1555"), Some(RGB16Encoding::ARGB1555));
        assert_eq!(RGB16Encoding::from_name("INVALID"), None);
    }

    #[test]
    fn set_rgb_encoding_then_get_rgb_encoding_round_trips() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_rgb_encoding(&mut settings, RGB16Encoding::RGB565);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::RGB565);

        def.set_rgb_encoding(&mut settings, RGB16Encoding::RGB555);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::RGB555);

        def.set_rgb_encoding(&mut settings, RGB16Encoding::ARGB1555);
        assert_eq!(def.get_rgb_encoding(Some(&settings)), RGB16Encoding::ARGB1555);
    }

    #[test]
    fn get_display_choice_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice_string(&settings), "RGB_565");

        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_display_choice_string(&settings), "RGB_555");

        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_display_choice_string(&settings), "ARGB_1555");
    }

    #[test]
    fn set_display_choice_string_sets_choice_by_string() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_display_choice_string(&mut settings, "RGB_555");
        assert_eq!(def.get_choice(&settings), 1);
        assert_eq!(def.get_display_choice_string(&settings), "RGB_555");

        def.set_display_choice_string(&mut settings, "ARGB_1555");
        assert_eq!(def.get_choice(&settings), 2);
        assert_eq!(def.get_display_choice_string(&settings), "ARGB_1555");
    }

    #[test]
    fn set_display_choice_string_does_nothing_for_invalid_string() {
        let mut settings = MockSettings::new();
        let def = RGB16EncodingSettingsDefinition::DEF;

        def.set_choice(&mut settings, 1);
        def.set_display_choice_string(&mut settings, "INVALID");
        assert_eq!(def.get_choice(&settings), 1);
    }
}
