use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Choice value for hexadecimal display.
pub const HEX: i32 = 0;
/// Choice value for decimal display.
pub const DECIMAL: i32 = 1;
/// Choice value for binary display.
pub const BINARY: i32 = 2;
/// Choice value for octal display.
pub const OCTAL: i32 = 3;
/// Choice value for character display.
pub const CHAR: i32 = 4;

// NOTE: if these strings change, the XML needs to be changed also...
const CHOICES: &[&str] = &["hex", "decimal", "binary", "octal", "char"];
const VALUE_POSTFIX: &[&str] = &["h", "", "b", "o", ""];
const RADIX: &[i32] = &[16, 10, 2, 8, 0];

const FORMAT: &str = "format";

/// The settings definition for the numeric display format.
///
/// Port of `ghidra.docking.settings.FormatSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSettingsDefinition {
    default_format: i32,
}

impl FormatSettingsDefinition {
    const fn new(default_format: i32) -> Self {
        FormatSettingsDefinition { default_format }
    }

    /// Definition with a default format of [`HEX`].
    pub const DEF_HEX: FormatSettingsDefinition = FormatSettingsDefinition::new(HEX);
    /// Definition with a default format of [`DECIMAL`].
    pub const DEF_DECIMAL: FormatSettingsDefinition = FormatSettingsDefinition::new(DECIMAL);
    /// Definition with a default format of [`BINARY`].
    pub const DEF_BINARY: FormatSettingsDefinition = FormatSettingsDefinition::new(BINARY);
    /// Definition with a default format of [`OCTAL`].
    pub const DEF_OCTAL: FormatSettingsDefinition = FormatSettingsDefinition::new(OCTAL);
    /// Definition with a default format of [`CHAR`].
    pub const DEF_CHAR: FormatSettingsDefinition = FormatSettingsDefinition::new(CHAR);

    /// The default definition (default format is [`HEX`]).
    pub const DEF: FormatSettingsDefinition = Self::DEF_HEX;

    /// Returns the format based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings or `None` for default value.
    ///
    /// # Returns
    /// The format value ([`HEX`], [`DECIMAL`], [`BINARY`], [`OCTAL`], [`CHAR`]), or [`HEX`] if
    /// invalid data is stored in the format settings value.
    pub fn get_format(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return self.default_format;
        };
        let Some(value) = settings.get_long(FORMAT) else {
            return self.default_format;
        };
        let format = value as i32;
        if !(0..=CHAR).contains(&format) {
            HEX
        } else {
            format
        }
    }

    /// Returns the numeric radix associated with the format identified by the specified
    /// settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings.
    ///
    /// # Returns
    /// The format radix.
    pub fn get_radix(&self, settings: &dyn Settings) -> i32 {
        RADIX[self.get_format(Some(settings)) as usize]
    }

    /// Returns a descriptive string suffix that should be appended after converting a value
    /// using the radix returned by [`Self::get_radix`].
    ///
    /// # Arguments
    /// * `settings` - the instance settings.
    ///
    /// # Returns
    /// String suffix, such as "h" for HEX, "o" for octal.
    pub fn get_representation_postfix(&self, settings: &dyn Settings) -> String {
        VALUE_POSTFIX[self.get_format(Some(settings)) as usize].to_string()
    }

    /// Returns the display string for the choice currently stored in the given settings.
    pub fn get_current_display_choice(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }

    /// Sets the settings object to the enum value indicating the specified choice as a string.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value.
    /// * `choice` - string representing a choice in the enum.
    pub fn set_display_choice(&self, settings: &mut dyn Settings, choice: &str) {
        if let Some(index) = CHOICES.iter().position(|c| *c == choice) {
            self.set_choice(settings, index as i32);
        }
    }
}

impl EnumSettingsDefinition for FormatSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_format(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        if !(0..=CHAR).contains(&value) {
            settings.clear_setting(FORMAT);
        } else {
            settings.set_long(FORMAT, value as i64);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for FormatSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(FORMAT).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Format".to_string()
    }

    fn get_storage_key(&self) -> String {
        FORMAT.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the display format".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(FORMAT);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(FORMAT) {
            Some(value) => dest_settings.set_long(FORMAT, value),
            None => dest_settings.clear_setting(FORMAT),
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
    fn get_format_returns_default_when_settings_is_none() {
        assert_eq!(FormatSettingsDefinition::DEF_DECIMAL.get_format(None), DECIMAL);
    }

    #[test]
    fn get_format_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(FormatSettingsDefinition::DEF.get_format(Some(&settings)), HEX);
        assert_eq!(
            FormatSettingsDefinition::DEF_OCTAL.get_format(Some(&settings)),
            OCTAL
        );
    }

    #[test]
    fn get_format_returns_hex_when_stored_value_is_invalid() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        settings.set_long(FORMAT, -1);
        assert_eq!(def.get_format(Some(&settings)), HEX);

        settings.set_long(FORMAT, (CHAR + 1) as i64);
        assert_eq!(def.get_format(Some(&settings)), HEX);
    }

    #[test]
    fn set_choice_then_get_format_round_trips() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_choice(&mut settings, BINARY);
        assert_eq!(def.get_format(Some(&settings)), BINARY);
    }

    #[test]
    fn set_choice_with_invalid_value_clears_setting() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_choice(&mut settings, OCTAL);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));

        def.set_choice(&mut settings, OCTAL);
        def.set_choice(&mut settings, CHAR + 1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_radix_matches_format() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert_eq!(def.get_radix(&settings), 16);

        def.set_choice(&mut settings, DECIMAL);
        assert_eq!(def.get_radix(&settings), 10);

        def.set_choice(&mut settings, BINARY);
        assert_eq!(def.get_radix(&settings), 2);

        def.set_choice(&mut settings, OCTAL);
        assert_eq!(def.get_radix(&settings), 8);

        def.set_choice(&mut settings, CHAR);
        assert_eq!(def.get_radix(&settings), 0);
    }

    #[test]
    fn get_representation_postfix_matches_format() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert_eq!(def.get_representation_postfix(&settings), "h");

        def.set_choice(&mut settings, DECIMAL);
        assert_eq!(def.get_representation_postfix(&settings), "");

        def.set_choice(&mut settings, OCTAL);
        assert_eq!(def.get_representation_postfix(&settings), "o");
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(HEX, &settings), "hex");
        assert_eq!(def.get_display_choice(DECIMAL, &settings), "decimal");
        assert_eq!(def.get_display_choice(CHAR, &settings), "char");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["hex", "decimal", "binary", "octal", "char"]
        );
    }

    #[test]
    fn get_current_display_choice_matches_stored_choice() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert_eq!(def.get_current_display_choice(&settings), "hex");

        def.set_choice(&mut settings, BINARY);
        assert_eq!(def.get_current_display_choice(&settings), "binary");
    }

    #[test]
    fn set_display_choice_by_name() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_display_choice(&mut settings, "octal");
        assert_eq!(def.get_format(Some(&settings)), OCTAL);

        // Unknown choice strings are ignored, leaving the setting unchanged.
        def.set_display_choice(&mut settings, "not-a-choice");
        assert_eq!(def.get_format(Some(&settings)), OCTAL);
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, BINARY);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("hex".to_string()));

        def.set_choice(&mut settings, DECIMAL);
        assert_eq!(def.get_value_string(&settings), Some("decimal".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_choice(&mut settings, CHAR);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_format(Some(&settings)), HEX);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_choice(&mut src, BINARY);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_format(Some(&dest)), BINARY);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = FormatSettingsDefinition::DEF;

        def.set_choice(&mut dest, OCTAL);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = FormatSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Format");
        assert_eq!(def.get_storage_key(), "format");
        assert_eq!(def.get_description(), "Selects the display format");
    }

    #[test]
    fn def_constants_have_expected_default_formats() {
        let settings = MockSettings::new();
        assert_eq!(FormatSettingsDefinition::DEF_HEX.get_format(Some(&settings)), HEX);
        assert_eq!(
            FormatSettingsDefinition::DEF_DECIMAL.get_format(Some(&settings)),
            DECIMAL
        );
        assert_eq!(
            FormatSettingsDefinition::DEF_BINARY.get_format(Some(&settings)),
            BINARY
        );
        assert_eq!(
            FormatSettingsDefinition::DEF_OCTAL.get_format(Some(&settings)),
            OCTAL
        );
        assert_eq!(
            FormatSettingsDefinition::DEF_CHAR.get_format(Some(&settings)),
            CHAR
        );
    }
}
