use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::util::signedness_format_mode::SignednessFormatMode;

// NOTE: if these strings change, the XML needs to be changed also...
const CHOICES: &[&str] = &["Default", "Unsigned", "Signed"];

const SIGN_FORMAT: &str = "signedness-mode";

/// The settings definition for the numeric display format for handling signed values.
///
/// Port of `ghidra.docking.settings.IntegerSignednessFormattingModeSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerSignednessFormattingModeSettingsDefinition {
    default_format: SignednessFormatMode,
}

impl IntegerSignednessFormattingModeSettingsDefinition {
    const fn new(default_format: SignednessFormatMode) -> Self {
        IntegerSignednessFormattingModeSettingsDefinition { default_format }
    }

    /// The default definition (default format is [`SignednessFormatMode::Default`]).
    pub const DEF: IntegerSignednessFormattingModeSettingsDefinition =
        Self::new(SignednessFormatMode::Default);
    /// Definition with a default format of [`SignednessFormatMode::Signed`].
    pub const DEF_SIGNED: IntegerSignednessFormattingModeSettingsDefinition =
        Self::new(SignednessFormatMode::Signed);
    /// Definition with a default format of [`SignednessFormatMode::Unsigned`].
    pub const DEF_UNSIGNED: IntegerSignednessFormattingModeSettingsDefinition =
        Self::new(SignednessFormatMode::Unsigned);

    /// Returns the format based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings or `None` for the default value.
    pub fn get_format_mode(&self, settings: Option<&dyn Settings>) -> SignednessFormatMode {
        let Some(settings) = settings else {
            return self.default_format;
        };
        let Some(value) = settings.get_long(SIGN_FORMAT) else {
            return self.default_format;
        };
        if value < 0 || value >= CHOICES.len() as i64 {
            return self.default_format;
        }

        SignednessFormatMode::parse(value as i32).unwrap_or(SignednessFormatMode::Default)
    }

    /// Sets, or clears if `mode` is `None`, the new mode in the provided settings.
    ///
    /// # Arguments
    /// * `settings` - settings object.
    /// * `mode` - new value to assign, or `None` to clear.
    pub fn set_format_mode(
        &self,
        settings: &mut dyn Settings,
        mode: Option<SignednessFormatMode>,
    ) {
        match mode {
            None => settings.clear_setting(SIGN_FORMAT),
            Some(mode) => settings.set_long(SIGN_FORMAT, mode.ordinal() as i64),
        }
    }

    /// Returns the display string for the choice currently stored in the given settings.
    pub fn get_current_display_choice(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }

    /// Sets the settings object to the enum value indicating the specified choice as a string.
    ///
    /// # Arguments
    /// * `settings` - the settings to store the value.
    /// * `choice` - enum string representing a choice in the enum.
    pub fn set_display_choice(&self, settings: &mut dyn Settings, choice: &str) {
        if let Some(index) = CHOICES.iter().position(|c| *c == choice) {
            self.set_choice(settings, index as i32);
        }
    }
}

impl EnumSettingsDefinition for IntegerSignednessFormattingModeSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_format_mode(Some(settings)).ordinal()
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        match SignednessFormatMode::parse(value) {
            Some(mode) => settings.set_long(SIGN_FORMAT, mode.ordinal() as i64),
            None => settings.clear_setting(SIGN_FORMAT),
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for IntegerSignednessFormattingModeSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(SIGN_FORMAT).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Signedness Mode".to_string()
    }

    fn get_storage_key(&self) -> String {
        SIGN_FORMAT.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the display mode for signed values".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(SIGN_FORMAT);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(SIGN_FORMAT) {
            Some(value) => dest_settings.set_long(SIGN_FORMAT, value),
            None => dest_settings.clear_setting(SIGN_FORMAT),
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
    fn get_format_mode_returns_default_when_settings_is_none() {
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF_SIGNED.get_format_mode(None),
            SignednessFormatMode::Signed
        );
    }

    #[test]
    fn get_format_mode_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF
                .get_format_mode(Some(&settings)),
            SignednessFormatMode::Default
        );
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF_UNSIGNED
                .get_format_mode(Some(&settings)),
            SignednessFormatMode::Unsigned
        );
    }

    #[test]
    fn get_format_mode_returns_default_when_stored_value_is_invalid() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF_SIGNED;

        settings.set_long(SIGN_FORMAT, -1);
        assert_eq!(def.get_format_mode(Some(&settings)), SignednessFormatMode::Signed);

        settings.set_long(SIGN_FORMAT, CHOICES.len() as i64);
        assert_eq!(def.get_format_mode(Some(&settings)), SignednessFormatMode::Signed);
    }

    #[test]
    fn set_format_mode_then_get_format_mode_round_trips() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_format_mode(&mut settings, Some(SignednessFormatMode::Unsigned));
        assert_eq!(def.get_format_mode(Some(&settings)), SignednessFormatMode::Unsigned);
    }

    #[test]
    fn set_format_mode_none_clears_setting() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_format_mode(&mut settings, Some(SignednessFormatMode::Signed));
        assert!(def.has_value(&settings));

        def.set_format_mode(&mut settings, None);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn set_choice_then_get_choice_round_trips() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_choice(&mut settings, SignednessFormatMode::Signed.ordinal());
        assert_eq!(def.get_choice(&settings), SignednessFormatMode::Signed.ordinal());
    }

    #[test]
    fn set_choice_with_invalid_value_clears_setting() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_choice(&mut settings, SignednessFormatMode::Unsigned.ordinal());
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "Default");
        assert_eq!(def.get_display_choice(1, &settings), "Unsigned");
        assert_eq!(def.get_display_choice(2, &settings), "Signed");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["Default", "Unsigned", "Signed"]
        );
    }

    #[test]
    fn get_current_display_choice_matches_stored_choice() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        assert_eq!(def.get_current_display_choice(&settings), "Default");

        def.set_choice(&mut settings, SignednessFormatMode::Signed.ordinal());
        assert_eq!(def.get_current_display_choice(&settings), "Signed");
    }

    #[test]
    fn set_display_choice_by_name() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_display_choice(&mut settings, "Unsigned");
        assert_eq!(
            def.get_format_mode(Some(&settings)),
            SignednessFormatMode::Unsigned
        );

        // Unknown choice strings are ignored, leaving the setting unchanged.
        def.set_display_choice(&mut settings, "not-a-choice");
        assert_eq!(
            def.get_format_mode(Some(&settings)),
            SignednessFormatMode::Unsigned
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, SignednessFormatMode::Signed.ordinal());
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("Default".to_string()));

        def.set_choice(&mut settings, SignednessFormatMode::Unsigned.ordinal());
        assert_eq!(def.get_value_string(&settings), Some("Unsigned".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_choice(&mut settings, SignednessFormatMode::Signed.ordinal());
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_format_mode(Some(&settings)), SignednessFormatMode::Default);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_choice(&mut src, SignednessFormatMode::Unsigned.ordinal());
        def.copy_setting(&src, &mut dest);

        assert_eq!(
            def.get_format_mode(Some(&dest)),
            SignednessFormatMode::Unsigned
        );
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;

        def.set_choice(&mut dest, SignednessFormatMode::Signed.ordinal());
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = IntegerSignednessFormattingModeSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Signedness Mode");
        assert_eq!(def.get_storage_key(), "signedness-mode");
        assert_eq!(
            def.get_description(),
            "Selects the display mode for signed values"
        );
    }

    #[test]
    fn def_constants_have_expected_default_formats() {
        let settings = MockSettings::new();
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF
                .get_format_mode(Some(&settings)),
            SignednessFormatMode::Default
        );
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF_SIGNED
                .get_format_mode(Some(&settings)),
            SignednessFormatMode::Signed
        );
        assert_eq!(
            IntegerSignednessFormattingModeSettingsDefinition::DEF_UNSIGNED
                .get_format_mode(Some(&settings)),
            SignednessFormatMode::Unsigned
        );
    }
}
