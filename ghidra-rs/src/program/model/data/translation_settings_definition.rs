use crate::docking::settings::java_enum_settings_definition::JavaEnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use std::fmt;

/// Translation display preference: show original value or translated value.
///
/// This enum is used to control whether string data displays the original
/// or translated version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationEnum {
    /// Show the original (untranslated) string value.
    ShowOriginal,
    /// Show the translated string value.
    ShowTranslated,
}

impl fmt::Display for TranslationEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranslationEnum::ShowOriginal => write!(f, "show original"),
            TranslationEnum::ShowTranslated => write!(f, "show translated"),
        }
    }
}

impl TranslationEnum {
    /// Inverts the translation state.
    pub fn invert(&self) -> Self {
        match self {
            TranslationEnum::ShowOriginal => TranslationEnum::ShowTranslated,
            TranslationEnum::ShowTranslated => TranslationEnum::ShowOriginal,
        }
    }
}

/// SettingsDefinition for translation display, handling the toggle of
/// "show original" vs "show translated".
///
/// Port of `ghidra.program.model.data.TranslationSettingsDefinition`.
///
/// Note: The property map management methods from the Java class
/// (hasTranslatedValue, getTranslatedValue, setTranslatedValue) are not included
/// in this port as they require access to Program.getUsrPropertyManager() which
/// is not available on the Program trait.
pub struct TranslationSettingsDefinition {
    def: JavaEnumSettingsDefinition<TranslationEnum>,
}

impl TranslationSettingsDefinition {
    /// Property map name for storing translated string values.
    pub const TRANSLATION_PROPERTY_MAP_NAME: &'static str = "StringTranslations";

    /// The setting name that stores the boolean toggle state.
    const SHOW_TRANSLATED_TOGGLE_SETTING_NAME: &'static str = "translated";

    /// Creates a new TranslationSettingsDefinition.
    pub fn new() -> Self {
        let def = JavaEnumSettingsDefinition::new(
            Self::SHOW_TRANSLATED_TOGGLE_SETTING_NAME,
            "Translation",
            "Selects the display of translated strings",
            vec![TranslationEnum::ShowOriginal, TranslationEnum::ShowTranslated],
            TranslationEnum::ShowOriginal,
        );
        TranslationSettingsDefinition { def }
    }

    /// Determine if translated strings should be shown.
    pub fn is_show_translated(&self, settings: &dyn Settings) -> bool {
        self.def.get_enum_value(settings) == TranslationEnum::ShowTranslated
    }

    /// Set whether to show translated strings or original strings.
    pub fn set_show_translated(&self, settings: &mut dyn Settings, should_show_translated_value: bool) {
        let enum_value = if should_show_translated_value {
            TranslationEnum::ShowTranslated
        } else {
            TranslationEnum::ShowOriginal
        };
        self.def.set_enum_value(settings, enum_value);
    }

    /// Get the underlying enum value from settings.
    pub fn get_enum_value(&self, settings: &dyn Settings) -> TranslationEnum {
        self.def.get_enum_value(settings)
    }

    /// Set the underlying enum value in settings.
    pub fn set_enum_value(&self, settings: &mut dyn Settings, value: TranslationEnum) {
        self.def.set_enum_value(settings, value);
    }
}

impl Default for TranslationSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
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

        fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
            self.longs
                .borrow()
                .get(name)
                .copied()
                .map(|v| Box::new(v) as Box<dyn Any>)
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
    fn translation_enum_display_format() {
        assert_eq!(TranslationEnum::ShowOriginal.to_string(), "show original");
        assert_eq!(TranslationEnum::ShowTranslated.to_string(), "show translated");
    }

    #[test]
    fn translation_enum_invert() {
        assert_eq!(
            TranslationEnum::ShowOriginal.invert(),
            TranslationEnum::ShowTranslated
        );
        assert_eq!(
            TranslationEnum::ShowTranslated.invert(),
            TranslationEnum::ShowOriginal
        );
    }

    #[test]
    fn is_show_translated_returns_false_when_unset() {
        let def = TranslationSettingsDefinition::new();
        let settings = MockSettings::new();
        assert!(!def.is_show_translated(&settings));
    }

    #[test]
    fn is_show_translated_returns_true_when_set() {
        let def = TranslationSettingsDefinition::new();
        let mut settings = MockSettings::new();
        def.set_show_translated(&mut settings, true);
        assert!(def.is_show_translated(&settings));
    }

    #[test]
    fn set_show_translated_toggles_setting() {
        let def = TranslationSettingsDefinition::new();
        let mut settings = MockSettings::new();

        def.set_show_translated(&mut settings, true);
        assert!(def.is_show_translated(&settings));

        def.set_show_translated(&mut settings, false);
        assert!(!def.is_show_translated(&settings));
    }

    #[test]
    fn is_show_translated_defaults_to_false() {
        let def = TranslationSettingsDefinition::new();
        let settings = MockSettings::new();
        assert_eq!(def.get_enum_value(&settings), TranslationEnum::ShowOriginal);
        assert!(!def.is_show_translated(&settings));
    }

    #[test]
    fn translation_enum_equality() {
        assert_eq!(TranslationEnum::ShowOriginal, TranslationEnum::ShowOriginal);
        assert_eq!(TranslationEnum::ShowTranslated, TranslationEnum::ShowTranslated);
        assert_ne!(TranslationEnum::ShowOriginal, TranslationEnum::ShowTranslated);
    }

    #[test]
    fn translation_settings_definition_default() {
        let def = TranslationSettingsDefinition::default();
        let settings = MockSettings::new();
        assert!(!def.is_show_translated(&settings));
    }

    #[test]
    fn get_and_set_enum_value() {
        let def = TranslationSettingsDefinition::new();
        let mut settings = MockSettings::new();

        assert_eq!(def.get_enum_value(&settings), TranslationEnum::ShowOriginal);

        def.set_enum_value(&mut settings, TranslationEnum::ShowTranslated);
        assert_eq!(def.get_enum_value(&settings), TranslationEnum::ShowTranslated);

        def.set_enum_value(&mut settings, TranslationEnum::ShowOriginal);
        assert_eq!(def.get_enum_value(&settings), TranslationEnum::ShowOriginal);
    }
}
