use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::java_enum_settings_definition::JavaEnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
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
/// Java extends `JavaEnumSettingsDefinition<TRANSLATION_ENUM>`; the Rust struct wraps one and
/// implements [`SettingsDefinition`]/[`EnumSettingsDefinition`] by delegating to it. The shared
/// `TRANSLATION` instance is [`TranslationSettingsDefinition::translation`].
///
/// Not yet ported: the property map methods (`hasTranslatedValue`, `getTranslatedValue`,
/// `setTranslatedValue`), which read the program's user property map through
/// `Program.getUsrPropertyManager()` -- not available on the Rust `Program` trait.
#[derive(Debug, Clone)]
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

    /// The shared instance, Java's `TranslationSettingsDefinition.TRANSLATION`.
    pub fn translation() -> &'static TranslationSettingsDefinition {
        static TRANSLATION: std::sync::OnceLock<TranslationSettingsDefinition> = std::sync::OnceLock::new();
        TRANSLATION.get_or_init(TranslationSettingsDefinition::new)
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

impl EnumSettingsDefinition for TranslationSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.def.get_choice(settings)
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        self.def.set_choice(settings, value)
    }

    fn get_display_choice(&self, value: i32, settings: &dyn Settings) -> String {
        self.def.get_display_choice(value, settings)
    }

    fn get_display_choices(&self, settings: &dyn Settings) -> Vec<String> {
        self.def.get_display_choices(settings)
    }
}

impl SettingsDefinition for TranslationSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        self.def.has_value(settings)
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        self.def.get_value_string(settings)
    }

    fn get_name(&self) -> String {
        self.def.get_name()
    }

    fn get_storage_key(&self) -> String {
        self.def.get_storage_key()
    }

    fn get_description(&self) -> String {
        self.def.get_description()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        self.def.clear(settings)
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        self.def.copy_setting(src_settings, dest_settings)
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

    #[test]
    fn is_a_settings_definition_with_java_names() {
        let def = TranslationSettingsDefinition::translation();
        let as_def: &dyn SettingsDefinition = def;
        assert_eq!(as_def.get_name(), "Translation");
        assert_eq!(as_def.get_storage_key(), "translated");
        assert_eq!(as_def.get_description(), "Selects the display of translated strings");
        let mut settings = MockSettings::new();
        assert!(!as_def.has_value(&settings));
        assert_eq!(as_def.get_value_string(&settings).as_deref(), Some("show original"));
        def.set_show_translated(&mut settings, true);
        assert_eq!(def.get_choice(&settings), 1);
        assert_eq!(as_def.get_value_string(&settings).as_deref(), Some("show translated"));
        as_def.clear(&mut settings);
        assert!(!def.is_show_translated(&settings));
    }
}
