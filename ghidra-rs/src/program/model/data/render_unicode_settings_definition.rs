use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderEnum {
    All,
    ByteSeq,
    EscSeq,
}

impl fmt::Display for RenderEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderEnum::All => write!(f, "all"),
            RenderEnum::ByteSeq => write!(f, "byte sequence"),
            RenderEnum::EscSeq => write!(f, "escape sequence"),
        }
    }
}

const CHOICES: &[&str] = &["all", "byte sequence", "escape sequence"];
const RENDER_UNICODE: &str = "renderUnicode";

/// Settings definition for controlling the display of UNICODE characters.
///
/// Port of `ghidra.program.model.data.RenderUnicodeSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderUnicodeSettingsDefinition;

impl RenderUnicodeSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: RenderUnicodeSettingsDefinition = RenderUnicodeSettingsDefinition;

    /// Gets the current rendering setting from the given settings object or returns
    /// the default if not set.
    pub fn get_enum_value(&self, settings: &dyn Settings) -> RenderEnum {
        let Some(value) = settings.get_long(RENDER_UNICODE) else {
            return RenderEnum::All;
        };
        match value {
            0 => RenderEnum::All,
            1 => RenderEnum::ByteSeq,
            2 => RenderEnum::EscSeq,
            _ => RenderEnum::All,
        }
    }

    /// Sets the rendering mode in the given settings object.
    pub fn set_enum_value(&self, settings: &mut dyn Settings, value: RenderEnum) {
        let ordinal = match value {
            RenderEnum::All => 0,
            RenderEnum::ByteSeq => 1,
            RenderEnum::EscSeq => 2,
        };
        self.set_choice(settings, ordinal);
    }

    /// Determines if alphanumeric-only rendering is enabled.
    ///
    /// Returns `true` if the current rendering setting is `ByteSeq`, which indicates
    /// that only alphanumeric characters should be rendered.
    ///
    /// # Arguments
    /// * `settings` - the instance settings
    ///
    /// # Returns
    /// `true` if only alphanumeric characters should be rendered
    pub fn is_render_alphanumeric_only(&self, settings: &dyn Settings) -> bool {
        self.get_enum_value(settings) == RenderEnum::ByteSeq
    }

    /// Determines if escape sequence rendering is enabled.
    ///
    /// Returns `true` if the current rendering setting is `EscSeq`.
    pub fn is_render_escape_seq(&self, settings: &dyn Settings) -> bool {
        self.get_enum_value(settings) == RenderEnum::EscSeq
    }
}

impl EnumSettingsDefinition for RenderUnicodeSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        let Some(value) = settings.get_long(RENDER_UNICODE) else {
            return 0;
        };
        let choice = value as i32;
        if choice < 0 || choice >= CHOICES.len() as i32 {
            0
        } else {
            choice
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        settings.set_long(RENDER_UNICODE, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for RenderUnicodeSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(RENDER_UNICODE).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Render non-ASCII Unicode".to_string()
    }

    fn get_storage_key(&self) -> String {
        RENDER_UNICODE.to_string()
    }

    fn get_description(&self) -> String {
        "Selects if the unicode string should render all characters or only alphanumeric characters".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(RENDER_UNICODE);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(RENDER_UNICODE) {
            Some(value) => dest_settings.set_long(RENDER_UNICODE, value),
            None => dest_settings.clear_setting(RENDER_UNICODE),
        }
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
    fn get_enum_value_returns_default_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(RenderUnicodeSettingsDefinition::DEF.get_enum_value(&settings), RenderEnum::All);
    }

    #[test]
    fn set_enum_value_then_get_enum_value_round_trips() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert_eq!(def.get_enum_value(&settings), RenderEnum::ByteSeq);

        def.set_enum_value(&mut settings, RenderEnum::EscSeq);
        assert_eq!(def.get_enum_value(&settings), RenderEnum::EscSeq);

        def.set_enum_value(&mut settings, RenderEnum::All);
        assert_eq!(def.get_enum_value(&settings), RenderEnum::All);
    }

    #[test]
    fn is_render_alphanumeric_only_returns_true_for_byte_seq() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert!(def.is_render_alphanumeric_only(&settings));

        def.set_enum_value(&mut settings, RenderEnum::All);
        assert!(!def.is_render_alphanumeric_only(&settings));

        def.set_enum_value(&mut settings, RenderEnum::EscSeq);
        assert!(!def.is_render_alphanumeric_only(&settings));
    }

    #[test]
    fn is_render_escape_seq_returns_true_for_esc_seq() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut settings, RenderEnum::EscSeq);
        assert!(def.is_render_escape_seq(&settings));

        def.set_enum_value(&mut settings, RenderEnum::All);
        assert!(!def.is_render_escape_seq(&settings));

        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert!(!def.is_render_escape_seq(&settings));
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_enum_value() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("all".to_string()));

        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert_eq!(
            def.get_value_string(&settings),
            Some("byte sequence".to_string())
        );

        def.set_enum_value(&mut settings, RenderEnum::EscSeq);
        assert_eq!(
            def.get_value_string(&settings),
            Some("escape sequence".to_string())
        );
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut settings, RenderEnum::ByteSeq);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_enum_value(&settings), RenderEnum::All);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut src, RenderEnum::EscSeq);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_enum_value(&dest), RenderEnum::EscSeq);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = RenderUnicodeSettingsDefinition::DEF;

        def.set_enum_value(&mut dest, RenderEnum::ByteSeq);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = RenderUnicodeSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Render non-ASCII Unicode");
        assert_eq!(def.get_storage_key(), "renderUnicode");
        assert_eq!(
            def.get_description(),
            "Selects if the unicode string should render all characters or only alphanumeric characters"
        );
    }

    #[test]
    fn render_enum_display_matches_java_values() {
        assert_eq!(RenderEnum::All.to_string(), "all");
        assert_eq!(RenderEnum::ByteSeq.to_string(), "byte sequence");
        assert_eq!(RenderEnum::EscSeq.to_string(), "escape sequence");
    }
}
