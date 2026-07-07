use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::lang::Endian;

const CHOICES: &[&str] = &["default", "little", "big"];
const ENDIAN_SETTING_NAME: &str = "endian";

/// Choice value meaning the endianness has not been overridden.
pub const DEFAULT: i32 = 0;
/// Choice value for little-endian.
pub const LITTLE: i32 = 1;
/// Choice value for big-endian.
pub const BIG: i32 = 2;

/// SettingsDefinition for endianness.
///
/// Port of `ghidra.program.model.data.EndianSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndianSettingsDefinition;

impl EndianSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: EndianSettingsDefinition = EndianSettingsDefinition;
    /// Alias for [`Self::DEF`].
    pub const ENDIAN: EndianSettingsDefinition = EndianSettingsDefinition;

    fn get_choice_internal(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return DEFAULT;
        };
        let Some(value) = settings.get_long(ENDIAN_SETTING_NAME) else {
            return DEFAULT;
        };
        let val = value as i32;
        if val < DEFAULT || val > BIG {
            DEFAULT
        } else {
            val
        }
    }

    /// Returns the endianness settings. First looks in settings, then defaultSettings and
    /// finally returns a default value if the first two have no value for this definition.
    ///
    /// # Arguments
    /// * `settings` - the instance settings to search for the value, or `None`
    /// * `buf` - the data context
    ///
    /// # Returns
    /// A boolean value for the endianness setting.
    pub fn is_big_endian(&self, settings: Option<&dyn Settings>, buf: &dyn MemBuffer) -> bool {
        let val = self.get_choice_internal(settings);
        if val == DEFAULT {
            return buf.is_big_endian();
        }
        val == BIG
    }

    /// Returns the [`Endian`] value indicated by the settings, or `default_value` if unset.
    pub fn get_endianness(&self, settings: Option<&dyn Settings>, default_value: Endian) -> Endian {
        match self.get_choice_internal(settings) {
            BIG => Endian::Big,
            LITTLE => Endian::Little,
            _ => default_value,
        }
    }

    /// Sets the endianness setting to big or little endian.
    pub fn set_big_endian(&self, settings: &mut dyn Settings, is_big_endian: bool) {
        self.set_choice(settings, if is_big_endian { BIG } else { LITTLE });
    }
}

impl EnumSettingsDefinition for EndianSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_choice_internal(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        settings.set_long(ENDIAN_SETTING_NAME, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for EndianSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(ENDIAN_SETTING_NAME).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Endian".to_string()
    }

    fn get_storage_key(&self) -> String {
        ENDIAN_SETTING_NAME.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the endianness of the data".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(ENDIAN_SETTING_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(ENDIAN_SETTING_NAME) {
            Some(value) => dest_settings.set_long(ENDIAN_SETTING_NAME, value),
            None => dest_settings.clear_setting(ENDIAN_SETTING_NAME),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::mem::MemoryAccessException;
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

    struct MockMemBuffer {
        big_endian: bool,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            Address::default()
        }

        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }

        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            0
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    #[test]
    fn is_big_endian_falls_back_to_buffer_when_settings_is_none() {
        let def = EndianSettingsDefinition::DEF;
        let buf = MockMemBuffer { big_endian: true };
        assert!(def.is_big_endian(None, &buf));

        let buf = MockMemBuffer { big_endian: false };
        assert!(!def.is_big_endian(None, &buf));
    }

    #[test]
    fn is_big_endian_falls_back_to_buffer_when_unset() {
        let def = EndianSettingsDefinition::DEF;
        let settings = MockSettings::new();
        let buf = MockMemBuffer { big_endian: true };
        assert!(def.is_big_endian(Some(&settings), &buf));
    }

    #[test]
    fn is_big_endian_reflects_explicit_choice() {
        let def = EndianSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        let buf = MockMemBuffer { big_endian: false };

        def.set_big_endian(&mut settings, true);
        assert!(def.is_big_endian(Some(&settings), &buf));

        def.set_big_endian(&mut settings, false);
        assert!(!def.is_big_endian(Some(&settings), &buf));
    }

    #[test]
    fn is_big_endian_falls_back_to_buffer_for_out_of_range_value() {
        let def = EndianSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        let buf = MockMemBuffer { big_endian: true };

        settings.set_long(ENDIAN_SETTING_NAME, -1);
        assert!(def.is_big_endian(Some(&settings), &buf));

        settings.set_long(ENDIAN_SETTING_NAME, (BIG + 1) as i64);
        assert!(def.is_big_endian(Some(&settings), &buf));
    }

    #[test]
    fn get_endianness_returns_default_when_unset() {
        let def = EndianSettingsDefinition::DEF;
        let settings = MockSettings::new();
        assert_eq!(
            def.get_endianness(Some(&settings), Endian::Little),
            Endian::Little
        );
        assert_eq!(def.get_endianness(None, Endian::Big), Endian::Big);
    }

    #[test]
    fn get_endianness_reflects_explicit_choice() {
        let def = EndianSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        def.set_big_endian(&mut settings, true);
        assert_eq!(
            def.get_endianness(Some(&settings), Endian::Little),
            Endian::Big
        );

        def.set_big_endian(&mut settings, false);
        assert_eq!(
            def.get_endianness(Some(&settings), Endian::Big),
            Endian::Little
        );
    }

    #[test]
    fn get_choice_reflects_set_choice() {
        let def = EndianSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        assert_eq!(def.get_choice(&settings), DEFAULT);

        def.set_choice(&mut settings, LITTLE);
        assert_eq!(def.get_choice(&settings), LITTLE);

        def.set_choice(&mut settings, BIG);
        assert_eq!(def.get_choice(&settings), BIG);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(DEFAULT, &settings), "default");
        assert_eq!(def.get_display_choice(LITTLE, &settings), "little");
        assert_eq!(def.get_display_choice(BIG, &settings), "big");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["default", "little", "big"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, BIG);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("default".to_string()));

        def.set_choice(&mut settings, LITTLE);
        assert_eq!(def.get_value_string(&settings), Some("little".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        def.set_choice(&mut settings, BIG);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        def.set_choice(&mut src, BIG);
        def.copy_setting(&src, &mut dest);

        assert_eq!(dest.get_long(ENDIAN_SETTING_NAME), Some(BIG as i64));
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = EndianSettingsDefinition::DEF;

        def.set_choice(&mut dest, LITTLE);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = EndianSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Endian");
        assert_eq!(def.get_storage_key(), "endian");
        assert_eq!(def.get_description(), "Selects the endianness of the data");
    }

    #[test]
    fn def_and_endian_are_equivalent() {
        assert_eq!(EndianSettingsDefinition::DEF, EndianSettingsDefinition::ENDIAN);
    }
}
