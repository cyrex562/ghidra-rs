use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Mnemonic style corresponding to the use of `DataType::get_name()`.
pub const DEFAULT: i32 = 0;
/// Mnemonic style using the processor's assembly mnemonic.
pub const ASSEMBLY: i32 = 1;
/// Mnemonic style using the C-spec mnemonic.
pub const CSPEC: i32 = 2;

// NOTE: if these strings change, the XML needs to changed also...
const CHOICES: &[&str] = &["default", "assembly", "C"];

const MNEMONIC: &str = "mnemonic";

/// The settings definition for the numeric display format.
///
/// Port of `ghidra.program.model.data.DataTypeMnemonicSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataTypeMnemonicSettingsDefinition;

impl DataTypeMnemonicSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: DataTypeMnemonicSettingsDefinition = DataTypeMnemonicSettingsDefinition;

    /// Returns the format based on the specified settings.
    ///
    /// # Arguments
    /// * `settings` - the instance settings, or `None` for the default value.
    ///
    /// # Returns
    /// The mnemonic style (`DEFAULT`, `ASSEMBLY`, `CSPEC`). `ASSEMBLY` is returned if no
    /// setting has been made. `DEFAULT` corresponds to the use of `DataType::get_name()`.
    pub fn get_mnemonic_style(&self, settings: Option<&dyn Settings>) -> i32 {
        let Some(settings) = settings else {
            return ASSEMBLY;
        };
        let Some(value) = settings.get_long(MNEMONIC) else {
            return ASSEMBLY;
        };
        let style = value as i32;
        if style < 0 || style > CSPEC {
            ASSEMBLY
        } else {
            style
        }
    }
}

impl EnumSettingsDefinition for DataTypeMnemonicSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_mnemonic_style(Some(settings))
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        if value < 0 || value > CSPEC {
            settings.clear_setting(MNEMONIC);
        } else {
            settings.set_long(MNEMONIC, value as i64);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for DataTypeMnemonicSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(MNEMONIC).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        "Mnemonic-style".to_string()
    }

    fn get_storage_key(&self) -> String {
        MNEMONIC.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the data-type mnemonic style".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(MNEMONIC);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(MNEMONIC) {
            Some(value) => dest_settings.set_long(MNEMONIC, value),
            None => dest_settings.clear_setting(MNEMONIC),
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
    fn get_mnemonic_style_returns_assembly_when_settings_is_none() {
        assert_eq!(
            DataTypeMnemonicSettingsDefinition::DEF.get_mnemonic_style(None),
            ASSEMBLY
        );
    }

    #[test]
    fn get_mnemonic_style_returns_assembly_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            DataTypeMnemonicSettingsDefinition::DEF.get_mnemonic_style(Some(&settings)),
            ASSEMBLY
        );
    }

    #[test]
    fn get_mnemonic_style_returns_assembly_for_out_of_range_values() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        settings.set_long(MNEMONIC, -1);
        assert_eq!(def.get_mnemonic_style(Some(&settings)), ASSEMBLY);

        settings.set_long(MNEMONIC, (CSPEC + 1) as i64);
        assert_eq!(def.get_mnemonic_style(Some(&settings)), ASSEMBLY);
    }

    #[test]
    fn set_choice_then_get_mnemonic_style_round_trips() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        def.set_choice(&mut settings, DEFAULT);
        assert_eq!(def.get_mnemonic_style(Some(&settings)), DEFAULT);

        def.set_choice(&mut settings, CSPEC);
        assert_eq!(def.get_mnemonic_style(Some(&settings)), CSPEC);
    }

    #[test]
    fn set_choice_clears_setting_for_out_of_range_value() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        def.set_choice(&mut settings, DEFAULT);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, CSPEC + 1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_choice_reflects_mnemonic_style() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        assert_eq!(def.get_choice(&settings), ASSEMBLY);

        def.set_choice(&mut settings, DEFAULT);
        assert_eq!(def.get_choice(&settings), DEFAULT);
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(DEFAULT, &settings), "default");
        assert_eq!(def.get_display_choice(ASSEMBLY, &settings), "assembly");
        assert_eq!(def.get_display_choice(CSPEC, &settings), "C");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["default", "assembly", "C"]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, ASSEMBLY);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("assembly".to_string()));

        def.set_choice(&mut settings, CSPEC);
        assert_eq!(def.get_value_string(&settings), Some("C".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        def.set_choice(&mut settings, DEFAULT);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_mnemonic_style(Some(&settings)), ASSEMBLY);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        def.set_choice(&mut src, CSPEC);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_mnemonic_style(Some(&dest)), CSPEC);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = DataTypeMnemonicSettingsDefinition::DEF;

        def.set_choice(&mut dest, DEFAULT);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = DataTypeMnemonicSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Mnemonic-style");
        assert_eq!(def.get_storage_key(), "mnemonic");
        assert_eq!(def.get_description(), "Selects the data-type mnemonic style");
    }
}
