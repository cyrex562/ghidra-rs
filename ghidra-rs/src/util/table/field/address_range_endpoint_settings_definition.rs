use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const ADDRESS_RANGE_ENDPOINT: &str = "Address Range Endpoint";
const ENDPOINT: &str = "Endpoint";

/// Display string for the "begin" choice.
pub const BEGIN: &str = "Begin";
/// Display string for the "end" choice.
pub const END: &str = "End";
const CHOICES: &[&str] = &[BEGIN, END];

/// Index of the "begin" choice within [`CHOICES`].
pub const BEGIN_CHOICE_INDEX: i32 = 0;
/// Index of the "end" choice within [`CHOICES`].
pub const END_CHOICE_INDEX: i32 = 1;
const DEFAULT: i32 = 0;

/// Settings definition for selecting whether to use the min address or the max address of an
/// address range for address range table columns.
///
/// Port of `ghidra.util.table.field.AddressRangeEndpointSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AddressRangeEndpointSettingsDefinition;

impl AddressRangeEndpointSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: AddressRangeEndpointSettingsDefinition = AddressRangeEndpointSettingsDefinition;
}

impl EnumSettingsDefinition for AddressRangeEndpointSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        match settings.get_long(ADDRESS_RANGE_ENDPOINT) {
            Some(value) if value >= 0 && (value as usize) < CHOICES.len() => value as i32,
            _ => DEFAULT,
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        if value < DEFAULT {
            settings.clear_setting(ADDRESS_RANGE_ENDPOINT);
        } else {
            let value = if value > CHOICES.len() as i32 {
                CHOICES.len() as i32
            } else {
                value
            };
            settings.set_long(ADDRESS_RANGE_ENDPOINT, value as i64);
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for AddressRangeEndpointSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(ADDRESS_RANGE_ENDPOINT).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        ENDPOINT.to_string()
    }

    fn get_storage_key(&self) -> String {
        ADDRESS_RANGE_ENDPOINT.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the base address".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(ADDRESS_RANGE_ENDPOINT);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(ADDRESS_RANGE_ENDPOINT) {
            Some(value) => dest_settings.set_long(ADDRESS_RANGE_ENDPOINT, value),
            None => dest_settings.clear_setting(ADDRESS_RANGE_ENDPOINT),
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
    fn default_choice_when_unset() {
        let settings = MockSettings::new();
        assert_eq!(
            AddressRangeEndpointSettingsDefinition::DEF.get_choice(&settings),
            BEGIN_CHOICE_INDEX
        );
    }

    #[test]
    fn default_choice_when_out_of_range() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        settings.set_long(ADDRESS_RANGE_ENDPOINT, -1);
        assert_eq!(def.get_choice(&settings), DEFAULT);

        settings.set_long(ADDRESS_RANGE_ENDPOINT, CHOICES.len() as i64);
        assert_eq!(def.get_choice(&settings), DEFAULT);
    }

    #[test]
    fn set_choice_then_get_choice_round_trips() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut settings, END_CHOICE_INDEX);
        assert_eq!(def.get_choice(&settings), END_CHOICE_INDEX);
    }

    #[test]
    fn set_choice_clears_setting_when_negative() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut settings, END_CHOICE_INDEX);
        assert!(def.has_value(&settings));

        def.set_choice(&mut settings, -1);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn set_choice_clamps_above_choices_length() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut settings, 100);
        assert_eq!(settings.get_long(ADDRESS_RANGE_ENDPOINT), Some(CHOICES.len() as i64));
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some(BEGIN.to_string()));

        def.set_choice(&mut settings, END_CHOICE_INDEX);
        assert_eq!(def.get_value_string(&settings), Some(END.to_string()));
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(BEGIN_CHOICE_INDEX, &settings), BEGIN);
        assert_eq!(def.get_display_choice(END_CHOICE_INDEX, &settings), END);
        assert_eq!(
            def.get_display_choices(&settings),
            vec![BEGIN.to_string(), END.to_string()]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, END_CHOICE_INDEX);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut settings, END_CHOICE_INDEX);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_choice(&settings), DEFAULT);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut src, END_CHOICE_INDEX);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_choice(&dest), END_CHOICE_INDEX);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = AddressRangeEndpointSettingsDefinition::DEF;

        def.set_choice(&mut dest, END_CHOICE_INDEX);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = AddressRangeEndpointSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Endpoint");
        assert_eq!(def.get_storage_key(), "Address Range Endpoint");
        assert_eq!(def.get_description(), "Selects the base address");
    }
}
