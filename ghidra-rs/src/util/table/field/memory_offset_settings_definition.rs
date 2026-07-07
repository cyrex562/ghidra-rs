use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const MEMORY_OFFSET: &str = "Memory offset";
const CHOICES: &[&str] = &[
    "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1", "0", "+1", "+2", "+3", "+4", "+5", "+6", "+7",
    "+8",
];

/// The default offset (no offset).
pub const DEFAULT_OFFSET: i32 = 0;
/// The smallest offset that may be selected.
pub const MIN_OFFSET: i32 = -8;
/// The largest offset that may be selected.
pub const MAX_OFFSET: i32 = 8;

/// Index into [`CHOICES`] corresponding to [`DEFAULT_OFFSET`].
pub const DEFAULT_CHOICE: i32 = 8;

/// Settings definition for the relative byte offset from which to display memory.
///
/// Port of `ghidra.util.table.field.MemoryOffsetSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryOffsetSettingsDefinition;

impl MemoryOffsetSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: MemoryOffsetSettingsDefinition = MemoryOffsetSettingsDefinition;

    /// Returns the offset to display, based on the current choice.
    pub fn get_offset(&self, settings: &dyn Settings) -> i32 {
        self.get_choice(settings) - DEFAULT_CHOICE
    }

    /// Sets the offset to display, clamped to `[MIN_OFFSET, MAX_OFFSET]`.
    pub fn set_offset(&self, settings: &mut dyn Settings, offset: i32) {
        let offset = offset.clamp(MIN_OFFSET, MAX_OFFSET);
        settings.set_long(MEMORY_OFFSET, (offset + DEFAULT_CHOICE) as i64);
    }

    /// Returns the display string for the current choice.
    pub fn get_display_value(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }
}

impl EnumSettingsDefinition for MemoryOffsetSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        match settings.get_long(MEMORY_OFFSET) {
            Some(value) if value >= 0 && (value as usize) < CHOICES.len() => value as i32,
            _ => DEFAULT_CHOICE,
        }
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        let value = value.clamp(0, CHOICES.len() as i32 - 1);
        settings.set_long(MEMORY_OFFSET, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|choice| choice.to_string()).collect()
    }
}

impl SettingsDefinition for MemoryOffsetSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(MEMORY_OFFSET).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        MEMORY_OFFSET.to_string()
    }

    fn get_storage_key(&self) -> String {
        MEMORY_OFFSET.to_string()
    }

    fn get_description(&self) -> String {
        "Selects the relative byte offset from which to display".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(MEMORY_OFFSET);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(MEMORY_OFFSET) {
            Some(value) => dest_settings.set_long(MEMORY_OFFSET, value),
            None => dest_settings.clear_setting(MEMORY_OFFSET),
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
            MemoryOffsetSettingsDefinition::DEF.get_choice(&settings),
            DEFAULT_CHOICE
        );
    }

    #[test]
    fn default_choice_when_out_of_range() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        settings.set_long(MEMORY_OFFSET, -1);
        assert_eq!(def.get_choice(&settings), DEFAULT_CHOICE);

        settings.set_long(MEMORY_OFFSET, CHOICES.len() as i64);
        assert_eq!(def.get_choice(&settings), DEFAULT_CHOICE);
    }

    #[test]
    fn set_choice_then_get_choice_round_trips() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_choice(&mut settings, 4);
        assert_eq!(def.get_choice(&settings), 4);
    }

    #[test]
    fn set_choice_clamps_to_valid_range() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_choice(&mut settings, 100);
        assert_eq!(def.get_choice(&settings), CHOICES.len() as i32 - 1);

        def.set_choice(&mut settings, -5);
        assert_eq!(def.get_choice(&settings), 0);
    }

    #[test]
    fn get_offset_is_choice_minus_default() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_offset(&settings), DEFAULT_OFFSET);

        def.set_choice(&mut settings, 0);
        assert_eq!(def.get_offset(&settings), MIN_OFFSET);

        def.set_choice(&mut settings, CHOICES.len() as i32 - 1);
        assert_eq!(def.get_offset(&settings), MAX_OFFSET);
    }

    #[test]
    fn set_offset_then_get_offset_round_trips() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_offset(&mut settings, 3);
        assert_eq!(def.get_offset(&settings), 3);

        def.set_offset(&mut settings, -3);
        assert_eq!(def.get_offset(&settings), -3);
    }

    #[test]
    fn set_offset_clamps_to_min_and_max() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_offset(&mut settings, 100);
        assert_eq!(def.get_offset(&settings), MAX_OFFSET);

        def.set_offset(&mut settings, -100);
        assert_eq!(def.get_offset(&settings), MIN_OFFSET);
    }

    #[test]
    fn get_value_string_matches_choice() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_value_string(&settings), Some("0".to_string()));

        def.set_offset(&mut settings, 2);
        assert_eq!(def.get_value_string(&settings), Some("+2".to_string()));
    }

    #[test]
    fn get_display_value_matches_choice() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_display_value(&settings), "0");

        def.set_offset(&mut settings, -1);
        assert_eq!(def.get_display_value(&settings), "-1");
    }

    #[test]
    fn get_display_choice_and_choices() {
        let settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        assert_eq!(def.get_display_choice(0, &settings), "-8");
        assert_eq!(def.get_display_choice(8, &settings), "0");
        assert_eq!(def.get_display_choice(16, &settings), "+8");
        assert_eq!(
            def.get_display_choices(&settings),
            vec![
                "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1", "0", "+1", "+2", "+3", "+4", "+5",
                "+6", "+7", "+8"
            ]
        );
    }

    #[test]
    fn has_value_reflects_storage() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        assert!(!def.has_value(&settings));
        def.set_choice(&mut settings, 2);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn clear_removes_stored_value() {
        let mut settings = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_offset(&mut settings, 6);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_choice(&settings), DEFAULT_CHOICE);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_offset(&mut src, 7);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_offset(&dest), 7);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        let def = MemoryOffsetSettingsDefinition::DEF;

        def.set_offset(&mut dest, 3);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description_match_java_source() {
        let def = MemoryOffsetSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Memory offset");
        assert_eq!(def.get_storage_key(), "Memory offset");
        assert_eq!(
            def.get_description(),
            "Selects the relative byte offset from which to display"
        );
    }
}
