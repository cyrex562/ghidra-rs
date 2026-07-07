use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// A [`SettingsDefinition`] implementation that uses a plain Rust enum-like value set.
///
/// Port of `ghidra.docking.settings.JavaEnumSettingsDefinition`.
///
/// The original Java implementation derives its full value set reflectively via
/// `defaultValue.getDeclaringClass().getEnumConstants()`. Rust has no equivalent reflection, so
/// callers pass the full ordered list of values explicitly; each value's position within that
/// list plays the role of the Java enum's ordinal.
#[derive(Debug, Clone)]
pub struct JavaEnumSettingsDefinition<T> {
    name: String,
    setting_name: String,
    description: String,
    values: Vec<T>,
    value_names: Vec<String>,
    default_value: T,
}

impl<T> JavaEnumSettingsDefinition<T>
where
    T: Copy + PartialEq + ToString,
{
    /// Creates a new `JavaEnumSettingsDefinition`.
    ///
    /// # Arguments
    /// * `setting_name` - specifies how this setting is stored
    /// * `name` - descriptive name of this setting
    /// * `description` - longer description
    /// * `values` - every possible value, ordered the same way as their ordinal
    /// * `default_value` - value returned when this setting has not been specified yet
    pub fn new(
        setting_name: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        values: Vec<T>,
        default_value: T,
    ) -> Self {
        let value_names = values.iter().map(|value| value.to_string()).collect();
        JavaEnumSettingsDefinition {
            name: name.into(),
            setting_name: setting_name.into(),
            description: description.into(),
            values,
            value_names,
            default_value,
        }
    }

    /// Returns the value that is returned when this settings definition has not been specified
    /// yet.
    pub fn get_default_enum(&self) -> T {
        self.default_value
    }

    /// Returns the value corresponding to the setting stored, or the [default value
    /// ](Self::get_default_enum) if the setting has not been assigned yet.
    ///
    /// # Arguments
    /// * `settings` - object that stores the settings values
    pub fn get_enum_value(&self, settings: &dyn Settings) -> T {
        self.get_enum_value_or(settings, self.default_value)
    }

    /// Returns the value corresponding to the setting stored, or `default_value_override` if the
    /// setting has not been assigned yet.
    ///
    /// # Arguments
    /// * `settings` - object that stores the settings values
    /// * `default_value_override` - custom default returned when unset or out of range
    pub fn get_enum_value_or(&self, settings: &dyn Settings, default_value_override: T) -> T {
        let Some(lvalue) = settings.get_long(&self.setting_name) else {
            return default_value_override;
        };
        if lvalue < 0 || lvalue as usize >= self.values.len() {
            return default_value_override;
        }
        self.values[lvalue as usize]
    }

    /// Sets the value of this settings definition using the ordinal of `enum_value`.
    ///
    /// # Arguments
    /// * `settings` - where settings values are stored
    /// * `enum_value` - value to store; must be one of the configured values
    pub fn set_enum_value(&self, settings: &mut dyn Settings, enum_value: T) {
        let ordinal = self.ordinal_of(enum_value);
        self.set_choice(settings, ordinal);
    }

    /// Returns the value that corresponds to the specified ordinal.
    pub fn get_enum_by_ordinal(&self, ordinal: usize) -> T {
        self.values[ordinal]
    }

    /// Returns the ordinal of the value whose string representation is `string_value`, or `-1`
    /// if no configured value matches.
    pub fn get_ordinal_by_string(&self, string_value: &str) -> i32 {
        self.value_names
            .iter()
            .position(|name| name == string_value)
            .map_or(-1, |index| index as i32)
    }

    fn ordinal_of(&self, value: T) -> i32 {
        self.values
            .iter()
            .position(|candidate| *candidate == value)
            .expect("enum_value must be one of the configured values") as i32
    }
}

impl<T> EnumSettingsDefinition for JavaEnumSettingsDefinition<T>
where
    T: Copy + PartialEq + ToString,
{
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        let value = settings
            .get_long(&self.setting_name)
            .map(|lvalue| lvalue as i32)
            .unwrap_or_else(|| self.ordinal_of(self.default_value));
        value.clamp(0, self.values.len() as i32 - 1)
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        settings.set_long(&self.setting_name, value as i64);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        self.values[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        self.value_names.clone()
    }
}

impl<T> SettingsDefinition for JavaEnumSettingsDefinition<T>
where
    T: Copy + PartialEq + ToString,
{
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(&self.setting_name).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(self.values[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_storage_key(&self) -> String {
        self.setting_name.clone()
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(&self.setting_name);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(&self.setting_name) {
            Some(value) => self.set_choice(dest_settings, value as i32),
            None => self.clear(dest_settings),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fmt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Color {
        Red,
        Green,
        Blue,
    }

    impl fmt::Display for Color {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name = match self {
                Color::Red => "RED",
                Color::Green => "GREEN",
                Color::Blue => "BLUE",
            };
            write!(f, "{name}")
        }
    }

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
                .map(|value| Box::new(value) as Box<dyn Any>)
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

    fn color_def() -> JavaEnumSettingsDefinition<Color> {
        JavaEnumSettingsDefinition::new(
            "color-setting",
            "Color",
            "Selects a color",
            vec![Color::Red, Color::Green, Color::Blue],
            Color::Red,
        )
    }

    #[test]
    fn get_default_enum_returns_configured_default() {
        let def = color_def();
        assert_eq!(def.get_default_enum(), Color::Red);
    }

    #[test]
    fn get_enum_value_returns_default_when_unset() {
        let def = color_def();
        let settings = MockSettings::new();
        assert_eq!(def.get_enum_value(&settings), Color::Red);
    }

    #[test]
    fn get_enum_value_or_returns_override_when_unset() {
        let def = color_def();
        let settings = MockSettings::new();
        assert_eq!(def.get_enum_value_or(&settings, Color::Blue), Color::Blue);
    }

    #[test]
    fn set_enum_value_then_get_enum_value_round_trips() {
        let def = color_def();
        let mut settings = MockSettings::new();

        def.set_enum_value(&mut settings, Color::Green);

        assert_eq!(def.get_enum_value(&settings), Color::Green);
    }

    #[test]
    fn get_enum_value_returns_default_when_stored_value_out_of_range() {
        let def = color_def();
        let mut settings = MockSettings::new();

        settings.set_long("color-setting", -1);
        assert_eq!(def.get_enum_value(&settings), Color::Red);

        settings.set_long("color-setting", 3);
        assert_eq!(def.get_enum_value(&settings), Color::Red);
    }

    #[test]
    fn get_enum_by_ordinal_returns_matching_value() {
        let def = color_def();
        assert_eq!(def.get_enum_by_ordinal(0), Color::Red);
        assert_eq!(def.get_enum_by_ordinal(1), Color::Green);
        assert_eq!(def.get_enum_by_ordinal(2), Color::Blue);
    }

    #[test]
    fn get_ordinal_by_string_finds_matching_and_missing_values() {
        let def = color_def();
        assert_eq!(def.get_ordinal_by_string("GREEN"), 1);
        assert_eq!(def.get_ordinal_by_string("not-a-color"), -1);
    }

    #[test]
    fn has_value_reflects_storage() {
        let def = color_def();
        let mut settings = MockSettings::new();

        assert!(!def.has_value(&settings));
        def.set_enum_value(&mut settings, Color::Blue);
        assert!(def.has_value(&settings));
    }

    #[test]
    fn name_storage_key_and_description_match_constructor_args() {
        let def = color_def();
        assert_eq!(def.get_name(), "Color");
        assert_eq!(def.get_storage_key(), "color-setting");
        assert_eq!(def.get_description(), "Selects a color");
    }

    #[test]
    fn clear_removes_stored_value() {
        let def = color_def();
        let mut settings = MockSettings::new();

        def.set_enum_value(&mut settings, Color::Blue);
        assert!(def.has_value(&settings));

        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_enum_value(&settings), Color::Red);
    }

    #[test]
    fn copy_setting_copies_stored_value() {
        let def = color_def();
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();

        def.set_enum_value(&mut src, Color::Green);
        def.copy_setting(&src, &mut dest);

        assert_eq!(def.get_enum_value(&dest), Color::Green);
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let def = color_def();
        let src = MockSettings::new();
        let mut dest = MockSettings::new();

        def.set_enum_value(&mut dest, Color::Blue);
        def.copy_setting(&src, &mut dest);

        assert!(!def.has_value(&dest));
    }

    #[test]
    fn get_choice_clamps_out_of_range_stored_values() {
        let def = color_def();
        let mut settings = MockSettings::new();

        settings.set_long("color-setting", -5);
        assert_eq!(def.get_choice(&settings), 0);

        settings.set_long("color-setting", 5);
        assert_eq!(def.get_choice(&settings), 2);
    }

    #[test]
    fn get_choice_defaults_to_default_value_ordinal_when_unset() {
        let def = JavaEnumSettingsDefinition::new(
            "color-setting",
            "Color",
            "Selects a color",
            vec![Color::Red, Color::Green, Color::Blue],
            Color::Green,
        );
        let settings = MockSettings::new();
        assert_eq!(def.get_choice(&settings), 1);
    }

    #[test]
    fn get_value_string_matches_stored_choice() {
        let def = color_def();
        let mut settings = MockSettings::new();

        assert_eq!(def.get_value_string(&settings), Some("RED".to_string()));

        def.set_enum_value(&mut settings, Color::Blue);
        assert_eq!(def.get_value_string(&settings), Some("BLUE".to_string()));
    }

    #[test]
    fn get_display_choice_and_choices() {
        let def = color_def();
        let settings = MockSettings::new();

        assert_eq!(def.get_display_choice(0, &settings), "RED");
        assert_eq!(def.get_display_choice(1, &settings), "GREEN");
        assert_eq!(def.get_display_choice(2, &settings), "BLUE");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["RED".to_string(), "GREEN".to_string(), "BLUE".to_string()]
        );
    }
}
