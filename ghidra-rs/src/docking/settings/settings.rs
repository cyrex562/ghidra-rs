use std::any::Any;

use crate::docking::seam_stubs::StringSettingsDefinition;
use crate::docking::settings::settings_definition::SettingsDefinition;

/// Settings objects store name-value pairs. Each `SettingsDefinition` defines one or more names
/// to use to store values in settings objects. Exactly what type of value and how to interpret
/// the value is done by the `SettingsDefinition` object.
///
/// Port of `ghidra.docking.settings.Settings`.
///
/// This trait was promoted from a minimal placeholder (see `program::seam_stubs`) that had no
/// methods. Every method (including ones abstract in the Java interface) is given a default so
/// that existing mock/test implementations which relied on the placeholder's blanket defaults are
/// unaffected by this promotion. Concrete implementations (`SettingsImpl`, `SettingsBuilder`,
/// etc.) will override these with real behavior once they are ported.
pub trait Settings {
    /// True if settings may not be modified.
    fn is_immutable_settings(&self) -> bool {
        false
    }

    /// Determine if a settings change corresponding to the specified settings definition is
    /// permitted.
    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        let _ = settings_definition;
        true
    }

    /// Get an array of suggested values for the specified string settings definition.
    fn get_suggested_values(
        &self,
        settings_definition: &dyn StringSettingsDefinition,
    ) -> Vec<String> {
        let _ = settings_definition;
        Vec::new()
    }

    /// Gets the Long value associated with the given name.
    fn get_long(&self, name: &str) -> Option<i64> {
        let _ = name;
        None
    }

    /// Gets the String value associated with the given name.
    fn get_string(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Gets the object associated with the given name.
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        let _ = name;
        None
    }

    /// Associates the given long value with the name.
    ///
    /// Note that an attempted setting change may be ignored if prohibited (e.g., immutable
    /// Settings, undefined setting name).
    fn set_long(&mut self, name: &str, value: i64) {
        let _ = (name, value);
    }

    /// Associates the given String value with the name.
    ///
    /// Note that an attempted setting change may be ignored if prohibited (e.g., immutable
    /// Settings, undefined setting name).
    fn set_string(&mut self, name: &str, value: &str) {
        let _ = (name, value);
    }

    /// Associates the given object with the name.
    ///
    /// Note that an attempted setting change may be ignored if prohibited (e.g., immutable
    /// Settings, undefined setting name).
    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        let _ = (name, value);
    }

    /// Removes any value associated with the given name.
    fn clear_setting(&mut self, name: &str) {
        let _ = name;
    }

    /// Removes all name-value pairs from this settings object.
    fn clear_all_settings(&mut self) {}

    /// Get this list of keys that currently have values associated with them.
    fn get_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns true if there are no key-value pairs stored in this settings object.
    ///
    /// This is not a reflection of the underlying default settings which may still contain a
    /// key-value pair when this settings object is empty.
    fn is_empty(&self) -> bool {
        true
    }

    /// Returns the underlying default settings for these settings or `None` if there are none.
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct RecordingSettings {
        long_value: Option<i64>,
        string_value: Option<String>,
    }

    impl Settings for RecordingSettings {
        fn get_long(&self, _name: &str) -> Option<i64> {
            self.long_value
        }

        fn get_string(&self, _name: &str) -> Option<String> {
            self.string_value.clone()
        }

        fn set_long(&mut self, _name: &str, value: i64) {
            self.long_value = Some(value);
        }

        fn set_string(&mut self, _name: &str, value: &str) {
            self.string_value = Some(value.to_string());
        }

        fn is_empty(&self) -> bool {
            self.long_value.is_none() && self.string_value.is_none()
        }
    }

    #[test]
    fn empty_impl_uses_defaults() {
        let settings = MockSettings;
        let dyn_settings: &dyn Settings = &settings;

        assert!(!dyn_settings.is_immutable_settings());
        assert_eq!(dyn_settings.get_long("x"), None);
        assert_eq!(dyn_settings.get_string("x"), None);
        assert!(dyn_settings.get_value("x").is_none());
        assert!(dyn_settings.get_names().is_empty());
        assert!(dyn_settings.is_empty());
        assert!(dyn_settings.get_default_settings().is_none());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut settings = RecordingSettings {
            long_value: None,
            string_value: None,
        };
        assert!(settings.is_empty());

        let dyn_settings: &mut dyn Settings = &mut settings;
        dyn_settings.set_long("count", 42);
        dyn_settings.set_string("label", "hex");

        assert_eq!(dyn_settings.get_long("count"), Some(42));
        assert_eq!(dyn_settings.get_string("label"), Some("hex".to_string()));
        assert!(!dyn_settings.is_empty());
    }
}
