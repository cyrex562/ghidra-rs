use crate::docking::settings::settings::Settings;

/// Generic interface for defining display options on data and dataTypes. Uses [`Settings`]
/// objects to store values which are interpreted by `SettingsDefinition` objects.
///
/// Port of `ghidra.docking.settings.SettingsDefinition`.
///
/// This trait was promoted from a minimal placeholder (see `program::seam_stubs`) that already
/// carried `is_same_kind`/`is_type_def_settings_definition`/`has_same_value`. `has_same_value`
/// maps directly onto this interface's abstract `hasSameValue` method. `is_same_kind` and
/// `is_type_def_settings_definition` have no counterpart on this interface (they stand in for
/// `getClass().equals(other.getClass())` and `instanceof TypeDefSettingsDefinition` checks, since
/// Rust trait objects cannot be downcast to another trait object without extra machinery); they
/// are retained here as a superset so existing callers keep compiling.
///
/// Every method (including ones abstract in the Java interface) is given a default so that
/// existing mock/test implementations which relied on the placeholder's blanket defaults are
/// unaffected by this promotion. Concrete implementations (`FormatSettingsDefinition`,
/// `BooleanSettingsDefinition`, etc.) will override these with real behavior once they are ported.
///
pub trait SettingsDefinition {
    /// Determine if a setting value has been stored.
    fn has_value(&self, settings: &dyn Settings) -> bool {
        let _ = settings;
        false
    }

    /// Get the setting value as a string which corresponds to this definition. A default value
    /// string will be returned if a setting has not been stored.
    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        let _ = settings;
        None
    }

    /// Returns the display name of this settings definition.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Get the [`Settings`] key which is used when storing a key/value entry.
    fn get_storage_key(&self) -> String {
        String::new()
    }

    /// Returns a description of this settings definition.
    fn get_description(&self) -> String {
        String::new()
    }

    /// Removes any values in the given settings object associated with this settings definition.
    fn clear(&self, settings: &dyn Settings) {
        let _ = settings;
    }

    /// Copies any setting value associated with this settings definition from `src_settings` to
    /// `dest_settings`.
    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &dyn Settings) {
        let _ = (src_settings, dest_settings);
    }

    /// Check two settings for equality which correspond to this settings definition.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        let _ = (settings1, settings2);
        false
    }

    /// Stands in for `getClass().equals(other.getClass())`, used by
    /// [`TypeDef::has_same_type_def_settings`](crate::program::model::data::typedef::TypeDef::has_same_type_def_settings)
    /// to confirm two settings-definition arrays declare definitions of the same kind in the
    /// same order. Not part of the original Java interface.
    fn is_same_kind(&self, other: &dyn SettingsDefinition) -> bool {
        let _ = other;
        false
    }

    /// Stands in for `instanceof TypeDefSettingsDefinition`. Not part of the original Java
    /// interface.
    fn is_type_def_settings_definition(&self) -> bool {
        false
    }
}

/// Port of `SettingsDefinition.concat(SettingsDefinition[], SettingsDefinition...)`.
///
/// Create a new list of settings definitions by concat'ing a base list with an additional list of
/// setting defs.
pub fn concat(
    settings: Vec<Box<dyn SettingsDefinition>>,
    additional: Vec<Box<dyn SettingsDefinition>>,
) -> Vec<Box<dyn SettingsDefinition>> {
    let mut combined = settings;
    combined.extend(additional);
    combined
}

/// Port of `SettingsDefinition.filterSettingsDefinitions(SettingsDefinition[], Predicate)`.
///
/// Get datatype settings definitions for the specified datatype exclusive of any
/// default-use-only definitions.
pub fn filter_settings_definitions(
    definitions: Vec<Box<dyn SettingsDefinition>>,
    filter: impl Fn(&dyn SettingsDefinition) -> bool,
) -> Vec<Box<dyn SettingsDefinition>> {
    definitions
        .into_iter()
        .filter(|def| filter(def.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockSettingsDefinition {
        name: String,
        value: Option<String>,
    }

    impl SettingsDefinition for MockSettingsDefinition {
        fn has_value(&self, _settings: &dyn Settings) -> bool {
            self.value.is_some()
        }

        fn get_value_string(&self, _settings: &dyn Settings) -> Option<String> {
            self.value.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_storage_key(&self) -> String {
            self.name.clone()
        }

        fn get_description(&self) -> String {
            format!("{} setting", self.name)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let def = MockSettingsDefinition {
            name: "format".to_string(),
            value: Some("hex".to_string()),
        };
        let settings = MockSettings;
        let dyn_def: &dyn SettingsDefinition = &def;

        assert!(dyn_def.has_value(&settings));
        assert_eq!(dyn_def.get_value_string(&settings), Some("hex".to_string()));
        assert_eq!(dyn_def.get_name(), "format");
        assert_eq!(dyn_def.get_storage_key(), "format");
        assert_eq!(dyn_def.get_description(), "format setting");
        assert!(!dyn_def.has_same_value(&settings, &settings));
    }

    #[test]
    fn empty_impl_uses_defaults() {
        struct Empty;
        impl SettingsDefinition for Empty {}

        let def = Empty;
        let settings = MockSettings;
        assert!(!def.has_value(&settings));
        assert_eq!(def.get_value_string(&settings), None);
        assert_eq!(def.get_name(), "");
        assert!(!def.is_type_def_settings_definition());
    }

    #[test]
    fn concat_joins_base_and_additional() {
        let base: Vec<Box<dyn SettingsDefinition>> = vec![Box::new(MockSettingsDefinition {
            name: "a".to_string(),
            value: None,
        })];
        let additional: Vec<Box<dyn SettingsDefinition>> = vec![Box::new(MockSettingsDefinition {
            name: "b".to_string(),
            value: None,
        })];

        let combined = concat(base, additional);
        assert_eq!(combined.len(), 2);
        assert_eq!(combined[1].get_name(), "b");
    }

    #[test]
    fn filter_settings_definitions_keeps_matching() {
        let defs: Vec<Box<dyn SettingsDefinition>> = vec![
            Box::new(MockSettingsDefinition {
                name: "a".to_string(),
                value: None,
            }),
            Box::new(MockSettingsDefinition {
                name: "b".to_string(),
                value: None,
            }),
        ];

        let filtered = filter_settings_definitions(defs, |def| def.get_name() == "b");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].get_name(), "b");
    }
}
