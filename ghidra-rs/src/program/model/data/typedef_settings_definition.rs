use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::settings::Settings;

/// Port of `ghidra.program.model.data.TypeDefSettingsDefinition`.
///
/// Specifies a [`SettingsDefinition`] whose use as a `TypeDef` setting will be available for use
/// within a non-Program DataType archive. Such settings will be considered for DataType
/// equivalence checks and preserved during DataType cloning and resolve processing. As such,
/// these settings are only currently supported as a default-setting on a `TypeDef` and do not
/// support component-specific or data-instance use.
pub trait TypeDefSettingsDefinition: SettingsDefinition {
    /// Get the `TypeDef` attribute specification for this setting and its current value.
    fn get_attribute_specification(&self, settings: &dyn Settings) -> Option<String>;
}

/// Port of `TypeDefSettingsDefinition.concat(TypeDefSettingsDefinition[], TypeDefSettingsDefinition...)`.
///
/// Concatenates a base list of settings defs with an additional list of settings defs.
pub fn concat(
    settings: Vec<Box<dyn TypeDefSettingsDefinition>>,
    additional: Vec<Box<dyn TypeDefSettingsDefinition>>,
) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
    let mut combined = settings;
    combined.extend(additional);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockTypeDefSettingsDefinition {
        spec: Option<String>,
    }

    impl SettingsDefinition for MockTypeDefSettingsDefinition {}

    impl TypeDefSettingsDefinition for MockTypeDefSettingsDefinition {
        fn get_attribute_specification(&self, _settings: &dyn Settings) -> Option<String> {
            self.spec.clone()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let def = MockTypeDefSettingsDefinition {
            spec: Some("pack(1)".to_string()),
        };
        let dyn_def: &dyn TypeDefSettingsDefinition = &def;
        let settings = MockSettings;
        assert_eq!(
            dyn_def.get_attribute_specification(&settings),
            Some("pack(1)".to_string())
        );
    }

    #[test]
    fn concat_joins_base_and_additional() {
        let base: Vec<Box<dyn TypeDefSettingsDefinition>> =
            vec![Box::new(MockTypeDefSettingsDefinition { spec: None })];
        let additional: Vec<Box<dyn TypeDefSettingsDefinition>> = vec![Box::new(
            MockTypeDefSettingsDefinition {
                spec: Some("extra".to_string()),
            },
        )];

        let combined = concat(base, additional);
        assert_eq!(combined.len(), 2);
        let settings = MockSettings;
        assert_eq!(combined[1].get_attribute_specification(&settings), Some("extra".to_string()));
    }
}
