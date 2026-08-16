//! Provides theme default values, such as those loaded from `*.theme.property` files.
//!
//! Mirrors `generic.theme.ApplicationThemeDefaults` from Ghidra.

use crate::generic::seam_stubs::{GThemeValueMap, LafType};

/// Provides theme default values, such as those loaded from `*.theme.property` files.
pub trait ApplicationThemeDefaults: Send + Sync {
    /// Returns the light default theme values.
    fn get_light_values(&self) -> Box<dyn GThemeValueMap>;

    /// Returns the dark default theme values.
    fn get_dark_values(&self) -> Box<dyn GThemeValueMap>;

    /// Returns the default values specific to a given Look and Feel type.
    fn get_look_and_feel_values(&self, laf_type: &dyn LafType) -> Box<dyn GThemeValueMap>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::seam_stubs::*;
    use std::any::Any;

    struct MockGThemeValueMap;

    impl GThemeValueMap for MockGThemeValueMap {
        fn add_color(&self, value: &dyn ColorValue) -> Box<dyn ColorValue> {
            Box::new(MockGThemeValueMap)
        }
        fn add_font(&self, value: &dyn FontValue) -> Box<dyn FontValue> {
            Box::new(MockGThemeValueMap)
        }
        fn add_icon(&self, value: &dyn IconValue) -> Box<dyn IconValue> {
            Box::new(MockGThemeValueMap)
        }
        fn add_property(&self, value: &dyn JavaPropertyValue) -> Box<dyn JavaPropertyValue> {
            Box::new(MockGThemeValueMap)
        }
        fn get_color(&self, _id: &str) -> Box<dyn ColorValue> {
            Box::new(MockGThemeValueMap)
        }
        fn get_font(&self, _id: &str) -> Box<dyn FontValue> {
            Box::new(MockGThemeValueMap)
        }
        fn get_icon(&self, _id: &str) -> Box<dyn IconValue> {
            Box::new(MockGThemeValueMap)
        }
        fn get_property(&self, _id: &str) -> Box<dyn JavaPropertyValue> {
            Box::new(MockGThemeValueMap)
        }
        fn load(&self, _value_map: &dyn GThemeValueMap) {}
        fn get_colors(&self) -> Vec<Box<dyn ColorValue>> {
            Vec::new()
        }
        fn get_fonts(&self) -> Vec<Box<dyn FontValue>> {
            Vec::new()
        }
        fn get_icons(&self) -> Vec<Box<dyn IconValue>> {
            Vec::new()
        }
        fn get_properties(&self) -> Vec<Box<dyn JavaPropertyValue>> {
            Vec::new()
        }
        fn contains_color(&self, _id: &str) -> bool {
            false
        }
        fn contains_font(&self, _id: &str) -> bool {
            false
        }
        fn contains_icon(&self, _id: &str) -> bool {
            false
        }
        fn contains_property(&self, _id: &str) -> bool {
            false
        }
        fn size(&self) -> Box<dyn Any> {
            Box::new(0usize)
        }
        fn clear(&self) {}
        fn is_empty(&self) -> bool {
            true
        }
        fn remove_color(&self, _id: &str) {}
        fn remove_font(&self, _id: &str) {}
        fn remove_icon(&self, _id: &str) {}
        fn remove_property(&self, _id: &str) {}
        fn get_changed_values(&self, _base: &dyn GThemeValueMap) -> Box<dyn GThemeValueMap> {
            Box::new(MockGThemeValueMap)
        }
        fn get_external_icon_files(&self) -> Vec<Box<dyn File>> {
            Vec::new()
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn equals(&self, _obj: &dyn Any) -> bool {
            false
        }
        fn check_for_unresolved_references(&self) {}
        fn get_color_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_font_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_icon_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_property_ids(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_resolved_color(&self, _id: &str) -> Box<dyn Color> {
            Box::new(MockGThemeValueMap)
        }
        fn get_resolved_font(&self, _id: &str) -> Box<dyn Font> {
            Box::new(MockGThemeValueMap)
        }
        fn get_resolved_icon(&self, _id: &str) -> Box<dyn Icon> {
            Box::new(MockGThemeValueMap)
        }
        fn get_resolved_property(&self, _id: &str) -> Box<dyn Any> {
            Box::new(0usize)
        }
    }

    impl ColorValue for MockGThemeValueMap {}
    impl FontValue for MockGThemeValueMap {}
    impl IconValue for MockGThemeValueMap {}
    impl JavaPropertyValue for MockGThemeValueMap {}
    impl File for MockGThemeValueMap {}
    impl Color for MockGThemeValueMap {}
    impl Font for MockGThemeValueMap {}
    impl Icon for MockGThemeValueMap {}

    struct MockLafType;

    impl LafType for MockLafType {
        fn get_display_string(&self) -> String {
            "Mock LAF".to_string()
        }
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn uses_dark_defaults(&self) -> bool {
            false
        }
        fn from_name(&self, _name: &str) -> Box<dyn LafType> {
            Box::new(MockLafType)
        }
        fn is_supported(&self) -> bool {
            true
        }
        fn get_look_and_feel_manager(&self, _theme_manager: &dyn ApplicationThemeManager) -> Box<dyn LookAndFeelManager> {
            Box::new(MockLafType)
        }
        fn get_default_look_and_feel(&self) -> Box<dyn LafType> {
            Box::new(MockLafType)
        }
        fn to_string(&self) -> String {
            "MockLafType".to_string()
        }
    }

    impl ApplicationThemeManager for MockLafType {}
    impl LookAndFeelManager for MockLafType {}

    struct MockApplicationThemeDefaults;

    impl ApplicationThemeDefaults for MockApplicationThemeDefaults {
        fn get_light_values(&self) -> Box<dyn GThemeValueMap> {
            Box::new(MockGThemeValueMap)
        }

        fn get_dark_values(&self) -> Box<dyn GThemeValueMap> {
            Box::new(MockGThemeValueMap)
        }

        fn get_look_and_feel_values(&self, _laf_type: &dyn LafType) -> Box<dyn GThemeValueMap> {
            Box::new(MockGThemeValueMap)
        }
    }

    #[test]
    fn test_mock_application_theme_defaults_returns_light_values() {
        let defaults = MockApplicationThemeDefaults;
        let light_values = defaults.get_light_values();
        assert!(light_values.is_empty());
    }

    #[test]
    fn test_mock_application_theme_defaults_returns_dark_values() {
        let defaults = MockApplicationThemeDefaults;
        let dark_values = defaults.get_dark_values();
        assert!(dark_values.is_empty());
    }

    #[test]
    fn test_mock_application_theme_defaults_returns_laf_values() {
        let defaults = MockApplicationThemeDefaults;
        let laf_type = MockLafType;
        let laf_values = defaults.get_look_and_feel_values(&laf_type);
        assert!(laf_values.is_empty());
    }
}
