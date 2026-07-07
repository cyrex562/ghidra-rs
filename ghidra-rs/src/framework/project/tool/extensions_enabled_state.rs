use std::collections::{HashMap, HashSet};

use crate::util::ClassFileInfo;

/// Describes extensions' enable state for a given tool.
pub trait ExtensionsEnabledState {
    /// Returns a map of all known extensions to a set of their plugins.
    fn get_all_known_extensions(&self) -> HashMap<String, HashSet<ClassFileInfo>>;

    /// Removes all plugins installed in the current tool from the given set.
    ///
    /// This allows the client to have a set of plugins that are not currently installed.
    fn remove_installed_plugins(&self, all_plugins: &mut HashSet<ClassFileInfo>);

    /// Shows a window to prompt the user to configure any new extension plugins.
    fn prompt_to_configure_new_plugins(&self, new_plugins: &HashSet<ClassFileInfo>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestExtensionsEnabledState {
        extensions: HashMap<String, HashSet<ClassFileInfo>>,
        installed: HashSet<ClassFileInfo>,
    }

    impl TestExtensionsEnabledState {
        fn new() -> Self {
            Self {
                extensions: HashMap::new(),
                installed: HashSet::new(),
            }
        }

        fn with_extension(mut self, name: String, plugins: HashSet<ClassFileInfo>) -> Self {
            self.extensions.insert(name, plugins);
            self
        }

        fn with_installed(mut self, plugin: ClassFileInfo) -> Self {
            self.installed.insert(plugin);
            self
        }
    }

    impl ExtensionsEnabledState for TestExtensionsEnabledState {
        fn get_all_known_extensions(&self) -> HashMap<String, HashSet<ClassFileInfo>> {
            self.extensions.clone()
        }

        fn remove_installed_plugins(&self, all_plugins: &mut HashSet<ClassFileInfo>) {
            for plugin in &self.installed {
                all_plugins.remove(plugin);
            }
        }

        fn prompt_to_configure_new_plugins(&self, _new_plugins: &HashSet<ClassFileInfo>) {
            // Test implementation - does nothing
        }
    }

    #[test]
    fn get_all_known_extensions_empty() {
        let state = TestExtensionsEnabledState::new();
        assert!(state.get_all_known_extensions().is_empty());
    }

    #[test]
    fn get_all_known_extensions_with_data() {
        let info1 = ClassFileInfo::new("com.example.Plugin1".to_string(), "example/Plugin1.class".to_string(), String::new(), String::new());
        let info2 = ClassFileInfo::new("com.example.Plugin2".to_string(), "example/Plugin2.class".to_string(), String::new(), String::new());

        let mut plugins = HashSet::new();
        plugins.insert(info1.clone());
        plugins.insert(info2.clone());

        let state = TestExtensionsEnabledState::new().with_extension("ext1".to_string(), plugins);

        let result = state.get_all_known_extensions();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("ext1"));
        assert_eq!(result["ext1"].len(), 2);
    }

    #[test]
    fn remove_installed_plugins_removes_matching_plugins() {
        let info1 = ClassFileInfo::new("com.example.Plugin1".to_string(), "example/Plugin1.class".to_string(), String::new(), String::new());
        let info2 = ClassFileInfo::new("com.example.Plugin2".to_string(), "example/Plugin2.class".to_string(), String::new(), String::new());

        let state = TestExtensionsEnabledState::new().with_installed(info1.clone());

        let mut all = HashSet::new();
        all.insert(info1);
        all.insert(info2.clone());

        state.remove_installed_plugins(&mut all);
        assert_eq!(all.len(), 1);
        assert!(all.contains(&info2));
    }

    #[test]
    fn remove_installed_plugins_empty_installed_set() {
        let info1 = ClassFileInfo::new("com.example.Plugin1".to_string(), "example/Plugin1.class".to_string(), String::new(), String::new());
        let info2 = ClassFileInfo::new("com.example.Plugin2".to_string(), "example/Plugin2.class".to_string(), String::new(), String::new());

        let state = TestExtensionsEnabledState::new();

        let mut all = HashSet::new();
        all.insert(info1);
        all.insert(info2);

        state.remove_installed_plugins(&mut all);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn remove_installed_plugins_empty_all_plugins_set() {
        let info = ClassFileInfo::new("com.example.Plugin1".to_string(), "example/Plugin1.class".to_string(), String::new(), String::new());

        let state = TestExtensionsEnabledState::new().with_installed(info);

        let mut all = HashSet::new();
        state.remove_installed_plugins(&mut all);
        assert!(all.is_empty());
    }

    #[test]
    fn remove_installed_plugins_removes_all_matching() {
        let info1 = ClassFileInfo::new("com.example.Plugin1".to_string(), "example/Plugin1.class".to_string(), String::new(), String::new());
        let info2 = ClassFileInfo::new("com.example.Plugin2".to_string(), "example/Plugin2.class".to_string(), String::new(), String::new());
        let info3 = ClassFileInfo::new("com.example.Plugin3".to_string(), "example/Plugin3.class".to_string(), String::new(), String::new());

        let state = TestExtensionsEnabledState::new()
            .with_installed(info1.clone())
            .with_installed(info2.clone());

        let mut all = HashSet::new();
        all.insert(info1);
        all.insert(info2);
        all.insert(info3);

        state.remove_installed_plugins(&mut all);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn prompt_to_configure_new_plugins_does_not_error() {
        let state = TestExtensionsEnabledState::new();
        let plugins = HashSet::new();
        state.prompt_to_configure_new_plugins(&plugins);
        // Test passes if no panic occurs
    }
}
