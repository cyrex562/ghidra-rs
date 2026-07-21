//! Port of `ghidra.framework.plugintool.PluginInstaller`.
//!
//! An interface that facilitates the adding and removing of plugins. Selected as a
//! dependency-cycle cut-point, so it is ported here as an object-safe trait rather than as a
//! concrete implementation tied to `PluginTool`.

use crate::framework::plugintool::util::PluginException;
use crate::framework::seam_stubs::PluginLike;

/// Facilitates the adding and removing of plugins.
///
/// Mirrors `ghidra.framework.plugintool.PluginInstaller`. Object-safe, so implementations can be
/// stored as `Box<dyn PluginInstaller>`/`Arc<dyn PluginInstaller>`.
pub trait PluginInstaller {
    /// Returns all currently installed plugins, mirroring `getManagedPlugins()`.
    fn managed_plugins(&self) -> Vec<Box<dyn PluginLike>>;

    /// Adds the given plugins to the system, mirroring `addPlugins(List<String>)`.
    ///
    /// `plugin_class_names` -- the plugin class names to add.
    ///
    /// Returns an error if there is an issue loading any of the plugins.
    fn add_plugins(&mut self, plugin_class_names: &[String]) -> Result<(), PluginException>;

    /// Removes the given plugins from the system, mirroring `removePlugins(List<Plugin>)`.
    fn remove_plugins(&mut self, plugins: &[Box<dyn PluginLike>]);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPlugin {
        class_name: String,
    }

    impl PluginLike for MockPlugin {}

    #[derive(Default)]
    struct MockPluginInstaller {
        installed: Vec<String>,
    }

    impl PluginInstaller for MockPluginInstaller {
        fn managed_plugins(&self) -> Vec<Box<dyn PluginLike>> {
            self.installed
                .iter()
                .cloned()
                .map(|class_name| Box::new(MockPlugin { class_name }) as Box<dyn PluginLike>)
                .collect()
        }

        fn add_plugins(&mut self, plugin_class_names: &[String]) -> Result<(), PluginException> {
            for name in plugin_class_names {
                if name.is_empty() {
                    return Err(PluginException::new(name, "empty class name"));
                }
                self.installed.push(name.clone());
            }
            Ok(())
        }

        fn remove_plugins(&mut self, plugins: &[Box<dyn PluginLike>]) {
            let _ = plugins.len();
            self.installed.clear();
        }
    }

    #[test]
    fn add_and_remove_plugins_through_trait_object() {
        let mut installer: Box<dyn PluginInstaller> = Box::new(MockPluginInstaller::default());

        installer
            .add_plugins(&["com.example.FooPlugin".to_string(), "com.example.BarPlugin".to_string()])
            .expect("add_plugins should succeed for non-empty class names");

        let managed = installer.managed_plugins();
        assert_eq!(managed.len(), 2);

        installer.remove_plugins(&managed);
        assert!(installer.managed_plugins().is_empty());
    }

    #[test]
    fn add_plugins_rejects_empty_class_name() {
        let mut installer = MockPluginInstaller::default();
        let result = installer.add_plugins(&[String::new()]);
        assert!(result.is_err());
    }
}
