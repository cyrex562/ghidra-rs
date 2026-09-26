//! Port of `ghidra.framework.plugintool.PluginsConfiguration`.
//!
//! Maintains the collection of plugin classes that are acceptable for a given tool type. Simple
//! applications with only one plugin type can use `DefaultPluginsConfiguration`; more complex
//! tools create custom implementations that filter out plugins not appropriate for that tool
//! type via [`PluginsConfiguration::accepts`]. Selected as a dependency-cycle cut-point, so it is
//! ported here as an object-safe trait rather than an abstract class holding
//! `Map<PluginPackage, List<PluginDescription>>`/`Map<String, PluginDescription>` fields.
//!
//! The Java constructor eagerly populates those two maps by asking `ClassSearcher` to scan the
//! classpath for `Plugin` subclasses accepted by [`accepts`](PluginsConfiguration::accepts) and
//! having a `(PluginTool)` constructor. Rust has no classpath/reflection equivalent -- as with
//! [`PluginUtils`](crate::framework::plugintool::util::PluginUtils), which replaced classpath
//! scanning with an explicit registry, implementations of this trait are expected to build their
//! plugin-description collection however they discover/register plugins, and expose it through
//! the raw accessors [`plugin_description`](PluginsConfiguration::plugin_description),
//! [`plugin_descriptions_in_package`](PluginsConfiguration::plugin_descriptions_in_package),
//! [`all_plugin_descriptions`](PluginsConfiguration::all_plugin_descriptions), and
//! [`plugin_packages`](PluginsConfiguration::plugin_packages). The remaining trait methods mirror
//! the rest of `PluginsConfiguration`'s public API with default bodies derived from those raw
//! accessors, matching the Java implementation.

use std::collections::HashSet;

use crate::framework::plugintool::util::{PluginDescription, PluginStatus};
use crate::framework::seam_stubs::{JdomElement, PluginLike, PluginPackageLike};

/// Mirrors `ghidra.framework.plugintool.PluginsConfiguration`. Object-safe, so implementations
/// can be stored as `Box<dyn PluginsConfiguration>`/`Arc<dyn PluginsConfiguration>`.
pub trait PluginsConfiguration {
    /// Returns true if the given plugin class is one that should be included by this
    /// configuration, mirroring the abstract `accepts(Class<? extends Plugin>)`. `Class<?>` is
    /// represented by its fully-qualified name, matching the convention already used by
    /// [`PluginDescription`].
    fn accepts(&self, plugin_class_name: &str) -> bool;

    /// Returns the plugin description for the given plugin class name, or `None` if there is no
    /// such description, mirroring `getPluginDescription(String)`.
    fn plugin_description(&self, plugin_class_name: &str) -> Option<Box<dyn PluginDescription>>;

    /// Returns every known plugin description belonging to the given package, unfiltered by
    /// status, mirroring the raw `descriptionsByPackage.get(pluginPackage)` lookup used
    /// internally by several public methods.
    fn plugin_descriptions_in_package(
        &self,
        plugin_package: &dyn PluginPackageLike,
    ) -> Vec<Box<dyn PluginDescription>>;

    /// Returns every known plugin description, unfiltered by status, mirroring the raw
    /// `descriptionsByName.values()` lookup used internally by several public methods.
    fn all_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>>;

    /// Returns all known plugin packages in sorted order, mirroring `getPluginPackages()`
    /// (`Collections.sort` over `descriptionsByPackage.keySet()`).
    fn plugin_packages(&self) -> Vec<Box<dyn PluginPackageLike>>;

    /// Gets all plugin descriptions for the given plugin package, excluding unstable and hidden
    /// plugins, mirroring `getPluginDescriptions(PluginPackage)`.
    fn plugin_descriptions(
        &self,
        plugin_package: &dyn PluginPackageLike,
    ) -> Vec<Box<dyn PluginDescription>> {
        self.plugin_descriptions_in_package(plugin_package)
            .into_iter()
            .filter(|pd| pd.status() != PluginStatus::Unstable && pd.status() != PluginStatus::Hidden)
            .collect()
    }

    /// Returns all plugin descriptions with `Unstable` status, mirroring
    /// `getUnstablePluginDescriptions()`.
    fn unstable_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>> {
        self.all_plugin_descriptions()
            .into_iter()
            .filter(|pd| pd.status() == PluginStatus::Unstable)
            .collect()
    }

    /// Returns all non-hidden plugin descriptions, mirroring `getManagedPluginDescriptions()`.
    fn managed_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>> {
        self.all_plugin_descriptions()
            .into_iter()
            .filter(|pd| pd.status() != PluginStatus::Hidden)
            .collect()
    }

    /// Converts an old-style tool XML file's plugin class names by mapping released plugins to
    /// their current package and pulling in every plugin in that package, mirroring
    /// `getPluginNamesByCurrentPackage(List<String>)`.
    fn plugin_names_by_current_package(&self, class_names: &[String]) -> HashSet<String> {
        let mut packages: Vec<Box<dyn PluginPackageLike>> = Vec::new();
        let mut adjusted_class_names: HashSet<String> = HashSet::new();

        for class_name in class_names {
            let Some(pd) = self.plugin_description(class_name) else {
                continue; // plugin no longer in tool
            };

            if pd.status() == PluginStatus::Released {
                let pkg = pd.plugin_package();
                if !packages.iter().any(|p| p.name() == pkg.name()) {
                    packages.push(pkg);
                }
            }
            else {
                adjusted_class_names.insert(class_name.clone());
            }
        }

        for plugin_package in &packages {
            for pd in self.plugin_descriptions_in_package(plugin_package.as_ref()) {
                adjusted_class_names.insert(pd.plugin_class_name());
            }
        }

        adjusted_class_names
    }

    /// Saves the given plugins to XML under `root`, mirroring `savePluginsToXml(Element,
    /// List<Plugin>)`. For each package with at least one plugin present in `plugins`, emits a
    /// `PACKAGE` element listing `Released` plugins that were excluded and non-`Released` plugins
    /// that were explicitly included.
    fn save_plugins_to_xml(&self, root: &mut dyn JdomElement, plugins: &[Box<dyn PluginLike>]) {
        let mut package_map: Vec<(Box<dyn PluginPackageLike>, Vec<String>)> = Vec::new();
        for plugin in plugins {
            let class_name = plugin.plugin_class_name();
            let Some(pd) = self.plugin_description(&class_name) else {
                continue;
            };
            let pkg = pd.plugin_package();
            match package_map.iter_mut().find(|(p, _)| p.name() == pkg.name()) {
                Some((_, classes)) => classes.push(class_name),
                None => package_map.push((pkg, vec![class_name])),
            }
        }

        for (plugin_package, included_classes) in &package_map {
            let mut package_element = root.new_child("PACKAGE");
            package_element.set_attribute("NAME", &plugin_package.name());

            for pd in self.plugin_descriptions_in_package(plugin_package.as_ref()) {
                let class_name = pd.plugin_class_name();
                if pd.status() == PluginStatus::Released {
                    if !included_classes.contains(&class_name) {
                        let mut excluded = package_element.new_child("EXCLUDE");
                        excluded.set_attribute("CLASS", &class_name);
                        package_element.add_content(excluded);
                    }
                }
                else if included_classes.contains(&class_name) {
                    let mut included = package_element.new_child("INCLUDE");
                    included.set_attribute("CLASS", &class_name);
                    package_element.add_content(included);
                }
            }

            root.add_content(package_element);
        }
    }

    /// Restores the set of plugin class names described by `element`, mirroring
    /// `getPluginClassNames(Element)`.
    fn plugin_class_names(&self, element: &dyn JdomElement) -> HashSet<String> {
        let mut class_names = HashSet::new();

        for package_element in element.children("PACKAGE") {
            let Some(package_name) = package_element.attribute_value("NAME") else {
                continue;
            };

            let excluded: HashSet<String> = package_element
                .children("EXCLUDE")
                .iter()
                .filter_map(|e| e.attribute_value("CLASS"))
                .collect();
            let included: HashSet<String> = package_element
                .children("INCLUDE")
                .iter()
                .filter_map(|e| e.attribute_value("CLASS"))
                .collect();

            let Some(plugin_package) =
                self.plugin_packages().into_iter().find(|p| p.name() == package_name)
            else {
                continue;
            };

            for pd in self.plugin_descriptions_in_package(plugin_package.as_ref()) {
                let class_name = pd.plugin_class_name();
                let should_add = if included.contains(&class_name) {
                    true
                }
                else if excluded.contains(&class_name) {
                    false
                }
                else {
                    pd.status() == PluginStatus::Released
                };

                if should_add {
                    class_names.insert(class_name);
                }
            }
        }

        class_names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockPackage {
        name: String,
    }

    impl PluginPackageLike for MockPackage {
        fn name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockDescription {
        class_name: String,
        package_name: String,
        status: PluginStatus,
    }

    impl PluginDescription for MockDescription {
        fn plugin_class_name(&self) -> String {
            self.class_name.clone()
        }

        fn name(&self) -> String {
            self.class_name.rsplit(['.', '$']).next().unwrap_or(&self.class_name).to_string()
        }

        fn short_description(&self) -> String {
            "no description".to_string()
        }

        fn description(&self) -> String {
            "no description".to_string()
        }

        fn category(&self) -> String {
            "NO_CATEGORY".to_string()
        }

        fn status(&self) -> PluginStatus {
            self.status
        }

        fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
            Box::new(MockPackage { name: self.package_name.clone() })
        }

        fn is_slow_installation(&self) -> bool {
            false
        }

        fn services_required(&self) -> Vec<String> {
            Vec::new()
        }

        fn services_provided(&self) -> Vec<String> {
            Vec::new()
        }

        fn events_consumed(&self) -> Vec<String> {
            Vec::new()
        }

        fn events_produced(&self) -> Vec<String> {
            Vec::new()
        }

        fn source_location(&self) -> String {
            String::new()
        }

        fn module_name(&self) -> String {
            String::new()
        }

        fn is_in_extension(&self) -> bool {
            false
        }
    }

    struct MockPlugin {
        class_name: String,
    }

    impl PluginLike for MockPlugin {
        fn plugin_class_name(&self) -> String {
            self.class_name.clone()
        }
    }

    #[derive(Default)]
    struct MockJdomElement {
        tag: String,
        attributes: Vec<(String, String)>,
        children: Vec<Box<dyn JdomElement>>,
    }

    impl JdomElement for MockJdomElement {
        fn new_child(&self, name: &str) -> Box<dyn JdomElement> {
            Box::new(MockJdomElement { tag: name.to_string(), ..Default::default() })
        }

        fn tag_name(&self) -> String {
            self.tag.clone()
        }

        fn set_attribute(&mut self, name: &str, value: &str) {
            self.attributes.push((name.to_string(), value.to_string()));
        }

        fn attribute_value(&self, name: &str) -> Option<String> {
            self.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
        }

        fn add_content(&mut self, child: Box<dyn JdomElement>) {
            self.children.push(child);
        }

        fn children(&self, name: &str) -> Vec<&dyn JdomElement> {
            self.children
                .iter()
                .filter(|c| c.tag_name() == name)
                .map(|c| c.as_ref())
                .collect()
        }
    }

    #[derive(Default)]
    struct MockConfiguration {
        descriptions: Vec<(String, String, PluginStatus)>, // class_name, package_name, status
    }

    impl PluginsConfiguration for MockConfiguration {
        fn accepts(&self, plugin_class_name: &str) -> bool {
            !plugin_class_name.contains("ProgramaticUseOnly")
        }

        fn plugin_description(&self, plugin_class_name: &str) -> Option<Box<dyn PluginDescription>> {
            self.descriptions.iter().find(|(c, _, _)| c == plugin_class_name).map(
                |(class_name, package_name, status)| {
                    Box::new(MockDescription {
                        class_name: class_name.clone(),
                        package_name: package_name.clone(),
                        status: *status,
                    }) as Box<dyn PluginDescription>
                },
            )
        }

        fn plugin_descriptions_in_package(
            &self,
            plugin_package: &dyn PluginPackageLike,
        ) -> Vec<Box<dyn PluginDescription>> {
            self.descriptions
                .iter()
                .filter(|(_, package_name, _)| package_name == &plugin_package.name())
                .map(|(class_name, package_name, status)| {
                    Box::new(MockDescription {
                        class_name: class_name.clone(),
                        package_name: package_name.clone(),
                        status: *status,
                    }) as Box<dyn PluginDescription>
                })
                .collect()
        }

        fn all_plugin_descriptions(&self) -> Vec<Box<dyn PluginDescription>> {
            self.descriptions
                .iter()
                .map(|(class_name, package_name, status)| {
                    Box::new(MockDescription {
                        class_name: class_name.clone(),
                        package_name: package_name.clone(),
                        status: *status,
                    }) as Box<dyn PluginDescription>
                })
                .collect()
        }

        fn plugin_packages(&self) -> Vec<Box<dyn PluginPackageLike>> {
            let mut names: Vec<String> =
                self.descriptions.iter().map(|(_, package_name, _)| package_name.clone()).collect();
            names.sort();
            names.dedup();
            names.into_iter().map(|name| Box::new(MockPackage { name }) as Box<dyn PluginPackageLike>).collect()
        }
    }

    fn fixture() -> MockConfiguration {
        MockConfiguration {
            descriptions: vec![
                ("com.example.FooPlugin".to_string(), "Core".to_string(), PluginStatus::Released),
                ("com.example.BarPlugin".to_string(), "Core".to_string(), PluginStatus::Unstable),
                (
                    "com.example.BazPlugin".to_string(),
                    "Experimental".to_string(),
                    PluginStatus::Hidden,
                ),
            ],
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let config = fixture();
        let boxed: Box<dyn PluginsConfiguration> = Box::new(config);
        assert!(boxed.accepts("com.example.FooPlugin"));
    }

    #[test]
    fn plugin_descriptions_excludes_unstable_and_hidden() {
        let config = fixture();
        let core = MockPackage { name: "Core".to_string() };
        let stable = config.plugin_descriptions(&core);
        assert_eq!(stable.len(), 1);
        assert_eq!(stable[0].plugin_class_name(), "com.example.FooPlugin");
    }

    #[test]
    fn unstable_and_managed_plugin_descriptions_filter_by_status() {
        let config = fixture();
        let unstable = config.unstable_plugin_descriptions();
        assert_eq!(unstable.len(), 1);
        assert_eq!(unstable[0].plugin_class_name(), "com.example.BarPlugin");

        let managed = config.managed_plugin_descriptions();
        assert_eq!(managed.len(), 2);
        assert!(managed.iter().all(|pd| pd.status() != PluginStatus::Hidden));
    }

    #[test]
    fn plugin_names_by_current_package_pulls_in_whole_package_for_released() {
        let config = fixture();
        let names = config.plugin_names_by_current_package(&["com.example.FooPlugin".to_string()]);
        // FooPlugin is Released, so its whole package (Core) is pulled in, including
        // the unstable BarPlugin that was not in the original list.
        assert!(names.contains("com.example.FooPlugin"));
        assert!(names.contains("com.example.BarPlugin"));
    }

    #[test]
    fn plugin_names_by_current_package_keeps_non_released_as_is() {
        let config = fixture();
        let names = config.plugin_names_by_current_package(&["com.example.BarPlugin".to_string()]);
        assert_eq!(names.len(), 1);
        assert!(names.contains("com.example.BarPlugin"));
    }

    #[test]
    fn save_and_restore_plugins_round_trips_through_xml() {
        let config = fixture();
        let plugins: Vec<Box<dyn PluginLike>> =
            vec![Box::new(MockPlugin { class_name: "com.example.FooPlugin".to_string() })];

        let mut root = MockJdomElement::default();
        config.save_plugins_to_xml(&mut root, &plugins);

        let restored = config.plugin_class_names(&root);
        // FooPlugin (Released) was included, so nothing needs to be excluded/included for it;
        // restoring from the resulting XML should still resolve it as present via the
        // default-include-if-released rule.
        assert!(restored.contains("com.example.FooPlugin"));
    }

    #[test]
    fn save_plugins_to_xml_excludes_released_plugin_left_out_of_tool() {
        let config = fixture();
        // Only BarPlugin is present in the tool; FooPlugin (Released) is in the same package
        // ("Core") but absent, so it must be written out as an explicit EXCLUDE entry, and
        // BarPlugin (Unstable) must be written out as an explicit INCLUDE entry.
        let plugins: Vec<Box<dyn PluginLike>> =
            vec![Box::new(MockPlugin { class_name: "com.example.BarPlugin".to_string() })];

        let mut root = MockJdomElement::default();
        config.save_plugins_to_xml(&mut root, &plugins);

        let restored = config.plugin_class_names(&root);
        assert!(restored.contains("com.example.BarPlugin"));
        assert!(!restored.contains("com.example.FooPlugin"));
    }
}
