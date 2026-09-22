//! Port of `ghidra.debug.api.action.AutoReadMemorySpecFactory`.
//!
//! A discoverable factory of auto-read memory specifications.
//!
//! # Shape
//!
//! Java is an `interface` with 2 abstract instance methods and 1 in-repo implementor, so this
//! becomes a `trait` (rule R-interface-open-ext-point).
//!
//! # Seams
//!
//! * **`AutoReadMemorySpec`.** Reuses the existing
//!   [`crate::app::seam_stubs::AutoReadMemorySpec`] placeholder (grown here with
//!   `get_config_name`/`get_menu_name`) rather than creating a second one -- see that trait's doc
//!   comment.
//! * **`PluginTool`.** Two unrelated placeholders for this Java class exist crate-wide
//!   ([`crate::framework::seam_stubs::PluginTool`], with 17 real callers, and
//!   [`crate::app::seam_stubs::PluginTool`], with 2); this file reuses the `framework` one, the
//!   dominant convention.
//! * **`ClassSearcher`-backed static methods.** Java's `static fromConfigName(String)` and
//!   `static allSuggested(PluginTool)` iterate every registered factory via
//!   `ClassSearcher.getInstances(AutoReadMemorySpecFactory.class)`. This crate has no
//!   classpath-scanning equivalent (the same gap already documented on
//!   [`PluginUtils`](crate::framework::plugintool::util::plugin_utils::PluginUtils),
//!   `Analyzer`, and `LanguageProvider`), so both become free functions that take the known
//!   factories as an explicit slice parameter instead of discovering them via a global registry.

use crate::app::seam_stubs::AutoReadMemorySpec;
use crate::framework::seam_stubs::PluginTool;
use crate::util::classfinder::ExtensionPoint;
use std::collections::BTreeMap;

/// Port of the Java interface `ghidra.debug.api.action.AutoReadMemorySpecFactory`.
///
/// Java also `extends ExtensionPoint`, a pure discovery marker with no methods, so it is not
/// modeled as a supertrait bound here -- nothing would be added to implementors.
pub trait AutoReadMemorySpecFactory: ExtensionPoint {
    /// Gets all the specifications currently suggested by this factory.
    ///
    /// Mirrors `AutoReadMemorySpecFactory.getSuggested(PluginTool)`.
    fn get_suggested(&self, tool: &dyn PluginTool) -> Vec<Box<dyn AutoReadMemorySpec>>;

    /// Attempts to parse the given configuration name as a specification.
    ///
    /// Mirrors `AutoReadMemorySpecFactory.parseSpec(String)`; `None` mirrors Java's `null`
    /// return, meaning this factory cannot parse the name.
    fn parse_spec(&self, name: &str) -> Option<Box<dyn AutoReadMemorySpec>>;
}

/// Gets the specification for the given configuration name.
///
/// Mirrors `AutoReadMemorySpecFactory.fromConfigName(String)`. See the module docs' Seams section
/// for why `factories` is an explicit parameter rather than a `ClassSearcher`-discovered set.
pub fn from_config_name(
    factories: &[Box<dyn AutoReadMemorySpecFactory>],
    name: &str,
) -> Option<Box<dyn AutoReadMemorySpec>> {
    for factory in factories {
        if let Some(spec) = factory.parse_spec(name) {
            return Some(spec);
        }
    }
    None
}

/// Gets a copy of all the known and visible specifications, keyed by configuration name.
///
/// Mirrors `AutoReadMemorySpecFactory.allSuggested(PluginTool)`. Uses a [`BTreeMap`] to match
/// Java's `TreeMap` (sorted-by-key iteration order). See the module docs' Seams section for why
/// `factories` is an explicit parameter rather than a `ClassSearcher`-discovered set.
pub fn all_suggested(
    factories: &[Box<dyn AutoReadMemorySpecFactory>],
    tool: &dyn PluginTool,
) -> BTreeMap<String, Box<dyn AutoReadMemorySpec>> {
    let mut all = BTreeMap::new();
    for factory in factories {
        for spec in factory.get_suggested(tool) {
            if spec.get_menu_name().is_some() {
                all.insert(spec.get_config_name(), spec);
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSpec {
        config_name: String,
        menu_name: Option<String>,
    }

    impl AutoReadMemorySpec for FakeSpec {
        fn get_config_name(&self) -> String {
            self.config_name.clone()
        }
        fn get_menu_name(&self) -> Option<String> {
            self.menu_name.clone()
        }
    }

    struct FakeFactory {
        prefix: &'static str,
        menu_name: Option<&'static str>,
    }

    impl ExtensionPoint for FakeFactory {}

    impl AutoReadMemorySpecFactory for FakeFactory {
        fn get_suggested(&self, _tool: &dyn PluginTool) -> Vec<Box<dyn AutoReadMemorySpec>> {
            vec![Box::new(FakeSpec {
                config_name: self.prefix.to_string(),
                menu_name: self.menu_name.map(|s| s.to_string()),
            })]
        }

        fn parse_spec(&self, name: &str) -> Option<Box<dyn AutoReadMemorySpec>> {
            if let Some(stripped) = name.strip_prefix(self.prefix) {
                Some(Box::new(FakeSpec {
                    config_name: self.prefix.to_string(),
                    menu_name: Some(stripped.to_string()),
                }))
            } else {
                None
            }
        }
    }

    struct MockTool;
    impl PluginTool for MockTool {}

    #[test]
    fn from_config_name_returns_first_matching_factory() {
        let factories: Vec<Box<dyn AutoReadMemorySpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "visible:", menu_name: Some("Visible") }),
            Box::new(FakeFactory { prefix: "none:", menu_name: None }),
        ];
        let spec = from_config_name(&factories, "visible:foo").expect("should parse");
        assert_eq!(spec.get_config_name(), "visible:");
    }

    #[test]
    fn from_config_name_returns_none_when_no_factory_matches() {
        let factories: Vec<Box<dyn AutoReadMemorySpecFactory>> =
            vec![Box::new(FakeFactory { prefix: "visible:", menu_name: Some("Visible") })];
        assert!(from_config_name(&factories, "other:foo").is_none());
    }

    #[test]
    fn all_suggested_omits_specs_with_no_menu_name() {
        let factories: Vec<Box<dyn AutoReadMemorySpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "visible:", menu_name: Some("Visible") }),
            Box::new(FakeFactory { prefix: "hidden:", menu_name: None }),
        ];
        let tool = MockTool;
        let all = all_suggested(&factories, &tool);
        assert_eq!(all.len(), 1);
        assert!(all.contains_key("visible:"));
        assert!(!all.contains_key("hidden:"));
    }

    #[test]
    fn all_suggested_sorted_by_config_name() {
        let factories: Vec<Box<dyn AutoReadMemorySpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "zzz:", menu_name: Some("Z") }),
            Box::new(FakeFactory { prefix: "aaa:", menu_name: Some("A") }),
        ];
        let tool = MockTool;
        let all = all_suggested(&factories, &tool);
        let keys: Vec<&String> = all.keys().collect();
        assert_eq!(keys, vec!["aaa:", "zzz:"]);
    }
}
