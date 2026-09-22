//! Port of `ghidra.debug.api.action.LocationTrackingSpecFactory`.
//!
//! A discoverable factory of tracking specifications.
//!
//! # Shape
//!
//! Java is an `interface` with 2 abstract instance methods and 2 in-repo implementors, so this
//! becomes a `trait` (rule R-interface-open-ext-point, per `scripts/shape_rules.py`).
//!
//! # Seams
//!
//! * **`LocationTrackingSpec`.** Not yet ported. Reuses (and grows) the existing
//!   [`crate::debug::seam_stubs::LocationTrackingSpec`] placeholder with a `get_config_name`
//!   method, needed to key [`all_suggested`]'s result map -- see that trait's doc comment.
//! * **`PluginTool`.** Two unrelated placeholders for this Java class exist crate-wide
//!   ([`crate::framework::seam_stubs::PluginTool`], with many real callers, and
//!   [`crate::app::seam_stubs::PluginTool`], with far fewer); this file reuses the `framework`
//!   one, matching the sibling [`AutoReadMemorySpecFactory`](super::AutoReadMemorySpecFactory)
//!   convention.
//! * **`ClassSearcher`-backed static methods.** Java's `static fromConfigName(String)` and
//!   `static allSuggested(PluginTool)` iterate every registered factory via
//!   `ClassSearcher.getInstances(LocationTrackingSpecFactory.class)`. This crate has no
//!   classpath-scanning equivalent (see `AutoReadMemorySpecFactory`'s module docs for the same
//!   gap), so both become free functions that take the known factories as an explicit slice
//!   parameter instead of discovering them via a global registry.

use crate::debug::seam_stubs::LocationTrackingSpec;
use crate::framework::seam_stubs::PluginTool;
use crate::util::classfinder::ExtensionPoint;
use std::collections::BTreeMap;

/// Port of the Java interface `ghidra.debug.api.action.LocationTrackingSpecFactory`.
///
/// Java also `extends ExtensionPoint`, a pure discovery marker with no methods, so it is not
/// modeled as a supertrait bound here -- nothing would be added to implementors.
pub trait LocationTrackingSpecFactory: ExtensionPoint {
    /// Gets all the specifications currently suggested by this factory.
    ///
    /// Mirrors `LocationTrackingSpecFactory.getSuggested(PluginTool)`.
    fn get_suggested(&self, tool: &dyn PluginTool) -> Vec<Box<dyn LocationTrackingSpec>>;

    /// Attempts to parse the given configuration name as a specification.
    ///
    /// Mirrors `LocationTrackingSpecFactory.parseSpec(String)`; `None` mirrors Java's `null`
    /// return, meaning this factory cannot parse the name.
    fn parse_spec(&self, name: &str) -> Option<Box<dyn LocationTrackingSpec>>;
}

/// Gets the specification for the given configuration name.
///
/// Mirrors `LocationTrackingSpecFactory.fromConfigName(String)`. See the module docs' Seams
/// section for why `factories` is an explicit parameter rather than a `ClassSearcher`-discovered
/// set.
pub fn from_config_name(
    factories: &[Box<dyn LocationTrackingSpecFactory>],
    name: &str,
) -> Option<Box<dyn LocationTrackingSpec>> {
    for factory in factories {
        if let Some(spec) = factory.parse_spec(name) {
            return Some(spec);
        }
    }
    None
}

/// Gets a copy of all the known specifications, keyed by configuration name.
///
/// Mirrors `LocationTrackingSpecFactory.allSuggested(PluginTool)`. Uses a [`BTreeMap`] to match
/// Java's `TreeMap` (sorted-by-key iteration order). See the module docs' Seams section for why
/// `factories` is an explicit parameter rather than a `ClassSearcher`-discovered set.
pub fn all_suggested(
    factories: &[Box<dyn LocationTrackingSpecFactory>],
    tool: &dyn PluginTool,
) -> BTreeMap<String, Box<dyn LocationTrackingSpec>> {
    let mut all = BTreeMap::new();
    for factory in factories {
        for spec in factory.get_suggested(tool) {
            all.insert(spec.get_config_name(), spec);
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSpec {
        config_name: String,
    }

    impl LocationTrackingSpec for FakeSpec {
        fn get_config_name(&self) -> String {
            self.config_name.clone()
        }
    }

    struct FakeFactory {
        prefix: &'static str,
    }

    impl ExtensionPoint for FakeFactory {}

    impl LocationTrackingSpecFactory for FakeFactory {
        fn get_suggested(&self, _tool: &dyn PluginTool) -> Vec<Box<dyn LocationTrackingSpec>> {
            vec![Box::new(FakeSpec {
                config_name: self.prefix.to_string(),
            })]
        }

        fn parse_spec(&self, name: &str) -> Option<Box<dyn LocationTrackingSpec>> {
            if name.starts_with(self.prefix) {
                Some(Box::new(FakeSpec {
                    config_name: self.prefix.to_string(),
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
        let factories: Vec<Box<dyn LocationTrackingSpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "pc:" }),
            Box::new(FakeFactory { prefix: "sp:" }),
        ];
        let spec = from_config_name(&factories, "pc:foo").expect("should parse");
        assert_eq!(spec.get_config_name(), "pc:");
    }

    #[test]
    fn from_config_name_returns_none_when_no_factory_matches() {
        let factories: Vec<Box<dyn LocationTrackingSpecFactory>> =
            vec![Box::new(FakeFactory { prefix: "pc:" })];
        assert!(from_config_name(&factories, "sp:foo").is_none());
    }

    #[test]
    fn all_suggested_sorted_by_config_name() {
        let factories: Vec<Box<dyn LocationTrackingSpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "sp:" }),
            Box::new(FakeFactory { prefix: "pc:" }),
        ];
        let tool = MockTool;
        let all = all_suggested(&factories, &tool);
        let keys: Vec<&String> = all.keys().collect();
        assert_eq!(keys, vec!["pc:", "sp:"]);
    }

    #[test]
    fn all_suggested_merges_across_factories() {
        let factories: Vec<Box<dyn LocationTrackingSpecFactory>> = vec![
            Box::new(FakeFactory { prefix: "pc:" }),
            Box::new(FakeFactory { prefix: "sp:" }),
        ];
        let tool = MockTool;
        let all = all_suggested(&factories, &tool);
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("pc:"));
        assert!(all.contains_key("sp:"));
    }
}
