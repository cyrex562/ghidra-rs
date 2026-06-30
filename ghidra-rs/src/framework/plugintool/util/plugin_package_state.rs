/// Indicates what portion of a [`PluginPackage`]'s plugins are currently loaded
/// in a tool.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginPackageState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginPackageState {
    /// None of the package's plugins are loaded.
    NoPluginsLoaded,
    /// At least one, but not all, of the package's plugins are loaded.
    SomePluginsLoaded,
    /// Every plugin in the package is loaded.
    AllPluginsLoaded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(PluginPackageState::NoPluginsLoaded, PluginPackageState::SomePluginsLoaded);
        assert_ne!(PluginPackageState::SomePluginsLoaded, PluginPackageState::AllPluginsLoaded);
        assert_ne!(PluginPackageState::NoPluginsLoaded, PluginPackageState::AllPluginsLoaded);
    }

    #[test]
    fn equality_holds_for_same_variant() {
        assert_eq!(PluginPackageState::NoPluginsLoaded, PluginPackageState::NoPluginsLoaded);
        assert_eq!(PluginPackageState::SomePluginsLoaded, PluginPackageState::SomePluginsLoaded);
        assert_eq!(PluginPackageState::AllPluginsLoaded, PluginPackageState::AllPluginsLoaded);
    }

    #[test]
    fn copy_semantics() {
        let a = PluginPackageState::SomePluginsLoaded;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = PluginPackageState::AllPluginsLoaded;
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", PluginPackageState::NoPluginsLoaded).contains("NoPluginsLoaded"));
        assert!(format!("{:?}", PluginPackageState::SomePluginsLoaded)
            .contains("SomePluginsLoaded"));
        assert!(format!("{:?}", PluginPackageState::AllPluginsLoaded).contains("AllPluginsLoaded"));
    }

    #[test]
    fn hash_equal_variants_match() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PluginPackageState::NoPluginsLoaded);
        set.insert(PluginPackageState::NoPluginsLoaded);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn all_three_variants_in_set() {
        use std::collections::HashSet;
        let set: HashSet<_> = [
            PluginPackageState::NoPluginsLoaded,
            PluginPackageState::SomePluginsLoaded,
            PluginPackageState::AllPluginsLoaded,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 3);
    }
}
