/// Indicates the stability and visibility status of a plugin.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginStatus {
    /// Released (Tested and Documented).
    Released,
    /// Useable, but not fully tested or documented.
    Stable,
    /// This plugin is under Development. Use of this plugin is not recommended.
    Unstable,
    /// This plugin is not available via the plugin configuration GUI.
    Hidden,
    /// This plugin is useable, but deprecated and may soon be removed.
    Deprecated,
}

impl PluginStatus {
    /// Returns the human-readable description for this status.
    pub fn description(self) -> &'static str {
        match self {
            PluginStatus::Released => "Released (Tested and Documented)",
            PluginStatus::Stable => "Useable, but not fully tested or documented",
            PluginStatus::Unstable => {
                "This plugin is under Development. Use of this plugin is not recommended."
            }
            PluginStatus::Hidden => {
                "This plugin is not available via the plugin configuration GUI"
            }
            PluginStatus::Deprecated => {
                "This plugin is useable, but deprecated and may soon be removed"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(PluginStatus::Released, PluginStatus::Stable);
        assert_ne!(PluginStatus::Stable, PluginStatus::Unstable);
        assert_ne!(PluginStatus::Unstable, PluginStatus::Hidden);
        assert_ne!(PluginStatus::Hidden, PluginStatus::Deprecated);
    }

    #[test]
    fn equality_holds_for_same_variant() {
        assert_eq!(PluginStatus::Released, PluginStatus::Released);
        assert_eq!(PluginStatus::Deprecated, PluginStatus::Deprecated);
    }

    #[test]
    fn copy_semantics() {
        let a = PluginStatus::Stable;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = PluginStatus::Hidden;
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn description_released() {
        assert_eq!(PluginStatus::Released.description(), "Released (Tested and Documented)");
    }

    #[test]
    fn description_stable() {
        assert_eq!(
            PluginStatus::Stable.description(),
            "Useable, but not fully tested or documented"
        );
    }

    #[test]
    fn description_unstable() {
        assert_eq!(
            PluginStatus::Unstable.description(),
            "This plugin is under Development. Use of this plugin is not recommended."
        );
    }

    #[test]
    fn description_hidden() {
        assert_eq!(
            PluginStatus::Hidden.description(),
            "This plugin is not available via the plugin configuration GUI"
        );
    }

    #[test]
    fn description_deprecated() {
        assert_eq!(
            PluginStatus::Deprecated.description(),
            "This plugin is useable, but deprecated and may soon be removed"
        );
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", PluginStatus::Released).contains("Released"));
        assert!(format!("{:?}", PluginStatus::Unstable).contains("Unstable"));
        assert!(format!("{:?}", PluginStatus::Deprecated).contains("Deprecated"));
    }

    #[test]
    fn hash_equal_variants_match() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PluginStatus::Released);
        set.insert(PluginStatus::Released);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn all_five_variants_in_set() {
        use std::collections::HashSet;
        let set: HashSet<_> = [
            PluginStatus::Released,
            PluginStatus::Stable,
            PluginStatus::Unstable,
            PluginStatus::Hidden,
            PluginStatus::Deprecated,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 5);
    }
}
