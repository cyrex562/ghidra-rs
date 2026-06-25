/// Categories for organizing scripts in the Script Quick Launch dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptGroup {
    RecentScripts,
    AllScripts,
}

impl ScriptGroup {
    pub fn display_name(self) -> &'static str {
        match self {
            ScriptGroup::RecentScripts => "Recent Scripts",
            ScriptGroup::AllScripts => "All Scripts",
        }
    }

    /// Returns the ScriptGroup matching the given display name, or None if not found.
    pub fn by_display_name(name: &str) -> Option<ScriptGroup> {
        match name {
            "Recent Scripts" => Some(ScriptGroup::RecentScripts),
            "All Scripts" => Some(ScriptGroup::AllScripts),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScriptGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_name_recent_scripts() {
        assert_eq!(ScriptGroup::RecentScripts.display_name(), "Recent Scripts");
    }

    #[test]
    fn test_display_name_all_scripts() {
        assert_eq!(ScriptGroup::AllScripts.display_name(), "All Scripts");
    }

    #[test]
    fn test_by_display_name_recent_scripts() {
        assert_eq!(
            ScriptGroup::by_display_name("Recent Scripts"),
            Some(ScriptGroup::RecentScripts)
        );
    }

    #[test]
    fn test_by_display_name_all_scripts() {
        assert_eq!(
            ScriptGroup::by_display_name("All Scripts"),
            Some(ScriptGroup::AllScripts)
        );
    }

    #[test]
    fn test_by_display_name_invalid() {
        assert_eq!(ScriptGroup::by_display_name("Invalid"), None);
    }

    #[test]
    fn test_by_display_name_case_sensitive() {
        assert_eq!(ScriptGroup::by_display_name("recent scripts"), None);
    }

    #[test]
    fn test_display_trait() {
        assert_eq!(ScriptGroup::RecentScripts.to_string(), "Recent Scripts");
        assert_eq!(ScriptGroup::AllScripts.to_string(), "All Scripts");
    }

    #[test]
    fn test_roundtrip_recent_scripts() {
        let group = ScriptGroup::RecentScripts;
        let name = group.display_name();
        assert_eq!(ScriptGroup::by_display_name(name), Some(group));
    }

    #[test]
    fn test_roundtrip_all_scripts() {
        let group = ScriptGroup::AllScripts;
        let name = group.display_name();
        assert_eq!(ScriptGroup::by_display_name(name), Some(group));
    }

    #[test]
    fn test_debug_derive() {
        let group = ScriptGroup::RecentScripts;
        assert_eq!(format!("{:?}", group), "RecentScripts");
    }

    #[test]
    fn test_clone_and_copy() {
        let group1 = ScriptGroup::RecentScripts;
        let group2 = group1;
        let group3 = group1.clone();
        assert_eq!(group1, group2);
        assert_eq!(group1, group3);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ScriptGroup::RecentScripts);
        set.insert(ScriptGroup::AllScripts);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&ScriptGroup::RecentScripts));
        assert!(set.contains(&ScriptGroup::AllScripts));
    }
}
