use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use std::collections::HashMap;

/// A chooser for filtering version-tracking tags.
///
/// Implementations determine which tags should be excluded from the user's view
/// based on the set of all available tags and the currently excluded tags.
pub trait TagFilterChooser {
    /// Returns a map of tag string values to tags that are **excluded**.
    ///
    /// That is, the returned map of tags are those which the client filter
    /// should exclude from view.
    ///
    /// # Arguments
    ///
    /// * `all_tags` - All known existing tags. This will be used to determine
    ///   which tags should be excluded.
    /// * `current_excluded_tags` - The current collection of excluded tags.
    ///   This will be used to seed the excluded tag choices for this chooser.
    ///
    /// # Returns
    ///
    /// A map of tag names to their corresponding `VtMatchTag` values that
    /// should be excluded from view.
    fn get_excluded_tags(
        &self,
        all_tags: &HashMap<String, VtMatchTag>,
        current_excluded_tags: &HashMap<String, VtMatchTag>,
    ) -> HashMap<String, VtMatchTag>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test implementation for basic testing purposes.
    struct TestFilterChooser {
        excluded: HashMap<String, VtMatchTag>,
    }

    impl TestFilterChooser {
        fn new(excluded: HashMap<String, VtMatchTag>) -> Self {
            Self { excluded }
        }
    }

    impl TagFilterChooser for TestFilterChooser {
        fn get_excluded_tags(
            &self,
            _all_tags: &HashMap<String, VtMatchTag>,
            _current_excluded_tags: &HashMap<String, VtMatchTag>,
        ) -> HashMap<String, VtMatchTag> {
            self.excluded.clone()
        }
    }

    #[test]
    fn returns_configured_excluded_tags() {
        let mut excluded = HashMap::new();
        excluded.insert("foo".to_string(), VtMatchTag::Named("foo".into()));
        excluded.insert("bar".to_string(), VtMatchTag::Named("bar".into()));

        let chooser = TestFilterChooser::new(excluded.clone());
        let result = chooser.get_excluded_tags(&HashMap::new(), &HashMap::new());

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get("foo"),
            Some(&VtMatchTag::Named("foo".into()))
        );
        assert_eq!(
            result.get("bar"),
            Some(&VtMatchTag::Named("bar".into()))
        );
    }

    #[test]
    fn handles_empty_all_tags() {
        let chooser = TestFilterChooser::new(HashMap::new());
        let result = chooser.get_excluded_tags(&HashMap::new(), &HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn handles_empty_current_excluded() {
        let mut excluded = HashMap::new();
        excluded.insert("test".to_string(), VtMatchTag::Named("test".into()));

        let chooser = TestFilterChooser::new(excluded);
        let result = chooser.get_excluded_tags(&HashMap::new(), &HashMap::new());

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("test"));
    }

    #[test]
    fn can_exclude_untagged() {
        let mut excluded = HashMap::new();
        excluded.insert("".to_string(), VtMatchTag::Untagged);

        let chooser = TestFilterChooser::new(excluded);
        let result = chooser.get_excluded_tags(&HashMap::new(), &HashMap::new());

        assert_eq!(result.len(), 1);
        assert_eq!(result.get(""), Some(&VtMatchTag::Untagged));
    }

    #[test]
    fn respects_all_tags_parameter() {
        let mut all_tags = HashMap::new();
        all_tags.insert("alpha".to_string(), VtMatchTag::Named("alpha".into()));
        all_tags.insert("beta".to_string(), VtMatchTag::Named("beta".into()));

        let chooser = TestFilterChooser::new(HashMap::new());
        let result = chooser.get_excluded_tags(&all_tags, &HashMap::new());

        // Test that the chooser has access to all_tags; in this case, it excludes nothing
        assert!(result.is_empty());
    }

    #[test]
    fn respects_current_excluded_parameter() {
        let mut current = HashMap::new();
        current.insert("current".to_string(), VtMatchTag::Named("current".into()));

        let chooser = TestFilterChooser::new(HashMap::new());
        let result = chooser.get_excluded_tags(&HashMap::new(), &current);

        // Test that the chooser has access to current_excluded_tags
        assert!(result.is_empty());
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        struct AlwaysExcludeAll;

        impl TagFilterChooser for AlwaysExcludeAll {
            fn get_excluded_tags(
                &self,
                all_tags: &HashMap<String, VtMatchTag>,
                _current_excluded_tags: &HashMap<String, VtMatchTag>,
            ) -> HashMap<String, VtMatchTag> {
                all_tags.clone()
            }
        }

        let mut all = HashMap::new();
        all.insert("x".to_string(), VtMatchTag::Named("x".into()));
        all.insert("y".to_string(), VtMatchTag::Named("y".into()));

        let chooser = AlwaysExcludeAll;
        let result = chooser.get_excluded_tags(&all, &HashMap::new());

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("x"));
        assert!(result.contains_key("y"));
    }
}
