use super::fixup::Fixup;
use super::seam_stubs::Location;

/// Documents an issue that arises during some action, operation, or task.
///
/// Typically, issues are reported within a task using a `TaskMonitor`.
///
/// Port of `ghidra.util.Issue`.
pub trait Issue: Send + Sync {
    /// Returns the category for this issue. Categories may use '.' as separators to present
    /// a hierarchical category structure.
    fn get_category(&self) -> String;

    /// Returns a detailed description of the issue.
    fn get_description(&self) -> String;

    /// Returns a location that describes where the issue occurred, if any.
    fn get_primary_location(&self) -> Option<Box<dyn Location>>;

    /// Returns locations related to the issue that are not the primary issue location.
    ///
    /// This list may be empty, but every element is guaranteed to be present.
    fn get_secondary_locations(&self) -> Vec<Box<dyn Location>>;

    /// Returns possible fixups for this issue.
    ///
    /// This list may be empty, but every element is guaranteed to be present.
    fn get_possible_fixups(&self) -> Vec<Box<dyn Fixup>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLocation;
    impl Location for MockLocation {}

    struct MockFixup;
    impl Fixup for MockFixup {
        fn get_description(&self) -> &str {
            "mock fixup"
        }

        fn can_fixup(&self) -> bool {
            false
        }

        fn fixup(&self, _provider: &dyn crate::framework::ServiceProvider) -> bool {
            false
        }
    }

    struct TestIssue;

    impl Issue for TestIssue {
        fn get_category(&self) -> String {
            "test.category".to_string()
        }

        fn get_description(&self) -> String {
            "test description".to_string()
        }

        fn get_primary_location(&self) -> Option<Box<dyn Location>> {
            Some(Box::new(MockLocation))
        }

        fn get_secondary_locations(&self) -> Vec<Box<dyn Location>> {
            vec![Box::new(MockLocation)]
        }

        fn get_possible_fixups(&self) -> Vec<Box<dyn Fixup>> {
            vec![Box::new(MockFixup)]
        }
    }

    #[test]
    fn trait_object_dispatch() {
        let issue: Box<dyn Issue> = Box::new(TestIssue);

        assert_eq!(issue.get_category(), "test.category");
        assert_eq!(issue.get_description(), "test description");
        assert!(issue.get_primary_location().is_some());
        assert_eq!(issue.get_secondary_locations().len(), 1);
        assert_eq!(issue.get_possible_fixups().len(), 1);
    }
}
