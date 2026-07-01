use super::{ClassFileInfo, ClassFilter};
use std::collections::HashSet;

/// Filters out classes that are in an exclusion set.
///
/// Port of `ghidra.util.classfinder.ClassExclusionFilter`.
#[derive(Debug, Clone)]
pub struct ClassExclusionFilter {
    exclusion_set: HashSet<String>,
}

impl ClassExclusionFilter {
    /// Creates a new filter that excludes the given class names.
    pub fn new(exclusions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let exclusion_set = exclusions.into_iter().map(|s| s.into()).collect();
        Self { exclusion_set }
    }

    /// Creates a new empty filter (accepts all classes).
    pub fn empty() -> Self {
        Self { exclusion_set: HashSet::new() }
    }
}

impl ClassFilter for ClassExclusionFilter {
    fn accepts(&self, class_info: &ClassFileInfo) -> bool {
        !self.exclusion_set.contains(&class_info.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(name: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/path/to/class".to_string(),
            name.to_string(),
            "suffix".to_string(),
            "module".to_string(),
        )
    }

    #[test]
    fn empty_filter_accepts_all() {
        let filter = ClassExclusionFilter::empty();
        assert!(filter.accepts(&make_info("com.example.Foo")));
        assert!(filter.accepts(&make_info("com.example.Bar")));
    }

    #[test]
    fn filter_excludes_by_name() {
        let filter = ClassExclusionFilter::new(["com.example.Foo", "com.example.Bar"]);
        assert!(!filter.accepts(&make_info("com.example.Foo")));
        assert!(!filter.accepts(&make_info("com.example.Bar")));
    }

    #[test]
    fn filter_accepts_non_excluded() {
        let filter = ClassExclusionFilter::new(["com.example.Foo"]);
        assert!(filter.accepts(&make_info("com.example.Baz")));
        assert!(filter.accepts(&make_info("com.other.Foo")));
    }

    #[test]
    fn filter_excludes_exact_match_only() {
        let filter = ClassExclusionFilter::new(["com.example.Foo"]);
        assert!(!filter.accepts(&make_info("com.example.Foo")));
        assert!(filter.accepts(&make_info("com.example.FooBar")));
        assert!(filter.accepts(&make_info("Foo")));
    }

    #[test]
    fn filter_with_vec() {
        let exclusions = vec!["com.a.A", "com.b.B"];
        let filter = ClassExclusionFilter::new(exclusions);
        assert!(!filter.accepts(&make_info("com.a.A")));
        assert!(filter.accepts(&make_info("com.a.C")));
    }

    #[test]
    fn filter_with_owned_strings() {
        let exclusions = vec!["com.a.A".to_string(), "com.b.B".to_string()];
        let filter = ClassExclusionFilter::new(exclusions);
        assert!(!filter.accepts(&make_info("com.a.A")));
        assert!(!filter.accepts(&make_info("com.b.B")));
    }

    #[test]
    fn filter_clone() {
        let filter = ClassExclusionFilter::new(["com.example.Foo"]);
        let cloned = filter.clone();
        assert!(!cloned.accepts(&make_info("com.example.Foo")));
        assert!(cloned.accepts(&make_info("com.example.Bar")));
    }

    #[test]
    fn filter_with_multiple_exclusions() {
        let exclusions = [
            "com.example.Foo",
            "com.example.Bar",
            "com.other.Baz",
        ];
        let filter = ClassExclusionFilter::new(exclusions);

        assert!(!filter.accepts(&make_info("com.example.Foo")));
        assert!(!filter.accepts(&make_info("com.example.Bar")));
        assert!(!filter.accepts(&make_info("com.other.Baz")));

        assert!(filter.accepts(&make_info("com.example.Qux")));
        assert!(filter.accepts(&make_info("com.yet.Another")));
    }
}
