use super::bookmark_type::BookmarkType;
use std::cmp::Ordering;

/// Provides an ordering for bookmark types.
///
/// Compares bookmark types lexicographically by their type string.
/// Mirrors Ghidra's `BookmarkTypeComparator`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BookmarkTypeComparator;

impl BookmarkTypeComparator {
    /// Compares two bookmark types for ordering.
    ///
    /// Compares the types lexicographically by their type string.
    /// Returns `Ordering::Less`, `Ordering::Equal`, or `Ordering::Greater`.
    pub fn compare(bt1: &dyn BookmarkType, bt2: &dyn BookmarkType) -> Ordering {
        bt1.get_type_string().cmp(bt2.get_type_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBookmarkType {
        type_string: String,
    }

    impl MockBookmarkType {
        fn new(type_string: &str) -> Self {
            Self {
                type_string: type_string.to_string(),
            }
        }
    }

    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            &self.type_string
        }

        fn get_icon(&self) -> Option<Box<dyn crate::program::model::data::playable::Icon>> {
            None
        }

        fn get_marker_color(&self) -> Option<crate::program::model::listing::bookmark_type::MarkerColor> {
            None
        }

        fn get_marker_priority(&self) -> i32 {
            -1
        }

        fn has_bookmarks(&self) -> bool {
            false
        }

        fn get_type_id(&self) -> i32 {
            0
        }
    }

    #[test]
    fn compares_lexicographically() {
        let bt_a = MockBookmarkType::new("Analysis");
        let bt_n = MockBookmarkType::new("Note");

        let result = BookmarkTypeComparator::compare(&bt_a, &bt_n);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkTypeComparator::compare(&bt_n, &bt_a);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn equal_when_type_strings_match() {
        let bt1 = MockBookmarkType::new("Error");
        let bt2 = MockBookmarkType::new("Error");

        let result = BookmarkTypeComparator::compare(&bt1, &bt2);
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn compares_different_types() {
        let bt_error = MockBookmarkType::new("Error");
        let bt_warning = MockBookmarkType::new("Warning");

        let result = BookmarkTypeComparator::compare(&bt_error, &bt_warning);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkTypeComparator::compare(&bt_warning, &bt_error);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn compares_info_and_note() {
        let bt_info = MockBookmarkType::new("Info");
        let bt_note = MockBookmarkType::new("Note");

        let result = BookmarkTypeComparator::compare(&bt_info, &bt_note);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkTypeComparator::compare(&bt_note, &bt_info);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn works_with_trait_objects() {
        let bt1: Box<dyn BookmarkType> = Box::new(MockBookmarkType::new("Analysis"));
        let bt2: Box<dyn BookmarkType> = Box::new(MockBookmarkType::new("Note"));

        let result = BookmarkTypeComparator::compare(&*bt1, &*bt2);
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn empty_string_compares_first() {
        let bt_empty = MockBookmarkType::new("");
        let bt_analysis = MockBookmarkType::new("Analysis");

        let result = BookmarkTypeComparator::compare(&bt_empty, &bt_analysis);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkTypeComparator::compare(&bt_analysis, &bt_empty);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn case_sensitive_comparison() {
        let bt_lower = MockBookmarkType::new("analysis");
        let bt_upper = MockBookmarkType::new("Analysis");

        let result = BookmarkTypeComparator::compare(&bt_lower, &bt_upper);
        assert_eq!(result, Ordering::Greater);
    }
}
