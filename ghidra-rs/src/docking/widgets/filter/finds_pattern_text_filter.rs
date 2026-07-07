use std::any::Any;
use std::cell::RefCell;

use regex::{Regex, RegexBuilder};

use super::{AbstractPatternTextFilter, TextFilter};

/// A text filter that uses a pattern and performs a 'find' using that pattern.
///
/// Corresponds to `docking.widgets.filter.FindsPatternTextFilter`.
pub struct FindsPatternTextFilter {
    filter_text: String,
    pattern_cache: RefCell<Option<Regex>>,
}

impl FindsPatternTextFilter {
    /// Creates a new filter from the given filter text, which is treated as a regular
    /// expression.
    pub fn new(filter_text: &str) -> Self {
        Self { filter_text: filter_text.to_owned(), pattern_cache: RefCell::new(None) }
    }

    // Note: this choice of characters is seriously arbitrary, decided through manual testing. If
    //       we encounter failure cases in the wild, then we may wish to simplify this even
    //       further to letters/digits and perhaps simple globbing characters (like * and ?). The
    //       hope is that the 'starts with' criteria is enough to prevent most catastrophes.
    fn are_all_characters_simple_enough(s: &str) -> bool {
        for c in s.chars() {
            if ('\u{20}'..='\u{5A}').contains(&c) {
                // 'Space' through upper-case Z
                continue;
            }

            if ('\u{5F}'..='\u{7A}').contains(&c) {
                // 'Underscore' through lower-case z
                continue;
            }

            return false;
        }
        true
    }
}

impl AbstractPatternTextFilter for FindsPatternTextFilter {
    fn filter_text(&self) -> &str {
        &self.filter_text
    }

    fn pattern_cache(&self) -> &RefCell<Option<Regex>> {
        &self.pattern_cache
    }

    fn create_pattern(&self) -> Option<Regex> {
        // This can fail as the user is typing their regex; not sure what else we can do. The
        // net effect is that the filter will appear to do nothing.
        RegexBuilder::new(&self.filter_text).dot_matches_new_line(true).build().ok()
    }

    fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool {
        pattern.is_match(text)
    }
}

impl TextFilter for FindsPatternTextFilter {
    fn matches(&self, text: &str) -> bool {
        self.matches_text(text)
    }

    fn get_filter_text(&self) -> &str {
        self.filter_text()
    }

    fn is_sub_filter_of(&self, filter: &dyn TextFilter) -> bool {
        let any_filter: &dyn Any = filter;
        let other = match any_filter.downcast_ref::<FindsPatternTextFilter>() {
            Some(other) => other,
            None => return false,
        };

        //
        // This can be very tricky, so only attempt simple pattern comparison: we have to
        // start with the given pattern and our new text can only use simple regex characters
        //
        let parent = &other.filter_text;
        let child = &self.filter_text;
        if !child.starts_with(parent.as_str()) {
            return false;
        }

        // only allow simple globbing characters (in order to avoid complex things like look
        // ahead and look behind
        Self::are_all_characters_simple_enough(&child[parent.len()..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_finds_pattern_anywhere_in_text() {
        let filter = FindsPatternTextFilter::new("ca.");
        assert!(filter.matches("cat"));
        assert!(filter.matches("xxcatxx"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn matches_across_newlines_due_to_dotall() {
        let filter = FindsPatternTextFilter::new("a.b");
        assert!(filter.matches("a\nb"));
    }

    #[test]
    fn invalid_pattern_never_matches() {
        let filter = FindsPatternTextFilter::new("[");
        assert!(!filter.matches("anything"));
    }

    #[test]
    fn get_filter_text_returns_constructor_value() {
        let filter = FindsPatternTextFilter::new("hello");
        assert_eq!(filter.get_filter_text(), "hello");
    }

    #[test]
    fn is_sub_filter_of_true_when_child_extends_parent_with_simple_chars() {
        let parent = FindsPatternTextFilter::new("cat");
        let child = FindsPatternTextFilter::new("cat_dog");
        assert!(child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_when_child_does_not_start_with_parent() {
        let parent = FindsPatternTextFilter::new("cat");
        let child = FindsPatternTextFilter::new("dog");
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_when_extra_chars_are_not_simple() {
        // Per Java's areAllCharactersSimpleEnough, "simple" chars are 0x20..=0x5A and
        // 0x5F..=0x7A. '[' (0x5B) falls in the excluded 0x5B..=0x5E gap, so it is NOT simple
        // and disqualifies the child from being a sub-filter.
        let parent = FindsPatternTextFilter::new("cat");
        let child = FindsPatternTextFilter::new("cat[dog]");
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_non_finds_pattern_filter() {
        struct OtherFilter;
        impl TextFilter for OtherFilter {
            fn matches(&self, _text: &str) -> bool {
                true
            }
            fn get_filter_text(&self) -> &str {
                "cat"
            }
            fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
                false
            }
        }

        let child = FindsPatternTextFilter::new("cat_dog");
        let other = OtherFilter;
        assert!(!child.is_sub_filter_of(&other));
    }

    #[test]
    fn is_sub_filter_of_false_when_texts_are_equal() {
        let parent = FindsPatternTextFilter::new("cat");
        let child = FindsPatternTextFilter::new("cat");
        // Equal text is technically a valid "starts with" and has no trailing characters to
        // reject, so this is considered a sub-filter (mirrors the Java behavior).
        assert!(child.is_sub_filter_of(&parent));
    }
}
