use std::fmt;

/// Container object that holds a start and end position within a string. A list of [`StringDiff`]
/// is used to keep track of changes made to a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringDiff {
    /// Start position of the string used when text is inserted or replaced.
    pub start: i32,
    /// End position of the string used when part of the string is replaced.
    pub end: i32,
    /// String being inserted. Both positions are -1 for a full replace; start is non-negative
    /// for an insert; `None` indicates a deletion.
    pub text: Option<String>,
}

impl StringDiff {
    /// Construct a [`StringDiff`] indicating that all text was replaced with `new_text`.
    /// Both `start` and `end` are set to -1.
    pub fn all_text_replaced(new_text: impl Into<String>) -> Self {
        Self { start: -1, end: -1, text: Some(new_text.into()) }
    }

    /// Construct a [`StringDiff`] indicating text was deleted from `start` to `end`.
    pub fn text_deleted(start: i32, end: i32) -> Self {
        Self { start, end, text: None }
    }

    /// Construct a [`StringDiff`] indicating `new_text` was inserted at `start`.
    /// `end` is set to -1.
    pub fn text_inserted(new_text: impl Into<String>, start: i32) -> Self {
        Self { start, end: -1, text: Some(new_text.into()) }
    }

    /// Restore a [`StringDiff`] from a saved record.
    pub fn restore(text: Option<String>, start: i32, end: i32) -> Self {
        Self { start, end, text }
    }
}

impl fmt::Display for StringDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.text {
            Some(text) if self.start >= 0 => {
                write!(f, "StringDiff: inserted <{}> at {}", text, self.start)
            }
            Some(text) => write!(f, "StringDiff: replace with <{}>", text),
            None => write!(f, "StringDiff: deleted text from {} to {}", self.start, self.end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_text_replaced_positions_are_neg_one() {
        let d = StringDiff::all_text_replaced("hello");
        assert_eq!(d.start, -1);
        assert_eq!(d.end, -1);
        assert_eq!(d.text.as_deref(), Some("hello"));
    }

    #[test]
    fn text_deleted_has_no_text() {
        let d = StringDiff::text_deleted(3, 7);
        assert_eq!(d.start, 3);
        assert_eq!(d.end, 7);
        assert!(d.text.is_none());
    }

    #[test]
    fn text_inserted_end_is_neg_one() {
        let d = StringDiff::text_inserted("world", 5);
        assert_eq!(d.start, 5);
        assert_eq!(d.end, -1);
        assert_eq!(d.text.as_deref(), Some("world"));
    }

    #[test]
    fn restore_roundtrips_with_text() {
        let d = StringDiff::restore(Some("abc".to_string()), 1, 4);
        assert_eq!(d.start, 1);
        assert_eq!(d.end, 4);
        assert_eq!(d.text.as_deref(), Some("abc"));
    }

    #[test]
    fn restore_roundtrips_without_text() {
        let d = StringDiff::restore(None, 2, 6);
        assert_eq!(d.start, 2);
        assert_eq!(d.end, 6);
        assert!(d.text.is_none());
    }

    #[test]
    fn equality_same_content() {
        let a = StringDiff::all_text_replaced("x");
        let b = StringDiff::all_text_replaced("x");
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_text() {
        assert_ne!(StringDiff::all_text_replaced("x"), StringDiff::all_text_replaced("y"));
    }

    #[test]
    fn equality_different_start() {
        assert_ne!(
            StringDiff::text_inserted("a", 1),
            StringDiff::text_inserted("a", 2)
        );
    }

    #[test]
    fn equality_different_end() {
        assert_ne!(StringDiff::text_deleted(0, 5), StringDiff::text_deleted(0, 6));
    }

    #[test]
    fn hash_consistent_with_equality() {
        let a = StringDiff::all_text_replaced("x");
        let b = StringDiff::all_text_replaced("x");
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn display_replace() {
        let d = StringDiff::all_text_replaced("new");
        assert_eq!(d.to_string(), "StringDiff: replace with <new>");
    }

    #[test]
    fn display_insert() {
        let d = StringDiff::text_inserted("hi", 2);
        assert_eq!(d.to_string(), "StringDiff: inserted <hi> at 2");
    }

    #[test]
    fn display_delete() {
        let d = StringDiff::text_deleted(1, 5);
        assert_eq!(d.to_string(), "StringDiff: deleted text from 1 to 5");
    }
}
