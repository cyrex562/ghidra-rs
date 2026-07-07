use std::cmp::Ordering;

/// Represents a function tag that can be associated with functions.
///
/// Maps to the `FunctionTagAdapter` table.
pub trait FunctionTag {
    /// Returns the unique id of this tag.
    fn id(&self) -> i64;

    /// Returns the tag name.
    fn name(&self) -> &str;

    /// Returns the tag comment.
    fn comment(&self) -> &str;

    /// Sets the name of this tag.
    fn set_name(&mut self, name: &str);

    /// Sets the comment for this tag.
    fn set_comment(&mut self, comment: &str);

    /// Deletes this tag from the program.
    fn delete(&mut self);

    /// Compares this tag with `other` for ordering.
    ///
    /// Mirrors Java's `Comparable<FunctionTag>.compareTo`.
    fn compare_to(&self, other: &dyn FunctionTag) -> Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleTag {
        id: i64,
        name: String,
        comment: String,
        deleted: bool,
    }

    impl SimpleTag {
        fn new(id: i64, name: &str, comment: &str) -> Self {
            Self {
                id,
                name: name.to_string(),
                comment: comment.to_string(),
                deleted: false,
            }
        }
    }

    impl FunctionTag for SimpleTag {
        fn id(&self) -> i64 {
            self.id
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn comment(&self) -> &str {
            &self.comment
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn set_comment(&mut self, comment: &str) {
            self.comment = comment.to_string();
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn compare_to(&self, other: &dyn FunctionTag) -> Ordering {
            self.name.as_str().cmp(other.name())
        }
    }

    #[test]
    fn id_returns_value() {
        let tag = SimpleTag::new(42, "hot", "");
        assert_eq!(tag.id(), 42);
    }

    #[test]
    fn name_returns_value() {
        let tag = SimpleTag::new(1, "inline", "mark inline fns");
        assert_eq!(tag.name(), "inline");
    }

    #[test]
    fn comment_returns_value() {
        let tag = SimpleTag::new(1, "inline", "mark inline fns");
        assert_eq!(tag.comment(), "mark inline fns");
    }

    #[test]
    fn set_name_updates_name() {
        let mut tag = SimpleTag::new(1, "old", "");
        tag.set_name("new");
        assert_eq!(tag.name(), "new");
    }

    #[test]
    fn set_comment_updates_comment() {
        let mut tag = SimpleTag::new(1, "t", "old comment");
        tag.set_comment("new comment");
        assert_eq!(tag.comment(), "new comment");
    }

    #[test]
    fn delete_marks_deleted() {
        let mut tag = SimpleTag::new(1, "t", "");
        assert!(!tag.deleted);
        tag.delete();
        assert!(tag.deleted);
    }

    #[test]
    fn compare_to_equal_names() {
        let a = SimpleTag::new(1, "alpha", "");
        let b = SimpleTag::new(2, "alpha", "");
        assert_eq!(a.compare_to(&b), Ordering::Equal);
    }

    #[test]
    fn compare_to_less() {
        let a = SimpleTag::new(1, "alpha", "");
        let b = SimpleTag::new(2, "beta", "");
        assert_eq!(a.compare_to(&b), Ordering::Less);
    }

    #[test]
    fn compare_to_greater() {
        let a = SimpleTag::new(1, "beta", "");
        let b = SimpleTag::new(2, "alpha", "");
        assert_eq!(a.compare_to(&b), Ordering::Greater);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut tags: Vec<Box<dyn FunctionTag>> = vec![
            Box::new(SimpleTag::new(3, "zzz", "")),
            Box::new(SimpleTag::new(1, "aaa", "")),
            Box::new(SimpleTag::new(2, "mmm", "")),
        ];
        tags.sort_by(|a, b| a.compare_to(b.as_ref()));
        assert_eq!(tags[0].name(), "aaa");
        assert_eq!(tags[1].name(), "mmm");
        assert_eq!(tags[2].name(), "zzz");
    }

    #[test]
    fn empty_name_and_comment() {
        let tag = SimpleTag::new(0, "", "");
        assert_eq!(tag.name(), "");
        assert_eq!(tag.comment(), "");
    }

    #[test]
    fn negative_id() {
        let tag = SimpleTag::new(-1, "t", "");
        assert_eq!(tag.id(), -1);
    }
}
