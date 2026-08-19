use crate::program::model::data::isf::IsfObject;
use crate::program::model::listing::Bookmark;

/// Represents an extended bookmark for SARIF export.
///
/// Mirrors `ExtBookmark` from Ghidra's `sarif.export.bkmk` package. Fields are
/// extracted from a [`Bookmark`] if they are non-empty.
pub struct ExtBookmark {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub kind: String,
}

impl ExtBookmark {
    /// Creates a new `ExtBookmark` from a [`Bookmark`].
    ///
    /// The `name` field is populated from the bookmark's category if it is not empty.
    /// The `comment` field is populated from the bookmark's comment if it is not empty.
    /// The `kind` field is always populated from the bookmark's type string.
    pub fn new(bookmark: &dyn Bookmark) -> Self {
        let name = {
            let category = bookmark.get_category();
            if !category.is_empty() {
                Some(category.to_string())
            } else {
                None
            }
        };

        let comment = {
            let bm_comment = bookmark.get_comment();
            if !bm_comment.is_empty() {
                Some(bm_comment.to_string())
            } else {
                None
            }
        };

        let kind = bookmark.get_type_string().to_string();

        Self { name, comment, kind }
    }
}

impl IsfObject for ExtBookmark {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;

    fn default_space() -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    use crate::program::model::listing::bookmark_type::BookmarkType;
    use std::cmp::Ordering;

    struct MockBookmarkType;
    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            "Mock"
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

    struct MockBookmark {
        category: String,
        comment: String,
        type_string: String,
    }

    impl MockBookmark {
        fn new(category: &str, comment: &str, type_string: &str) -> Self {
            Self {
                category: category.to_string(),
                comment: comment.to_string(),
                type_string: type_string.to_string(),
            }
        }
    }

    impl Bookmark for MockBookmark {
        fn get_id(&self) -> i64 {
            0
        }

        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::Address::new(default_space(), 0)
        }

        fn get_type(&self) -> &dyn BookmarkType {
            &MockBookmarkType
        }

        fn get_type_string(&self) -> &str {
            &self.type_string
        }

        fn get_category(&self) -> &str {
            &self.category
        }

        fn get_comment(&self) -> &str {
            &self.comment
        }

        fn set(&mut self, _category: &str, _comment: &str) {}

        fn compare_to(&self, _other: &dyn Bookmark) -> Ordering {
            Ordering::Equal
        }
    }

    #[test]
    fn extracts_category_as_name() {
        let bm = MockBookmark::new("MyCategory", "", "Note");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.name.as_deref(), Some("MyCategory"));
    }

    #[test]
    fn extracts_comment() {
        let bm = MockBookmark::new("Cat", "My comment", "Note");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.comment.as_deref(), Some("My comment"));
    }

    #[test]
    fn extracts_type_string_as_kind() {
        let bm = MockBookmark::new("Cat", "Comment", "Analysis");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.kind, "Analysis");
    }

    #[test]
    fn empty_category_yields_none() {
        let bm = MockBookmark::new("", "comment", "Note");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.name, None);
    }

    #[test]
    fn empty_comment_yields_none() {
        let bm = MockBookmark::new("Category", "", "Note");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.comment, None);
    }

    #[test]
    fn all_empty_fields_except_kind() {
        let bm = MockBookmark::new("", "", "Error");
        let ext = ExtBookmark::new(&bm);
        assert_eq!(ext.name, None);
        assert_eq!(ext.comment, None);
        assert_eq!(ext.kind, "Error");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let bm = MockBookmark::new("Test", "Comment", "Info");
        let ext = ExtBookmark::new(&bm);
        accepts_isf_object(&ext);
    }
}
