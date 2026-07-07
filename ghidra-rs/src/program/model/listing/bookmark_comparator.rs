use super::bookmark::Bookmark;
use std::cmp::Ordering;

/// Compares bookmarks by type string, then by category.
///
/// Mirrors Ghidra's `BookmarkComparator`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BookmarkComparator;

impl BookmarkComparator {
    /// Compares two bookmarks for ordering.
    ///
    /// First compares by type string; if equal, compares by category.
    /// Returns `Ordering::Less`, `Ordering::Equal`, or `Ordering::Greater`.
    pub fn compare(bm1: &dyn Bookmark, bm2: &dyn Bookmark) -> Ordering {
        let type_cmp = bm1.get_type_string().cmp(bm2.get_type_string());
        if type_cmp == Ordering::Equal {
            bm1.get_category().cmp(bm2.get_category())
        } else {
            type_cmp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::bookmark_type::BookmarkType;

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
        id: i64,
        address: Address,
        bookmark_type: MockBookmarkType,
        type_string: String,
        category: String,
        comment: String,
    }

    impl MockBookmark {
        fn new(id: i64, type_string: &str, category: &str) -> Self {
            Self {
                id,
                address: test_address(0x0),
                bookmark_type: MockBookmarkType,
                type_string: type_string.to_string(),
                category: category.to_string(),
                comment: String::new(),
            }
        }
    }

    impl Bookmark for MockBookmark {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_type(&self) -> &dyn BookmarkType {
            &self.bookmark_type
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

        fn set(&mut self, category: &str, comment: &str) {
            self.category = category.to_string();
            self.comment = comment.to_string();
        }

        fn compare_to(&self, other: &dyn Bookmark) -> std::cmp::Ordering {
            self.get_address()
                .offset()
                .cmp(&other.get_address().offset())
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    #[test]
    fn compares_by_type_string_first() {
        let bm_note = MockBookmark::new(1, "Note", "general");
        let bm_todo = MockBookmark::new(2, "Todo", "general");

        let result = BookmarkComparator::compare(&bm_note, &bm_todo);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkComparator::compare(&bm_todo, &bm_note);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn compares_by_category_when_types_equal() {
        let bm_alpha = MockBookmark::new(1, "Note", "alpha");
        let bm_beta = MockBookmark::new(2, "Note", "beta");

        let result = BookmarkComparator::compare(&bm_alpha, &bm_beta);
        assert_eq!(result, Ordering::Less);

        let result = BookmarkComparator::compare(&bm_beta, &bm_alpha);
        assert_eq!(result, Ordering::Greater);
    }

    #[test]
    fn equal_when_type_and_category_match() {
        let bm1 = MockBookmark::new(1, "Note", "general");
        let bm2 = MockBookmark::new(2, "Note", "general");

        let result = BookmarkComparator::compare(&bm1, &bm2);
        assert_eq!(result, Ordering::Equal);
    }

    #[test]
    fn type_difference_overrides_category_difference() {
        let bm_note_z = MockBookmark::new(1, "Note", "zebra");
        let bm_todo_a = MockBookmark::new(2, "Todo", "apple");

        let result = BookmarkComparator::compare(&bm_note_z, &bm_todo_a);
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn works_with_trait_objects() {
        let bm1: Box<dyn Bookmark> = Box::new(MockBookmark::new(1, "Alpha", "cat"));
        let bm2: Box<dyn Bookmark> = Box::new(MockBookmark::new(2, "Beta", "dog"));

        let result = BookmarkComparator::compare(&*bm1, &*bm2);
        assert_eq!(result, Ordering::Less);
    }

    #[test]
    fn empty_strings_compare_first() {
        let bm_empty = MockBookmark::new(1, "", "category");
        let bm_note = MockBookmark::new(2, "Note", "category");

        let result = BookmarkComparator::compare(&bm_empty, &bm_note);
        assert_eq!(result, Ordering::Less);
    }
}
