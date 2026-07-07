use std::cmp::Ordering;

use crate::program::model::address::Address;
use crate::program::model::listing::bookmark_type::BookmarkType;

/// Interface for bookmarks. Bookmarks are locations that are marked within the program so
/// that they can be easily found.
///
/// Mirrors Java's `Comparable<Bookmark>.compareTo` via [`Bookmark::compare_to`].
pub trait Bookmark {
    /// Returns the id of the bookmark.
    fn get_id(&self) -> i64;

    /// Returns address at which this bookmark is applied.
    fn get_address(&self) -> Address;

    /// Returns bookmark type object.
    fn get_type(&self) -> &dyn BookmarkType;

    /// Returns bookmark type as a string.
    fn get_type_string(&self) -> &str;

    /// Returns bookmark category.
    fn get_category(&self) -> &str;

    /// Returns bookmark comment.
    fn get_comment(&self) -> &str;

    /// Set the category and comment associated with a bookmark.
    ///
    /// # Arguments
    /// * `category` - category
    /// * `comment` - single line comment
    fn set(&mut self, category: &str, comment: &str);

    /// Compares this bookmark with `other` for ordering.
    fn compare_to(&self, other: &dyn Bookmark) -> Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;

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
        fn new(id: i64, address: Address, type_string: &str) -> Self {
            Self {
                id,
                address,
                bookmark_type: MockBookmarkType,
                type_string: type_string.to_string(),
                category: String::new(),
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

        fn compare_to(&self, other: &dyn Bookmark) -> Ordering {
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
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    #[test]
    fn set_updates_category_and_comment() {
        let mut bookmark = MockBookmark::new(1, test_address(0x1000), "Note");
        bookmark.set("general", "hello");
        assert_eq!(bookmark.get_category(), "general");
        assert_eq!(bookmark.get_comment(), "hello");
    }

    #[test]
    fn compare_to_orders_by_address() {
        let a = MockBookmark::new(1, test_address(0x1000), "Note");
        let b = MockBookmark::new(2, test_address(0x2000), "Note");
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let bookmark: Box<dyn Bookmark> = Box::new(MockBookmark::new(7, test_address(0x400), "Todo"));
        assert_eq!(bookmark.get_id(), 7);
        assert_eq!(bookmark.get_type_string(), "Todo");
    }
}
