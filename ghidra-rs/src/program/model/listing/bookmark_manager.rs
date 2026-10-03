use std::sync::Arc;

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::data::playable::Icon;
use crate::program::model::listing::bookmark_type::MarkerColor;
use crate::program::model::listing::{Bookmark, BookmarkType, Program};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// 1st version of bookmark property object class (schema change and class moved).
pub const OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1: &str = "ghidra.app.plugin.bookmark.BookmarkInfo";

/// 2nd version of bookmark property object class (class moved, property map no longer used).
pub const OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2: &str = "ghidra.program.util.Bookmark";

/// Interface for managing bookmarks.
///
/// Port of `ghidra.program.model.listing.BookmarkManager`. Java's overloaded `getBookmarks`
/// and `removeBookmarks` methods are split into distinctly-named methods since Rust traits
/// do not support overloading.
pub trait BookmarkManager {
    /// Define a bookmark type with its marker icon and color. The icon and color values are
    /// not permanently stored. Therefore, this method must be re-invoked by a plugin each time
    /// a program is opened if a custom icon and color are desired.
    ///
    /// # Arguments
    /// * `type_name` - bookmark type
    /// * `icon` - marker icon which may get scaled
    /// * `color` - marker color
    /// * `priority` - the bookmark priority
    fn define_type(
        &mut self,
        type_name: &str,
        icon: Box<dyn Icon>,
        color: MarkerColor,
        priority: i32,
    ) -> Arc<dyn BookmarkType>;

    /// Returns list of known bookmark types.
    fn get_bookmark_types(&self) -> Vec<Arc<dyn BookmarkType>>;

    /// Get a bookmark type, or `None` if the type is unknown.
    fn get_bookmark_type(&self, type_name: &str) -> Option<Arc<dyn BookmarkType>>;

    /// Get list of categories used for a specified type.
    fn get_categories(&self, type_name: &str) -> Vec<String>;

    /// Set a bookmark.
    ///
    /// # Arguments
    /// * `addr` - the address at which to set a bookmark
    /// * `type_name` - the name of the bookmark type
    /// * `category` - the category for the bookmark
    /// * `comment` - the comment to associate with the bookmark
    fn set_bookmark(
        &mut self,
        addr: Address,
        type_name: &str,
        category: &str,
        comment: &str,
    ) -> Arc<dyn Bookmark>;

    /// Get a specific bookmark with the given attributes, or `None` if no bookmarks match.
    fn get_bookmark(
        &self,
        addr: Address,
        type_name: &str,
        category: &str,
    ) -> Option<Arc<dyn Bookmark>>;

    /// Remove the given bookmark.
    fn remove_bookmark(&mut self, bookmark: &dyn Bookmark);

    /// Removes all bookmarks of the given type.
    fn remove_bookmarks_of_type(&mut self, type_name: &str);

    /// Removes all bookmarks with the given type and category.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user (via the monitor) cancelled the operation.
    fn remove_bookmarks_of_type_and_category(
        &mut self,
        type_name: &str,
        category: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes all bookmarks over the given address set.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user (via the monitor) cancelled the operation.
    fn remove_bookmarks_in_set(
        &mut self,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes all bookmarks of the given type over the given address set.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user (via the monitor) cancelled the operation.
    fn remove_bookmarks_in_set_of_type(
        &mut self,
        set: &dyn AddressSetView,
        type_name: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Removes all bookmarks of the given type and category over the given address set.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user (via the monitor) cancelled the operation.
    fn remove_bookmarks_in_set_of_type_and_category(
        &mut self,
        set: &dyn AddressSetView,
        type_name: &str,
        category: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Get bookmarks of the indicated type on a specific address.
    fn get_bookmarks_at_of_type(&self, address: Address, type_name: &str) -> Vec<Arc<dyn Bookmark>>;

    /// Get all bookmarks on a specific address.
    fn get_bookmarks_at(&self, addr: Address) -> Vec<Arc<dyn Bookmark>>;

    /// Get addresses for bookmarks of a specified type.
    fn get_bookmark_addresses(&self, type_name: &str) -> Box<dyn AddressSetView>;

    /// Returns an iterator over all bookmarks of the specified type.
    fn get_bookmarks_iterator_of_type(
        &self,
        type_name: &str,
    ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_>;

    /// Returns an iterator over all bookmarks.
    fn get_bookmarks_iterator(&self) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_>;

    /// Returns an iterator over all bookmark types, starting at the given address, with
    /// traversal in the given direction.
    ///
    /// # Arguments
    /// * `start_address` - the address at which to start
    /// * `forward` - true to iterate in the forward direction; false for backwards
    fn get_bookmarks_iterator_from(
        &self,
        start_address: Address,
        forward: bool,
    ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_>;

    /// Returns the bookmark that has the given id, or `None` if no such bookmark exists.
    fn get_bookmark_by_id(&self, id: i64) -> Option<Arc<dyn Bookmark>>;

    /// Returns true if program contains one or more bookmarks of the given type.
    fn has_bookmarks(&self, type_name: &str) -> bool;

    /// Return the number of bookmarks of the given type.
    fn get_bookmark_count_of_type(&self, type_name: &str) -> usize;

    /// Returns the total number of bookmarks in the program.
    fn get_bookmark_count(&self) -> usize;

    /// Returns the program associated with this bookmark manager.
    fn get_program(&self) -> Arc<dyn Program>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::bookmark_type::MarkerColor;
    use std::collections::HashMap;

    struct MockBookmarkType {
        type_string: String,
    }

    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            &self.type_string
        }

        fn get_icon(&self) -> Option<Box<dyn Icon>> {
            None
        }

        fn get_marker_color(&self) -> Option<MarkerColor> {
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
        type_string: String,
        category: String,
        comment: String,
        bookmark_type: Arc<MockBookmarkType>,
    }

    impl Bookmark for MockBookmark {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_type(&self) -> &dyn BookmarkType {
            self.bookmark_type.as_ref()
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
            self.get_address().offset().cmp(&other.get_address().offset())
        }
    }

    struct MockBookmarkManager {
        bookmarks: Vec<Arc<MockBookmark>>,
        next_id: i64,
    }

    impl MockBookmarkManager {
        fn new() -> Self {
            Self {
                bookmarks: Vec::new(),
                next_id: 1,
            }
        }
    }

    impl BookmarkManager for MockBookmarkManager {
        fn define_type(
            &mut self,
            type_name: &str,
            _icon: Box<dyn Icon>,
            _color: MarkerColor,
            _priority: i32,
        ) -> Arc<dyn BookmarkType> {
            Arc::new(MockBookmarkType {
                type_string: type_name.to_string(),
            })
        }

        fn get_bookmark_types(&self) -> Vec<Arc<dyn BookmarkType>> {
            Vec::new()
        }

        fn get_bookmark_type(&self, _type_name: &str) -> Option<Arc<dyn BookmarkType>> {
            None
        }

        fn get_categories(&self, type_name: &str) -> Vec<String> {
            self.bookmarks
                .iter()
                .filter(|b| b.type_string == type_name)
                .map(|b| b.category.clone())
                .collect()
        }

        fn set_bookmark(
            &mut self,
            addr: Address,
            type_name: &str,
            category: &str,
            comment: &str,
        ) -> Arc<dyn Bookmark> {
            let bookmark = Arc::new(MockBookmark {
                id: self.next_id,
                address: addr,
                type_string: type_name.to_string(),
                category: category.to_string(),
                comment: comment.to_string(),
                bookmark_type: Arc::new(MockBookmarkType {
                    type_string: type_name.to_string(),
                }),
            });
            self.next_id += 1;
            self.bookmarks.push(bookmark.clone());
            bookmark
        }

        fn get_bookmark(
            &self,
            addr: Address,
            type_name: &str,
            category: &str,
        ) -> Option<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .find(|b| {
                    b.address.offset() == addr.offset()
                        && b.type_string == type_name
                        && b.category == category
                })
                .map(|b| b.clone() as Arc<dyn Bookmark>)
        }

        fn remove_bookmark(&mut self, bookmark: &dyn Bookmark) {
            self.bookmarks.retain(|b| b.get_id() != bookmark.get_id());
        }

        fn remove_bookmarks_of_type(&mut self, type_name: &str) {
            self.bookmarks.retain(|b| b.type_string != type_name);
        }

        fn remove_bookmarks_of_type_and_category(
            &mut self,
            type_name: &str,
            category: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.bookmarks
                .retain(|b| !(b.type_string == type_name && b.category == category));
            Ok(())
        }

        fn remove_bookmarks_in_set(
            &mut self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.bookmarks.clear();
            Ok(())
        }

        fn remove_bookmarks_in_set_of_type(
            &mut self,
            _set: &dyn AddressSetView,
            type_name: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.bookmarks.retain(|b| b.type_string != type_name);
            Ok(())
        }

        fn remove_bookmarks_in_set_of_type_and_category(
            &mut self,
            _set: &dyn AddressSetView,
            type_name: &str,
            category: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.bookmarks
                .retain(|b| !(b.type_string == type_name && b.category == category));
            Ok(())
        }

        fn get_bookmarks_at_of_type(&self, address: Address, type_name: &str) -> Vec<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| b.address.offset() == address.offset() && b.type_string == type_name)
                .map(|b| b.clone() as Arc<dyn Bookmark>)
                .collect()
        }

        fn get_bookmarks_at(&self, addr: Address) -> Vec<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| b.address.offset() == addr.offset())
                .map(|b| b.clone() as Arc<dyn Bookmark>)
                .collect()
        }

        fn get_bookmark_addresses(&self, _type_name: &str) -> Box<dyn AddressSetView> {
            unimplemented!("not needed for smoke test")
        }

        fn get_bookmarks_iterator_of_type(
            &self,
            type_name: &str,
        ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            let type_name = type_name.to_string();
            Box::new(
                self.bookmarks
                    .iter()
                    .filter(move |b| b.type_string == type_name)
                    .map(|b| b.clone() as Arc<dyn Bookmark>),
            )
        }

        fn get_bookmarks_iterator(&self) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            Box::new(self.bookmarks.iter().map(|b| b.clone() as Arc<dyn Bookmark>))
        }

        fn get_bookmarks_iterator_from(
            &self,
            start_address: Address,
            forward: bool,
        ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            let start = start_address.offset();
            let mut items: Vec<Arc<dyn Bookmark>> = self
                .bookmarks
                .iter()
                .filter(|b| {
                    if forward {
                        b.address.offset() >= start
                    } else {
                        b.address.offset() <= start
                    }
                })
                .map(|b| b.clone() as Arc<dyn Bookmark>)
                .collect();
            if forward {
                items.sort_by_key(|b| b.get_address().offset());
            } else {
                items.sort_by_key(|b| std::cmp::Reverse(b.get_address().offset()));
            }
            Box::new(items.into_iter())
        }

        fn get_bookmark_by_id(&self, id: i64) -> Option<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .find(|b| b.id == id)
                .map(|b| b.clone() as Arc<dyn Bookmark>)
        }

        fn has_bookmarks(&self, type_name: &str) -> bool {
            self.bookmarks.iter().any(|b| b.type_string == type_name)
        }

        fn get_bookmark_count_of_type(&self, type_name: &str) -> usize {
            self.bookmarks.iter().filter(|b| b.type_string == type_name).count()
        }

        fn get_bookmark_count(&self) -> usize {
            self.bookmarks.len()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for smoke test")
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn set_and_get_bookmark_round_trips() {
        let mut manager = MockBookmarkManager::new();
        manager.set_bookmark(test_address(0x1000), "Note", "general", "hello");
        let found = manager.get_bookmark(test_address(0x1000), "Note", "general");
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_comment(), "hello");
    }

    #[test]
    fn remove_bookmarks_of_type_clears_matching_entries() {
        let mut manager = MockBookmarkManager::new();
        manager.set_bookmark(test_address(0x1000), "Note", "cat", "a");
        manager.set_bookmark(test_address(0x2000), "Todo", "cat", "b");
        manager.remove_bookmarks_of_type("Note");
        assert_eq!(manager.get_bookmark_count(), 1);
        assert!(!manager.has_bookmarks("Note"));
        assert!(manager.has_bookmarks("Todo"));
    }

    #[test]
    fn bookmarks_iterator_of_type_filters_by_type() {
        let mut manager = MockBookmarkManager::new();
        manager.set_bookmark(test_address(0x1000), "Note", "cat", "a");
        manager.set_bookmark(test_address(0x2000), "Todo", "cat", "b");
        manager.set_bookmark(test_address(0x3000), "Note", "cat", "c");
        let notes: Vec<_> = manager.get_bookmarks_iterator_of_type("Note").collect();
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let manager: Box<dyn BookmarkManager> = Box::new(MockBookmarkManager::new());
        assert_eq!(manager.get_bookmark_count(), 0);
    }

    #[test]
    fn old_bookmark_property_object_class_constants_match_java() {
        assert_eq!(
            OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1,
            "ghidra.app.plugin.bookmark.BookmarkInfo"
        );
        assert_eq!(OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2, "ghidra.program.util.Bookmark");
    }
}
