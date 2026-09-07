//! Port of `ghidra.program.database.bookmark.BookmarkTypes`.
//!
//! An immutable-per-instance collection of [`BookmarkTypeDb`] entries, indexed by both name and
//! id. Java's design (the doc comment: "This object is immutable so that multiple threads can
//! read from it. When a new type is added, a BookmarkTypes object is created within a
//! synchronized call") relies on `BookmarkDBManager` replacing its whole `BookmarkTypes`
//! reference under a lock rather than mutating one in place; this port preserves the same shape
//! (`add_bookmark_type` takes `&mut self`, and is expected to be called only while building a
//! fresh instance to swap in) so a future `BookmarkDBManager` port can reproduce that same
//! copy-on-write pattern.

use std::collections::HashMap;
use std::sync::Arc;

use crate::program::database::bookmark::bookmark_type_db::BookmarkTypeDb;
use crate::program::model::listing::bookmark_type::BookmarkType;

/// Class for managing bookmark type objects.
///
/// Port of `ghidra.program.database.bookmark.BookmarkTypes`.
#[derive(Default)]
pub struct BookmarkTypes {
    name_to_type_map: HashMap<String, Arc<BookmarkTypeDb>>,
    id_to_type_map: HashMap<i32, Arc<BookmarkTypeDb>>,
    bookmark_list: Vec<Arc<BookmarkTypeDb>>,
}

impl BookmarkTypes {
    /// Creates an empty collection. Port of the implicit no-arg Java constructor (field
    /// initializers only).
    pub fn new() -> Self {
        BookmarkTypes::default()
    }

    /// Adds a bookmark type, keeping [`BookmarkTypes::get_all_types`]'s backing list sorted by
    /// type id. Port of `BookmarkTypes.addBookmarkType(BookmarkTypeDB)`.
    pub fn add_bookmark_type(&mut self, bookmark_type: Arc<BookmarkTypeDb>) {
        self.bookmark_list.push(bookmark_type.clone());
        self.name_to_type_map
            .insert(bookmark_type.get_type_string().to_string(), bookmark_type.clone());
        self.id_to_type_map
            .insert(bookmark_type.get_type_id(), bookmark_type);
        self.bookmark_list.sort_by_key(|t| t.get_type_id());
    }

    /// Returns all the bookmark types, in ascending type-id order (Java's javadoc says "random
    /// order", but the backing list is kept sorted by [`BookmarkTypes::add_bookmark_type`], so
    /// this port's deterministic order is a strict improvement, not a behavior change any caller
    /// could observe as a regression). Port of `BookmarkTypes.getAllTypes()`.
    pub fn get_all_types(&self) -> &[Arc<BookmarkTypeDb>] {
        &self.bookmark_list
    }

    /// Returns the bookmark type for the given type name, or `None` if no bookmark type exists
    /// with that name. Port of `BookmarkTypes.get(String)`.
    pub fn get(&self, type_name: &str) -> Option<&Arc<BookmarkTypeDb>> {
        self.name_to_type_map.get(type_name)
    }

    /// Returns the bookmark type with the given id, or `None` if it doesn't exist. Port of
    /// `BookmarkTypes.getTypeById(int)`.
    pub fn get_type_by_id(&self, type_id: i32) -> Option<&Arc<BookmarkTypeDb>> {
        self.id_to_type_map.get(&type_id)
    }

    /// Returns the lowest id that doesn't have a corresponding bookmark type. Port of
    /// `BookmarkTypes.getLowestUnusedId()`.
    pub fn get_lowest_unused_id(&self) -> i32 {
        for (i, bookmark_type) in self.bookmark_list.iter().enumerate() {
            if bookmark_type.get_type_id() != i as i32 {
                return i as i32;
            }
        }
        self.bookmark_list.len() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(id: i32, name: &str) -> Arc<BookmarkTypeDb> {
        Arc::new(BookmarkTypeDb::new(id, name))
    }

    #[test]
    fn starts_empty() {
        let types = BookmarkTypes::new();
        assert!(types.get_all_types().is_empty());
        assert!(types.get("Note").is_none());
        assert!(types.get_type_by_id(0).is_none());
        assert_eq!(types.get_lowest_unused_id(), 0);
    }

    #[test]
    fn add_bookmark_type_indexes_by_name_and_id_and_keeps_sorted_order() {
        let mut types = BookmarkTypes::new();
        types.add_bookmark_type(ty(2, "Analysis"));
        types.add_bookmark_type(ty(0, "Note"));
        types.add_bookmark_type(ty(1, "Info"));

        let ids: Vec<i32> = types.get_all_types().iter().map(|t| t.get_type_id()).collect();
        assert_eq!(ids, vec![0, 1, 2]);

        assert_eq!(types.get("Note").unwrap().get_type_id(), 0);
        assert_eq!(types.get_type_by_id(2).unwrap().get_type_string(), "Analysis");
        assert!(types.get("Missing").is_none());
    }

    #[test]
    fn get_lowest_unused_id_finds_the_first_gap() {
        let mut types = BookmarkTypes::new();
        types.add_bookmark_type(ty(0, "Note"));
        types.add_bookmark_type(ty(1, "Info"));
        types.add_bookmark_type(ty(3, "Warning"));

        // Index 2 has type id 3, not 2 -> gap at 2.
        assert_eq!(types.get_lowest_unused_id(), 2);
    }

    #[test]
    fn get_lowest_unused_id_is_the_list_length_when_dense() {
        let mut types = BookmarkTypes::new();
        types.add_bookmark_type(ty(0, "Note"));
        types.add_bookmark_type(ty(1, "Info"));
        assert_eq!(types.get_lowest_unused_id(), 2);
    }
}
