//! Port of `ghidra.program.database.bookmark.BookmarkTypeDB`.
//!
//! A concrete, mutable [`BookmarkType`] implementation used by the (not yet ported)
//! `BookmarkDBManager` to track each known bookmark type's icon/marker-color/priority/has-marks
//! state in memory. Java's `icon`/`markerColor` fields are `javax.swing.Icon`/`java.awt.Color`;
//! this port uses [`Icon`] (already reduced in this codebase to just an id string, see
//! `playable.rs`) and [`MarkerColor`] (already ported), matching every other bookmark-family
//! port's convention for those two types.
//!
//! Java's `Icon` field is stored and handed back by direct reference (`return icon;`); this
//! port's [`BookmarkType::get_icon`] returns an owned `Box<dyn Icon>` (a trait-object-safety
//! requirement -- see `bookmark_type.rs`), so [`BookmarkTypeDb`] stores just the icon's id string
//! and reconstructs a small private [`StoredIcon`] wrapper on each [`BookmarkTypeDb::get_icon`]
//! call.
//!
//! Java's fields are all package-private, mutated only by `BookmarkDBManager` in the same
//! package. This port exposes the equivalent setters as `pub(crate)` for the same reason (a
//! future `BookmarkDBManager` port, once landed in this same `bookmark` module tree, is the only
//! intended caller).

use std::sync::RwLock;

use crate::program::model::data::playable::Icon;
use crate::program::model::listing::bookmark_type::{BookmarkType, MarkerColor};

/// A private, minimal [`Icon`] wrapper reconstructed on demand from a stored id string. See the
/// module docs for why [`BookmarkTypeDb`] cannot simply hand back a stored `Box<dyn Icon>`.
struct StoredIcon(String);

impl Icon for StoredIcon {
    fn icon_id(&self) -> &str {
        &self.0
    }
}

/// Mutable in-memory record of a bookmark type's display metadata.
///
/// Port of `ghidra.program.database.bookmark.BookmarkTypeDB`.
pub struct BookmarkTypeDb {
    type_id: i32,
    type_string: String,
    icon_id: RwLock<Option<String>>,
    marker_color: RwLock<Option<MarkerColor>>,
    priority: RwLock<i32>,
    has_marks: RwLock<bool>,
}

impl BookmarkTypeDb {
    /// Constructs a bookmark type with the given id and name. Port of
    /// `BookmarkTypeDB(int, String)`.
    pub fn new(type_id: i32, type_string: impl Into<String>) -> Self {
        BookmarkTypeDb {
            type_id,
            type_string: type_string.into(),
            icon_id: RwLock::new(None),
            marker_color: RwLock::new(None),
            priority: RwLock::new(-1),
            has_marks: RwLock::new(false),
        }
    }

    /// Sets whether this type has any bookmarks currently stored in the program. Port of the
    /// package-private `BookmarkTypeDB.setHasBookmarks(boolean)`.
    pub(crate) fn set_has_bookmarks(&self, has_marks: bool) {
        *self.has_marks.write().unwrap() = has_marks;
    }

    /// Sets this type's icon (by id -- see the module docs). Port of the package-private
    /// `BookmarkTypeDB.setIcon(Icon)`.
    pub(crate) fn set_icon(&self, icon_id: Option<String>) {
        *self.icon_id.write().unwrap() = icon_id;
    }

    /// Sets this type's marker color. Port of the package-private
    /// `BookmarkTypeDB.setMarkerColor(Color)`.
    pub(crate) fn set_marker_color(&self, color: Option<MarkerColor>) {
        *self.marker_color.write().unwrap() = color;
    }

    /// Sets this type's marker priority. Port of the package-private
    /// `BookmarkTypeDB.setMarkerPriority(int)`.
    pub(crate) fn set_marker_priority(&self, priority: i32) {
        *self.priority.write().unwrap() = priority;
    }
}

impl BookmarkType for BookmarkTypeDb {
    fn get_type_string(&self) -> &str {
        &self.type_string
    }

    fn get_icon(&self) -> Option<Box<dyn Icon>> {
        self.icon_id
            .read()
            .unwrap()
            .clone()
            .map(|id| Box::new(StoredIcon(id)) as Box<dyn Icon>)
    }

    fn get_marker_color(&self) -> Option<MarkerColor> {
        *self.marker_color.read().unwrap()
    }

    fn get_marker_priority(&self) -> i32 {
        *self.priority.read().unwrap()
    }

    fn has_bookmarks(&self) -> bool {
        *self.has_marks.read().unwrap()
    }

    fn get_type_id(&self) -> i32 {
        self.type_id
    }
}

impl std::fmt::Display for BookmarkTypeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.type_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_match_java() {
        let bt = BookmarkTypeDb::new(3, "Note");
        assert_eq!(bt.get_type_id(), 3);
        assert_eq!(bt.get_type_string(), "Note");
        assert_eq!(bt.get_marker_priority(), -1);
        assert!(!bt.has_bookmarks());
        assert!(bt.get_icon().is_none());
        assert!(bt.get_marker_color().is_none());
    }

    #[test]
    fn setters_update_state() {
        let bt = BookmarkTypeDb::new(1, "Info");
        bt.set_has_bookmarks(true);
        bt.set_icon(Some("icon.bookmark.info".to_string()));
        bt.set_marker_color(Some(MarkerColor::rgb(0, 255, 0)));
        bt.set_marker_priority(5);

        assert!(bt.has_bookmarks());
        assert_eq!(bt.get_icon().unwrap().icon_id(), "icon.bookmark.info");
        assert_eq!(bt.get_marker_color(), Some(MarkerColor::rgb(0, 255, 0)));
        assert_eq!(bt.get_marker_priority(), 5);
    }

    #[test]
    fn to_string_returns_type_string() {
        let bt = BookmarkTypeDb::new(2, "Warning");
        assert_eq!(bt.to_string(), "Warning");
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let bt: Box<dyn BookmarkType> = Box::new(BookmarkTypeDb::new(0, "Analysis"));
        assert_eq!(bt.get_type_string(), "Analysis");
    }
}
