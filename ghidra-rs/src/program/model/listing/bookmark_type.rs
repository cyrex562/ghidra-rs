use crate::program::model::data::playable::Icon;

/// Standard bookmark type name for general notes.
pub const NOTE: &str = "Note";
/// Standard bookmark type name for informational bookmarks.
pub const INFO: &str = "Info";
/// Standard bookmark type name for error bookmarks.
pub const ERROR: &str = "Error";
/// Standard bookmark type name for warning bookmarks.
pub const WARNING: &str = "Warning";
/// Standard bookmark type name for analysis bookmarks.
pub const ANALYSIS: &str = "Analysis";

/// RGBA marker color, standing in for `java.awt.Color` as used by
/// [`BookmarkType::get_marker_color`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MarkerColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl MarkerColor {
    /// Creates an opaque color from RGB components.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Creates a color from RGBA components.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }
}

/// Interface for bookmark types.
///
/// Port of `ghidra.program.model.listing.BookmarkType`.
pub trait BookmarkType {
    /// Returns the type as a string.
    fn get_type_string(&self) -> &str;

    /// Returns the icon associated with this type, or `None` if one has not been set by a
    /// plugin.
    fn get_icon(&self) -> Option<Box<dyn Icon>>;

    /// Returns the marker color associated with this type, or `None` if one has not been set
    /// by a plugin.
    fn get_marker_color(&self) -> Option<MarkerColor>;

    /// Returns the marker priority associated with this type, or `-1` if one has not been set
    /// by a plugin.
    fn get_marker_priority(&self) -> i32;

    /// Returns true if there is at least one bookmark defined for this type.
    fn has_bookmarks(&self) -> bool;

    /// Returns the id associated with this bookmark type.
    fn get_type_id(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockIcon;

    impl Icon for MockIcon {
        fn icon_id(&self) -> &str {
            "icon.bookmark.mock"
        }
    }

    struct MockBookmarkType {
        type_string: String,
        type_id: i32,
        has_bookmarks: bool,
    }

    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            &self.type_string
        }

        fn get_icon(&self) -> Option<Box<dyn Icon>> {
            Some(Box::new(MockIcon))
        }

        fn get_marker_color(&self) -> Option<MarkerColor> {
            Some(MarkerColor::rgb(255, 0, 0))
        }

        fn get_marker_priority(&self) -> i32 {
            -1
        }

        fn has_bookmarks(&self) -> bool {
            self.has_bookmarks
        }

        fn get_type_id(&self) -> i32 {
            self.type_id
        }
    }

    #[test]
    fn reports_configured_values() {
        let bt = MockBookmarkType {
            type_string: NOTE.to_string(),
            type_id: 3,
            has_bookmarks: true,
        };
        assert_eq!(bt.get_type_string(), "Note");
        assert_eq!(bt.get_type_id(), 3);
        assert!(bt.has_bookmarks());
        assert_eq!(bt.get_marker_priority(), -1);
        assert_eq!(bt.get_marker_color(), Some(MarkerColor::rgb(255, 0, 0)));
        assert_eq!(bt.get_icon().unwrap().icon_id(), "icon.bookmark.mock");
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let bt: Box<dyn BookmarkType> = Box::new(MockBookmarkType {
            type_string: ANALYSIS.to_string(),
            type_id: 0,
            has_bookmarks: false,
        });
        assert_eq!(bt.get_type_string(), "Analysis");
        assert!(!bt.has_bookmarks());
    }

    #[test]
    fn standard_type_constants_match_java() {
        assert_eq!(NOTE, "Note");
        assert_eq!(INFO, "Info");
        assert_eq!(ERROR, "Error");
        assert_eq!(WARNING, "Warning");
        assert_eq!(ANALYSIS, "Analysis");
    }
}
