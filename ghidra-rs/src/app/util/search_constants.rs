//! Constants for search functionality in Ghidra.
//!
//! Provides miscellaneous constants for search operations, including search limits,
//! option names, and highlighting colors for search results.

use crate::app::seam_stubs::GColor;

/// The default search limit.
pub const DEFAULT_SEARCH_LIMIT: i32 = 500;

/// Name of the Options object for Search.
pub const SEARCH_OPTION_NAME: &str = "Search";

/// Option for the max number of hits found in a search; the search
/// stops when it reaches this limit.
pub const SEARCH_LIMIT_NAME: &str = "Search Limit";

/// Option name for whether to highlight search results.
pub const SEARCH_HIGHLIGHT_NAME: &str = "Highlight Search Results";

/// Color for highlighting for searches.
pub const SEARCH_HIGHLIGHT_COLOR_OPTION_NAME: &str = " Highlight Color";

/// GColor instance for highlighting search results.
pub const SEARCH_HIGHLIGHT_COLOR: GColor = GColor::new("color.bg.search.highlight");

/// Option name for the highlight color used when something to highlight is at the current address.
pub const SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME: &str = "Highlight Color for Current Match";

/// GColor instance for highlighting the current search result match at the current address.
pub const SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR: GColor =
    GColor::new("color.bg.search.highlight.current.line");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_search_limit() {
        assert_eq!(DEFAULT_SEARCH_LIMIT, 500);
    }

    #[test]
    fn test_search_option_name() {
        assert_eq!(SEARCH_OPTION_NAME, "Search");
    }

    #[test]
    fn test_search_limit_name() {
        assert_eq!(SEARCH_LIMIT_NAME, "Search Limit");
    }

    #[test]
    fn test_search_highlight_name() {
        assert_eq!(SEARCH_HIGHLIGHT_NAME, "Highlight Search Results");
    }

    #[test]
    fn test_search_highlight_color_option_name() {
        assert_eq!(SEARCH_HIGHLIGHT_COLOR_OPTION_NAME, " Highlight Color");
    }

    #[test]
    fn test_search_highlight_current_color_option_name() {
        assert_eq!(
            SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME,
            "Highlight Color for Current Match"
        );
    }

    #[test]
    fn test_search_highlight_color() {
        assert_eq!(SEARCH_HIGHLIGHT_COLOR.get_id(), "color.bg.search.highlight");
    }

    #[test]
    fn test_search_highlight_current_addr_color() {
        assert_eq!(
            SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR.get_id(),
            "color.bg.search.highlight.current.line"
        );
    }

    #[test]
    fn test_all_color_constants_are_valid() {
        // Verify that all GColor constants have non-empty IDs
        assert!(!SEARCH_HIGHLIGHT_COLOR.get_id().is_empty());
        assert!(!SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR.get_id().is_empty());
    }
}
