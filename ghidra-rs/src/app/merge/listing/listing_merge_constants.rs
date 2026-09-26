//! Constants used throughout all of the Listing merge managers for multi-user merges.
//!
//! Ported from `ghidra.app.merge.listing.ListingMergeConstants`, a Java constant-interface
//! (no methods, only `static final` fields). Rust has no need for a class to hang statics off,
//! so these are free `pub const`s rather than a fieldless struct.

use crate::app::seam_stubs::merge_constants;

/// Conflict Option indicating the user canceled the merge.
pub const CANCELED: i32 = -1;
/// Conflict Option indicating to prompt the user for a response.
pub const ASK_USER: i32 = 0;
/// Indicates a row on the conflicts panel is strictly information and doesn't contain a choice.
pub const INFO_ROW: i32 = 0;
/// Keep the Original program's information to resolve a conflict.
pub const KEEP_ORIGINAL: i32 = 1;
/// Keep the Latest program's information to resolve a conflict.
pub const KEEP_LATEST: i32 = 2;
/// Keep My program's information to resolve a conflict.
pub const KEEP_MY: i32 = 4;
/// Keep Result program's existing information to resolve a conflict.
pub const KEEP_RESULT: i32 = 8;
/// Keep both the Latest program's and My program's information to resolve a conflict.
pub const KEEP_BOTH: i32 = KEEP_LATEST | KEEP_MY;
/// Keep the Original program's, the Latest program's, and My program's information to resolve
/// a conflict.
pub const KEEP_ALL: i32 = KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL;
/// Remove the Latest program's conflict item to resolve a conflict.
pub const REMOVE_LATEST: i32 = 8;
/// Rename the conflict item as in the Latest program to resolve a conflict.
pub const RENAME_LATEST: i32 = 16;
/// Remove the My program's conflict item to resolve a conflict.
pub const REMOVE_MY: i32 = 32;
/// Rename the conflict item as in My program to resolve a conflict.
pub const RENAME_MY: i32 = 64;

/// Maximum length to display before truncating occurs in conflict panel.
/// This is needed for comments, etc. which could be very large.
pub const TRUNCATE_LENGTH: i32 = 160;

// Standardized strings for referring to each of the versioned programs.
pub const RESULT_TITLE: &str = merge_constants::RESULT_TITLE;
pub const ORIGINAL_TITLE: &str = merge_constants::ORIGINAL_TITLE;
pub const LATEST_TITLE: &str = merge_constants::LATEST_TITLE;
pub const MY_TITLE: &str = merge_constants::MY_TITLE;

// The following are names necessary for referencing GUI components.
pub const LATEST_LIST_BUTTON_NAME: &str = "LatestListRB";
pub const CHECKED_OUT_LIST_BUTTON_NAME: &str = "CheckedOutListRB";
pub const LATEST_BUTTON_NAME: &str = "LatestVersionRB";
pub const CHECKED_OUT_BUTTON_NAME: &str = "CheckedOutVersionRB";
pub const ORIGINAL_BUTTON_NAME: &str = "OriginalVersionRB";
pub const RESULT_BUTTON_NAME: &str = "ResultVersionRB";
pub const LATEST_CHECK_BOX_NAME: &str = "LatestVersionCheckBox";
pub const CHECKED_OUT_CHECK_BOX_NAME: &str = "CheckedOutVersionCheckBox";
pub const ORIGINAL_CHECK_BOX_NAME: &str = "OriginalVersionCheckBox";
pub const LATEST_LABEL_NAME: &str = "LatestVersionLabel";
pub const CHECKED_OUT_LABEL_NAME: &str = "CheckedOutVersionLabel";
pub const ORIGINAL_LABEL_NAME: &str = "OriginalVersionLabel";
pub const REMOVE_LATEST_BUTTON_NAME: &str = "RemoveLatestRB";
pub const RENAME_LATEST_BUTTON_NAME: &str = "RenameLatestRB";
pub const REMOVE_CHECKED_OUT_BUTTON_NAME: &str = "RemoveCheckedOutRB";
pub const RENAME_CHECKED_OUT_BUTTON_NAME: &str = "RenameCheckedOutRB";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_option_bit_flags_match_java() {
        // Java: KEEP_BOTH = KEEP_LATEST | KEEP_MY; KEEP_ALL = KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL
        assert_eq!(KEEP_BOTH, 6);
        assert_eq!(KEEP_ALL, 7);
        assert_eq!(REMOVE_LATEST, KEEP_RESULT); // both defined as 8 in Java
    }

    #[test]
    fn version_titles_come_from_merge_constants() {
        assert_eq!(RESULT_TITLE, "Result");
        assert_eq!(ORIGINAL_TITLE, "Original");
        assert_eq!(LATEST_TITLE, "Latest");
        assert_eq!(MY_TITLE, "Checked Out");
    }

    #[test]
    fn gui_component_names_match_java() {
        assert_eq!(LATEST_LIST_BUTTON_NAME, "LatestListRB");
        assert_eq!(RENAME_CHECKED_OUT_BUTTON_NAME, "RenameCheckedOutRB");
        assert_eq!(TRUNCATE_LENGTH, 160);
    }
}
