use std::fmt;
use std::time::SystemTime;

use crate::program::model::address::Address;
use crate::program::model::listing::comment_type::CommentType;

/// Container class for information about changes to a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentHistory {
    addr: Address,
    comment_type: CommentType,
    modification_date: SystemTime,
    user_name: String,
    comments: String,
}

impl CommentHistory {
    /// Constructs a new `CommentHistory` object.
    ///
    /// # Arguments
    /// * `addr` - the address of the comment
    /// * `comment_type` - the type of comment
    /// * `user_name` - the name of the user that changed the comment
    /// * `comments` - the list of comments
    /// * `modification_date` - the date the comment was changed
    pub fn new(
        addr: Address,
        comment_type: CommentType,
        user_name: impl Into<String>,
        comments: impl Into<String>,
        modification_date: SystemTime,
    ) -> Self {
        Self {
            addr,
            comment_type,
            user_name: user_name.into(),
            comments: comments.into(),
            modification_date,
        }
    }

    /// Get address for this label history object.
    pub fn address(&self) -> &Address {
        &self.addr
    }

    /// Get the user that made the change.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Get the comments for this history object.
    pub fn comments(&self) -> &str {
        &self.comments
    }

    /// Get the comment type.
    pub fn comment_type(&self) -> CommentType {
        self.comment_type
    }

    /// Get the modification date.
    pub fn modification_date(&self) -> SystemTime {
        self.modification_date
    }
}

impl fmt::Display for CommentHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\n\tuser: {},\n\tdate: {:?},\n\taddress: {},\n\tcomment: {}\n}}",
            self.user_name,
            self.modification_date,
            self.addr,
            abbreviate(&self.comments, 10)
        )
    }
}

/// Truncates `s` to at most `max_width` characters, replacing the final
/// characters with `"..."` when truncation occurs, matching the behavior of
/// Apache Commons Lang's `StringUtils.abbreviate(String, int)`.
fn abbreviate(s: &str, max_width: usize) -> String {
    if s.chars().count() <= max_width {
        return s.to_string();
    }
    let keep = max_width.saturating_sub(3);
    let truncated: String = s.chars().take(keep).collect();
    format!("{truncated}...")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::time::{Duration, UNIX_EPOCH};

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x1000)
    }

    #[test]
    fn stores_fields() {
        let addr = test_address();
        let date = UNIX_EPOCH + Duration::from_secs(100);
        let history = CommentHistory::new(
            addr.clone(),
            CommentType::Eol,
            "user1",
            "a short comment",
            date,
        );

        assert_eq!(history.address(), &addr);
        assert_eq!(history.user_name(), "user1");
        assert_eq!(history.comments(), "a short comment");
        assert_eq!(history.comment_type(), CommentType::Eol);
        assert_eq!(history.modification_date(), date);
    }

    #[test]
    fn abbreviate_short_string_unchanged() {
        assert_eq!(abbreviate("short", 10), "short");
        assert_eq!(abbreviate("exactly10c", 10), "exactly10c");
    }

    #[test]
    fn abbreviate_long_string_truncated() {
        assert_eq!(abbreviate("this is a long comment", 10), "this is...");
    }

    #[test]
    fn display_contains_expected_fields() {
        let addr = test_address();
        let date = UNIX_EPOCH + Duration::from_secs(5);
        let history = CommentHistory::new(
            addr,
            CommentType::Plate,
            "someone",
            "this comment is definitely too long",
            date,
        );

        let text = history.to_string();
        assert!(text.contains("user: someone"));
        assert!(text.contains("address:"));
        assert!(text.contains("comment: this comm..."));
    }

    #[test]
    fn clone_and_equality() {
        let addr = test_address();
        let date = UNIX_EPOCH + Duration::from_secs(7);
        let a = CommentHistory::new(addr.clone(), CommentType::Post, "u", "c", date);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
