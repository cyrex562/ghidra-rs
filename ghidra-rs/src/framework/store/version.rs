/// Immutable information about a specific version of a versioned item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemVersion {
    version: i32,
    create_time: i64,
    user: String,
    comment: String,
}

impl ItemVersion {
    /// Creates a new `ItemVersion`.
    ///
    /// - `version`: file version number
    /// - `create_time`: milliseconds since the Unix epoch when the version was created
    /// - `user`: name of the user who created the version
    /// - `comment`: version comment (may be empty)
    pub fn new(
        version: i32,
        create_time: i64,
        user: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            version,
            create_time,
            user: user.into(),
            comment: comment.into(),
        }
    }

    /// Returns the version number.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the time (milliseconds since Unix epoch) at which the version was created.
    pub fn create_time(&self) -> i64 {
        self.create_time
    }

    /// Returns the version comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns the name of the user who created this version.
    pub fn user(&self) -> &str {
        &self.user
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version() -> ItemVersion {
        ItemVersion::new(3, 1_700_000_000_000, "alice", "initial commit")
    }

    #[test]
    fn test_accessors() {
        let v = make_version();
        assert_eq!(v.version(), 3);
        assert_eq!(v.create_time(), 1_700_000_000_000);
        assert_eq!(v.user(), "alice");
        assert_eq!(v.comment(), "initial commit");
    }

    #[test]
    fn test_empty_comment() {
        let v = ItemVersion::new(1, 0, "bob", "");
        assert_eq!(v.comment(), "");
    }

    #[test]
    fn test_clone_eq() {
        let v = make_version();
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn test_ne_different_version() {
        let a = ItemVersion::new(1, 0, "alice", "msg");
        let b = ItemVersion::new(2, 0, "alice", "msg");
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_user() {
        let a = ItemVersion::new(1, 0, "alice", "msg");
        let b = ItemVersion::new(1, 0, "bob", "msg");
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_comment() {
        let a = ItemVersion::new(1, 0, "alice", "foo");
        let b = ItemVersion::new(1, 0, "alice", "bar");
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_time() {
        let a = ItemVersion::new(1, 100, "alice", "msg");
        let b = ItemVersion::new(1, 200, "alice", "msg");
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(make_version());
        set.insert(make_version());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_debug_contains_fields() {
        let v = make_version();
        let s = format!("{:?}", v);
        assert!(s.contains("ItemVersion"));
        assert!(s.contains("alice"));
    }
}
