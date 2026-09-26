/// Immutable information about a specific version of a versioned item.
///
/// Port of `ghidra.framework.store.Version`. The Java class implements `Serializable` via a
/// custom `writeObject`/`readObject` pair that writes a leading format-version tag (`VERSION =
/// 1`) followed by the four fields, and rejects deserializing a payload tagged with a newer
/// format version than the reader understands. This port uses plain derived
/// [`serde::Serialize`]/[`serde::Deserialize`] (matching the convention used for other
/// `Serializable` ports, e.g.
/// [`ServerInfo`](crate::framework::model::server_info::ServerInfo)) rather than replicating that
/// hand-rolled wire format, since nothing in this codebase deserializes the Java form directly.
///
/// One field-level quirk *is* preserved by the constructor accepting any string for `comment`:
/// Java's `writeObject` substitutes `""` for a `null` comment on write, but `readObject` does not
/// re-apply that substitution on read (it calls `in.readUTF()` unconditionally), and the public
/// getter (`getComment()`) never normalizes a `null` set via the constructor either. A `Version`
/// constructed directly with a `null` comment and never serialized keeps returning `null` from
/// `getComment()`. This port's `comment` is a plain (non-`Option`) `String`, so there is no `null`
/// state to reproduce; `""` is used as the not-applicable/empty case, matching the *serialized*
/// Java behavior.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ItemVersion {
    version: i32,
    create_time: i64,
    user: String,
    comment: String,
}

impl ItemVersion {
    /// Creates a new `ItemVersion`. Port of `Version(int, long, String, String)`.
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

    /// Returns the version number. Port of `getVersion()`.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the time (milliseconds since Unix epoch) at which the version was created. Port
    /// of `getCreateTime()`.
    pub fn create_time(&self) -> i64 {
        self.create_time
    }

    /// Returns the version comment. Port of `getComment()`.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns the name of the user who created this version. Port of `getUser()`.
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

    /// Stands in for the round-trip that Java's custom `writeObject`/`readObject` performs,
    /// using derived `serde` (de)serialization rather than the hand-rolled Java wire format (see
    /// the type-level doc comment).
    #[test]
    fn test_serde_roundtrip() {
        let v = make_version();
        let json = serde_json::to_string(&v).expect("serialize");
        let back: ItemVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, back);
    }
}
