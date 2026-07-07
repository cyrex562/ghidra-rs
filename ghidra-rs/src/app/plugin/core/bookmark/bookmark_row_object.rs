use std::cmp::Ordering;
use std::fmt;

/// A row object representing a bookmark in a table, identified by a unique numeric key.
#[derive(Clone, Copy, Debug)]
pub struct BookmarkRowObject {
    key: i64,
}

impl BookmarkRowObject {
    pub fn new(key: i64) -> Self {
        Self { key }
    }

    pub fn key(&self) -> i64 {
        self.key
    }
}

impl PartialEq for BookmarkRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for BookmarkRowObject {}

impl std::hash::Hash for BookmarkRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl PartialOrd for BookmarkRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BookmarkRowObject {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl fmt::Display for BookmarkRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BookmarkRowObject[key={}]", self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_new_and_key() {
        let obj = BookmarkRowObject::new(42);
        assert_eq!(obj.key(), 42);
    }

    #[test]
    fn test_equality() {
        let a = BookmarkRowObject::new(10);
        let b = BookmarkRowObject::new(10);
        let c = BookmarkRowObject::new(20);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_ordering() {
        let lo = BookmarkRowObject::new(1);
        let hi = BookmarkRowObject::new(2);
        assert!(lo < hi);
        assert!(hi > lo);
        assert_eq!(lo.cmp(&lo), Ordering::Equal);
    }

    #[test]
    fn test_negative_key_ordering() {
        let neg = BookmarkRowObject::new(-5);
        let pos = BookmarkRowObject::new(5);
        assert!(neg < pos);
    }

    #[test]
    fn test_hash_consistency() {
        let a = BookmarkRowObject::new(99);
        let b = BookmarkRowObject::new(99);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_display() {
        let obj = BookmarkRowObject::new(7);
        assert_eq!(obj.to_string(), "BookmarkRowObject[key=7]");
    }

    #[test]
    fn test_display_negative() {
        let obj = BookmarkRowObject::new(-1);
        assert_eq!(obj.to_string(), "BookmarkRowObject[key=-1]");
    }

    #[test]
    fn test_max_key() {
        let obj = BookmarkRowObject::new(i64::MAX);
        assert_eq!(obj.key(), i64::MAX);
        assert_eq!(obj.to_string(), format!("BookmarkRowObject[key={}]", i64::MAX));
    }
}
