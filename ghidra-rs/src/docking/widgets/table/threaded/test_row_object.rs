use std::fmt;

/// A simple row object used in table threading tests, holding a string and a long value.
///
/// Corresponds to `docking.widgets.table.threaded.TestRowObject`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestRowObject {
    s: String,
    l: i64,
}

impl TestRowObject {
    pub fn new(s: impl Into<String>, l: i64) -> Self {
        Self { s: s.into(), l }
    }

    pub fn get_string_value(&self) -> &str {
        &self.s
    }

    pub fn get_long_value(&self) -> i64 {
        self.l
    }
}

impl fmt::Display for TestRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestRowObject[string={}, long={}]", self.s, self.l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn construction_and_getters() {
        let obj = TestRowObject::new("hello", 42);
        assert_eq!(obj.get_string_value(), "hello");
        assert_eq!(obj.get_long_value(), 42);
    }

    #[test]
    fn display_format() {
        let obj = TestRowObject::new("foo", 7);
        assert_eq!(obj.to_string(), "TestRowObject[string=foo, long=7]");
    }

    #[test]
    fn equality_same_fields() {
        let a = TestRowObject::new("x", 1);
        let b = TestRowObject::new("x", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_string() {
        let a = TestRowObject::new("x", 1);
        let b = TestRowObject::new("y", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_long() {
        let a = TestRowObject::new("x", 1);
        let b = TestRowObject::new("x", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_equal_for_equal_objects() {
        let a = TestRowObject::new("abc", 99);
        let b = TestRowObject::new("abc", 99);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn clone_is_equal() {
        let obj = TestRowObject::new("test", 0);
        assert_eq!(obj, obj.clone());
    }
}
