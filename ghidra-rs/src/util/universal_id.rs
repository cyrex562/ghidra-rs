use std::fmt;

/// A unique identifier wrapping a 64-bit signed integer value.
///
/// Port of `ghidra.util.UniversalID`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UniversalID {
    id: i64,
}

impl UniversalID {
    pub fn new(id: i64) -> Self {
        Self { id }
    }

    pub fn value(&self) -> i64 {
        self.id
    }
}

impl fmt::Display for UniversalID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn new_and_value() {
        let uid = UniversalID::new(42);
        assert_eq!(uid.value(), 42);
    }

    #[test]
    fn equality_same_id() {
        assert_eq!(UniversalID::new(1), UniversalID::new(1));
    }

    #[test]
    fn equality_different_id() {
        assert_ne!(UniversalID::new(1), UniversalID::new(2));
    }

    #[test]
    fn display_positive() {
        assert_eq!(UniversalID::new(12345).to_string(), "12345");
    }

    #[test]
    fn display_negative() {
        assert_eq!(UniversalID::new(-1).to_string(), "-1");
    }

    #[test]
    fn display_zero() {
        assert_eq!(UniversalID::new(0).to_string(), "0");
    }

    #[test]
    fn display_max() {
        assert_eq!(UniversalID::new(i64::MAX).to_string(), i64::MAX.to_string());
    }

    #[test]
    fn hash_equal_ids_same_bucket() {
        let mut set = HashSet::new();
        set.insert(UniversalID::new(99));
        assert!(set.contains(&UniversalID::new(99)));
        assert!(!set.contains(&UniversalID::new(100)));
    }

    #[test]
    fn copy_clone() {
        let a = UniversalID::new(7);
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }
}
