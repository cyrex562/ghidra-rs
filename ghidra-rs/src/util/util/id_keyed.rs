use std::fmt;
use std::hash::{Hash, Hasher};

/// Wrapper that uses pointer-identity for both hashing and equality.
///
/// Mirrors Java's `IDKeyed<T>`, which extends `IDHashed<T>` and overrides
/// `equals()` to compare wrapped objects by reference identity (`==`) rather
/// than by value. Two `IdKeyed` values are considered equal if and only if
/// they were constructed from the same object reference (i.e., their
/// captured pointer addresses match).
pub struct IdKeyed<T> {
    /// The wrapped object.
    pub obj: T,
    hash_code: u64,
}

impl<T> IdKeyed<T> {
    /// Wraps `obj`, capturing its current address as the identity hash code.
    pub fn new(obj: T) -> Self {
        let hash_code = &obj as *const T as u64;
        Self { obj, hash_code }
    }
}

impl<T> Hash for IdKeyed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code.hash(state);
    }
}

impl<T> PartialEq for IdKeyed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hash_code == other.hash_code
    }
}

impl<T> Eq for IdKeyed<T> {}

impl<T: fmt::Display> fmt::Display for IdKeyed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.obj.fmt(f)
    }
}

impl<T: fmt::Debug> fmt::Debug for IdKeyed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdKeyed")
            .field("obj", &self.obj)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash_of<T: Hash>(v: &T) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn obj_is_accessible() {
        let w = IdKeyed::new(42i32);
        assert_eq!(w.obj, 42);
    }

    #[test]
    fn reflexive_equality() {
        let a = IdKeyed::new(String::from("hello"));
        assert_eq!(a, a);
    }

    #[test]
    fn different_values_not_equal() {
        let a = IdKeyed::new(1i32);
        let b = IdKeyed::new(2i32);
        assert_ne!(a, b);
    }

    #[test]
    fn identity_not_value_equality() {
        // Two separately constructed instances wrapping the same value are
        // distinct objects, so IdKeyed treats them as unequal (unlike IdHashed).
        let a = IdKeyed::new(String::from("hello"));
        let b = IdKeyed::new(String::from("hello"));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_stable_per_instance() {
        let w = IdKeyed::new(99i32);
        assert_eq!(hash_of(&w), hash_of(&w));
    }

    #[test]
    fn display_delegates_to_obj() {
        let w = IdKeyed::new(String::from("test_value"));
        assert_eq!(w.to_string(), "test_value");
    }

    #[test]
    fn display_numeric() {
        let w = IdKeyed::new(42i32);
        assert_eq!(w.to_string(), "42");
    }

    #[test]
    fn debug_contains_obj() {
        let w = IdKeyed::new(7i32);
        let s = format!("{:?}", w);
        assert!(s.contains("IdKeyed"));
        assert!(s.contains("7"));
    }
}
