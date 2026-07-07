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
}

impl<T> IdKeyed<T> {
    /// Wraps `obj`.
    pub fn new(obj: T) -> Self {
        Self { obj }
    }
}

impl<T> Hash for IdKeyed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Identity hash: use this wrapper's own address, which is stable for the
        // lifetime of the instance and consistent with reference-identity equality.
        (self as *const Self as usize).hash(state);
    }
}

impl<T> PartialEq for IdKeyed<T> {
    fn eq(&self, other: &Self) -> bool {
        // Java's IDKeyed compares wrapped objects by reference identity
        // (`this.obj == that.obj`). Since an `IdKeyed` owns its `obj`, two
        // distinct instances can never share the same object; only an instance
        // is identity-equal to itself.
        std::ptr::eq(self, other)
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
