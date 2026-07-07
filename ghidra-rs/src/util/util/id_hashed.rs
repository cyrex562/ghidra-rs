use std::fmt;
use std::hash::{Hash, Hasher};

/// Wrapper that uses pointer-identity-based hashing with value-based equality.
///
/// Mirrors Java's `IDHashed<T>`, which hashes using `System.identityHashCode`
/// (the object's address at construction time) while delegating equality to the
/// wrapped object's `equals` method.
///
/// # Note on hash/equality contract
/// The hash code is derived from the wrapped value's stack address at construction
/// time. Two `IdHashed` values wrapping equal-but-distinct objects will compare as
/// equal but may have different hash codes. Only use in `HashMap`/`HashSet` when
/// each logical object is always wrapped from the same allocation, matching the
/// Java usage pattern.
pub struct IdHashed<T> {
    /// The wrapped object.
    pub obj: T,
    hash_code: u64,
}

impl<T> IdHashed<T> {
    /// Wraps `obj`, capturing its current address as the identity hash code.
    pub fn new(obj: T) -> Self {
        let hash_code = &obj as *const T as u64;
        Self { obj, hash_code }
    }
}

impl<T: fmt::Display> fmt::Display for IdHashed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.obj.fmt(f)
    }
}

impl<T> Hash for IdHashed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code.hash(state);
    }
}

impl<T: PartialEq> PartialEq for IdHashed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.obj == other.obj
    }
}

impl<T: Eq> Eq for IdHashed<T> {}

impl<T: fmt::Debug> fmt::Debug for IdHashed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdHashed")
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
        let w = IdHashed::new(42i32);
        assert_eq!(w.obj, 42);
    }

    #[test]
    fn equal_when_obj_equal() {
        let a = IdHashed::new(String::from("hello"));
        let b = IdHashed::new(String::from("hello"));
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_obj_differ() {
        let a = IdHashed::new(1i32);
        let b = IdHashed::new(2i32);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_stable_per_instance() {
        let w = IdHashed::new(99i32);
        assert_eq!(hash_of(&w), hash_of(&w));
    }

    #[test]
    fn display_delegates_to_obj() {
        let w = IdHashed::new(String::from("test_value"));
        assert_eq!(w.to_string(), "test_value");
    }

    #[test]
    fn display_numeric() {
        let w = IdHashed::new(42i32);
        assert_eq!(w.to_string(), "42");
    }
}
