use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

/// Identity-based wrapper providing reference-equality and identity-based hashing.
///
/// Mirrors `generic.ID<T>` from Ghidra. Two `Id` instances are equal iff they
/// hold a pointer to the same allocation, regardless of the wrapped value's own
/// equality semantics. The hash is derived from the allocation address, matching
/// Java's `System.identityHashCode`.
pub struct Id<T> {
    obj: Rc<T>,
}

impl<T> Id<T> {
    /// Wraps an existing `Rc<T>`, preserving shared identity.
    ///
    /// Two `Id`s created from clones of the same `Rc` will compare equal,
    /// mirroring `ID.of(obj)` called twice with the same Java reference.
    pub fn of(obj: Rc<T>) -> Self {
        Self { obj }
    }

    /// Allocates `obj` on the heap and returns an `Id` owning that allocation.
    pub fn new(obj: T) -> Self {
        Self { obj: Rc::new(obj) }
    }

    /// Returns a reference to the wrapped object.
    pub fn get_object(&self) -> &T {
        &self.obj
    }

    /// Returns a clone of the inner `Rc<T>`, allowing shared ownership.
    pub fn rc(&self) -> Rc<T> {
        Rc::clone(&self.obj)
    }
}

impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({:p})", Rc::as_ptr(&self.obj))
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        Self { obj: Rc::clone(&self.obj) }
    }
}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.obj, &other.obj)
    }
}

impl<T> Eq for Id<T> {}

impl<T> Hash for Id<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Rc::as_ptr(&self.obj).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_same_rc_are_equal() {
        let rc = Rc::new(42);
        let id1 = Id::of(Rc::clone(&rc));
        let id2 = Id::of(Rc::clone(&rc));
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_allocations_not_equal() {
        let id1 = Id::new(42);
        let id2 = Id::new(42);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_clone_is_equal() {
        let id = Id::new(99);
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn test_get_object() {
        let id = Id::new("hello");
        assert_eq!(*id.get_object(), "hello");
    }

    #[test]
    fn test_of_preserves_identity() {
        let rc = Rc::new(String::from("world"));
        let id = Id::of(Rc::clone(&rc));
        assert_eq!(id.get_object().as_str(), "world");
        assert!(Rc::ptr_eq(&id.rc(), &rc));
    }

    #[test]
    fn test_hash_consistent_with_eq() {
        let rc = Rc::new(7u32);
        let id1 = Id::of(Rc::clone(&rc));
        let id2 = Id::of(Rc::clone(&rc));
        // Equal Ids must hash the same — HashSet membership verifies this.
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_distinct_ids_may_differ_in_hash_set() {
        let id1 = Id::new(1u32);
        let id2 = Id::new(1u32);
        let mut set = HashSet::new();
        set.insert(id1);
        // id2 has a different allocation, so it is a distinct key.
        assert!(!set.contains(&id2));
    }

    #[test]
    fn test_reflexive_equality() {
        let id = Id::new(0i32);
        assert_eq!(id, id.clone());
    }
}
