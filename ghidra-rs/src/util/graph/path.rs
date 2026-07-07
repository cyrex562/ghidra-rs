use std::sync::Arc;

/// A vector of paths, where each path is a sequence of reference-counted items.
///
/// Elements within each path are compared by pointer identity, matching the Java semantics
/// of `!=` / `==` on `Object` references.
///
/// Port of `ghidra.util.graph.Path` (deprecated since Ghidra 10.2).
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct Path<T: ?Sized> {
    elements: Vec<Vec<Arc<T>>>,
}

#[allow(deprecated)]
impl<T: ?Sized> Path<T> {
    /// Creates an empty `Path`.
    pub fn new() -> Self {
        Self { elements: Vec::new() }
    }

    /// Returns `true` if any stored path has at least as many elements as `other`
    /// and every element of `other` is the same pointer as the corresponding element
    /// of that stored path.
    pub fn contains_in_some_element(&self, other: &[Arc<T>]) -> bool {
        for path in &self.elements {
            if path.len() >= other.len() && Self::has_same_children(path, other) {
                return true;
            }
        }
        false
    }

    fn has_same_children(v1: &[Arc<T>], v2: &[Arc<T>]) -> bool {
        v2.iter().zip(v1.iter()).all(|(a, b)| Arc::ptr_eq(a, b))
    }
}

#[allow(deprecated)]
impl<T: ?Sized> Default for Path<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)]
impl<T: ?Sized> std::ops::Deref for Path<T> {
    type Target = Vec<Vec<Arc<T>>>;

    fn deref(&self) -> &Self::Target {
        &self.elements
    }
}

#[allow(deprecated)]
impl<T: ?Sized> std::ops::DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.elements
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let p: Path<str> = Path::new();
        assert!(p.is_empty());
    }

    #[test]
    fn default_is_empty() {
        let p: Path<str> = Path::default();
        assert!(p.is_empty());
    }

    #[test]
    fn push_and_len_via_deref() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        p.push(vec![a]);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn contains_in_some_element_matches_by_pointer() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(10u32);
        let b = Arc::new(20u32);
        p.push(vec![Arc::clone(&a), Arc::clone(&b)]);

        // exact match
        assert!(p.contains_in_some_element(&[Arc::clone(&a), Arc::clone(&b)]));
    }

    #[test]
    fn contains_in_some_element_prefix_of_stored_path() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        let b = Arc::new(2u32);
        let c = Arc::new(3u32);
        p.push(vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);

        // other is shorter — stored path has >= length, should match
        assert!(p.contains_in_some_element(&[Arc::clone(&a), Arc::clone(&b)]));
    }

    #[test]
    fn contains_in_some_element_other_longer_than_stored_path() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        let b = Arc::new(2u32);
        p.push(vec![Arc::clone(&a)]);

        // other is longer than the stored path — cannot match
        assert!(!p.contains_in_some_element(&[Arc::clone(&a), Arc::clone(&b)]));
    }

    #[test]
    fn contains_in_some_element_different_pointer_not_equal() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        p.push(vec![Arc::clone(&a)]);

        // different Arc pointing to equal value but different allocation
        let a2 = Arc::new(1u32);
        assert!(!p.contains_in_some_element(&[Arc::clone(&a2)]));
    }

    #[test]
    fn contains_in_some_element_empty_other_always_true() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        p.push(vec![Arc::clone(&a)]);

        // empty other: has_same_children vacuously true; stored path len (1) >= 0
        assert!(p.contains_in_some_element(&[]));
    }

    #[test]
    fn contains_in_some_element_empty_path_list() {
        let p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        assert!(!p.contains_in_some_element(&[Arc::clone(&a)]));
    }

    #[test]
    fn contains_in_some_element_matches_second_path() {
        let mut p: Path<u32> = Path::new();
        let a = Arc::new(1u32);
        let b = Arc::new(2u32);
        // first path doesn't match
        p.push(vec![Arc::clone(&b)]);
        // second path matches
        p.push(vec![Arc::clone(&a)]);

        assert!(p.contains_in_some_element(&[Arc::clone(&a)]));
    }
}
