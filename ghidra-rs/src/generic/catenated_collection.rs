use crate::generic::abstract_unioned_collection::UnionedCollection;

/// A collection that concatenates multiple inner collections in order.
///
/// Mirrors `generic.CatenatedCollection` from Ghidra. The Java class extends
/// `AbstractUnionedCollection` and overrides `iterator()` to produce a flat,
/// in-order concatenation via `Stream.flatMap`. The Rust [`UnionedCollection`]
/// already provides that semantics through [`UnionedCollection::iter`], so this
/// is a transparent newtype that delegates everything to it.
pub struct CatenatedCollection<E>(UnionedCollection<E>);

impl<E> CatenatedCollection<E> {
    /// Creates a `CatenatedCollection` from a vec of inner vecs.
    pub fn new(collections: Vec<Vec<E>>) -> Self {
        Self(UnionedCollection::new(collections))
    }

    /// Total number of elements across all inner collections.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if every inner collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over every element in all inner collections, in order.
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.0.iter()
    }

    /// Clears all inner collections.
    pub fn clear(&mut self) {
        self.0.clear()
    }
}

impl<E: PartialEq> CatenatedCollection<E> {
    /// Returns `true` if any inner collection contains `e`.
    pub fn contains(&self, e: &E) -> bool {
        self.0.contains(e)
    }

    /// Removes the first occurrence of `e` across the inner collections.
    pub fn remove(&mut self, e: &E) -> bool {
        self.0.remove(e)
    }

    /// Removes all elements also present in `other`.
    pub fn remove_all(&mut self, other: &[E]) -> bool {
        self.0.remove_all(other)
    }

    /// Retains only elements also present in `other`.
    pub fn retain_all(&mut self, other: &[E]) -> bool {
        self.0.retain_all(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make() -> CatenatedCollection<i32> {
        CatenatedCollection::new(vec![vec![1, 2, 3], vec![4, 5, 6]])
    }

    #[test]
    fn test_iter_order() {
        let cc = make();
        let items: Vec<&i32> = cc.iter().collect();
        assert_eq!(items, [&1, &2, &3, &4, &5, &6]);
    }

    #[test]
    fn test_len() {
        assert_eq!(make().len(), 6);
    }

    #[test]
    fn test_is_empty_false() {
        assert!(!make().is_empty());
    }

    #[test]
    fn test_is_empty_true() {
        let cc: CatenatedCollection<i32> = CatenatedCollection::new(vec![vec![], vec![]]);
        assert!(cc.is_empty());
    }

    #[test]
    fn test_is_empty_no_collections() {
        let cc: CatenatedCollection<i32> = CatenatedCollection::new(vec![]);
        assert!(cc.is_empty());
    }

    #[test]
    fn test_contains_found() {
        assert!(make().contains(&4));
    }

    #[test]
    fn test_contains_not_found() {
        assert!(!make().contains(&99));
    }

    #[test]
    fn test_remove() {
        let mut cc = make();
        assert!(cc.remove(&3));
        assert_eq!(cc.len(), 5);
        assert!(!cc.contains(&3));
    }

    #[test]
    fn test_remove_absent() {
        let mut cc = make();
        assert!(!cc.remove(&99));
        assert_eq!(cc.len(), 6);
    }

    #[test]
    fn test_remove_all() {
        let mut cc = make();
        assert!(cc.remove_all(&[1, 4]));
        assert!(!cc.contains(&1));
        assert!(!cc.contains(&4));
        assert_eq!(cc.len(), 4);
    }

    #[test]
    fn test_retain_all() {
        let mut cc = make();
        assert!(cc.retain_all(&[2, 5]));
        let items: Vec<&i32> = cc.iter().collect();
        assert_eq!(items, [&2, &5]);
    }

    #[test]
    fn test_clear() {
        let mut cc = make();
        cc.clear();
        assert!(cc.is_empty());
        assert_eq!(cc.len(), 0);
    }

    #[test]
    fn test_single_collection() {
        let cc = CatenatedCollection::new(vec![vec![10, 20, 30]]);
        let items: Vec<&i32> = cc.iter().collect();
        assert_eq!(items, [&10, &20, &30]);
    }

    #[test]
    fn test_empty_collections_interspersed() {
        let cc = CatenatedCollection::new(vec![vec![1], vec![], vec![2]]);
        let items: Vec<&i32> = cc.iter().collect();
        assert_eq!(items, [&1, &2]);
    }

    #[test]
    fn test_three_collections_order() {
        let cc = CatenatedCollection::new(vec![vec![1, 2], vec![3, 4], vec![5, 6]]);
        let items: Vec<&i32> = cc.iter().collect();
        assert_eq!(items, [&1, &2, &3, &4, &5, &6]);
    }
}
