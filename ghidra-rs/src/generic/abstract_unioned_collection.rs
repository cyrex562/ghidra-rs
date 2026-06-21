/// A collection that presents the logical union of multiple inner collections.
///
/// Mirrors `generic.AbstractUnionedCollection` from Ghidra. In Java this was an
/// abstract class extending `AbstractCollection`; here it is a concrete, generic
/// struct. All mutating operations are applied across every inner collection in
/// order, matching the Java semantics.
pub struct UnionedCollection<E> {
    collections: Vec<Vec<E>>,
}

impl<E> UnionedCollection<E> {
    /// Creates a `UnionedCollection` wrapping the given inner collections.
    pub fn new(collections: Vec<Vec<E>>) -> Self {
        Self { collections }
    }

    /// Total number of elements across all inner collections.
    pub fn len(&self) -> usize {
        self.collections.iter().map(|c| c.len()).sum()
    }

    /// Returns `true` if every inner collection is empty.
    pub fn is_empty(&self) -> bool {
        self.collections.iter().all(|c| c.is_empty())
    }

    /// Clears all inner collections.
    pub fn clear(&mut self) {
        for c in &mut self.collections {
            c.clear();
        }
    }

    /// Iterates over every element in all inner collections, in order.
    pub fn iter(&self) -> impl Iterator<Item = &E> {
        self.collections.iter().flat_map(|c| c.iter())
    }
}

impl<E: PartialEq> UnionedCollection<E> {
    /// Returns `true` if any inner collection contains `e`.
    pub fn contains(&self, e: &E) -> bool {
        self.collections.iter().any(|c| c.contains(e))
    }

    /// Removes the first occurrence of `e` found across the inner collections.
    /// Returns `true` if an element was removed.
    pub fn remove(&mut self, e: &E) -> bool {
        for c in &mut self.collections {
            if let Some(pos) = c.iter().position(|x| x == e) {
                c.remove(pos);
                return true;
            }
        }
        false
    }

    /// Removes from each inner collection every element that is also present in `other`.
    /// Returns `true` if any collection was modified.
    pub fn remove_all(&mut self, other: &[E]) -> bool {
        let mut changed = false;
        for c in &mut self.collections {
            let before = c.len();
            c.retain(|x| !other.contains(x));
            changed |= c.len() != before;
        }
        changed
    }

    /// Retains in each inner collection only the elements that are also present in `other`.
    /// Returns `true` if any collection was modified.
    pub fn retain_all(&mut self, other: &[E]) -> bool {
        let mut changed = false;
        for c in &mut self.collections {
            let before = c.len();
            c.retain(|x| other.contains(x));
            changed |= c.len() != before;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make() -> UnionedCollection<i32> {
        UnionedCollection::new(vec![vec![1, 2, 3], vec![4, 5, 6]])
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
        let uc: UnionedCollection<i32> = UnionedCollection::new(vec![vec![], vec![]]);
        assert!(uc.is_empty());
    }

    #[test]
    fn test_is_empty_no_collections() {
        let uc: UnionedCollection<i32> = UnionedCollection::new(vec![]);
        assert!(uc.is_empty());
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
    fn test_remove_first_collection() {
        let mut uc = make();
        assert!(uc.remove(&2));
        assert_eq!(uc.len(), 5);
        assert!(!uc.contains(&2));
    }

    #[test]
    fn test_remove_second_collection() {
        let mut uc = make();
        assert!(uc.remove(&5));
        assert_eq!(uc.len(), 5);
        assert!(!uc.contains(&5));
    }

    #[test]
    fn test_remove_absent() {
        let mut uc = make();
        assert!(!uc.remove(&99));
        assert_eq!(uc.len(), 6);
    }

    #[test]
    fn test_remove_all() {
        let mut uc = make();
        let changed = uc.remove_all(&[2, 5]);
        assert!(changed);
        assert!(!uc.contains(&2));
        assert!(!uc.contains(&5));
        assert_eq!(uc.len(), 4);
    }

    #[test]
    fn test_remove_all_no_overlap() {
        let mut uc = make();
        let changed = uc.remove_all(&[99, 100]);
        assert!(!changed);
        assert_eq!(uc.len(), 6);
    }

    #[test]
    fn test_retain_all() {
        let mut uc = make();
        let changed = uc.retain_all(&[1, 4]);
        assert!(changed);
        assert_eq!(uc.len(), 2);
        assert!(uc.contains(&1));
        assert!(uc.contains(&4));
        assert!(!uc.contains(&2));
    }

    #[test]
    fn test_retain_all_no_change() {
        let mut uc = make();
        let changed = uc.retain_all(&[1, 2, 3, 4, 5, 6]);
        assert!(!changed);
        assert_eq!(uc.len(), 6);
    }

    #[test]
    fn test_clear() {
        let mut uc = make();
        uc.clear();
        assert!(uc.is_empty());
        assert_eq!(uc.len(), 0);
    }

    #[test]
    fn test_iter_order() {
        let uc = make();
        let items: Vec<&i32> = uc.iter().collect();
        assert_eq!(items, [&1, &2, &3, &4, &5, &6]);
    }
}
