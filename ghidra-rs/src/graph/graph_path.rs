use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A path through a graph with O(1) vertex membership testing.
///
/// Vertices are stored in both insertion order (for indexed access and ordering) and
/// a hash set (for fast `contains` checks). Each vertex may appear at most once.
#[derive(Clone)]
pub struct GraphPath<V> {
    path_set: HashSet<V>,
    path_list: Vec<V>,
}

impl<V: Eq + Hash + Clone> GraphPath<V> {
    /// Creates a new empty path.
    pub fn new() -> Self {
        GraphPath {
            path_set: HashSet::new(),
            path_list: Vec::new(),
        }
    }

    /// Creates a new path containing a single vertex.
    pub fn with_vertex(v: V) -> Self {
        let mut path = GraphPath::new();
        path.add(v);
        path
    }

    /// Returns a shallow clone of this path.
    pub fn copy(&self) -> Self {
        GraphPath {
            path_set: self.path_set.clone(),
            path_list: self.path_list.clone(),
        }
    }

    /// Returns `true` if this path begins with every vertex of `other` in the same order.
    pub fn starts_with(&self, other: &GraphPath<V>) -> bool {
        if self.size() < other.size() {
            return false;
        }
        self.path_list[..other.size()] == other.path_list[..]
    }

    /// Returns the longest common prefix shared by this path and `other`.
    ///
    /// For example, given `a-b-c-d-e-f` and `a-b-c-d-k-l-z`, the result is `a-b-c-d`.
    /// Returns an empty path when there is no common prefix.
    pub fn get_common_start_path(&self, other: &GraphPath<V>) -> GraphPath<V> {
        let n = self.size().min(other.size());
        let split = (0..n)
            .find(|&i| self.path_list[i] != other.path_list[i])
            .unwrap_or(n);
        self.sub_path(0, split)
    }

    /// Returns the number of vertices in this path.
    pub fn size(&self) -> usize {
        self.path_list.len()
    }

    /// Returns `true` if `v` is in this path.
    pub fn contains(&self, v: &V) -> bool {
        self.path_set.contains(v)
    }

    /// Appends `v` to the end of this path.
    pub fn add(&mut self, v: V) {
        self.path_set.insert(v.clone());
        self.path_list.push(v);
    }

    /// Returns a reference to the last vertex in this path.
    ///
    /// # Panics
    ///
    /// Panics if the path is empty.
    pub fn get_last(&self) -> &V {
        self.path_list.last().expect("path is empty")
    }

    /// Returns the zero-based depth (index) of `v` in this path, or `None` if absent.
    pub fn depth(&self, v: &V) -> Option<usize> {
        self.path_list.iter().position(|x| x == v)
    }

    /// Returns the vertex at the given zero-based depth.
    ///
    /// # Panics
    ///
    /// Panics if `depth` is out of bounds.
    pub fn get(&self, depth: usize) -> &V {
        &self.path_list[depth]
    }

    /// Removes and returns the last vertex in this path.
    ///
    /// # Panics
    ///
    /// Panics if the path is empty.
    pub fn remove_last(&mut self) -> V {
        let v = self.path_list.pop().expect("path is empty");
        self.path_set.remove(&v);
        v
    }

    /// Returns the set of all vertices at or before `v` in the path (predecessors plus `v`).
    ///
    /// Returns an empty set if `v` is not in the path.
    pub fn get_predecessors(&self, v: &V) -> HashSet<V> {
        self.path_list
            .iter()
            .position(|x| x == v)
            .map(|index| self.path_list[..=index].iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the set of all vertices at or after `v` in the path (successors plus `v`).
    ///
    /// Returns an empty set if `v` is not in the path.
    pub fn get_successors(&self, v: &V) -> HashSet<V> {
        self.path_list
            .iter()
            .position(|x| x == v)
            .map(|index| self.path_list[index..].iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the sub-path from index `start` (inclusive) to `end` (exclusive).
    ///
    /// # Panics
    ///
    /// Panics if `start > end` or either bound is out of range for this path.
    pub fn sub_path(&self, start: usize, end: usize) -> GraphPath<V> {
        let path_list: Vec<V> = self.path_list[start..end].to_vec();
        let path_set: HashSet<V> = path_list.iter().cloned().collect();
        GraphPath { path_set, path_list }
    }
}

impl<V: Eq + Hash + Clone> Default for GraphPath<V> {
    fn default() -> Self {
        GraphPath::new()
    }
}

impl<V: fmt::Debug> fmt::Debug for GraphPath<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path_list.fmt(f)
    }
}

impl<V: Eq + Hash + Clone> PartialEq for GraphPath<V> {
    fn eq(&self, other: &Self) -> bool {
        self.path_list == other.path_list
    }
}

impl<V: Eq + Hash + Clone> Eq for GraphPath<V> {}

impl<V: Eq + Hash + Clone> Hash for GraphPath<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path_list.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let path: GraphPath<i32> = GraphPath::new();
        assert_eq!(path.size(), 0);
    }

    #[test]
    fn test_with_vertex() {
        let path = GraphPath::with_vertex(42i32);
        assert_eq!(path.size(), 1);
        assert!(path.contains(&42));
    }

    #[test]
    fn test_add_and_contains() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        assert!(path.contains(&1));
        assert!(path.contains(&2));
        assert!(path.contains(&3));
        assert!(!path.contains(&4));
        assert_eq!(path.size(), 3);
    }

    #[test]
    fn test_get() {
        let mut path = GraphPath::new();
        path.add("a");
        path.add("b");
        path.add("c");
        assert_eq!(path.get(0), &"a");
        assert_eq!(path.get(1), &"b");
        assert_eq!(path.get(2), &"c");
    }

    #[test]
    fn test_get_last() {
        let mut path = GraphPath::new();
        path.add(10i32);
        path.add(20i32);
        assert_eq!(path.get_last(), &20);
    }

    #[test]
    fn test_remove_last() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        assert_eq!(path.remove_last(), 3);
        assert_eq!(path.size(), 2);
        assert!(!path.contains(&3));
        assert!(path.contains(&1));
        assert!(path.contains(&2));
    }

    #[test]
    fn test_depth() {
        let mut path = GraphPath::new();
        path.add("x");
        path.add("y");
        path.add("z");
        assert_eq!(path.depth(&"x"), Some(0));
        assert_eq!(path.depth(&"y"), Some(1));
        assert_eq!(path.depth(&"z"), Some(2));
        assert_eq!(path.depth(&"w"), None);
    }

    #[test]
    fn test_copy_is_independent() {
        let mut original = GraphPath::new();
        original.add(1i32);
        original.add(2i32);
        let mut copy = original.copy();
        copy.add(3i32);
        assert_eq!(original.size(), 2);
        assert_eq!(copy.size(), 3);
        assert!(!original.contains(&3));
    }

    #[test]
    fn test_starts_with_true() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        let mut prefix = GraphPath::new();
        prefix.add(1i32);
        prefix.add(2i32);
        assert!(path.starts_with(&prefix));
    }

    #[test]
    fn test_starts_with_same() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        let copy = path.copy();
        assert!(path.starts_with(&copy));
    }

    #[test]
    fn test_starts_with_empty_prefix() {
        let mut path = GraphPath::new();
        path.add(1i32);
        let empty: GraphPath<i32> = GraphPath::new();
        assert!(path.starts_with(&empty));
    }

    #[test]
    fn test_starts_with_false_wrong_order() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        let mut other = GraphPath::new();
        other.add(2i32);
        other.add(1i32);
        assert!(!path.starts_with(&other));
    }

    #[test]
    fn test_starts_with_false_longer() {
        let mut path = GraphPath::new();
        path.add(1i32);
        let mut other = GraphPath::new();
        other.add(1i32);
        other.add(2i32);
        assert!(!path.starts_with(&other));
    }

    #[test]
    fn test_get_common_start_path() {
        let mut a = GraphPath::new();
        for v in [1i32, 2, 3, 4, 5, 6] {
            a.add(v);
        }
        let mut b = GraphPath::new();
        for v in [1i32, 2, 3, 4, 10, 11, 12] {
            b.add(v);
        }
        let common = a.get_common_start_path(&b);
        assert_eq!(common.size(), 4);
        assert_eq!(common.get(0), &1);
        assert_eq!(common.get(3), &4);
    }

    #[test]
    fn test_get_common_start_path_none() {
        let mut a = GraphPath::new();
        a.add(1i32);
        let mut b = GraphPath::new();
        b.add(2i32);
        let common = a.get_common_start_path(&b);
        assert_eq!(common.size(), 0);
    }

    #[test]
    fn test_get_predecessors() {
        let mut path = GraphPath::new();
        for v in [1i32, 2, 3, 4, 5] {
            path.add(v);
        }
        let preds = path.get_predecessors(&3);
        assert_eq!(preds, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn test_get_predecessors_not_in_path() {
        let mut path = GraphPath::new();
        path.add(1i32);
        assert_eq!(path.get_predecessors(&99), HashSet::new());
    }

    #[test]
    fn test_get_successors() {
        let mut path = GraphPath::new();
        for v in [1i32, 2, 3, 4, 5] {
            path.add(v);
        }
        let succs = path.get_successors(&3);
        assert_eq!(succs, HashSet::from([3, 4, 5]));
    }

    #[test]
    fn test_get_successors_not_in_path() {
        let mut path = GraphPath::new();
        path.add(1i32);
        assert_eq!(path.get_successors(&99), HashSet::new());
    }

    #[test]
    fn test_sub_path() {
        let mut path = GraphPath::new();
        for v in [10i32, 20, 30, 40, 50] {
            path.add(v);
        }
        let sub = path.sub_path(1, 4);
        assert_eq!(sub.size(), 3);
        assert_eq!(sub.get(0), &20);
        assert_eq!(sub.get(1), &30);
        assert_eq!(sub.get(2), &40);
        assert!(sub.contains(&20));
        assert!(!sub.contains(&10));
    }

    #[test]
    fn test_sub_path_empty() {
        let mut path = GraphPath::new();
        path.add(1i32);
        let sub = path.sub_path(0, 0);
        assert_eq!(sub.size(), 0);
    }

    #[test]
    fn test_debug_format() {
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        assert_eq!(format!("{:?}", path), "[1, 2, 3]");
    }

    #[test]
    fn test_default_is_empty() {
        let path: GraphPath<i32> = GraphPath::default();
        assert_eq!(path.size(), 0);
    }
}
