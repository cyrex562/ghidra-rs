use super::graph_path::GraphPath;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

/// A collection of graph paths with O(1) membership testing.
pub struct GraphPathSet<V> {
    paths: HashSet<GraphPath<V>>,
}

impl<V: Eq + Hash + Clone> GraphPathSet<V> {
    /// Creates a new empty set of paths.
    pub fn new() -> Self {
        GraphPathSet {
            paths: HashSet::new(),
        }
    }

    /// Returns `true` if this set contains some path that starts with `other_path`.
    pub fn contains_some_path_starting_with(&self, other_path: &GraphPath<V>) -> bool {
        self.paths.iter().any(|path| path.starts_with(other_path))
    }

    /// Adds a path to this set.
    pub fn add(&mut self, path: GraphPath<V>) {
        self.paths.insert(path);
    }

    /// Returns all paths in this set that contain vertex `v`.
    pub fn get_paths_containing(&self, v: &V) -> HashSet<GraphPath<V>> {
        self.paths
            .iter()
            .filter(|path| path.contains(v))
            .cloned()
            .collect()
    }

    /// Returns the number of paths in this set.
    pub fn size(&self) -> usize {
        self.paths.len()
    }
}

impl<V: Eq + Hash + Clone> Default for GraphPathSet<V> {
    fn default() -> Self {
        GraphPathSet::new()
    }
}

impl<V: Eq + Hash + Clone + fmt::Debug> fmt::Display for GraphPathSet<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = Vec::new();
        for path in &self.paths {
            lines.push(format!("{:?}", path));
        }
        write!(f, "{}", lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let set: GraphPathSet<i32> = GraphPathSet::new();
        assert_eq!(set.size(), 0);
    }

    #[test]
    fn test_default_is_empty() {
        let set: GraphPathSet<i32> = GraphPathSet::default();
        assert_eq!(set.size(), 0);
    }

    #[test]
    fn test_add_single_path() {
        let mut set = GraphPathSet::new();
        let path = GraphPath::with_vertex(1i32);
        set.add(path);
        assert_eq!(set.size(), 1);
    }

    #[test]
    fn test_add_multiple_paths() {
        let mut set = GraphPathSet::new();
        let path1 = GraphPath::with_vertex(1i32);
        let path2 = GraphPath::with_vertex(2i32);
        set.add(path1);
        set.add(path2);
        assert_eq!(set.size(), 2);
    }

    #[test]
    fn test_add_duplicate_paths() {
        let mut set = GraphPathSet::new();
        let path1 = GraphPath::with_vertex(1i32);
        let path2 = GraphPath::with_vertex(1i32);
        set.add(path1);
        set.add(path2);
        assert_eq!(set.size(), 1);
    }

    #[test]
    fn test_contains_some_path_starting_with_true() {
        let mut set = GraphPathSet::new();
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        set.add(path);

        let mut prefix = GraphPath::new();
        prefix.add(1i32);
        prefix.add(2i32);

        assert!(set.contains_some_path_starting_with(&prefix));
    }

    #[test]
    fn test_contains_some_path_starting_with_false() {
        let mut set = GraphPathSet::new();
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        set.add(path);

        let mut prefix = GraphPath::new();
        prefix.add(2i32);
        prefix.add(3i32);

        assert!(!set.contains_some_path_starting_with(&prefix));
    }

    #[test]
    fn test_contains_some_path_starting_with_empty_prefix() {
        let mut set = GraphPathSet::new();
        let path = GraphPath::with_vertex(1i32);
        set.add(path);

        let empty: GraphPath<i32> = GraphPath::new();
        assert!(set.contains_some_path_starting_with(&empty));
    }

    #[test]
    fn test_contains_some_path_starting_with_multiple_paths() {
        let mut set = GraphPathSet::new();
        let mut path1 = GraphPath::new();
        path1.add(1i32);
        path1.add(2i32);
        set.add(path1);

        let mut path2 = GraphPath::new();
        path2.add(3i32);
        path2.add(4i32);
        set.add(path2);

        let mut prefix = GraphPath::new();
        prefix.add(3i32);

        assert!(set.contains_some_path_starting_with(&prefix));
    }

    #[test]
    fn test_get_paths_containing() {
        let mut set = GraphPathSet::new();
        let mut path1 = GraphPath::new();
        path1.add(1i32);
        path1.add(2i32);
        set.add(path1);

        let mut path2 = GraphPath::new();
        path2.add(2i32);
        path2.add(3i32);
        set.add(path2);

        let mut path3 = GraphPath::new();
        path3.add(5i32);
        set.add(path3);

        let paths = set.get_paths_containing(&2);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_get_paths_containing_none() {
        let mut set = GraphPathSet::new();
        let path = GraphPath::with_vertex(1i32);
        set.add(path);

        let paths = set.get_paths_containing(&99);
        assert_eq!(paths.len(), 0);
    }

    #[test]
    fn test_get_paths_containing_single() {
        let mut set = GraphPathSet::new();
        let mut path = GraphPath::new();
        path.add(1i32);
        path.add(2i32);
        path.add(3i32);
        set.add(path);

        let paths = set.get_paths_containing(&2);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_size() {
        let mut set = GraphPathSet::new();
        assert_eq!(set.size(), 0);

        let path1 = GraphPath::with_vertex(1i32);
        set.add(path1);
        assert_eq!(set.size(), 1);

        let path2 = GraphPath::with_vertex(2i32);
        set.add(path2);
        assert_eq!(set.size(), 2);
    }

    #[test]
    fn test_display_empty_set() {
        let set: GraphPathSet<i32> = GraphPathSet::new();
        let display = format!("{}", set);
        assert_eq!(display, "");
    }

    #[test]
    fn test_display_with_paths() {
        let mut set = GraphPathSet::new();
        let path = GraphPath::with_vertex(1i32);
        set.add(path);
        let display = format!("{}", set);
        assert!(display.contains("1"));
    }
}
