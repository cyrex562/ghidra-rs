use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A vertex that groups simple vertices and nested composites for use in graph
/// decomposition algorithms.
#[derive(Debug)]
pub struct CompositeVertex<V, E> {
    vertices: Vec<V>,
    internal_edges: Vec<E>,
    nested_composites: Vec<CompositeVertex<V, E>>,
}

impl<V, E> CompositeVertex<V, E> {
    /// Creates a composite vertex wrapping a single simple vertex.
    pub fn new_single(vertex: V) -> Self {
        Self::new(vec![vertex], vec![])
    }

    /// Creates a composite vertex from nested composites with no direct simple vertices.
    pub fn new_from_composites(nested_composites: Vec<Self>) -> Self {
        Self::new(vec![], nested_composites)
    }

    /// Creates a composite vertex from simple vertices and nested composites.
    pub fn new(vertices: Vec<V>, nested_composites: Vec<Self>) -> Self {
        Self {
            vertices,
            internal_edges: Vec::new(),
            nested_composites,
        }
    }

    /// Adds an internal edge to this composite vertex.
    pub fn add_internal_edge(&mut self, edge: E) {
        self.internal_edges.push(edge);
    }
}

impl<V: Eq + Hash, E: Eq + Hash> CompositeVertex<V, E> {
    /// Collects all simple vertices recursively from this composite and all nested composites.
    pub fn collect_simple_vertices(&self) -> HashSet<&V> {
        let mut result = HashSet::new();
        for v in &self.vertices {
            result.insert(v);
        }
        for composite in &self.nested_composites {
            result.extend(composite.collect_simple_vertices());
        }
        result
    }

    /// Collects all internal edges recursively from this composite and all nested composites.
    pub fn collect_internal_edges(&self) -> HashSet<&E> {
        let mut result = HashSet::new();
        for e in &self.internal_edges {
            result.insert(e);
        }
        for composite in &self.nested_composites {
            result.extend(composite.collect_internal_edges());
        }
        result
    }
}

impl<V: Eq + Hash, E: Eq + Hash> PartialEq for CompositeVertex<V, E> {
    fn eq(&self, other: &Self) -> bool {
        self.collect_simple_vertices() == other.collect_simple_vertices()
            && self.collect_internal_edges() == other.collect_internal_edges()
    }
}

impl<V: Eq + Hash, E: Eq + Hash> Eq for CompositeVertex<V, E> {}

impl<V: Eq + Hash, E: Eq + Hash> Hash for CompositeVertex<V, E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // XOR individual vertex hashes for order-independence, mirroring the
        // Java implementation's bit-rotation XOR over collectSimpleVertices().
        use std::collections::hash_map::DefaultHasher;
        let mut combined: u64 = 0;
        for v in self.collect_simple_vertices() {
            let mut vh = DefaultHasher::new();
            v.hash(&mut vh);
            combined ^= vh.finish();
        }
        combined.hash(state);
    }
}

impl<V: Eq + Hash + fmt::Debug, E: Eq + Hash + fmt::Debug> fmt::Display
    for CompositeVertex<V, E>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "V: {:?} E: {:?}",
            self.collect_simple_vertices(),
            self.collect_internal_edges()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_single_contains_one_vertex() {
        let cv: CompositeVertex<i32, i32> = CompositeVertex::new_single(42);
        let verts = cv.collect_simple_vertices();
        assert_eq!(verts.len(), 1);
        assert!(verts.contains(&42));
    }

    #[test]
    fn new_from_composites_collects_nested_vertices() {
        let a: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        let b: CompositeVertex<i32, i32> = CompositeVertex::new_single(2);
        let outer = CompositeVertex::new_from_composites(vec![a, b]);
        let verts = outer.collect_simple_vertices();
        assert_eq!(verts.len(), 2);
        assert!(verts.contains(&1));
        assert!(verts.contains(&2));
    }

    #[test]
    fn new_with_vertices_and_composites() {
        let inner: CompositeVertex<i32, i32> = CompositeVertex::new_single(10);
        let outer = CompositeVertex::new(vec![20, 30], vec![inner]);
        let verts = outer.collect_simple_vertices();
        assert_eq!(verts.len(), 3);
        assert!(verts.contains(&10));
        assert!(verts.contains(&20));
        assert!(verts.contains(&30));
    }

    #[test]
    fn add_internal_edge_is_collected() {
        let mut cv: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv.add_internal_edge(100);
        let edges = cv.collect_internal_edges();
        assert_eq!(edges.len(), 1);
        assert!(edges.contains(&100));
    }

    #[test]
    fn collect_internal_edges_recursive() {
        let mut a: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        a.add_internal_edge(10);
        let mut outer = CompositeVertex::new_from_composites(vec![a]);
        outer.add_internal_edge(20);
        let edges = outer.collect_internal_edges();
        assert_eq!(edges.len(), 2);
        assert!(edges.contains(&10));
        assert!(edges.contains(&20));
    }

    #[test]
    fn empty_composite_has_no_vertices_or_edges() {
        let cv: CompositeVertex<i32, i32> = CompositeVertex::new(vec![], vec![]);
        assert!(cv.collect_simple_vertices().is_empty());
        assert!(cv.collect_internal_edges().is_empty());
    }

    #[test]
    fn equality_for_same_vertices_and_edges() {
        let mut cv1: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv1.add_internal_edge(99);
        let mut cv2: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv2.add_internal_edge(99);
        assert_eq!(cv1, cv2);
    }

    #[test]
    fn inequality_for_different_vertices() {
        let cv1: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        let cv2: CompositeVertex<i32, i32> = CompositeVertex::new_single(2);
        assert_ne!(cv1, cv2);
    }

    #[test]
    fn inequality_for_different_edges() {
        let mut cv1: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv1.add_internal_edge(10);
        let mut cv2: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv2.add_internal_edge(20);
        assert_ne!(cv1, cv2);
    }

    #[test]
    fn usable_as_hash_map_key() {
        use std::collections::HashMap;
        let mut map: HashMap<CompositeVertex<i32, i32>, &str> = HashMap::new();
        let cv = CompositeVertex::new_single(42);
        map.insert(cv, "value");
        let cv2 = CompositeVertex::new_single(42);
        assert_eq!(map.get(&cv2), Some(&"value"));
    }

    #[test]
    fn display_contains_vertex_and_edge_markers() {
        let mut cv: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        cv.add_internal_edge(100);
        let s = format!("{}", cv);
        assert!(s.starts_with("V:"));
        assert!(s.contains("E:"));
    }

    #[test]
    fn deep_nesting_collects_all_vertices() {
        let a: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        let b: CompositeVertex<i32, i32> = CompositeVertex::new_single(2);
        let inner = CompositeVertex::new_from_composites(vec![a, b]);
        let c: CompositeVertex<i32, i32> = CompositeVertex::new_single(3);
        let outer = CompositeVertex::new(vec![4], vec![inner, c]);
        let verts = outer.collect_simple_vertices();
        assert_eq!(verts.len(), 4);
        for i in 1..=4 {
            assert!(verts.contains(&i));
        }
    }

    #[test]
    fn deep_nesting_collects_all_edges() {
        let mut a: CompositeVertex<i32, i32> = CompositeVertex::new_single(1);
        a.add_internal_edge(10);
        let mut inner = CompositeVertex::new_from_composites(vec![a]);
        inner.add_internal_edge(20);
        let mut outer = CompositeVertex::new_from_composites(vec![inner]);
        outer.add_internal_edge(30);
        let edges = outer.collect_internal_edges();
        assert_eq!(edges.len(), 3);
        assert!(edges.contains(&10));
        assert!(edges.contains(&20));
        assert!(edges.contains(&30));
    }
}
