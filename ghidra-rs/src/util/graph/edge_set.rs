use crate::util::graph::edge::Edge;
use crate::util::graph::key_indexable_set::KeyIndexableSet;

/// Container for a set of edges ([`Edge`]), threaded with links to adjacent edges that share the
/// same `from` or `to` vertex.
///
/// Port of `ghidra.util.graph.EdgeSet` (deprecated since Ghidra 10.2, package-private), cut to a
/// trait to break a dependency cycle at this node in the port graph. The Java class also holds a
/// reference to its owning `DirectedGraph` (not yet ported) so that `add`/`remove` can update the
/// endpoint vertices' first/last edge pointers via `DirectedGraph#vertices()`. That wiring is an
/// implementation detail of construction rather than part of the public surface described here,
/// so `DirectedGraph` and `VertexSet` do not appear in this trait and no placeholder stub is
/// needed for them. `add`/`remove`/`contains`/`size`/`capacity`/`iterator`/`get_keyed_object`/
/// `to_array`/`modification_number` are inherited from [`KeyIndexableSet`]; `toSet()` is omitted
/// since it is equivalent to the inherited `to_array()` (the backing store already guarantees
/// edges are unique by key).
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait EdgeSet<E: Edge>: KeyIndexableSet<E> {
    /// Returns the edge at the specified index in the internal arrays, if any.
    fn get_by_index(&self, index: usize) -> Option<&E>;

    /// Returns the internal index of the given edge within this edge set, or `None` if it is
    /// not present.
    fn index(&self, e: &E) -> Option<usize>;

    /// Returns the next edge having the same `from` vertex as `e`, if any.
    fn get_next_edge_with_same_from(&self, e: &E) -> Option<&E>;

    /// Returns the next edge having the same `to` vertex as `e`, if any.
    fn get_next_edge_with_same_to(&self, e: &E) -> Option<&E>;

    /// Returns the previous edge having the same `from` vertex as `e`, if any.
    fn get_previous_edge_with_same_from(&self, e: &E) -> Option<&E>;

    /// Returns the previous edge having the same `to` vertex as `e`, if any.
    fn get_previous_edge_with_same_to(&self, e: &E) -> Option<&E>;

    /// Empties the edge set while leaving capacity unchanged. Much faster than removing edges
    /// one by one.
    fn clear(&mut self);

    /// Either compacts the edge set by removing vacant positions if there are many, or grows it
    /// so there is additional space.
    fn grow(&mut self);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::graph::keyed_object::KeyedObject;
    use crate::util::graph::vertex::Vertex;
    use crate::util::seam_stubs::GraphIteratorLike;

    struct MockVertex {
        key: i64,
    }

    impl KeyedObject for MockVertex {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Vertex for MockVertex {
        fn referent(&self) -> Option<&dyn std::fmt::Display> {
            None
        }
    }

    struct MockEdge {
        key: i64,
        from: MockVertex,
        to: MockVertex,
    }

    impl KeyedObject for MockEdge {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Edge for MockEdge {
        fn from(&self) -> &dyn Vertex {
            &self.from
        }

        fn to(&self) -> &dyn Vertex {
            &self.to
        }
    }

    struct MockIterator<'a> {
        remaining: std::slice::Iter<'a, MockEdge>,
    }

    impl<'a> GraphIteratorLike<MockEdge> for MockIterator<'a> {
        fn has_next(&self) -> bool {
            self.remaining.clone().next().is_some()
        }

        fn next(&mut self) -> Option<MockEdge> {
            self.remaining.next().map(|e| MockEdge {
                key: e.key,
                from: MockVertex { key: e.from.key },
                to: MockVertex { key: e.to.key },
            })
        }

        fn remove(&mut self) -> bool {
            false
        }
    }

    /// A trivial two-edge chain (edge 0 -> edge 1, both sharing `from`) proving the trait is
    /// object-safe and its adjacency accessors behave as expected.
    struct MockEdgeSet {
        edges: Vec<MockEdge>,
        modification_number: i64,
    }

    impl KeyIndexableSet<MockEdge> for MockEdgeSet {
        fn modification_number(&self) -> i64 {
            self.modification_number
        }

        fn size(&self) -> usize {
            self.edges.len()
        }

        fn capacity(&self) -> usize {
            self.edges.capacity()
        }

        fn add(&mut self, obj: MockEdge) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.edges.push(obj);
            self.modification_number += 1;
            true
        }

        fn remove(&mut self, obj: &MockEdge) -> bool {
            let before = self.edges.len();
            self.edges.retain(|e| e.key != obj.key);
            let removed = self.edges.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }

        fn contains(&self, obj: &MockEdge) -> bool {
            self.edges.iter().any(|e| e.key == obj.key)
        }

        fn iterator(&self) -> Box<dyn GraphIteratorLike<MockEdge> + '_> {
            Box::new(MockIterator { remaining: self.edges.iter() })
        }

        fn to_array(&self) -> Vec<&MockEdge> {
            self.edges.iter().collect()
        }

        fn get_keyed_object(&self, key: i64) -> Option<&MockEdge> {
            self.edges.iter().find(|e| e.key == key)
        }
    }

    impl EdgeSet<MockEdge> for MockEdgeSet {
        fn get_by_index(&self, index: usize) -> Option<&MockEdge> {
            self.edges.get(index)
        }

        fn index(&self, e: &MockEdge) -> Option<usize> {
            self.edges.iter().position(|edge| edge.key == e.key)
        }

        fn get_next_edge_with_same_from(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges.get(i + 1).filter(|next| next.from.key == e.from.key)
        }

        fn get_next_edge_with_same_to(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            self.edges.get(i + 1).filter(|next| next.to.key == e.to.key)
        }

        fn get_previous_edge_with_same_from(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            i.checked_sub(1)
                .and_then(|prev| self.edges.get(prev))
                .filter(|prev| prev.from.key == e.from.key)
        }

        fn get_previous_edge_with_same_to(&self, e: &MockEdge) -> Option<&MockEdge> {
            let i = self.index(e)?;
            i.checked_sub(1)
                .and_then(|prev| self.edges.get(prev))
                .filter(|prev| prev.to.key == e.to.key)
        }

        fn clear(&mut self) {
            self.edges.clear();
            self.modification_number += 1;
        }

        fn grow(&mut self) {
            self.edges.reserve(self.edges.len() + 1);
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut set: Box<dyn EdgeSet<MockEdge>> =
            Box::new(MockEdgeSet { edges: Vec::new(), modification_number: 0 });

        assert!(set.add(MockEdge { key: 1, from: MockVertex { key: 10 }, to: MockVertex { key: 20 } }));
        assert!(set.add(MockEdge { key: 2, from: MockVertex { key: 10 }, to: MockVertex { key: 30 } }));
        assert_eq!(set.size(), 2);

        let first = set.get_by_index(0).unwrap();
        assert_eq!(first.key(), 1);

        let next = set.get_next_edge_with_same_from(first);
        assert_eq!(next.map(|e| e.key()), Some(2));
        assert!(set.get_next_edge_with_same_to(first).is_none());

        let second_key = 2;
        let second = set.get_keyed_object(second_key).unwrap();
        let prev = set.get_previous_edge_with_same_from(second);
        assert_eq!(prev.map(|e| e.key()), Some(1));

        set.clear();
        assert_eq!(set.size(), 0);
    }
}
