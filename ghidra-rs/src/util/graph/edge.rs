use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::util::graph::keyed_object::KeyedObject;
use crate::util::graph::vertex::Vertex;

/// An edge joins a pair of vertices. The from and to vertex of an edge can not be changed.
///
/// Port of `ghidra.util.graph.Edge` (deprecated since Ghidra 10.2), cut to a trait to break a
/// dependency cycle at this node in the port graph. The Java class assigns its `key` at
/// construction time via the process-wide `KeyedObjectFactory` singleton
/// (`ghidra.util.graph.KeyedObjectFactory`, not yet ported) and logs an error (via `Msg`) if
/// either vertex is null; both are implementation details of construction rather than part of
/// the public surface, so implementers are expected to obtain a unique key however their
/// concrete backend prefers and report it via [`KeyedObject::key`].
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait Edge: KeyedObject {
    /// Returns the from (parent) vertex.
    fn from(&self) -> &dyn Vertex;

    /// Returns the to (child) vertex.
    fn to(&self) -> &dyn Vertex;
}

#[allow(deprecated)]
impl PartialEq for dyn Edge {
    /// Port of `Edge#equals(Object)`: true if and only if the other edge has the same key.
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

#[allow(deprecated)]
impl Eq for dyn Edge {}

#[allow(deprecated)]
impl Hash for dyn Edge {
    /// Port of `Edge#hashCode()`, which narrows the `long` key to an `int`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.key() as i32).hash(state);
    }
}

#[allow(deprecated)]
impl PartialOrd for dyn Edge {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(deprecated)]
impl Ord for dyn Edge {
    /// Port of `Edge#compareTo(Edge)`: ascending key order, based on time of creation.
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

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

    #[test]
    fn boxed_trait_object_is_usable() {
        let e: Box<dyn Edge> =
            Box::new(MockEdge { key: 1, from: MockVertex { key: 1 }, to: MockVertex { key: 2 } });
        assert_eq!(e.key(), 1);
        assert_eq!(e.from().key(), 1);
        assert_eq!(e.to().key(), 2);
    }

    #[test]
    fn equals_and_ord_compare_by_key_only() {
        let a = MockEdge { key: 1, from: MockVertex { key: 1 }, to: MockVertex { key: 2 } };
        let b = MockEdge { key: 1, from: MockVertex { key: 9 }, to: MockVertex { key: 8 } };
        let c = MockEdge { key: 2, from: MockVertex { key: 1 }, to: MockVertex { key: 2 } };
        let a_ref: &dyn Edge = &a;
        let b_ref: &dyn Edge = &b;
        let c_ref: &dyn Edge = &c;
        assert_eq!(a_ref, b_ref);
        assert_eq!(a_ref.cmp(c_ref), Ordering::Less);
        assert_eq!(c_ref.cmp(a_ref), Ordering::Greater);
    }
}
