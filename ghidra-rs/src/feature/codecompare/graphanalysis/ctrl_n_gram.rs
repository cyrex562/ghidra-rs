//! Port of `ghidra.features.codecompare.graphanalysis.CtrlNGram`.
//!
//! # Shape
//!
//! Concrete Java class nothing extends -> `struct` (rule R14). The Java `root` field is a
//! `CtrlVertex` reference; per `OWNERSHIP_MIGRATION.md` convention 1 it is held here as a `Copy`
//! [`CtrlVertexId`] resolved against the owning control-flow graph. `CtrlVertex`, `CtrlGraph` and
//! `Pinning` are not yet ported, so the ID and [`Side`] are placeholders in
//! [`crate::feature::seam_stubs`].

use crate::feature::seam_stubs::CtrlVertexId;
#[cfg(doc)]
use crate::feature::seam_stubs::pinning::Side;

/// N-gram hash on the control-flow graph rooted at a specific control-flow vertex.
///
/// The n-gram depth is the maximum number of (backward) edge traversals from the root node to
/// any other node involved in the hash. The n-gram weight is the total number of nodes involved
/// in the hash.
///
/// Fields are public because, as in Java (package-private fields), the vertex and graph code
/// updates them in place -- e.g. `CtrlVertex.addEdgeColor` re-hashes the 0-gram's `hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtrlNGram {
    /// The number of nodes involved in this hash.
    pub weight: i32,
    /// The maximum distance between nodes in this n-gram set.
    pub depth: i32,
    /// The hash.
    pub hash: i32,
    /// The root node of the n-gram.
    pub root: CtrlVertexId,
}

impl CtrlNGram {
    /// Construct a control-flow n-gram. Java: `CtrlNGram(CtrlVertex node, int weight, int depth,
    /// int hash)`.
    pub fn new(root: CtrlVertexId, weight: i32, depth: i32, hash: i32) -> Self {
        Self {
            weight,
            depth,
            hash,
            root,
        }
    }

    /// Compare the hash of this n-gram with another. The weight and depth must also be equal;
    /// the node(s) underlying the n-grams may differ. Java's `null` argument (which returns
    /// `false`) is expressed as `None`.
    pub fn equal_hash(&self, other: Option<&CtrlNGram>) -> bool {
        match other {
            None => false,
            Some(other) => {
                self.weight == other.weight && self.depth == other.depth && self.hash == other.hash
            }
        }
    }

    /// Check if this and another n-gram are rooted in different control-flow graphs
    /// (Java: `root.graph.side != other.root.graph.side`).
    pub fn graphs_differ(&self, other: &CtrlNGram) -> bool {
        self.root.side != other.root.side
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::pinning::Side;

    fn vid(side: Side, index: u32) -> CtrlVertexId {
        CtrlVertexId { side, index }
    }

    #[test]
    fn new_stores_all_fields() {
        let g = CtrlNGram::new(vid(Side::Right, 3), 5, 2, -17);
        assert_eq!(g.weight, 5);
        assert_eq!(g.depth, 2);
        assert_eq!(g.hash, -17);
        assert_eq!(g.root, vid(Side::Right, 3));
        // CtrlVertex uid encoding: id * 2 + side.getValue()
        assert_eq!(g.root.uid(), 7);
    }

    #[test]
    fn equal_hash_compares_weight_depth_and_hash_only() {
        let a = CtrlNGram::new(vid(Side::Left, 0), 3, 1, 0x1234);
        let b = CtrlNGram::new(vid(Side::Right, 9), 3, 1, 0x1234);
        assert!(a.equal_hash(Some(&b)), "different roots, same hash data");
        assert!(!a.equal_hash(Some(&CtrlNGram::new(a.root, 4, 1, 0x1234))));
        assert!(!a.equal_hash(Some(&CtrlNGram::new(a.root, 3, 2, 0x1234))));
        assert!(!a.equal_hash(Some(&CtrlNGram::new(a.root, 3, 1, 0x1235))));
    }

    #[test]
    fn equal_hash_with_null_is_false() {
        let a = CtrlNGram::new(vid(Side::Left, 0), 1, 0, 0);
        assert!(!a.equal_hash(None));
    }

    #[test]
    fn graphs_differ_compares_root_graph_side() {
        let left0 = CtrlNGram::new(vid(Side::Left, 0), 1, 0, 1);
        let left5 = CtrlNGram::new(vid(Side::Left, 5), 1, 0, 1);
        let right0 = CtrlNGram::new(vid(Side::Right, 0), 1, 0, 1);
        assert!(!left0.graphs_differ(&left5));
        assert!(left0.graphs_differ(&right0));
        assert!(right0.graphs_differ(&left5));
    }
}
