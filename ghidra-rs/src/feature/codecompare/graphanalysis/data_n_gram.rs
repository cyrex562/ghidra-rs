//! Port of `ghidra.features.codecompare.graphanalysis.DataNGram`.
//!
//! # Shape
//!
//! Concrete Java class nothing extends -> `struct` (rule R14); Java's `Comparable<DataNGram>`
//! becomes [`Ord`]. The Java `root` field is a `DataVertex` reference; per
//! `OWNERSHIP_MIGRATION.md` convention 1 it is held here as a `Copy` [`DataVertexId`] resolved
//! against the owning data-flow graph. `DataVertex`, `DataGraph` and `Pinning` are not yet
//! ported, so the ID and its `Side` are placeholders in [`crate::feature::seam_stubs`].

use std::cmp::Ordering;
use std::fmt;

use crate::feature::seam_stubs::DataVertexId;

/// N-gram hash on the data-flow graph rooted at a specific data-flow vertex.
///
/// The n-gram depth is the maximum number of edge traversals from the root node to any other
/// node involved in the hash. The n-gram weight is the total number of nodes involved in the
/// hash. N-grams sort with bigger weights first, so n-grams involving more nodes are paired
/// first.
///
/// Fields are public because, as in Java (package-private fields), the Pinning algorithm reads
/// them directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataNGram {
    /// The number of nodes involved in this hash.
    pub weight: i32,
    /// The maximum distance between nodes in this n-gram set.
    pub depth: i32,
    /// The hash.
    pub hash: i32,
    /// The root node of the n-gram.
    pub root: DataVertexId,
}

impl DataNGram {
    /// Construct a data-flow n-gram. Java: `DataNGram(DataVertex node, int weight, int depth,
    /// int hash)`.
    pub fn new(root: DataVertexId, weight: i32, depth: i32, hash: i32) -> Self {
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
    pub fn equal_hash(&self, other: Option<&DataNGram>) -> bool {
        match other {
            None => false,
            Some(other) => {
                self.weight == other.weight && self.depth == other.depth && self.hash == other.hash
            }
        }
    }

    /// Check if this and another n-gram are rooted in different data-flow graphs. Java compares
    /// graph identity (`root.graph != other.root.graph`); the Pinning algorithm builds exactly one
    /// data-flow graph per side, so the root's side identifies its graph.
    pub fn graphs_differ(&self, other: &DataNGram) -> bool {
        self.root.side != other.root.side
    }
}

impl Ord for DataNGram {
    /// Java `compareTo`: bigger weight first, then bigger depth, then bigger hash, then bigger
    /// root uid, and finally the graph side (`other.side.compareTo(this.side)`, i.e. `RIGHT`
    /// before `LEFT`). All comparisons are on Java's signed `int` values.
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .weight
            .cmp(&self.weight)
            .then_with(|| other.depth.cmp(&self.depth))
            .then_with(|| other.hash.cmp(&self.hash))
            .then_with(|| other.root.uid().cmp(&self.root.uid()))
            .then_with(|| other.root.side.cmp(&self.root.side))
    }
}

impl PartialOrd for DataNGram {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for DataNGram {
    /// Java `toString`: `d=<depth> h=<hash> w=<weight> vert=<root uid>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "d={} h={} w={} vert={}",
            self.depth,
            self.hash,
            self.weight,
            self.root.uid()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::pinning::Side;

    fn vid(side: Side, index: u32) -> DataVertexId {
        DataVertexId { side, index }
    }

    #[test]
    fn display_matches_java_to_string() {
        // uid = 4 * 2 + RIGHT(1) = 9
        let g = DataNGram::new(vid(Side::Right, 4), 7, 3, -5);
        assert_eq!(g.to_string(), "d=3 h=-5 w=7 vert=9");
    }

    #[test]
    fn sorts_bigger_weight_first() {
        let heavy = DataNGram::new(vid(Side::Left, 0), 10, 0, 0);
        let light = DataNGram::new(vid(Side::Left, 1), 2, 5, 100);
        assert_eq!(heavy.cmp(&light), Ordering::Less);
        assert_eq!(light.cmp(&heavy), Ordering::Greater);
    }

    #[test]
    fn ties_broken_by_depth_then_hash_then_uid_all_descending() {
        let base = DataNGram::new(vid(Side::Left, 2), 5, 2, 50);
        let deeper = DataNGram::new(vid(Side::Left, 2), 5, 3, 50);
        assert_eq!(deeper.cmp(&base), Ordering::Less);

        let bigger_hash = DataNGram::new(vid(Side::Left, 2), 5, 2, 51);
        assert_eq!(bigger_hash.cmp(&base), Ordering::Less);

        // Hash comparison is signed, as Java's int comparison is.
        let negative_hash = DataNGram::new(vid(Side::Left, 2), 5, 2, i32::MIN);
        assert_eq!(negative_hash.cmp(&base), Ordering::Greater);

        let bigger_uid = DataNGram::new(vid(Side::Left, 3), 5, 2, 50);
        assert_eq!(bigger_uid.cmp(&base), Ordering::Less);
    }

    #[test]
    fn uid_breaks_ties_before_side() {
        // LEFT index 3 -> uid 6; RIGHT index 2 -> uid 5. Bigger uid sorts first.
        let left = DataNGram::new(vid(Side::Left, 3), 1, 0, 0);
        let right = DataNGram::new(vid(Side::Right, 2), 1, 0, 0);
        assert_eq!(left.cmp(&right), Ordering::Less);
    }

    #[test]
    fn sort_orders_list_like_java_collections_sort() {
        let mut grams = vec![
            DataNGram::new(vid(Side::Left, 0), 1, 0, 9),
            DataNGram::new(vid(Side::Right, 1), 3, 1, 1),
            DataNGram::new(vid(Side::Left, 1), 3, 1, 1),
            DataNGram::new(vid(Side::Left, 2), 3, 2, 0),
        ];
        grams.sort();
        let order: Vec<(i32, i32, i32, i32)> = grams
            .iter()
            .map(|g| (g.weight, g.depth, g.hash, g.root.uid()))
            .collect();
        assert_eq!(order, vec![(3, 2, 0, 4), (3, 1, 1, 3), (3, 1, 1, 2), (1, 0, 9, 0)]);
    }

    #[test]
    fn equal_n_grams_compare_equal() {
        let a = DataNGram::new(vid(Side::Right, 4), 2, 1, 3);
        assert_eq!(a.cmp(&a.clone()), Ordering::Equal);
    }

    #[test]
    fn equal_hash_ignores_root() {
        let a = DataNGram::new(vid(Side::Left, 0), 3, 1, 77);
        let b = DataNGram::new(vid(Side::Right, 8), 3, 1, 77);
        assert!(a.equal_hash(Some(&b)));
        assert!(!a.equal_hash(Some(&DataNGram::new(a.root, 3, 1, 78))));
        assert!(!a.equal_hash(Some(&DataNGram::new(a.root, 2, 1, 77))));
        assert!(!a.equal_hash(Some(&DataNGram::new(a.root, 3, 0, 77))));
        assert!(!a.equal_hash(None));
    }

    #[test]
    fn graphs_differ_by_side() {
        let a = DataNGram::new(vid(Side::Left, 0), 1, 0, 0);
        let b = DataNGram::new(vid(Side::Left, 7), 1, 0, 0);
        let c = DataNGram::new(vid(Side::Right, 0), 1, 0, 0);
        assert!(!a.graphs_differ(&b));
        assert!(a.graphs_differ(&c));
    }
}
