//! Port of `ghidra.feature.vt.api.FunctionPair`.

use std::hash::{Hash, Hasher};

use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::feature::vt::api::main::vt_match_info::VtMatchInfo;
use crate::feature::vt::api::main::vt_score::VtScore;

use super::function_node::NodeId;
use super::function_node_container::FunctionNodeContainer;

/// A possible match between a source and a destination function.
///
/// The Java object holds both `FunctionNode`s; here they are [`NodeId`]s, `source` resolving in
/// the source program's [`FunctionNodeContainer`] and `dest` in the destination's. A pair is an
/// immutable value, so the copies stored in each endpoint's associate map stand in for Java's one
/// shared object. Equality and hashing use the two nodes only, as in Java.
#[derive(Debug, Clone, Copy)]
pub struct FunctionPair {
    source_node: NodeId,
    dest_node: NodeId,
    sim_result: f64,
    conf_result: f64,
}

impl FunctionPair {
    /// Creates a pair with the computed similarity (0.0 to 1.0) and confidence scores.
    pub fn new(source: NodeId, dest: NodeId, sim_res: f64, conf_res: f64) -> Self {
        Self { source_node: source, dest_node: dest, sim_result: sim_res, conf_result: conf_res }
    }

    /// Builds the formal Version Tracking match record for this pair, for the match set with id
    /// `match_set_id`. `sources`/`dests` are the containers this pair's nodes live in.
    pub fn get_match<V>(
        &self,
        match_set_id: i32,
        sources: &FunctionNodeContainer<V>,
        dests: &FunctionNodeContainer<V>,
    ) -> VtMatchInfo {
        let source = sources.node(self.source_node);
        let dest = dests.node(self.dest_node);
        let mut result = VtMatchInfo::new(match_set_id);
        result.set_similarity_score(VtScore::new(self.sim_result));
        result.set_confidence_score(VtScore::new(self.conf_result));
        result.set_association_type(VtAssociationType::Function);
        result.set_source_address(source.address().clone());
        result.set_destination_address(dest.address().clone());
        result.set_source_length(source.len());
        result.set_destination_length(dest.len());
        result
    }

    /// Java `toString()`: `"<source name>,<dest name>"`.
    pub fn display<V>(
        &self,
        sources: &FunctionNodeContainer<V>,
        dests: &FunctionNodeContainer<V>,
    ) -> String {
        format!("{},{}", sources.node(self.source_node), dests.node(self.dest_node))
    }

    /// Returns the source function's node.
    pub fn source_node(&self) -> NodeId {
        self.source_node
    }

    /// Returns the destination function's node.
    pub fn dest_node(&self) -> NodeId {
        self.dest_node
    }

    /// Returns the similarity score of the pair.
    pub fn sim_result(&self) -> f64 {
        self.sim_result
    }

    /// Returns the confidence score of the pair.
    pub fn conf_result(&self) -> f64 {
        self.conf_result
    }
}

impl PartialEq for FunctionPair {
    fn eq(&self, other: &Self) -> bool {
        self.dest_node == other.dest_node && self.source_node == other.source_node
    }
}

impl Eq for FunctionPair {}

impl Hash for FunctionPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dest_node.hash(state);
        self.source_node.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::feature::vt::api::function_node::tests::{addr, node};
    use crate::feature::vt::api::function_node_container::tests::container;

    #[test]
    fn equality_ignores_scores() {
        let a = FunctionPair::new(NodeId(1), NodeId(2), 0.9, 10.0);
        let b = FunctionPair::new(NodeId(1), NodeId(2), 0.1, 0.0);
        let c = FunctionPair::new(NodeId(2), NodeId(1), 0.9, 10.0);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let set: HashSet<_> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn get_match_fills_the_match_info() {
        let sources = container(vec![node(0x1000, "src_func", &[], 0x20)], |_| None);
        let dests = container(vec![node(0x4000, "dst_func", &[], 0)], |_| None);
        let pair = FunctionPair::new(NodeId(0), NodeId(0), 0.8766, 14.2);

        let info = pair.get_match(3, &sources, &dests);
        assert_eq!(info.match_set_id(), 3);
        assert_eq!(info.association_type(), Some(VtAssociationType::Function));
        // VTScore rounds to three decimals
        assert_eq!(info.similarity_score().unwrap().score(), 0.877);
        assert_eq!(info.confidence_score().unwrap().score(), 14.2);
        assert_eq!(info.source_address(), Some(&addr(0x1000)));
        assert_eq!(info.destination_address(), Some(&addr(0x4000)));
        assert_eq!(info.source_length(), 0x20);
        // a zero-length body is recorded as length 1
        assert_eq!(info.destination_length(), 1);
        assert_eq!(pair.display(&sources, &dests), "src_func,dst_func");
    }
}
