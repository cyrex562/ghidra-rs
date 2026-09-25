//! Port of `ghidra.feature.vt.api.FunctionNode`.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::address::Address;
use crate::program::model::listing::Function;

use super::function_pair::FunctionPair;

/// Identifies a [`FunctionNode`] inside the
/// [`FunctionNodeContainer`](super::function_node_container::FunctionNodeContainer) that owns it.
/// Ids are assigned in address order, so comparing ids of one container compares addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub usize);

/// Information about a single function the BSim correlator is attempting to match.
///
/// Java links nodes to each other directly (call-graph `children`/`parents` and the
/// `associates` map of potential matches). Here each node lives in its program's
/// [`FunctionNodeContainer`](super::function_node_container::FunctionNodeContainer) arena and
/// those links are [`NodeId`]s: `children`/`parents` name nodes of the *same* container, while
/// `associates` keys name nodes of the *other* program's container (source <-> destination).
///
/// Identity (equality, hashing, ordering) is the entry-point address, as in Java.
///
/// `V` is the concrete [`LSHVector`](crate::generic::lsh::vector::lsh_vector::LSHVector) type the
/// correlator's vector factory builds.
#[derive(Debug, Clone)]
pub struct FunctionNode<V> {
    addr: Address,
    name: String,
    vec: V,
    call_addresses: Option<Vec<Address>>,
    children: HashSet<NodeId>,
    parents: HashSet<NodeId>,
    associates: HashMap<NodeId, FunctionPair>,
    len: i32,
    accepted_match: bool,
}

impl<V> FunctionNode<V> {
    /// Allocates a container for node neighbourhoods, as needed by the neighbor generators:
    /// small sets that are checked for containment constantly.
    pub fn neighborhood_allocate() -> HashSet<NodeId> {
        HashSet::new()
    }

    /// Creates the node for `function`. The raw `call_addresses` are resolved into call-graph
    /// links later, by the owning container.
    pub fn new(function: &dyn Function, vector: V, call_addresses: Vec<Address>) -> Self {
        Self::from_parts(
            function.get_entry_point(),
            Function::get_name(function),
            vector,
            call_addresses,
            function.get_body().num_addresses(),
        )
    }

    /// Creates a node from the values Java's constructor reads off a `Function`: its entry
    /// point, name and number of addresses in its body. A zero-length body is recorded as length
    /// 1 so the length is never zero.
    pub fn from_parts(
        addr: Address,
        name: String,
        vector: V,
        call_addresses: Vec<Address>,
        body_num_addresses: u64,
    ) -> Self {
        // Java: `(int) function.getBody().getNumAddresses()` -- a truncating long-to-int cast
        let val = body_num_addresses as i32;
        Self {
            addr,
            name,
            vec: vector,
            call_addresses: Some(call_addresses),
            children: Self::neighborhood_allocate(),
            parents: Self::neighborhood_allocate(),
            associates: HashMap::new(),
            len: if val == 0 { 1 } else { val },
            accepted_match: false,
        }
    }

    /// Returns the entry point of the function this node represents.
    pub fn address(&self) -> &Address {
        &self.addr
    }

    /// Returns the name of the function this node represents.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the feature vector of this node's function.
    pub fn vector(&self) -> &V {
        &self.vec
    }

    /// Takes the raw call addresses, releasing them. Returns `None` once they have been taken.
    pub fn release_call_addresses(&mut self) -> Option<Vec<Address>> {
        self.call_addresses.take()
    }

    /// Returns the functions this function calls.
    pub fn children(&self) -> &HashSet<NodeId> {
        &self.children
    }

    /// Returns the functions this function calls, for modification.
    pub fn children_mut(&mut self) -> &mut HashSet<NodeId> {
        &mut self.children
    }

    /// Returns the functions that call this function.
    pub fn parents(&self) -> &HashSet<NodeId> {
        &self.parents
    }

    /// Returns the functions that call this function, for modification.
    pub fn parents_mut(&mut self) -> &mut HashSet<NodeId> {
        &mut self.parents
    }

    /// Records `other` (a node of the other program) as a potential match, described by `pair`.
    pub fn add_associate(&mut self, other: NodeId, pair: FunctionPair) {
        self.associates.insert(other, pair);
    }

    /// Removes what was previously considered a potential match.
    pub fn remove_associate(&mut self, other: NodeId) {
        self.associates.remove(&other);
    }

    /// Clears all potential matches.
    pub fn clear_associates(&mut self) {
        self.associates.clear();
    }

    /// Iterates over all potential matches of this node (Java `getAssociateIterator()`).
    pub fn associates(&self) -> impl Iterator<Item = (NodeId, &FunctionPair)> {
        self.associates.iter().map(|(&id, pair)| (id, pair))
    }

    /// Returns the pair describing the similarity with `other` if it is a potential match.
    pub fn find_edge(&self, other: NodeId) -> Option<&FunctionPair> {
        self.associates.get(&other)
    }

    /// Returns the number of addresses in this function's body (never zero).
    pub fn len(&self) -> i32 {
        self.len
    }

    /// Always false: a node's length is at least 1.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns true if the correlator has formally matched this node.
    pub fn is_accepted_match(&self) -> bool {
        self.accepted_match
    }

    /// Marks whether the correlator has matched this node.
    pub fn set_accepted_match(&mut self, used: bool) {
        self.accepted_match = used;
    }
}

impl<V> PartialEq for FunctionNode<V> {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl<V> Eq for FunctionNode<V> {}

impl<V> Hash for FunctionNode<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl<V> PartialOrd for FunctionNode<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<V> Ord for FunctionNode<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl<V> fmt::Display for FunctionNode<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    pub(crate) fn addr(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    pub(crate) fn node(offset: i64, name: &str, calls: &[i64], len: u64) -> FunctionNode<()> {
        FunctionNode::from_parts(
            addr(offset),
            name.to_string(),
            (),
            calls.iter().map(|&c| addr(c)).collect(),
            len,
        )
    }

    #[test]
    fn zero_length_body_becomes_one() {
        assert_eq!(node(0x100, "f", &[], 0).len(), 1);
        assert_eq!(node(0x100, "f", &[], 12).len(), 12);
        // truncating long-to-int cast, as in Java
        assert_eq!(node(0x100, "f", &[], 0x1_0000_0005).len(), 5);
        assert_eq!(node(0x100, "f", &[], 0x1_0000_0000).len(), 1);
    }

    #[test]
    fn identity_is_the_address() {
        let a = node(0x100, "a", &[], 4);
        let b = node(0x100, "b", &[0x200], 8);
        let c = node(0x200, "a", &[], 4);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.cmp(&c), Ordering::Less);
        assert_eq!(a.to_string(), "a");
    }

    #[test]
    fn call_addresses_are_released_once() {
        let mut n = node(0x100, "f", &[0x200, 0x300], 4);
        assert_eq!(n.release_call_addresses(), Some(vec![addr(0x200), addr(0x300)]));
        assert_eq!(n.release_call_addresses(), None);
    }

    #[test]
    fn associates_add_find_remove_clear() {
        let mut n = node(0x100, "f", &[], 4);
        let pair = FunctionPair::new(NodeId(0), NodeId(3), 0.9, 12.5);
        n.add_associate(NodeId(3), pair);
        n.add_associate(NodeId(4), FunctionPair::new(NodeId(0), NodeId(4), 0.5, 1.0));
        assert_eq!(n.find_edge(NodeId(3)), Some(&pair));
        assert_eq!(n.associates().count(), 2);
        n.remove_associate(NodeId(3));
        assert!(n.find_edge(NodeId(3)).is_none());
        n.clear_associates();
        assert_eq!(n.associates().count(), 0);
    }

    #[test]
    fn accepted_match_flag() {
        let mut n = node(0x100, "f", &[], 4);
        assert!(!n.is_accepted_match());
        n.set_accepted_match(true);
        assert!(n.is_accepted_match());
    }
}
