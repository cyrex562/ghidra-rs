//! Port of `ghidra.feature.vt.api.FunctionNodeContainer`.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::{FunctionManager, Program};

use super::function_node::{FunctionNode, NodeId};

/// The [`FunctionNode`]s of every function in a single program, and the arena that owns them.
///
/// Nodes are stored in address order, so a [`NodeId`] is also a position in that order.
/// Construction resolves each node's raw call addresses into call-graph links (following thunks
/// to the functions they thunk), after which the raw addresses are released.
pub struct FunctionNodeContainer<V> {
    program: Arc<dyn Program>,
    nodes: Vec<FunctionNode<V>>,
    addr_to_node: BTreeMap<Address, NodeId>,
}

impl<V> FunctionNodeContainer<V> {
    /// Builds the container and its call graph.
    ///
    /// `function_manager` is `program.getFunctionManager()` in Java; it is passed separately
    /// because [`Program::get_function_manager`] needs `&mut` access that a shared
    /// `Arc<dyn Program>` cannot give. When two nodes share an address the later one wins, as with
    /// Java's `TreeMap.put`.
    pub fn new(
        program: Arc<dyn Program>,
        node_list: Vec<FunctionNode<V>>,
        function_manager: &dyn FunctionManager,
    ) -> Self {
        Self::with_thunk_resolver(program, node_list, |addr| {
            function_manager
                .get_function_at(addr)
                .filter(|f| f.is_thunk())
                .and_then(|f| f.get_thunked_function(false))
                .map(|thunked| thunked.get_entry_point())
        })
    }

    /// Builds the container with an explicit thunk lookup: `thunk_target(addr)` returns the entry
    /// point of the function thunked by the thunk function at `addr`, or `None` if there is no
    /// thunk function there. [`new`](Self::new) derives it from the program's function manager.
    pub fn with_thunk_resolver(
        program: Arc<dyn Program>,
        node_list: Vec<FunctionNode<V>>,
        thunk_target: impl Fn(&Address) -> Option<Address>,
    ) -> Self {
        let mut by_address = BTreeMap::new();
        for node in node_list {
            by_address.insert(node.address().clone(), node);
        }
        let mut nodes = Vec::with_capacity(by_address.len());
        let mut addr_to_node = BTreeMap::new();
        for (addr, node) in by_address {
            addr_to_node.insert(addr, NodeId(nodes.len()));
            nodes.push(node);
        }
        let mut container = Self { program, nodes, addr_to_node };
        container.generate_call_graph(thunk_target);
        container
    }

    /// Returns the program whose functions this container holds.
    pub fn program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// Returns the node of the function at `addr`, if any.
    pub fn get(&self, addr: &Address) -> Option<NodeId> {
        self.addr_to_node.get(addr).copied()
    }

    /// Resolves a node id.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this container.
    pub fn node(&self, id: NodeId) -> &FunctionNode<V> {
        &self.nodes[id.0]
    }

    /// Resolves a node id for modification.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this container.
    pub fn node_mut(&mut self, id: NodeId) -> &mut FunctionNode<V> {
        &mut self.nodes[id.0]
    }

    /// Returns the number of nodes in this container.
    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Iterates over all nodes in address order.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &FunctionNode<V>)> {
        self.nodes.iter().enumerate().map(|(i, node)| (NodeId(i), node))
    }

    /// Links each node to the nodes it calls, then releases its raw call addresses. A call
    /// address that is not a node is most likely a thunk, which is followed to the function it
    /// thunks.
    fn generate_call_graph(&mut self, thunk_target: impl Fn(&Address) -> Option<Address>) {
        for index in 0..self.nodes.len() {
            let node = NodeId(index);
            let Some(call_addresses) = self.nodes[index].release_call_addresses() else {
                continue;
            };
            for mut addr in call_addresses {
                let kid = loop {
                    if let Some(kid) = self.get(&addr) {
                        break Some(kid);
                    }
                    match thunk_target(&addr) {
                        Some(target) => addr = target,
                        None => break None,
                    }
                };
                if let Some(kid) = kid {
                    self.nodes[node.0].children_mut().insert(kid);
                    self.nodes[kid.0].parents_mut().insert(node);
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::feature::vt::api::function_node::tests::{addr, node};

    struct TestProgram;

    impl crate::framework::model::DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    /// Builds a container over a bare program with a thunk map given as offsets.
    pub(crate) fn container(
        nodes: Vec<FunctionNode<()>>,
        thunks: impl Fn(i64) -> Option<i64>,
    ) -> FunctionNodeContainer<()> {
        FunctionNodeContainer::with_thunk_resolver(Arc::new(TestProgram), nodes, |a| {
            thunks(a.offset()).map(addr)
        })
    }

    fn ids(container: &FunctionNodeContainer<()>, offsets: &[i64]) -> HashSet<NodeId> {
        offsets.iter().map(|&o| container.get(&addr(o)).unwrap()).collect()
    }

    #[test]
    fn nodes_are_ordered_by_address() {
        let c = container(
            vec![node(0x300, "c", &[], 1), node(0x100, "a", &[], 1), node(0x200, "b", &[], 1)],
            |_| None,
        );
        assert_eq!(c.size(), 3);
        let names: Vec<_> = c.iter().map(|(_, n)| n.name().to_string()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
        assert_eq!(c.get(&addr(0x200)), Some(NodeId(1)));
        assert_eq!(c.get(&addr(0x250)), None);
        assert_eq!(Program::get_name(c.program().as_ref()), "test.bin");
    }

    #[test]
    fn duplicate_address_keeps_the_later_node() {
        let c = container(vec![node(0x100, "first", &[], 1), node(0x100, "second", &[], 1)], |_| None);
        assert_eq!(c.size(), 1);
        assert_eq!(c.node(NodeId(0)).name(), "second");
    }

    #[test]
    fn call_graph_links_children_and_parents() {
        // a calls b and c, b calls c and itself, c calls an address that is no function
        let c = container(
            vec![
                node(0x100, "a", &[0x200, 0x300], 1),
                node(0x200, "b", &[0x300, 0x200], 1),
                node(0x300, "c", &[0x999], 1),
            ],
            |_| None,
        );
        let (a, b, cc) = (NodeId(0), NodeId(1), NodeId(2));
        assert_eq!(c.node(a).children(), &ids(&c, &[0x200, 0x300]));
        assert_eq!(c.node(b).children(), &ids(&c, &[0x300, 0x200]));
        assert!(c.node(cc).children().is_empty());
        assert!(c.node(a).parents().is_empty());
        assert_eq!(c.node(b).parents(), &ids(&c, &[0x100, 0x200]));
        assert_eq!(c.node(cc).parents(), &ids(&c, &[0x100, 0x200]));
    }

    #[test]
    fn calls_through_thunk_chains_reach_the_thunked_function() {
        // 0x500 thunks to 0x600, which thunks to node 0x200; 0x700 is a thunk to nothing known
        let c = container(
            vec![node(0x100, "a", &[0x500, 0x700], 1), node(0x200, "b", &[], 1)],
            |off| match off {
                0x500 => Some(0x600),
                0x600 => Some(0x200),
                0x700 => Some(0x800),
                _ => None,
            },
        );
        assert_eq!(c.node(NodeId(0)).children(), &ids(&c, &[0x200]));
        assert_eq!(c.node(NodeId(1)).parents(), &ids(&c, &[0x100]));
    }

    #[test]
    fn raw_call_addresses_are_released_after_building() {
        let mut c = container(vec![node(0x100, "a", &[0x100], 1)], |_| None);
        assert!(c.node_mut(NodeId(0)).release_call_addresses().is_none());
    }
}
