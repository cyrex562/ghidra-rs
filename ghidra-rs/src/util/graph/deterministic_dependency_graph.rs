//! Port of `ghidra.util.graph.DeterministicDependencyGraph`.
//!
//! Unlike its two ancestors in this module -- [`AbstractDependencyGraph`], a trait describing the
//! visiting/removal contract, and [`DependencyGraph`](super::DependencyGraph), a trait adding only
//! the hash-backed copy-constructor helper -- neither of which has a concrete, directly
//! instantiable implementation in this crate yet (their only implementors are `#[cfg(test)]` mock
//! structs proving the traits are usable behind `Box<dyn ...>`), this is ported as a real,
//! directly-constructible generic struct. The Java class is a leaf: nothing in `orig_src` extends
//! it further, and `ghidra.program.model.data.DataTypeWriter` instantiates it directly
//! (`new DeterministicDependencyGraph<>()`) to topologically order data types before emitting their
//! C-like declarations, so this port needs to be a real, usable value rather than another trait
//! seam -- there is no dependency cycle here to cut.
//!
//! Fidelity notes versus the Java source:
//!   - Java backs `nodeMap` with a `TreeMap` (sorted by `T`'s `Comparable` order) and both
//!     `unvisitedIndependentSet` and each node's `setOfNodesThatDependOnMe` with
//!     `org.apache.commons.collections4.set.ListOrderedSet` (hash-set semantics plus
//!     insertion-order iteration). This port uses `BTreeMap`/`BTreeSet` throughout instead of
//!     reproducing insertion-order sets, since this crate has no ordered-set (e.g. `indexmap`)
//!     dependency. The class's own doc comment states its purpose is simply to "provide
//!     determinism" (as opposed to `DependencyGraph`'s hash-based nondeterminism) for
//!     developmental debugging; `Ord`-sorted iteration is just as deterministic and reproducible
//!     as insertion-order iteration, it is merely a *different* deterministic order, which this
//!     doc comment calls out as an intentional, documented simplification rather than an
//!     oversight. One consequence worth knowing: `get_node_map_values()`/`pop()` here always
//!     yield values in `Ord` order, whereas Java's `pop()` yields values in the order they first
//!     became independent (insertion order into `unvisitedIndependentSet`). Both are equally
//!     valid topological orderings of an acyclic dependency graph.
//!   - Java's `T` merely needs to be a legal `TreeMap`/`ListOrderedSet` key (`Comparable` plus
//!     `equals`/`hashCode`); the Rust bound is `T: Ord + Clone + Hash + Eq`. `Clone` is needed
//!     because, unlike Java references, Rust values stored as both a map key and inside a
//!     dependent's edge set must be independently owned.
//!   - The private `DependencyNode` inner class (a `value` plus `setOfNodesThatDependOnMe` plus
//!     `numberOfNodesThatIDependOn`) is reproduced verbatim as the private [`DependencyNode`]
//!     struct in this file; it is exactly as much an implementation detail here as it is in Java.
//!   - `getNodeMap()` is omitted, matching the precedent already set by
//!     [`AbstractDependencyGraph`]'s doc comment: it merely exposes the private bookkeeping map
//!     and has no callers outside the class itself.
//!   - The Java copy constructor `DeterministicDependencyGraph(DeterministicDependencyGraph<T>
//!     other)` is ported as the inherent [`DeterministicDependencyGraph::copy_from`] associated
//!     function (naming precedent: `DependencyGraph::copy_from` in this same module), and
//!     [`AbstractDependencyGraph::copy`] is implemented in terms of it.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;

use super::{AbstractDependencyGraph, CycleDetectedError};

/// Port of the private `AbstractDependencyGraph.DependencyNode` inner class, as it applies to
/// this concrete implementation. `dependents` is the Java `setOfNodesThatDependOnMe` (renamed
/// for clarity), storing dependent *values* directly rather than references to sibling
/// `DependencyNode`s, since owned `T` values keyed by `Ord` make that unnecessary indirection.
#[derive(Debug, Clone)]
struct DependencyNode<T> {
    /// Port of `DependencyNode.value`.
    value: T,
    /// Port of `DependencyNode.setOfNodesThatDependOnMe`: the values that depend on this node's
    /// value (i.e. edges pointing *at* this node).
    dependents: BTreeSet<T>,
    /// Port of `DependencyNode.numberOfNodesThatIDependOn`.
    depends_on_count: usize,
}

impl<T: Ord + Clone> DependencyNode<T> {
    fn new(value: T) -> Self {
        Self { value, dependents: BTreeSet::new(), depends_on_count: 0 }
    }
}

/// Port of `ghidra.util.graph.DeterministicDependencyGraph<T>`. See the module doc comment for
/// fidelity notes.
#[derive(Debug, Clone)]
pub struct DeterministicDependencyGraph<T: Ord + Clone> {
    /// Port of `AbstractDependencyGraph.nodeMap` (a `TreeMap` in this subclass).
    node_map: BTreeMap<T, DependencyNode<T>>,
    /// Port of `AbstractDependencyGraph.unvisitedIndependentSet` (a `ListOrderedSet` in this
    /// subclass; see the module doc comment for why this is a `BTreeSet` here instead).
    unvisited_independent_set: BTreeSet<T>,
    /// Port of `AbstractDependencyGraph.visitedButNotDeletedCount`.
    ///
    /// Java's field is a plain `int` and its `remove(T)` unconditionally does
    /// `visitedButNotDeletedCount--` whenever `value` was still present in
    /// `unvisitedIndependentSet` at the time of removal -- which includes the ordinary case of
    /// removing an independent value that was never `pop()`-ed or fetched via
    /// `getUnvisitedIndependentValues()` in the first place (those two accessors are the only
    /// places that increment the counter, and both already remove the value from
    /// `unvisitedIndependentSet` themselves before delegating to `remove()`, so `remove()`'s own
    /// decrement never fires for values that actually came from them). So a direct `remove()` of
    /// an untouched independent value silently drives this counter negative in Java (harmless
    /// there: `int` underflow just yields `-1`, and the only read of this field is an `== 0`
    /// check in `checkCycleState`, which now requires one extra future increment before it can
    /// read zero again). `i64` (rather than `usize`) reproduces that exact quirk instead of
    /// panicking on an unsigned subtraction underflow, which a literal `usize` port would do the
    /// first time a caller removes a value without going through `pop()`/
    /// `get_unvisited_independent_values()` first -- an entirely ordinary usage pattern, not an
    /// edge case.
    visited_but_not_deleted_count: i64,
}

impl<T: Ord + Clone> Default for DeterministicDependencyGraph<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone> DeterministicDependencyGraph<T> {
    /// Port of the no-arg `DeterministicDependencyGraph()` constructor.
    pub fn new() -> Self {
        Self {
            node_map: BTreeMap::new(),
            unvisited_independent_set: BTreeSet::new(),
            visited_but_not_deleted_count: 0,
        }
    }

    /// Port of the copy constructor `DeterministicDependencyGraph(DeterministicDependencyGraph<T>
    /// other)`. Reproduces every value and dependency edge of `other`, mirroring
    /// `DependencyGraph::copy_from`'s approach in this same module but using only the inherent
    /// (non-trait) helpers below, so this associated function does not need a `Hash` bound on
    /// `T` the way the `AbstractDependencyGraph` trait impl does.
    pub fn copy_from(other: &Self) -> Self {
        let mut graph = Self::new();
        for (value, node) in &other.node_map {
            graph.ensure_node(value.clone());
            for dependent in &node.dependents {
                graph.add_dependency_inner(dependent.clone(), value.clone());
            }
        }
        graph
    }

    /// Inherent equivalent of `AbstractDependencyGraph::add_dependency`, usable without a `Hash`
    /// bound on `T`. See that trait method (implemented below by delegating here) for the port
    /// commentary.
    fn add_dependency_inner(&mut self, value1: T, value2: T) {
        self.ensure_node(value1.clone());
        self.ensure_node(value2.clone());
        // Port of `valueNode2.addNodeThatDependsOnMe(valueNode1)`.
        let inserted =
            self.node_map.get_mut(&value2).expect("just ensured").dependents.insert(value1.clone());
        if inserted {
            if let Some(node1) = self.node_map.get_mut(&value1) {
                node1.depends_on_count += 1;
            }
            self.unvisited_independent_set.remove(&value1);
        }
    }

    fn ensure_node(&mut self, value: T) {
        if !self.node_map.contains_key(&value) {
            self.node_map.insert(value.clone(), DependencyNode::new(value.clone()));
            self.unvisited_independent_set.insert(value);
        }
    }

    /// Port of the `checkCycleState()` private helper.
    fn check_cycle_state(&self) -> Result<(), CycleDetectedError> {
        if !self.node_map.is_empty()
            && self.unvisited_independent_set.is_empty()
            && self.visited_but_not_deleted_count == 0
        {
            return Err(CycleDetectedError);
        }
        Ok(())
    }

    /// Port of `DependencyNode.releaseDependencies()` for the node currently stored at `value`
    /// (used by `has_cycles`, where nodes stay in `node_map` throughout the traversal). `remove`
    /// has its own inline copy of this logic since there the node has already been taken out of
    /// `node_map`.
    fn release_dependencies_of(&mut self, value: &T) {
        let dependents: Vec<T> = match self.node_map.get(value) {
            Some(node) => node.dependents.iter().cloned().collect(),
            None => return,
        };
        for dependent in dependents {
            if let Some(node) = self.node_map.get_mut(&dependent) {
                node.depends_on_count -= 1;
                if node.depends_on_count == 0 {
                    self.unvisited_independent_set.insert(dependent);
                }
            }
        }
    }

    fn compute_all_independent_values(&self) -> BTreeSet<T> {
        self.node_map
            .values()
            .filter(|node| node.depends_on_count == 0)
            .map(|node| node.value.clone())
            .collect()
    }

    /// Port of the `reset()` private helper, called from `hasCycles()`'s `finally` block to
    /// restore bookkeeping after a non-destructive traversal.
    fn reset(&mut self) {
        self.visited_but_not_deleted_count = 0;
        for node in self.node_map.values_mut() {
            node.depends_on_count = 0;
        }
        let edges: Vec<T> =
            self.node_map.values().flat_map(|node| node.dependents.iter().cloned()).collect();
        for child in edges {
            if let Some(node) = self.node_map.get_mut(&child) {
                node.depends_on_count += 1;
            }
        }
        self.unvisited_independent_set = self.compute_all_independent_values();
    }
}

impl<T: Ord + Clone + Hash + 'static> AbstractDependencyGraph<T> for DeterministicDependencyGraph<T> {
    fn add_value(&mut self, value: T) {
        self.ensure_node(value);
    }

    fn size(&self) -> usize {
        self.node_map.len()
    }

    fn contains(&self, value: &T) -> bool {
        self.node_map.contains_key(value)
    }

    fn get_values(&self) -> HashSet<T> {
        self.node_map.keys().cloned().collect()
    }

    fn get_node_map_values(&self) -> HashSet<T> {
        self.node_map.keys().cloned().collect()
    }

    fn add_dependency(&mut self, value1: T, value2: T) {
        self.add_dependency_inner(value1, value2);
    }

    fn has_unvisited_independent_values(&mut self) -> Result<bool, CycleDetectedError> {
        if !self.unvisited_independent_set.is_empty() {
            return Ok(true);
        }
        self.check_cycle_state()?;
        Ok(false)
    }

    fn pop(&mut self) -> Result<Option<T>, CycleDetectedError> {
        self.check_cycle_state()?;
        let Some(value) = self.unvisited_independent_set.iter().next().cloned() else {
            return Ok(None);
        };
        self.unvisited_independent_set.remove(&value);
        self.remove(&value);
        Ok(Some(value))
    }

    fn has_cycles(&mut self) -> bool {
        let result = (|| {
            let mut visited: BTreeSet<T> = BTreeSet::new();
            while !self.unvisited_independent_set.is_empty() {
                // Port of the inlined `getUnvisitedIndependentValues()` call in `hasCycles()`.
                self.visited_but_not_deleted_count += self.unvisited_independent_set.len() as i64;
                let values: Vec<T> = self.unvisited_independent_set.iter().cloned().collect();
                self.unvisited_independent_set.clear();

                for value in &values {
                    visited.insert(value.clone());
                }
                for value in &values {
                    self.release_dependencies_of(value);
                }
            }
            visited.len() != self.node_map.len()
        })();
        // Port of the `finally { reset(); }` block: always restore bookkeeping, regardless of
        // whether a cycle was found.
        self.reset();
        result
    }

    fn get_unvisited_independent_values(&mut self) -> Result<HashSet<T>, CycleDetectedError> {
        self.check_cycle_state()?;
        self.visited_but_not_deleted_count += self.unvisited_independent_set.len() as i64;
        let result: HashSet<T> = self.unvisited_independent_set.iter().cloned().collect();
        self.unvisited_independent_set.clear();
        Ok(result)
    }

    fn get_all_independent_values(&self) -> HashSet<T> {
        self.compute_all_independent_values().into_iter().collect()
    }

    fn remove(&mut self, value: &T) {
        if let Some(node) = self.node_map.remove(value) {
            for dependent in &node.dependents {
                if let Some(dependent_node) = self.node_map.get_mut(dependent) {
                    dependent_node.depends_on_count -= 1;
                    if dependent_node.depends_on_count == 0 {
                        self.unvisited_independent_set.insert(dependent.clone());
                    }
                }
            }
            if self.unvisited_independent_set.remove(value) {
                self.visited_but_not_deleted_count -= 1;
            }
        }
    }

    fn get_dependent_values(&self, value: &T) -> HashSet<T> {
        match self.node_map.get(value) {
            Some(node) => node.dependents.iter().cloned().collect(),
            None => HashSet::new(),
        }
    }

    fn copy(&self) -> Box<dyn AbstractDependencyGraph<T>> {
        Box::new(Self::copy_from(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_value_and_dependency_track_size_and_containment() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_value(1);
        assert_eq!(graph.size(), 1);
        assert!(graph.contains(&1));

        graph.add_dependency(2, 1); // 2 depends on 1
        assert_eq!(graph.size(), 2);
        assert!(graph.contains(&2));
        assert_eq!(graph.get_dependent_values(&1), HashSet::from([2]));
        assert_eq!(graph.get_values(), HashSet::from([1, 2]));
    }

    #[test]
    fn get_node_map_values_is_sorted_by_ord() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_value(3);
        graph.add_value(1);
        graph.add_value(2);
        // BTreeMap iteration is sorted; confirm the deterministic (if different-from-Java) order
        // documented at the top of this file.
        let ordered: Vec<i32> = graph.node_map.keys().cloned().collect();
        assert_eq!(ordered, vec![1, 2, 3]);
        assert_eq!(graph.get_node_map_values(), HashSet::from([1, 2, 3]));
    }

    #[test]
    fn pop_only_returns_independent_values_and_unblocks_dependents() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_dependency(2, 1); // 2 depends on 1
        graph.add_dependency(3, 2); // 3 depends on 2

        assert_eq!(graph.get_all_independent_values(), HashSet::from([1]));

        let popped = graph.pop().unwrap();
        assert_eq!(popped, Some(1));
        assert_eq!(graph.size(), 2);
        assert_eq!(graph.get_all_independent_values(), HashSet::from([2]));

        let popped = graph.pop().unwrap();
        assert_eq!(popped, Some(2));
        assert_eq!(graph.get_all_independent_values(), HashSet::from([3]));

        let popped = graph.pop().unwrap();
        assert_eq!(popped, Some(3));
        assert!(graph.is_empty());

        // Now empty: pop() returns Ok(None), not a cycle error.
        assert_eq!(graph.pop().unwrap(), None);
    }

    #[test]
    fn duplicate_dependency_is_not_double_counted() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_dependency(2, 1);
        graph.add_dependency(2, 1); // duplicate edge, should be a no-op the second time
        assert_eq!(graph.get_all_independent_values(), HashSet::from([1]));

        graph.remove(&1);
        // If the duplicate had been double-counted, 2 would still show a dependency count of 1.
        assert_eq!(graph.get_all_independent_values(), HashSet::from([2]));
    }

    #[test]
    fn has_cycles_detects_a_cycle_without_mutating_the_graph() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_dependency(1, 2); // 1 depends on 2
        graph.add_dependency(2, 1); // 2 depends on 1 -- cycle

        assert!(graph.has_cycles());
        // has_cycles() must restore state (Java's `finally { reset(); }`), so the graph is still
        // fully usable and still reports the same cycle afterward.
        assert_eq!(graph.size(), 2);
        assert!(graph.has_cycles());
    }

    #[test]
    fn has_cycles_is_false_for_acyclic_graph_and_pop_still_works_after() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_dependency(2, 1);
        graph.add_dependency(3, 1);

        assert!(!graph.has_cycles());
        assert_eq!(graph.get_all_independent_values(), HashSet::from([1]));
        assert_eq!(graph.pop().unwrap(), Some(1));
    }

    #[test]
    fn pop_on_pure_cycle_eventually_reports_cycle_detected() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_dependency(1, 2);
        graph.add_dependency(2, 1);

        // Nothing is independent, and the graph is non-empty, so pop() must report the cycle.
        assert!(graph.pop().is_err());
    }

    #[test]
    fn copy_from_and_trait_copy_reproduce_values_and_dependencies() {
        let mut original: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        original.add_dependency(2, 1);
        original.add_value(3);

        let copy = DeterministicDependencyGraph::copy_from(&original);
        assert_eq!(copy.size(), original.size());
        assert!(copy.contains(&1));
        assert!(copy.contains(&2));
        assert!(copy.contains(&3));
        assert_eq!(copy.get_dependent_values(&1), HashSet::from([2]));
        assert_eq!(copy.get_all_independent_values(), original.get_all_independent_values());

        let trait_copy: Box<dyn AbstractDependencyGraph<i32>> =
            AbstractDependencyGraph::copy(&original);
        assert_eq!(trait_copy.size(), original.size());
        assert_eq!(trait_copy.get_dependent_values(&1), HashSet::from([2]));
    }

    #[test]
    fn get_unvisited_independent_values_hides_them_from_pop_until_removed() {
        let mut graph: DeterministicDependencyGraph<i32> = DeterministicDependencyGraph::new();
        graph.add_value(1);
        graph.add_value(2);

        let batch = graph.get_unvisited_independent_values().unwrap();
        assert_eq!(batch, HashSet::from([1, 2]));

        // Both values were "visited" via the batch call, so pop() must not hand them out again
        // even though they're still independent and still in the graph.
        assert_eq!(graph.pop().unwrap(), None);

        // Removing them (as the batch API contract expects the caller to do) does not trip the
        // cycle detector, since visited_but_not_deleted_count tracks them.
        graph.remove(&1);
        graph.remove(&2);
        assert!(graph.is_empty());
    }
}
