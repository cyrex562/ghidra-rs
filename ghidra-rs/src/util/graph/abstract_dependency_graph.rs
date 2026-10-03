use std::collections::HashSet;
use std::error::Error;
use std::fmt;

/// Error indicating a cycle was detected in the dependency graph.
///
/// Port of the `IllegalStateException("Cycle detected!")` thrown by
/// `ghidra.util.graph.AbstractDependencyGraph` when a traversal method is called on a
/// non-empty graph that has no unvisited independent values left to hand out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleDetectedError;

impl fmt::Display for CycleDetectedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cycle detected!")
    }
}

impl Error for CycleDetectedError {}

/// Manages visiting (processing) a set of values where some values depend on other values
/// being processed first, forming an acyclic directed graph whose vertexes are the values and
/// whose edges represent dependencies. Values can only be removed once they have no
/// dependencies; as dependency-free values are removed, other values that depended on them
/// become eligible in turn. Introducing a cycle eventually surfaces as a [`CycleDetectedError`].
///
/// Port of `ghidra.util.graph.AbstractDependencyGraph`, cut to a trait to break a dependency
/// cycle at this node in the port graph. The Java class's private `DependencyNode` inner class
/// and its `nodeMap` / `unvisitedIndependentSet` bookkeeping fields are therefore an
/// implementation detail behind this trait rather than something the trait itself prescribes;
/// `getNodeMap()`, which merely exposes that bookkeeping and has no callers outside the class
/// itself, is likewise omitted here.
///
/// See also `DependencyGraph` and `DeterministicDependencyGraph` (not yet ported), the two
/// concrete Java subclasses.
pub trait AbstractDependencyGraph<T> {
    /// Adds `value` to this graph.
    fn add_value(&mut self, value: T);

    /// Returns the number of values in this graph.
    fn size(&self) -> usize;

    /// Returns `true` if the graph has no values.
    fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Returns `true` if this graph has the given value.
    fn contains(&self, value: &T) -> bool;

    /// Returns the set of values in this graph.
    fn get_values(&self) -> HashSet<T>;

    /// Returns the set of values in this graph, as tracked by the node map.
    fn get_node_map_values(&self) -> HashSet<T>;

    /// Adds a dependency such that `value1` depends on `value2`. Both values are added to the
    /// graph if they are not already present.
    fn add_dependency(&mut self, value1: T, value2: T);

    /// Returns `true` if there are unvisited values ready (no dependencies) for processing.
    ///
    /// Returns [`CycleDetectedError`] if the graph is non-empty and there are no nodes without
    /// dependencies, which indicates a cycle.
    fn has_unvisited_independent_values(&mut self) -> Result<bool, CycleDetectedError>;

    /// Removes and returns a value that has no dependencies and hasn't been visited, or `None`
    /// if the graph is empty or every dependency-free value is currently visited.
    fn pop(&mut self) -> Result<Option<T>, CycleDetectedError>;

    /// Returns `true` if this graph has cycles. Allows "fail fast" cycle detection without
    /// processing values.
    fn has_cycles(&mut self) -> bool;

    /// Returns the set of unvisited values without dependencies, marking them visited so that
    /// future calls will not return them again until they are removed from the graph.
    fn get_unvisited_independent_values(&mut self) -> Result<HashSet<T>, CycleDetectedError>;

    /// Returns the set of all values without dependencies, regardless of whether they have
    /// already been visited.
    fn get_all_independent_values(&self) -> HashSet<T>;

    /// Removes `value` from the graph. Any dependency from this value to another is released,
    /// possibly making values that depended on it eligible for processing.
    fn remove(&mut self, value: &T);

    /// Returns the set of values that depend on `value`.
    fn get_dependent_values(&self, value: &T) -> HashSet<T>;

    /// Returns a copy of this graph.
    fn copy(&self) -> Box<dyn AbstractDependencyGraph<T>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Trivial mock proving `AbstractDependencyGraph` is object-safe and usable behind
    /// `Box<dyn AbstractDependencyGraph<T>>`. Dependencies are tracked with plain maps rather
    /// than the Java class's `DependencyNode` graph; that bookkeeping is exactly what the
    /// trait leaves up to implementers.
    #[derive(Clone)]
    struct MockDependencyGraph {
        dependents_of: HashMap<i32, HashSet<i32>>,
        depends_on_count: HashMap<i32, usize>,
        visited_not_deleted: usize,
    }

    impl MockDependencyGraph {
        fn new() -> Self {
            Self {
                dependents_of: HashMap::new(),
                depends_on_count: HashMap::new(),
                visited_not_deleted: 0,
            }
        }

        fn ensure(&mut self, value: i32) {
            self.dependents_of.entry(value).or_default();
            self.depends_on_count.entry(value).or_insert(0);
        }
    }

    impl AbstractDependencyGraph<i32> for MockDependencyGraph {
        fn add_value(&mut self, value: i32) {
            self.ensure(value);
        }

        fn size(&self) -> usize {
            self.depends_on_count.len()
        }

        fn contains(&self, value: &i32) -> bool {
            self.depends_on_count.contains_key(value)
        }

        fn get_values(&self) -> HashSet<i32> {
            self.depends_on_count.keys().copied().collect()
        }

        fn get_node_map_values(&self) -> HashSet<i32> {
            self.get_values()
        }

        fn add_dependency(&mut self, value1: i32, value2: i32) {
            self.ensure(value1);
            self.ensure(value2);
            if self.dependents_of.get_mut(&value2).unwrap().insert(value1) {
                *self.depends_on_count.get_mut(&value1).unwrap() += 1;
            }
        }

        fn has_unvisited_independent_values(&mut self) -> Result<bool, CycleDetectedError> {
            Ok(self.get_all_independent_values().len() > self.visited_not_deleted)
        }

        fn pop(&mut self) -> Result<Option<i32>, CycleDetectedError> {
            let independent = self.get_all_independent_values();
            if let Some(&value) = independent.iter().next() {
                self.remove(&value);
                Ok(Some(value))
            } else if self.is_empty() {
                Ok(None)
            } else {
                Err(CycleDetectedError)
            }
        }

        fn has_cycles(&mut self) -> bool {
            let mut remaining = self.clone();
            let mut visited = 0;
            loop {
                let independent = remaining.get_all_independent_values();
                if independent.is_empty() {
                    break;
                }
                for value in &independent {
                    remaining.remove(value);
                    visited += 1;
                }
            }
            visited != self.size()
        }

        fn get_unvisited_independent_values(&mut self) -> Result<HashSet<i32>, CycleDetectedError> {
            let values = self.get_all_independent_values();
            self.visited_not_deleted += values.len();
            Ok(values)
        }

        fn get_all_independent_values(&self) -> HashSet<i32> {
            self.depends_on_count
                .iter()
                .filter(|&(_, &count)| count == 0)
                .map(|(&value, _)| value)
                .collect()
        }

        fn remove(&mut self, value: &i32) {
            if let Some(dependents) = self.dependents_of.remove(value) {
                for dependent in dependents {
                    if let Some(count) = self.depends_on_count.get_mut(&dependent) {
                        *count -= 1;
                    }
                }
            }
            self.depends_on_count.remove(value);
        }

        fn get_dependent_values(&self, value: &i32) -> HashSet<i32> {
            self.dependents_of.get(value).cloned().unwrap_or_default()
        }

        fn copy(&self) -> Box<dyn AbstractDependencyGraph<i32>> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn add_and_pop_respects_dependencies_behind_trait_object() {
        let mut graph: Box<dyn AbstractDependencyGraph<i32>> = Box::new(MockDependencyGraph::new());

        graph.add_value(1);
        graph.add_dependency(2, 1); // 2 depends on 1
        assert_eq!(graph.size(), 2);
        assert!(graph.contains(&1));
        assert_eq!(graph.get_dependent_values(&1), HashSet::from([2]));

        // 1 has no dependencies, 2 does — only 1 should be independent.
        assert_eq!(graph.get_all_independent_values(), HashSet::from([1]));

        let popped = graph.pop().unwrap();
        assert_eq!(popped, Some(1));

        // now that 1 is gone, 2 becomes independent
        assert_eq!(graph.get_all_independent_values(), HashSet::from([2]));
        assert!(!graph.has_cycles());

        let copy = graph.copy();
        assert_eq!(copy.size(), graph.size());
    }
}
