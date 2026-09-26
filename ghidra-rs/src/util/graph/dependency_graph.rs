use super::AbstractDependencyGraph;

/// Original dependency graph implementation that uses hash-based maps/sets. Side effect of this
/// is that data pulled from the graph (`pop()`) is not performed in a deterministic order.
/// However, load time for the graph is O(1).
///
/// Port of `ghidra.util.graph.DependencyGraph`, cut to a trait to break a dependency cycle at
/// this node in the port graph. The Java class is a thin `AbstractDependencyGraph` subclass that
/// only chooses hash-based backing storage (`createNodeMap`/`createNodeSet` returning
/// `HashMap`/`HashSet`) and overrides `copy()`/`getNodeMapValues()` to match; those factory
/// methods are exactly the bookkeeping `AbstractDependencyGraph` already hides behind its own
/// trait, so they are not repeated here. The Java copy constructor walks the other graph's
/// private `DependencyNode` objects directly; [`DependencyGraph::copy_from`] reproduces the same
/// value/dependency copying using only [`AbstractDependencyGraph`]'s public API, so no
/// `DependencyNode` placeholder is needed.
///
/// See also `AbstractDependencyGraph` and `DeterministicDependencyGraph` (not yet ported), the
/// other concrete Java subclass.
pub trait DependencyGraph<T>: AbstractDependencyGraph<T> {
    /// Creates a new, empty dependency graph.
    fn new() -> Self
    where
        Self: Sized;

    /// Populates this (expected to be empty) graph as a copy of `other`, copying every value and
    /// dependency edge. Port of the Java copy constructor `DependencyGraph(DependencyGraph<T>
    /// other)`.
    fn copy_from(&mut self, other: &dyn AbstractDependencyGraph<T>)
    where
        T: Clone,
    {
        for value in other.get_node_map_values() {
            self.add_value(value.clone());
            for dependent in other.get_dependent_values(&value) {
                self.add_dependency(dependent, value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// Trivial mock proving `DependencyGraph` is usable behind `Box<dyn DependencyGraph<T>>`
    /// (object-safe aside from the `Self: Sized` constructor) and that `copy_from` reproduces
    /// values and dependency edges via the `AbstractDependencyGraph` API alone.
    #[derive(Clone, Default)]
    struct MockDependencyGraph {
        dependents_of: HashMap<i32, HashSet<i32>>,
        depends_on_count: HashMap<i32, usize>,
    }

    impl MockDependencyGraph {
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

        fn has_unvisited_independent_values(
            &mut self,
        ) -> Result<bool, super::super::CycleDetectedError> {
            Ok(!self.get_all_independent_values().is_empty())
        }

        fn pop(&mut self) -> Result<Option<i32>, super::super::CycleDetectedError> {
            let independent = self.get_all_independent_values();
            if let Some(&value) = independent.iter().next() {
                self.remove(&value);
                Ok(Some(value))
            } else if self.is_empty() {
                Ok(None)
            } else {
                Err(super::super::CycleDetectedError)
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

        fn get_unvisited_independent_values(
            &mut self,
        ) -> Result<HashSet<i32>, super::super::CycleDetectedError> {
            Ok(self.get_all_independent_values())
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

    impl DependencyGraph<i32> for MockDependencyGraph {
        fn new() -> Self {
            Self::default()
        }
    }

    #[test]
    fn copy_from_reproduces_values_and_dependencies_behind_trait_object() {
        let mut original = MockDependencyGraph::new();
        original.add_value(1);
        original.add_dependency(2, 1); // 2 depends on 1

        let mut copy: Box<dyn DependencyGraph<i32>> = Box::new(MockDependencyGraph::new());
        copy.copy_from(&original);

        assert_eq!(copy.size(), original.size());
        assert!(copy.contains(&1));
        assert!(copy.contains(&2));
        assert_eq!(copy.get_dependent_values(&1), HashSet::from([2]));
        assert_eq!(
            copy.get_all_independent_values(),
            original.get_all_independent_values()
        );
    }
}
