use crate::graph::algo::GraphAlgorithmStatusListener;
use crate::graph::{GDirectedGraph, GEdge};
use crate::util::datastruct::Accumulator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Finds paths between two vertices in a directed graph.
pub trait FindPathsAlgorithm<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq> {
    /// Finds all paths from `start` to `end` in `g`, adding each discovered path (as a
    /// list of vertices) to `accumulator` as it is found.
    fn find_paths(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut impl Accumulator<Vec<V>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Installs a listener that is notified as vertex processing status changes.
    fn set_status_listener(&mut self, listener: GraphAlgorithmStatusListener<V>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::algo::Status;
    use crate::graph::g_implicit_directed_graph::GImplicitDirectedGraph;
    use crate::util::datastruct::ListAccumulator;
    use crate::util::task::DummyMonitor;

    #[derive(Clone, PartialEq, Debug)]
    struct Edge {
        start: i32,
        end: i32,
    }

    impl GEdge<i32> for Edge {
        fn get_start(&self) -> &i32 {
            &self.start
        }

        fn get_end(&self) -> &i32 {
            &self.end
        }
    }

    #[derive(Default, Clone)]
    struct SimpleGraph {
        edges: Vec<Edge>,
    }

    impl GImplicitDirectedGraph<i32, Edge> for SimpleGraph {
        fn get_in_edges(&self, v: &i32) -> Vec<Edge> {
            self.edges.iter().filter(|e| &e.end == v).cloned().collect()
        }

        fn get_out_edges(&self, v: &i32) -> Vec<Edge> {
            self.edges.iter().filter(|e| &e.start == v).cloned().collect()
        }

        fn copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            Box::new(self.clone())
        }
    }

    impl GDirectedGraph<i32, Edge> for SimpleGraph {
        fn add_vertex(&mut self, _v: i32) -> bool {
            true
        }

        fn remove_vertex(&mut self, _v: &i32) -> bool {
            false
        }

        fn add_edge(&mut self, e: Edge) {
            self.edges.push(e);
        }

        fn remove_edge(&mut self, _e: &Edge) -> bool {
            false
        }

        fn find_edge(&self, start: &i32, end: &i32) -> Option<Edge> {
            self.edges.iter().find(|e| &e.start == start && &e.end == end).cloned()
        }

        fn get_vertices(&self) -> Vec<i32> {
            Vec::new()
        }

        fn get_edges(&self) -> Vec<Edge> {
            self.edges.clone()
        }

        fn contains_vertex(&self, _v: &i32) -> bool {
            true
        }

        fn contains_edge(&self, e: &Edge) -> bool {
            self.edges.contains(e)
        }

        fn contains_edge_between(&self, from: &i32, to: &i32) -> bool {
            self.edges.iter().any(|e| &e.start == from && &e.end == to)
        }

        fn is_empty(&self) -> bool {
            self.edges.is_empty()
        }

        fn get_vertex_count(&self) -> usize {
            0
        }

        fn get_edge_count(&self) -> usize {
            self.edges.len()
        }

        fn empty_copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            Box::new(SimpleGraph::default())
        }
    }

    /// A depth-first mock implementation, just complex enough to prove the trait is
    /// usable across implementations and object-safe with respect to `&self`/`&mut self`.
    struct DepthFirstFinder {
        listener: Option<GraphAlgorithmStatusListener<i32>>,
    }

    impl FindPathsAlgorithm<i32, Edge> for DepthFirstFinder {
        fn find_paths(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            start: &i32,
            end: &i32,
            accumulator: &mut impl Accumulator<Vec<i32>>,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            let mut path = vec![*start];
            self.visit(g, *start, end, &mut path, accumulator, monitor)
        }

        fn set_status_listener(&mut self, listener: GraphAlgorithmStatusListener<i32>) {
            self.listener = Some(listener);
        }
    }

    impl DepthFirstFinder {
        fn visit(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            current: i32,
            end: &i32,
            path: &mut Vec<i32>,
            accumulator: &mut impl Accumulator<Vec<i32>>,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            if &current == end {
                accumulator.add(path.clone());
                return Ok(());
            }
            for e in g.get_out_edges(&current) {
                let next = *e.get_end();
                if path.contains(&next) {
                    continue;
                }
                path.push(next);
                self.visit(g, next, end, path, accumulator, monitor)?;
                path.pop();
            }
            Ok(())
        }
    }

    fn build_graph() -> SimpleGraph {
        let mut g = SimpleGraph::default();
        g.add_edge(Edge { start: 1, end: 2 });
        g.add_edge(Edge { start: 1, end: 3 });
        g.add_edge(Edge { start: 2, end: 3 });
        g
    }

    #[test]
    fn find_paths_collects_every_path() {
        let g = build_graph();
        let finder = DepthFirstFinder { listener: None };
        let mut acc = ListAccumulator::new();
        let monitor = DummyMonitor;
        finder.find_paths(&g, &1, &3, &mut acc, &monitor).unwrap();

        let paths: Vec<Vec<i32>> = acc.into_iter().collect();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![1, 3]));
        assert!(paths.contains(&vec![1, 2, 3]));
    }

    #[test]
    fn find_paths_reports_none_when_unreachable() {
        let g = build_graph();
        let finder = DepthFirstFinder { listener: None };
        let mut acc = ListAccumulator::new();
        let monitor = DummyMonitor;
        finder.find_paths(&g, &3, &1, &mut acc, &monitor).unwrap();
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn set_status_listener_stores_listener() {
        let mut finder = DepthFirstFinder { listener: None };
        assert!(finder.listener.is_none());
        finder.set_status_listener(GraphAlgorithmStatusListener::new());
        assert!(finder.listener.is_some());
        finder.listener.as_mut().unwrap().status_changed(&1, Status::InPath);
    }
}
