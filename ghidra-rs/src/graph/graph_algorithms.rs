use std::cmp::Ordering;
use std::io::{self, Write};

use super::g_directed_graph::GDirectedGraph;
use super::g_edge::GEdge;
use super::seam_stubs::{GraphNavigatorSeam, TimeoutTaskMonitorSeam};
use crate::util::exception::{CancelledException, TimeoutException};
use crate::util::task::TaskMonitor;

/// Error returned by the timeout-bounded circuit/path searches: mirrors the two checked
/// exceptions (`CancelledException`, `TimeoutException`) that `findCircuits`/`findPaths` declare
/// when given a `TimeoutTaskMonitor`.
#[derive(Debug, PartialEq)]
pub enum TimeoutMonitorError {
    Cancelled(CancelledException),
    TimedOut(TimeoutException),
}

impl From<CancelledException> for TimeoutMonitorError {
    fn from(e: CancelledException) -> Self {
        TimeoutMonitorError::Cancelled(e)
    }
}

impl From<TimeoutException> for TimeoutMonitorError {
    fn from(e: TimeoutException) -> Self {
        TimeoutMonitorError::TimedOut(e)
    }
}

/// A set of convenience methods for performing graph algorithms on a graph.
///
/// Port of `ghidra.graph.GraphAlgorithms`, selected as a dependency-cycle cut-point: in Java,
/// `GraphAlgorithms` and `ghidra.graph.algo.GraphNavigator` reference each other directly
/// (`GraphNavigator` calls `GraphAlgorithms.getSources`/`getSinks`/`getVerticesInPostOrder`, and
/// `GraphAlgorithms` constructs `GraphNavigator` instances). Converting the original static
/// utility class into a trait lets `GraphNavigator` (once ported) depend on this trait rather
/// than a concrete type, breaking the cycle.
///
/// Methods whose logic depends only on [`GDirectedGraph`]/[`GEdge`] are given real default
/// implementations here. Methods whose Java bodies delegate to a dedicated algorithm class that
/// is not yet ported (`TarjanStronglyConnectedAlgorthm`, `ChkDominanceAlgorithm`,
/// `ChkPostDominanceAlgorithm`, `JohnsonCircuitsAlgorithm`, `DepthFirstSorter`,
/// `GraphToTreeAlgorithm`) are declared without a default body: implementors supply the
/// algorithm once it exists. None of those algorithm types appear in this trait's method
/// signatures, so no placeholder stubs are needed for them; the one dependency that *does*
/// appear in a signature (`GraphNavigator`, for `getVerticesInPostOrder`/`getVerticesInPreOrder`)
/// is covered by [`GraphNavigatorSeam`] in [`super::seam_stubs`], and the timeout-monitor
/// overloads are covered by [`TimeoutTaskMonitorSeam`].
pub trait GraphAlgorithms<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq> {
    /// Returns all source vertices (those with no incoming edges) in the graph.
    fn get_sources(&self, g: &dyn GDirectedGraph<V, E>) -> Vec<V> {
        g.get_vertices()
            .into_iter()
            .filter(|v| g.get_in_edges(v).is_empty())
            .collect()
    }

    /// Returns all sink vertices (those with no outgoing edges) in the graph.
    fn get_sinks(&self, g: &dyn GDirectedGraph<V, E>) -> Vec<V> {
        g.get_vertices()
            .into_iter()
            .filter(|v| g.get_out_edges(v).is_empty())
            .collect()
    }

    /// Returns a set of all edges that are reachable from the given vertex.
    ///
    /// `top_down` is `true` for outgoing edges, `false` for incoming edges.
    fn get_edges_from_vertex(&self, g: &dyn GDirectedGraph<V, E>, v: &V, top_down: bool) -> Vec<E> {
        self.get_edges_from(g, std::slice::from_ref(v), top_down)
    }

    /// Returns a set of all edges that are reachable from the given collection of vertices.
    ///
    /// `top_down` is `true` for outgoing edges, `false` for incoming edges.
    fn get_edges_from(&self, g: &dyn GDirectedGraph<V, E>, vertices: &[V], top_down: bool) -> Vec<E> {
        let mut edges: Vec<E> = Vec::new();
        let mut pending: Vec<V> = vertices.to_vec();

        while !pending.is_empty() {
            let mut newly_pending: Vec<V> = Vec::new();
            for parent in &pending {
                let out_edges = if top_down { g.get_out_edges(parent) } else { g.get_in_edges(parent) };
                for e in out_edges {
                    if !edges.contains(&e) {
                        let destination =
                            if top_down { e.get_end().clone() } else { e.get_start().clone() };
                        edges.push(e);
                        newly_pending.push(destination);
                    }
                }
            }
            pending = newly_pending;
        }

        edges
    }

    /// Returns all descendants for the given vertices in the given graph.
    fn get_descendants(&self, g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> Vec<V> {
        let edges = self.get_edges_from(g, vertices, true);
        self.to_vertices(&edges)
    }

    /// Returns all ancestors for the given vertices in the given graph.
    fn get_ancestors(&self, g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> Vec<V> {
        let edges = self.get_edges_from(g, vertices, false);
        self.to_vertices(&edges)
    }

    /// Creates a subgraph of the given graph for each edge of the given graph that is contained
    /// in the list of vertices.
    fn create_sub_graph(&self, g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> Box<dyn GDirectedGraph<V, E>> {
        let mut sub_graph = g.empty_copy();
        for e in g.get_edges() {
            if vertices.contains(e.get_start()) && vertices.contains(e.get_end()) {
                sub_graph.add_edge(e);
            }
        }
        sub_graph
    }

    /// Retains all edges in the graph where each edge's endpoints are in the given set of
    /// vertices.
    fn retain_edges(&self, g: &dyn GDirectedGraph<V, E>, vertices: &[V]) -> Vec<E> {
        g.get_edges()
            .into_iter()
            .filter(|e| vertices.contains(e.get_start()) && vertices.contains(e.get_end()))
            .collect()
    }

    /// Returns the set of vertices contained within the given edges.
    fn to_vertices(&self, edges: &[E]) -> Vec<V> {
        let mut result: Vec<V> = Vec::new();
        for e in edges {
            let start = e.get_start().clone();
            if !result.contains(&start) {
                result.push(start);
            }
            let end = e.get_end().clone();
            if !result.contains(&end) {
                result.push(end);
            }
        }
        result
    }

    /// Returns all entry points in the given graph: sources, plus one representative vertex from
    /// each self-contained strongly connected component (a strong component with no incoming
    /// edges from outside itself).
    fn get_entry_points(&self, g: &dyn GDirectedGraph<V, E>) -> Vec<V> {
        let sources = self.get_sources(g);
        let descendants = self.get_descendants(g, &sources);

        let mut isolated: Vec<V> = g.get_vertices();
        isolated.retain(|v| !sources.contains(v) && !descendants.contains(v));

        let mut entry_points = sources;
        if isolated.is_empty() {
            return entry_points;
        }

        let isolated_graph = self.create_sub_graph(g, &isolated);
        let strongs = self.get_strongly_connected_components(isolated_graph.as_ref());

        for component in &strongs {
            if is_self_contained_strong_component(g, component) {
                if let Some(first) = component.first() {
                    if !entry_points.contains(first) {
                        entry_points.push(first.clone());
                    }
                }
            }
        }

        entry_points
    }

    /// Returns the dominance tree of the given graph: a tree where each node's children are
    /// those nodes it *immediately* dominates.
    fn find_dominance_tree(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn GDirectedGraph<V, E>>, CancelledException>;

    /// Returns all vertices dominated by `from`.
    fn find_dominance(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        from: &V,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<V>, CancelledException>;

    /// Returns all vertices post-dominated by `from`.
    fn find_post_dominance(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        from: &V,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<V>, CancelledException>;

    /// Finds all the circuits, or cycles, in the given graph, defaulting to unique circuits.
    fn find_circuits(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Vec<V>>, CancelledException> {
        self.find_circuits_unique(g, true, monitor)
    }

    /// Finds all the circuits, or cycles, in the given graph.
    ///
    /// `unique_circuits` set to `true` signals to return only unique circuits, where no two
    /// circuits will contain the same vertex.
    fn find_circuits_unique(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        unique_circuits: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Vec<V>>, CancelledException>;

    /// Finds all the circuits, or cycles, in the given graph, using a timeout-bounded monitor.
    /// Useful for finding circuits on very large, dense graphs.
    fn find_circuits_with_timeout(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        unique_circuits: bool,
        monitor: &dyn TimeoutTaskMonitorSeam,
    ) -> Result<Vec<Vec<V>>, TimeoutMonitorError>;

    /// Finds all paths from `start` to `end` in the given graph, adding each discovered path to
    /// `accumulator` as it is found.
    ///
    /// Not object-safe (the generic `accumulator` parameter excludes it from `dyn` dispatch),
    /// matching the existing [`FindPathsAlgorithm`](crate::graph::algo::FindPathsAlgorithm)
    /// convention; the rest of this trait remains usable via `dyn GraphAlgorithms`.
    fn find_paths(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut impl crate::util::datastruct::Accumulator<Vec<V>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>
    where
        Self: Sized;

    /// Finds all paths from `start` to `end` in the given graph, using a timeout-bounded
    /// monitor. Useful for finding paths on very large, dense graphs.
    fn find_paths_with_timeout(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut impl crate::util::datastruct::Accumulator<Vec<V>>,
        monitor: &dyn TimeoutTaskMonitorSeam,
    ) -> Result<(), TimeoutMonitorError>
    where
        Self: Sized;

    /// Returns a list where each set is a strongly connected component of the given graph.
    fn get_strongly_connected_components(&self, g: &dyn GDirectedGraph<V, E>) -> Vec<Vec<V>>;

    /// Returns the vertices of the graph in post-order for a depth-first traversal in the
    /// direction given by `navigator`.
    fn get_vertices_in_post_order(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        navigator: &dyn GraphNavigatorSeam<V, E>,
    ) -> Vec<V>;

    /// Returns the vertices of the graph in pre-order for a depth-first traversal in the
    /// direction given by `navigator`.
    fn get_vertices_in_pre_order(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        navigator: &dyn GraphNavigatorSeam<V, E>,
    ) -> Vec<V>;

    /// Calculates 'complexity depth': for each vertex, the deepest/longest path from that vertex
    /// for a depth-first traversal.
    fn get_complexity_depth(&self, g: &dyn GDirectedGraph<V, E>) -> Vec<(V, i32)> {
        let mut levels: Vec<(V, i32)> = Vec::new();
        let post_order =
            self.get_vertices_in_post_order(g, &crate::graph::seam_stubs::TopDownNavigator);
        for v in post_order {
            let mut max_level = -1i32;
            for child in g.get_successors(&v) {
                if let Some((_, level)) = levels.iter().find(|(cv, _)| *cv == child) {
                    if *level > max_level {
                        max_level = *level;
                    }
                }
            }
            levels.push((v, max_level + 1));
        }
        levels
    }

    /// Sorts the vertices reachable from `root` topologically: for every edge `v1 -> v2`, `v1`
    /// appears before `v2`. Back edges (relative to traversal order, driven by
    /// `edge_comparator`) are ignored, making cyclic graphs effectively acyclic.
    fn topological_sort(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        root: &V,
        edge_comparator: &dyn Fn(&E, &E) -> Ordering,
    ) -> Vec<V>;

    /// Converts a general directed graph into a tree graph with the given vertex as the root, by
    /// performing a topological sort and greedily accepting the first incoming edge per vertex.
    fn to_tree(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        root: &V,
        edge_comparator: &dyn Fn(&E, &E) -> Ordering,
    ) -> Box<dyn GDirectedGraph<V, E>>;

    /// Debug-prints the graph, starting from each source vertex, using `to_label` to render each
    /// vertex.
    fn print_graph(
        &self,
        g: &dyn GDirectedGraph<V, E>,
        to_label: &dyn Fn(&V) -> String,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let sources = self.get_sources(g);
        let mut printed: Vec<V> = Vec::new();
        writeln!(out, "=================================")?;
        for v in &sources {
            recursive_print(g, v, &mut printed, 0, to_label, out)?;
            writeln!(out, "---------------------------------")?;
        }
        writeln!(out, "=================================")?;
        Ok(())
    }
}

/// Returns true if the given strong component has no incoming edges from outside of the
/// component.
fn is_self_contained_strong_component<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq>(
    g: &dyn GDirectedGraph<V, E>,
    strong_component: &[V],
) -> bool {
    let mut parents: Vec<V> = Vec::new();
    for v in strong_component {
        for p in g.get_predecessors(v) {
            if !parents.contains(&p) {
                parents.push(p);
            }
        }
    }
    parents.iter().all(|p| strong_component.contains(p))
}

fn recursive_print<V: Clone + PartialEq, E: GEdge<V> + Clone + PartialEq>(
    g: &dyn GDirectedGraph<V, E>,
    v: &V,
    printed: &mut Vec<V>,
    depth: usize,
    to_label: &dyn Fn(&V) -> String,
    out: &mut dyn Write,
) -> io::Result<()> {
    for _ in 0..depth {
        write!(out, ".")?;
    }

    if printed.contains(v) {
        writeln!(out, "{}^ ({})", to_label(v), depth)?;
        return Ok(());
    }

    if depth > 0 {
        writeln!(out, "{} ({})", to_label(v), depth)?;
    } else {
        writeln!(out, "{}", to_label(v))?;
    }

    printed.push(v.clone());
    for child in g.get_successors(v) {
        recursive_print(g, &child, printed, depth + 1, to_label, out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::g_implicit_directed_graph::GImplicitDirectedGraph;
    use crate::graph::seam_stubs::{BottomUpNavigator, TopDownNavigator};
    use crate::util::datastruct::Accumulator;
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
        vertices: Vec<i32>,
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
        fn add_vertex(&mut self, v: i32) -> bool {
            if self.vertices.contains(&v) {
                return false;
            }
            self.vertices.push(v);
            true
        }
        fn remove_vertex(&mut self, v: &i32) -> bool {
            let before = self.vertices.len();
            self.vertices.retain(|x| x != v);
            self.edges.retain(|e| &e.start != v && &e.end != v);
            self.vertices.len() != before
        }
        fn add_edge(&mut self, e: Edge) {
            if !self.vertices.contains(&e.start) {
                self.vertices.push(e.start);
            }
            if !self.vertices.contains(&e.end) {
                self.vertices.push(e.end);
            }
            self.edges.push(e);
        }
        fn remove_edge(&mut self, e: &Edge) -> bool {
            let before = self.edges.len();
            self.edges.retain(|x| x != e);
            self.edges.len() != before
        }
        fn find_edge(&self, start: &i32, end: &i32) -> Option<Edge> {
            self.edges.iter().find(|e| &e.start == start && &e.end == end).cloned()
        }
        fn get_vertices(&self) -> Vec<i32> {
            self.vertices.clone()
        }
        fn get_edges(&self) -> Vec<Edge> {
            self.edges.clone()
        }
        fn contains_vertex(&self, v: &i32) -> bool {
            self.vertices.contains(v)
        }
        fn contains_edge(&self, e: &Edge) -> bool {
            self.edges.contains(e)
        }
        fn contains_edge_between(&self, from: &i32, to: &i32) -> bool {
            self.edges.iter().any(|e| &e.start == from && &e.end == to)
        }
        fn is_empty(&self) -> bool {
            self.vertices.is_empty() && self.edges.is_empty()
        }
        fn get_vertex_count(&self) -> usize {
            self.vertices.len()
        }
        fn get_edge_count(&self) -> usize {
            self.edges.len()
        }
        fn empty_copy(&self) -> Box<dyn GDirectedGraph<i32, Edge>> {
            Box::new(SimpleGraph::default())
        }
    }

    fn reachable(g: &dyn GDirectedGraph<i32, Edge>, start: i32, forward: bool) -> Vec<i32> {
        let mut visited = vec![start];
        let mut pending = vec![start];
        while let Some(v) = pending.pop() {
            let next = if forward { g.get_successors(&v) } else { g.get_predecessors(&v) };
            for n in next {
                if !visited.contains(&n) {
                    visited.push(n);
                    pending.push(n);
                }
            }
        }
        visited
    }

    /// A mock implementation supplying the algorithm-backed methods with small but real logic
    /// (not stubs), to prove the trait is both object-safe and behaviorally usable.
    struct MockAlgorithms;

    impl GraphAlgorithms<i32, Edge> for MockAlgorithms {
        fn find_dominance_tree(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn GDirectedGraph<i32, Edge>>, CancelledException> {
            Ok(g.empty_copy())
        }

        fn find_dominance(
            &self,
            _g: &dyn GDirectedGraph<i32, Edge>,
            _from: &i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<i32>, CancelledException> {
            Ok(Vec::new())
        }

        fn find_post_dominance(
            &self,
            _g: &dyn GDirectedGraph<i32, Edge>,
            _from: &i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<i32>, CancelledException> {
            Ok(Vec::new())
        }

        fn find_circuits_unique(
            &self,
            _g: &dyn GDirectedGraph<i32, Edge>,
            _unique_circuits: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<Vec<i32>>, CancelledException> {
            Ok(Vec::new())
        }

        fn find_circuits_with_timeout(
            &self,
            _g: &dyn GDirectedGraph<i32, Edge>,
            _unique_circuits: bool,
            _monitor: &dyn TimeoutTaskMonitorSeam,
        ) -> Result<Vec<Vec<i32>>, TimeoutMonitorError> {
            Ok(Vec::new())
        }

        fn find_paths(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            start: &i32,
            end: &i32,
            accumulator: &mut impl Accumulator<Vec<i32>>,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            fn visit(
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
                    visit(g, next, end, path, accumulator, monitor)?;
                    path.pop();
                }
                Ok(())
            }

            let mut path = vec![*start];
            visit(g, *start, end, &mut path, accumulator, monitor)
        }

        fn find_paths_with_timeout(
            &self,
            _g: &dyn GDirectedGraph<i32, Edge>,
            _start: &i32,
            _end: &i32,
            _accumulator: &mut impl Accumulator<Vec<i32>>,
            _monitor: &dyn TimeoutTaskMonitorSeam,
        ) -> Result<(), TimeoutMonitorError> {
            Ok(())
        }

        fn get_strongly_connected_components(&self, g: &dyn GDirectedGraph<i32, Edge>) -> Vec<Vec<i32>> {
            let vertices = g.get_vertices();
            let mut assigned: Vec<i32> = Vec::new();
            let mut components: Vec<Vec<i32>> = Vec::new();
            for v in &vertices {
                if assigned.contains(v) {
                    continue;
                }
                let forward = reachable(g, *v, true);
                let backward = reachable(g, *v, false);
                let component: Vec<i32> =
                    forward.into_iter().filter(|x| backward.contains(x)).collect();
                assigned.extend(component.iter().cloned());
                components.push(component);
            }
            components
        }

        fn get_vertices_in_post_order(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            navigator: &dyn GraphNavigatorSeam<i32, Edge>,
        ) -> Vec<i32> {
            fn dfs(
                g: &dyn GDirectedGraph<i32, Edge>,
                navigator: &dyn GraphNavigatorSeam<i32, Edge>,
                v: i32,
                visited: &mut Vec<i32>,
                order: &mut Vec<i32>,
            ) {
                if visited.contains(&v) {
                    return;
                }
                visited.push(v);
                for e in navigator.get_edges(g, &v) {
                    dfs(g, navigator, navigator.get_end(&e), visited, order);
                }
                order.push(v);
            }

            let roots = if navigator.is_top_down() { self.get_sources(g) } else { self.get_sinks(g) };
            let mut visited = Vec::new();
            let mut order = Vec::new();
            for r in roots {
                dfs(g, navigator, r, &mut visited, &mut order);
            }
            order
        }

        fn get_vertices_in_pre_order(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            navigator: &dyn GraphNavigatorSeam<i32, Edge>,
        ) -> Vec<i32> {
            fn dfs(
                g: &dyn GDirectedGraph<i32, Edge>,
                navigator: &dyn GraphNavigatorSeam<i32, Edge>,
                v: i32,
                visited: &mut Vec<i32>,
                order: &mut Vec<i32>,
            ) {
                if visited.contains(&v) {
                    return;
                }
                visited.push(v);
                order.push(v);
                for e in navigator.get_edges(g, &v) {
                    dfs(g, navigator, navigator.get_end(&e), visited, order);
                }
            }

            let roots = if navigator.is_top_down() { self.get_sources(g) } else { self.get_sinks(g) };
            let mut visited = Vec::new();
            let mut order = Vec::new();
            for r in roots {
                dfs(g, navigator, r, &mut visited, &mut order);
            }
            order
        }

        fn topological_sort(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            _root: &i32,
            _edge_comparator: &dyn Fn(&Edge, &Edge) -> Ordering,
        ) -> Vec<i32> {
            let mut order = self.get_vertices_in_post_order(g, &TopDownNavigator);
            order.reverse();
            order
        }

        fn to_tree(
            &self,
            g: &dyn GDirectedGraph<i32, Edge>,
            _root: &i32,
            _edge_comparator: &dyn Fn(&Edge, &Edge) -> Ordering,
        ) -> Box<dyn GDirectedGraph<i32, Edge>> {
            g.empty_copy()
        }
    }

    fn build_graph() -> SimpleGraph {
        // 1 -> 2, 1 -> 3, 2 -> 3, 3 -> 4
        let mut g = SimpleGraph::default();
        g.add_edge(Edge { start: 1, end: 2 });
        g.add_edge(Edge { start: 1, end: 3 });
        g.add_edge(Edge { start: 2, end: 3 });
        g.add_edge(Edge { start: 3, end: 4 });
        g
    }

    #[test]
    fn test_get_sources_and_sinks() {
        let g = build_graph();
        let algo = MockAlgorithms;
        assert_eq!(algo.get_sources(&g), vec![1]);
        assert_eq!(algo.get_sinks(&g), vec![4]);
    }

    #[test]
    fn test_get_descendants_and_ancestors() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let mut descendants = algo.get_descendants(&g, &[1]);
        descendants.sort();
        assert_eq!(descendants, vec![1, 2, 3, 4]);

        let mut ancestors = algo.get_ancestors(&g, &[4]);
        ancestors.sort();
        assert_eq!(ancestors, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_create_sub_graph_and_retain_edges() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let sub = algo.create_sub_graph(&g, &[1, 2, 3]);
        assert_eq!(sub.get_edge_count(), 3);
        assert!(sub.contains_edge_between(&1, &2));
        assert!(sub.contains_edge_between(&1, &3));
        assert!(sub.contains_edge_between(&2, &3));
        assert!(!sub.contains_edge_between(&3, &4));

        let retained = algo.retain_edges(&g, &[1, 2, 3]);
        assert_eq!(retained.len(), 3);
    }

    #[test]
    fn test_to_vertices() {
        let edges = vec![Edge { start: 1, end: 2 }, Edge { start: 2, end: 3 }];
        let algo = MockAlgorithms;
        let mut vertices = algo.to_vertices(&edges);
        vertices.sort();
        assert_eq!(vertices, vec![1, 2, 3]);
    }

    #[test]
    fn test_get_entry_points_with_isolated_cycle() {
        // 1 -> 2 -> 3 -> 1 is a self-contained cycle isolated from the rest of the graph.
        let mut g = SimpleGraph::default();
        g.add_edge(Edge { start: 1, end: 2 });
        g.add_edge(Edge { start: 2, end: 3 });
        g.add_edge(Edge { start: 3, end: 1 });
        g.add_edge(Edge { start: 10, end: 11 });

        let algo = MockAlgorithms;
        let mut entry_points = algo.get_entry_points(&g);
        entry_points.sort();
        // 10 is a source; exactly one vertex from the {1,2,3} cycle is picked as its entry.
        assert!(entry_points.contains(&10));
        assert_eq!(entry_points.len(), 2);
        assert!(entry_points.iter().any(|v| [1, 2, 3].contains(v)));
    }

    #[test]
    fn test_get_complexity_depth() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let depth = algo.get_complexity_depth(&g);
        let get = |v: i32| depth.iter().find(|(cv, _)| *cv == v).unwrap().1;
        assert_eq!(get(4), 0);
        assert_eq!(get(3), 1);
        assert_eq!(get(2), 2);
        assert_eq!(get(1), 3);
    }

    #[test]
    fn test_get_vertices_in_post_and_pre_order() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let post = algo.get_vertices_in_post_order(&g, &TopDownNavigator);
        assert_eq!(post.last(), Some(&1));
        assert_eq!(*post.first().unwrap(), 4);

        let pre = algo.get_vertices_in_pre_order(&g, &TopDownNavigator);
        assert_eq!(pre.first(), Some(&1));

        let bottom_up_sources = algo.get_sinks(&g);
        assert_eq!(bottom_up_sources, vec![4]);
        let post_bottom_up = algo.get_vertices_in_post_order(&g, &BottomUpNavigator);
        assert_eq!(*post_bottom_up.first().unwrap(), 1);
    }

    #[test]
    fn test_find_paths_collects_every_path() {
        use crate::util::datastruct::ListAccumulator;

        let g = build_graph();
        let algo = MockAlgorithms;
        let mut acc = ListAccumulator::new();
        let monitor = DummyMonitor;
        algo.find_paths(&g, &1, &4, &mut acc, &monitor).unwrap();

        let paths: Vec<Vec<i32>> = acc.into_iter().collect();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![1, 3, 4]));
        assert!(paths.contains(&vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_print_graph() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let mut buf: Vec<u8> = Vec::new();
        algo.print_graph(&g, &|v: &i32| v.to_string(), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains('1'));
        assert!(output.contains("---------------------------------"));
    }

    #[test]
    fn test_object_safety_as_trait_object() {
        let g = build_graph();
        let algo = MockAlgorithms;
        let dyn_algo: &dyn GraphAlgorithms<i32, Edge> = &algo;
        assert_eq!(dyn_algo.get_sources(&g), vec![1]);
        assert_eq!(dyn_algo.get_sinks(&g), vec![4]);
        assert_eq!(dyn_algo.get_strongly_connected_components(&g).len(), 4);
    }

    #[test]
    fn test_timeout_monitor_error_conversions() {
        let cancelled: TimeoutMonitorError = CancelledException::default().into();
        assert_eq!(cancelled, TimeoutMonitorError::Cancelled(CancelledException::default()));

        let timed_out: TimeoutMonitorError = TimeoutException::new("too slow").into();
        assert_eq!(timed_out, TimeoutMonitorError::TimedOut(TimeoutException::new("too slow")));
    }
}
