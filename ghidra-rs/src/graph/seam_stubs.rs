//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::g_directed_graph::GDirectedGraph;
use super::g_edge::GEdge;
use crate::util::task::TaskMonitor;

/// Placeholder for `ghidra.graph.algo.GraphNavigator`, referenced by
/// [`GraphAlgorithms`](crate::graph::graph_algorithms::GraphAlgorithms)'s
/// `getVerticesInPostOrder`/`getVerticesInPreOrder` methods before the real port exists.
/// `GraphNavigator` and `GraphAlgorithms` reference each other in Java (`GraphNavigator`'s
/// `getSources`/`getSinks`/`getVerticesInPostOrder` call back into the corresponding
/// `GraphAlgorithms` static methods), forming the cycle this stub breaks. Only the
/// direction-aware edge/vertex accessors `GraphAlgorithms` needs are declared here.
pub trait GraphNavigatorSeam<V, E> {
    /// True if this navigator walks from source to sink (mirrors `isTopDown()`).
    fn is_top_down(&self) -> bool;

    /// Gets the edges leaving `v`, in the direction this navigator walks (mirrors `getEdges`).
    fn get_edges(&self, g: &dyn GDirectedGraph<V, E>, v: &V) -> Vec<E>;

    /// Gets the vertex at the far end of `e`, in the direction this navigator walks (mirrors
    /// `getEnd`).
    fn get_end(&self, e: &E) -> V;
}

/// Stand-in for `GraphNavigator.topDownNavigator()`, walking from source to sink.
pub struct TopDownNavigator;

/// Stand-in for `GraphNavigator.bottomUpNavigator()`, walking from sink to source.
pub struct BottomUpNavigator;

impl<V: Clone + PartialEq, E: GEdge<V> + Clone> GraphNavigatorSeam<V, E> for TopDownNavigator {
    fn is_top_down(&self) -> bool {
        true
    }

    fn get_edges(&self, g: &dyn GDirectedGraph<V, E>, v: &V) -> Vec<E> {
        g.get_out_edges(v)
    }

    fn get_end(&self, e: &E) -> V {
        e.get_end().clone()
    }
}

impl<V: Clone + PartialEq, E: GEdge<V> + Clone> GraphNavigatorSeam<V, E> for BottomUpNavigator {
    fn is_top_down(&self) -> bool {
        false
    }

    fn get_edges(&self, g: &dyn GDirectedGraph<V, E>, v: &V) -> Vec<E> {
        g.get_in_edges(v)
    }

    fn get_end(&self, e: &E) -> V {
        e.get_start().clone()
    }
}

/// Placeholder for `ghidra.util.task.TimeoutTaskMonitor`, referenced by
/// [`GraphAlgorithms`](crate::graph::graph_algorithms::GraphAlgorithms)'s timeout-bounded
/// `findCircuits`/`findPaths` overloads before the real port exists. `TimeoutTaskMonitor`
/// implements `TaskMonitor` in Java and adds timeout-specific members (`finished()`, a timeout
/// listener); `GraphAlgorithms` itself never calls those, only using the type to signal (at the
/// API level) that callers should pass a timeout-bounded monitor for large graphs, so this stub
/// declares no members beyond the `TaskMonitor` supertrait bound.
pub trait TimeoutTaskMonitorSeam: TaskMonitor {}
