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

/// Placeholder for the unported Java type `VisualEdge`, referenced by `FGEdge`.
/// VisualEdge is generic over vertex and edge types in Java; here we use `any::Any` for those.
/// This is a partial stub; replace with the real port when available.
pub trait VisualEdge: Send + Sync {
    fn set_selected(&self, selected: bool);
    fn is_selected(&self) -> bool;
    fn set_in_hovered_vertex_path(&self, in_path: bool);
    fn is_in_hovered_vertex_path(&self) -> bool;
    fn set_in_focused_vertex_path(&self, in_path: bool);
    fn is_in_focused_vertex_path(&self) -> bool;
    fn get_articulation_points(&self) -> Vec<Box<dyn std::any::Any>>;
    fn set_articulation_points(&self, points: Vec<Box<dyn std::any::Any>>);
    fn clone_edge(&self, start: &dyn std::any::Any, end: &dyn std::any::Any) -> Box<dyn VisualEdge>;
    fn set_emphasis(&self, emphasis_level: f64);
    fn get_emphasis(&self) -> f64;
    fn set_alpha(&self, alpha: f64);
    fn get_alpha(&self) -> f64;
}

/// Placeholder for the unported Java type `VisualGraph`, referenced by `FGLayout`.
/// Generated stub: only a shape hint. This is a seam to break the cycle where FGLayout
/// references VisualGraph. Replace with the real port when available.
pub trait VisualGraph: Send + Sync {
    fn vertex_location_changed(&self, v: &dyn std::any::Any, point: &dyn std::any::Any, change_type: &dyn std::any::Any);
    fn get_focused_vertex(&self) -> Box<dyn std::any::Any>;
    fn set_vertex_focused(&self, v: &dyn std::any::Any, b: bool);
    fn clear_selected_vertices(&self);
    fn set_selected_vertices(&self, vertices: Vec<Box<dyn std::any::Any>>);
    fn get_selected_vertices(&self) -> Vec<Box<dyn std::any::Any>>;
    fn add_graph_change_listener(&self, l: &dyn std::any::Any);
    fn remove_graph_change_listener(&self, l: &dyn std::any::Any);
    fn get_layout(&self) -> Box<dyn VisualGraphLayout>;
    fn copy(&self) -> Box<dyn VisualGraph>;
}

/// Placeholder for the unported Java type `VisualGraphLayout`, referenced by `FGLayout`.
/// Generated stub: only a shape hint. This is a seam to break the cycle where FGLayout
/// references VisualGraphLayout. Replace with the real port when available.
pub trait VisualGraphLayout: Send + Sync {
    fn add_layout_listener(&self, listener: &dyn std::any::Any);
    fn remove_layout_listener(&self, listener: &dyn std::any::Any);
    fn uses_edge_articulations(&self) -> bool;
    fn calculate_locations(&self, graph: &dyn VisualGraph, monitor: &dyn TaskMonitor) -> Box<dyn std::any::Any>;
    fn clone_layout(&self, new_graph: &dyn VisualGraph) -> Box<dyn VisualGraphLayout>;
    fn set_location(&self, v: &dyn std::any::Any, location: &dyn std::any::Any, change_type: &dyn std::any::Any);
    fn get_visual_graph(&self) -> Box<dyn VisualGraph>;
    fn get_edge_renderer(&self) -> Box<dyn std::any::Any>;
    fn get_edge_shape_transformer(&self, context: &dyn std::any::Any) -> Box<dyn std::any::Any>;
    fn get_edge_label_renderer(&self) -> Box<dyn std::any::Any>;
    fn dispose(&self);
}
