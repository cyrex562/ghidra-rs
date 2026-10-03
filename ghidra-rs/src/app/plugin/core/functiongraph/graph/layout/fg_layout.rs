use crate::app::seam_stubs::FunctionGraph;
use crate::graph::seam_stubs::{VisualGraph, VisualGraphLayout};

/// A layout specifically for function graphs that specializes the generic [`VisualGraphLayout`].
///
/// This trait extends [`VisualGraphLayout`] to provide specific return types for function graphs:
/// - [`clone_layout`] returns an [`FGLayout`] instead of a generic [`VisualGraphLayout`]
/// - [`get_visual_graph`] returns a [`FunctionGraph`] instead of a generic [`VisualGraph`]
///
/// Port of `ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout`.
pub trait FGLayout: VisualGraphLayout + Send + Sync {
    /// Clone this layout for a new function graph.
    ///
    /// Overrides [`VisualGraphLayout::clone_layout`] to specialize the return type.
    ///
    /// Port of `FGLayout.cloneLayout(VisualGraph<FGVertex, FGEdge>)`.
    fn clone_layout_fg(&self, new_graph: &dyn VisualGraph) -> Box<dyn FGLayout>;

    /// Get the underlying function graph for this layout.
    ///
    /// Overrides [`VisualGraphLayout::get_visual_graph`] to specialize the return type.
    ///
    /// Port of `FGLayout.getVisualGraph()`.
    fn get_visual_graph_fg(&self) -> Box<dyn FunctionGraph>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fg_layout_is_send() {
        fn assert_send<T: Send>() {}
        fn check() {
            assert_send::<Box<dyn FGLayout>>();
        }
        check();
    }

    #[test]
    fn test_fg_layout_is_sync() {
        fn assert_sync<T: Sync>() {}
        fn check() {
            assert_sync::<Box<dyn FGLayout>>();
        }
        check();
    }
}
