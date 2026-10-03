use crate::app::seam_stubs::FGVertex;
use crate::graph::seam_stubs::VisualEdge;
use crate::program::seam_stubs::FlowType;

/// This version of the [`VisualEdge`] adds a few methods specific to function graph edges.
///
/// The `set_default_alpha` method was added here instead of the base interface, as it
/// was not needed any higher at the time of writing. It can be pulled-up, but there is most
/// likely a better pattern for specifying visual attributes of an edge. If we find we need more
/// methods like this, then that is a good time for a refactor to change how we manipulate
/// rendering attributes from various parts of the API (e.g., from the layouts and from animation
/// jobs).
///
/// Port of `ghidra.app.plugin.core.functiongraph.graph.FGEdge`.
pub trait FGEdge: VisualEdge + Send + Sync {
    /// Get the flow type for this edge.
    ///
    /// Port of `FGEdge.getFlowType()`.
    fn get_flow_type(&self) -> Box<dyn FlowType>;

    /// Get the label for this edge.
    ///
    /// Port of `FGEdge.getLabel()`.
    fn get_label(&self) -> String;

    /// Set the label for this edge.
    ///
    /// Port of `FGEdge.setLabel(String)`.
    fn set_label(&self, label: String);

    /// Set this edge's base alpha, which determines how much of the edge is visible/transparent.
    ///
    /// 0 is completely transparent.
    ///
    /// This differs from [`VisualEdge::set_alpha`] in that the latter is used for
    /// temporary display effects. This method is used to set the alpha value for the edge when
    /// it is not part of a temporary display effect.
    ///
    /// Port of `FGEdge.setDefaultAlpha(double)`.
    fn set_default_alpha(&self, alpha: f64);

    /// Get this edge's base alpha, which determines how much of the edge is visible/transparent.
    ///
    /// 0 is completely transparent.
    ///
    /// This differs from [`VisualEdge::get_alpha`] in that the latter is used for
    /// temporary display effects. This method is used to get the alpha value for the edge when
    /// it is not part of a temporary display effect.
    ///
    /// Port of `FGEdge.getDefaultAlpha()`.
    fn get_default_alpha(&self) -> f64;

    /// Clone this edge with new start and end vertices.
    ///
    /// Port of `FGEdge.cloneEdge(FGVertex, FGVertex)`.
    fn clone_edge_fg(&self, start: &dyn FGVertex, end: &dyn FGVertex) -> Box<dyn FGEdge>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fg_edge_is_send() {
        fn assert_send<T: Send>() {}
        fn check() {
            assert_send::<Box<dyn FGEdge>>();
        }
        check();
    }

    #[test]
    fn test_fg_edge_is_sync() {
        fn assert_sync<T: Sync>() {}
        fn check() {
            assert_sync::<Box<dyn FGEdge>>();
        }
        check();
    }
}
