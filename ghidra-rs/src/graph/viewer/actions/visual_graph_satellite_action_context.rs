//! Port of `ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext`.

use crate::graph::viewer::actions::visual_graph_action_context::VisualGraphActionContext;

/// Context for the satellite viewer of a visual graph.
///
/// Port of the Java marker interface `ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext`,
/// which declares no members of its own beyond those inherited from
/// [`VisualGraphActionContext`]. It is kept as an empty subtrait so the Java hierarchy stays
/// legible; satellite-viewer contexts (e.g. the function graph's) implement it alongside the
/// parent trait.
pub trait VisualGraphSatelliteActionContext: VisualGraphActionContext {}

#[cfg(test)]
mod tests {
    use super::*;

    struct SatelliteContext;
    impl VisualGraphActionContext for SatelliteContext {}
    impl VisualGraphSatelliteActionContext for SatelliteContext {}

    fn shows(ctx: &dyn VisualGraphSatelliteActionContext) -> bool {
        ctx.should_show_satellite_actions()
    }

    #[test]
    fn satellite_context_inherits_parent_default() {
        // The marker adds no override, so the inherited default (`true`) applies.
        assert!(shows(&SatelliteContext));
    }
}
