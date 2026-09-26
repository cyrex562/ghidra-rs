//! Port of `ghidra.app.plugin.core.functiongraph.EdgeDisplayType`.
//!
//! An enum for mapping the [`PathHighlightMode`] to values for use in UI actions.

use crate::graph::viewer::path_highlight_mode::PathHighlightMode;

/// Port of `ghidra.app.plugin.core.functiongraph.EdgeDisplayType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeDisplayType {
    PathsToVertex,
    PathsFromVertex,
    PathsFromToVertex,
    Cycles,
    AllCycles,
    PathsFromVertexToVertex,
    ScopedFlowsFromVertex,
    ScopedFlowsToVertex,
    Off,
}

impl EdgeDisplayType {
    /// Port of `getAsPathHighlightHoverMode()`.
    pub fn get_as_path_highlight_hover_mode(&self) -> PathHighlightMode {
        match self {
            EdgeDisplayType::PathsToVertex => PathHighlightMode::In,
            EdgeDisplayType::PathsFromVertex => PathHighlightMode::Out,
            EdgeDisplayType::PathsFromToVertex => PathHighlightMode::InOut,
            EdgeDisplayType::Cycles => PathHighlightMode::Cycle,
            EdgeDisplayType::AllCycles => PathHighlightMode::AllCycle,
            EdgeDisplayType::PathsFromVertexToVertex => PathHighlightMode::Path,
            EdgeDisplayType::ScopedFlowsFromVertex => PathHighlightMode::ScopedForward,
            EdgeDisplayType::ScopedFlowsToVertex => PathHighlightMode::ScopedReverse,
            // Java's `switch` falls through `case Off:` into the `default` branch; both map to
            // `PathHighlightMode.OFF`, so a bare match arm reproduces the same result.
            EdgeDisplayType::Off => PathHighlightMode::Off,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_to_vertex_maps_to_in() {
        assert_eq!(EdgeDisplayType::PathsToVertex.get_as_path_highlight_hover_mode(), PathHighlightMode::In);
    }

    #[test]
    fn paths_from_vertex_maps_to_out() {
        assert_eq!(EdgeDisplayType::PathsFromVertex.get_as_path_highlight_hover_mode(), PathHighlightMode::Out);
    }

    #[test]
    fn paths_from_to_vertex_maps_to_inout() {
        assert_eq!(
            EdgeDisplayType::PathsFromToVertex.get_as_path_highlight_hover_mode(),
            PathHighlightMode::InOut
        );
    }

    #[test]
    fn cycles_maps_to_cycle() {
        assert_eq!(EdgeDisplayType::Cycles.get_as_path_highlight_hover_mode(), PathHighlightMode::Cycle);
    }

    #[test]
    fn all_cycles_maps_to_allcycle() {
        assert_eq!(EdgeDisplayType::AllCycles.get_as_path_highlight_hover_mode(), PathHighlightMode::AllCycle);
    }

    #[test]
    fn paths_from_vertex_to_vertex_maps_to_path() {
        assert_eq!(
            EdgeDisplayType::PathsFromVertexToVertex.get_as_path_highlight_hover_mode(),
            PathHighlightMode::Path
        );
    }

    #[test]
    fn scoped_flows_from_vertex_maps_to_scoped_forward() {
        assert_eq!(
            EdgeDisplayType::ScopedFlowsFromVertex.get_as_path_highlight_hover_mode(),
            PathHighlightMode::ScopedForward
        );
    }

    #[test]
    fn scoped_flows_to_vertex_maps_to_scoped_reverse() {
        assert_eq!(
            EdgeDisplayType::ScopedFlowsToVertex.get_as_path_highlight_hover_mode(),
            PathHighlightMode::ScopedReverse
        );
    }

    #[test]
    fn off_maps_to_off() {
        assert_eq!(EdgeDisplayType::Off.get_as_path_highlight_hover_mode(), PathHighlightMode::Off);
    }

    #[test]
    fn all_variants_are_covered() {
        let variants = [
            EdgeDisplayType::PathsToVertex,
            EdgeDisplayType::PathsFromVertex,
            EdgeDisplayType::PathsFromToVertex,
            EdgeDisplayType::Cycles,
            EdgeDisplayType::AllCycles,
            EdgeDisplayType::PathsFromVertexToVertex,
            EdgeDisplayType::ScopedFlowsFromVertex,
            EdgeDisplayType::ScopedFlowsToVertex,
            EdgeDisplayType::Off,
        ];
        for v in variants {
            let _ = v.get_as_path_highlight_hover_mode();
        }
    }
}
