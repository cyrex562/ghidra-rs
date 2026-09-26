/// An enum that lists possible states for highlighting paths between vertices in a graph.
///
/// See `VisualGraphPathHighlighter`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathHighlightMode {
    /// Shows all cycles in the graph
    AllCycle,
    /// Shows all cycles for a given vertex
    Cycle,
    /// Shows all paths that can reach the given vertex
    In,
    /// Shows all paths coming into and out of a vertex
    InOut,
    /// Shows no paths
    Off,
    /// Shows all paths reachable from the current vertex
    Out,
    /// Shows all paths between two vertices
    Path,
    /// Shows all paths that must have been traveled to reach the current vertex
    ScopedForward,
    /// Shows all paths that will be traveled after leaving the current vertex
    ScopedReverse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_exist() {
        let _all_cycle = PathHighlightMode::AllCycle;
        let _cycle = PathHighlightMode::Cycle;
        let _in_mode = PathHighlightMode::In;
        let _in_out = PathHighlightMode::InOut;
        let _off = PathHighlightMode::Off;
        let _out = PathHighlightMode::Out;
        let _path = PathHighlightMode::Path;
        let _scoped_forward = PathHighlightMode::ScopedForward;
        let _scoped_reverse = PathHighlightMode::ScopedReverse;
    }

    #[test]
    fn test_equality() {
        assert_eq!(PathHighlightMode::AllCycle, PathHighlightMode::AllCycle);
        assert_ne!(PathHighlightMode::AllCycle, PathHighlightMode::Cycle);
    }

    #[test]
    fn test_clone() {
        let mode = PathHighlightMode::Off;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_match_all_variants() {
        let modes = [
            PathHighlightMode::AllCycle,
            PathHighlightMode::Cycle,
            PathHighlightMode::In,
            PathHighlightMode::InOut,
            PathHighlightMode::Off,
            PathHighlightMode::Out,
            PathHighlightMode::Path,
            PathHighlightMode::ScopedForward,
            PathHighlightMode::ScopedReverse,
        ];

        for mode in &modes {
            match mode {
                PathHighlightMode::AllCycle => {}
                PathHighlightMode::Cycle => {}
                PathHighlightMode::In => {}
                PathHighlightMode::InOut => {}
                PathHighlightMode::Off => {}
                PathHighlightMode::Out => {}
                PathHighlightMode::Path => {}
                PathHighlightMode::ScopedForward => {}
                PathHighlightMode::ScopedReverse => {}
            }
        }
    }
}
