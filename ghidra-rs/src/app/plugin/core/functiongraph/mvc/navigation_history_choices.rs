use std::fmt;

/// Options controlling when the Function Graph records navigation history.
///
/// Maps to `ghidra.app.plugin.core.functiongraph.mvc.NavigationHistoryChoices`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationHistoryChoices {
    /// A navigation event is a double-click or Go To operation.
    NavigationEvents,
    /// When a new vertex is focused.
    VertexChanges,
}

impl NavigationHistoryChoices {
    fn display_name(self) -> &'static str {
        match self {
            NavigationHistoryChoices::NavigationEvents => "Navigation Events",
            NavigationHistoryChoices::VertexChanges => "Vertex Changes",
        }
    }
}

impl fmt::Display for NavigationHistoryChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_navigation_events() {
        assert_eq!(NavigationHistoryChoices::NavigationEvents.to_string(), "Navigation Events");
    }

    #[test]
    fn display_vertex_changes() {
        assert_eq!(NavigationHistoryChoices::VertexChanges.to_string(), "Vertex Changes");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(NavigationHistoryChoices::NavigationEvents, NavigationHistoryChoices::VertexChanges);
    }

    #[test]
    fn copy_and_clone() {
        let a = NavigationHistoryChoices::NavigationEvents;
        let b = a;
        assert_eq!(a, b);
    }
}
