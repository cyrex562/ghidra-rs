//! Port of `datagraph.data.graph.DegEdge`.

use std::sync::Arc;

use super::seam_stubs::DegVertex;
use crate::graph::g_edge::GEdge;

/// An edge for the `DataExplorationGraph`.
///
/// Mirrors Java's `DegEdge extends EgEdge<DegVertex>`. Rust has no implementation
/// inheritance, so the `EgEdge`/`AbstractVisualEdge` chain collapses into a direct
/// [`GEdge`] implementation over [`DegVertex`] endpoints.
pub struct DegEdge {
    start: Arc<DegVertex>,
    end: Arc<DegVertex>,
}

impl DegEdge {
    /// Creates a new edge between `start` and `end` (mirrors the Java constructor).
    pub fn new(start: Arc<DegVertex>, end: Arc<DegVertex>) -> Self {
        Self { start, end }
    }

    /// Returns the start (tail) vertex of this edge.
    pub fn start(&self) -> &Arc<DegVertex> {
        &self.start
    }

    /// Returns the end (head) vertex of this edge.
    pub fn end(&self) -> &Arc<DegVertex> {
        &self.end
    }

    /// Clones this edge with new endpoints (mirrors `cloneEdge`).
    pub fn clone_edge(&self, start: Arc<DegVertex>, end: Arc<DegVertex>) -> DegEdge {
        DegEdge::new(start, end)
    }
}

impl GEdge<Arc<DegVertex>> for DegEdge {
    fn get_start(&self) -> &Arc<DegVertex> {
        &self.start
    }

    fn get_end(&self) -> &Arc<DegVertex> {
        &self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_start_and_end() {
        let start = Arc::new(DegVertex);
        let end = Arc::new(DegVertex);
        let edge = DegEdge::new(Arc::clone(&start), Arc::clone(&end));
        assert!(Arc::ptr_eq(edge.start(), &start));
        assert!(Arc::ptr_eq(edge.end(), &end));
    }

    #[test]
    fn get_start_and_get_end_match_constructor_args() {
        let start = Arc::new(DegVertex);
        let end = Arc::new(DegVertex);
        let edge = DegEdge::new(Arc::clone(&start), Arc::clone(&end));
        assert!(Arc::ptr_eq(GEdge::get_start(&edge), &start));
        assert!(Arc::ptr_eq(GEdge::get_end(&edge), &end));
    }

    #[test]
    fn clone_edge_returns_new_edge_with_given_endpoints() {
        let orig_start = Arc::new(DegVertex);
        let orig_end = Arc::new(DegVertex);
        let edge = DegEdge::new(orig_start, orig_end);

        let new_start = Arc::new(DegVertex);
        let new_end = Arc::new(DegVertex);
        let cloned = edge.clone_edge(Arc::clone(&new_start), Arc::clone(&new_end));

        assert!(Arc::ptr_eq(cloned.start(), &new_start));
        assert!(Arc::ptr_eq(cloned.end(), &new_end));
    }
}
