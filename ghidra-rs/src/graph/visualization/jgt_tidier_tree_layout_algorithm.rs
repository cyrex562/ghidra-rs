use std::cmp::Ordering;

use crate::service::graph::{AttributedEdge, AttributedVertex};

/// Represents the dimensions of a layout, mirroring jungrapht's `Dimension`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Dimension {
    pub width: i32,
    pub height: i32,
}

impl Dimension {
    pub fn new(width: i32, height: i32) -> Self {
        Dimension { width, height }
    }

    pub fn of(width: i32, height: i32) -> Self {
        Dimension { width, height }
    }
}

/// Layout algorithm configuration for the Tidier Tree layout.
///
/// Mirrors `ghidra.graph.visualization.layout.JgtTidierTreeLayoutAlgorithm`. The Java class
/// subclasses jungrapht-visualization's `TidierTreeLayoutAlgorithm` to fix spacing issues by
/// disabling layout expansion and fixing vertex dimensions to 50x50. Since that base class is
/// a third-party UI library type with no Rust port, this struct represents the configuration
/// directly.
pub struct JgtTidierTreeLayoutAlgorithm {
    expand_layout: bool,
    edge_comparator: Option<Box<dyn Fn(&AttributedEdge, &AttributedEdge) -> Ordering>>,
}

impl JgtTidierTreeLayoutAlgorithm {
    /// Creates a new builder for the tidier tree layout algorithm.
    pub fn edge_aware_builder() -> Builder {
        Builder::new()
    }

    /// Computes a fixed average vertex dimension for consistent spacing.
    ///
    /// Unlike the parent class which computes dimensions from actual vertex sizes, this method
    /// returns a fixed dimension of 50x50 to prevent large vertices from causing excessive
    /// spacing on the x-axis.
    pub fn compute_average_vertex_dimension(&self) -> Dimension {
        Dimension::of(50, 50)
    }

    pub fn is_expand_layout(&self) -> bool {
        self.expand_layout
    }

    pub fn edge_comparator(&self) -> Option<&dyn Fn(&AttributedEdge, &AttributedEdge) -> Ordering> {
        self.edge_comparator.as_ref().map(|b| b.as_ref())
    }
}

/// Builder for creating a `JgtTidierTreeLayoutAlgorithm`.
pub struct Builder {
    expand_layout: bool,
    edge_comparator: Option<Box<dyn Fn(&AttributedEdge, &AttributedEdge) -> Ordering>>,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            expand_layout: false,
            edge_comparator: None,
        }
    }

    /// Sets the edge comparator for ordering edges in the layout.
    pub fn edge_comparator<F>(mut self, comparator: F) -> Self
    where
        F: Fn(&AttributedEdge, &AttributedEdge) -> Ordering + 'static,
    {
        self.edge_comparator = Some(Box::new(comparator));
        self
    }

    /// Sets whether to expand the layout.
    pub fn expand_layout(mut self, expand: bool) -> Self {
        self.expand_layout = expand;
        self
    }

    /// Builds the layout algorithm configuration.
    pub fn build(self) -> JgtTidierTreeLayoutAlgorithm {
        JgtTidierTreeLayoutAlgorithm {
            expand_layout: self.expand_layout,
            edge_comparator: self.edge_comparator,
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_new_creates_correct_dimensions() {
        let dim = Dimension::new(50, 50);
        assert_eq!(dim.width, 50);
        assert_eq!(dim.height, 50);
    }

    #[test]
    fn dimension_of_creates_correct_dimensions() {
        let dim = Dimension::of(100, 75);
        assert_eq!(dim.width, 100);
        assert_eq!(dim.height, 75);
    }

    #[test]
    fn builder_creates_algorithm_with_expand_layout_false() {
        let algo = JgtTidierTreeLayoutAlgorithm::edge_aware_builder().build();
        assert!(!algo.is_expand_layout());
    }

    #[test]
    fn builder_can_set_expand_layout() {
        let algo = JgtTidierTreeLayoutAlgorithm::edge_aware_builder()
            .expand_layout(true)
            .build();
        assert!(algo.is_expand_layout());
    }

    #[test]
    fn compute_average_vertex_dimension_returns_fixed_50x50() {
        let algo = JgtTidierTreeLayoutAlgorithm::edge_aware_builder().build();
        let dim = algo.compute_average_vertex_dimension();
        assert_eq!(dim.width, 50);
        assert_eq!(dim.height, 50);
    }

    #[test]
    fn builder_can_set_edge_comparator() {
        let algo = JgtTidierTreeLayoutAlgorithm::edge_aware_builder()
            .edge_comparator(|a, b| a.get_id().cmp(b.get_id()))
            .build();
        assert!(algo.edge_comparator().is_some());
    }

    #[test]
    fn builder_default_has_no_edge_comparator() {
        let algo = Builder::default().build();
        assert!(algo.edge_comparator().is_none());
    }

    #[test]
    fn dimension_equality() {
        let dim1 = Dimension::new(50, 50);
        let dim2 = Dimension::of(50, 50);
        assert_eq!(dim1, dim2);
    }
}
