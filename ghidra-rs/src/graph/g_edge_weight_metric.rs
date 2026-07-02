use super::g_edge::GEdge;
use super::g_weighted_edge::GWeightedEdge;

/// A callback to compute the weight of an edge.
///
/// Analogous to Java's `Comparator`, this trait provides a means to override the weight of an edge
/// in a graph, or provide a weight in the absence of a natural weight, when executing various graph
/// algorithms, e.g., shortest path.
pub trait GEdgeWeightMetric<E, V>
where
    E: GEdge<V>,
{
    /// Compute or retrieve the weight of the given edge.
    fn compute_weight(&self, edge: &E) -> f64;
}

/// A metric that measures every edge as having a weight of 1.
#[derive(Clone, Copy)]
pub struct UnitMetric;

impl<E: GEdge<V>, V> GEdgeWeightMetric<E, V> for UnitMetric {
    fn compute_weight(&self, _edge: &E) -> f64 {
        1.0
    }
}

/// A metric that uses the natural weight of each edge.
///
/// This metric assumes every edge is a `GWeightedEdge`. If not, you will likely encounter
/// a type error or panic.
#[derive(Clone, Copy)]
pub struct NaturalMetric;

impl<E, V> GEdgeWeightMetric<E, V> for NaturalMetric
where
    E: GEdge<V> + GWeightedEdge<V>,
{
    fn compute_weight(&self, edge: &E) -> f64 {
        edge.get_weight()
    }
}

/// Returns a metric that measures every edge as having a weight of 1.
pub fn unit_metric<E: GEdge<V>, V>() -> UnitMetric {
    UnitMetric
}

/// Returns a metric that uses the natural weight of each edge.
///
/// The metric assumes every edge is a `GWeightedEdge`. If not, you will likely encounter
/// a type error or panic.
pub fn natural_metric<E, V>() -> NaturalMetric
where
    E: GEdge<V> + GWeightedEdge<V>,
{
    NaturalMetric
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleEdge<V> {
        start: V,
        end: V,
    }

    impl<V> GEdge<V> for SimpleEdge<V> {
        fn get_start(&self) -> &V {
            &self.start
        }

        fn get_end(&self) -> &V {
            &self.end
        }
    }

    struct SimpleWeightedEdge<V> {
        start: V,
        end: V,
        weight: f64,
    }

    impl<V> GEdge<V> for SimpleWeightedEdge<V> {
        fn get_start(&self) -> &V {
            &self.start
        }

        fn get_end(&self) -> &V {
            &self.end
        }
    }

    impl<V> GWeightedEdge<V> for SimpleWeightedEdge<V> {
        fn get_weight(&self) -> f64 {
            self.weight
        }
    }

    #[test]
    fn test_unit_metric_returns_one() {
        let metric = unit_metric::<SimpleEdge<i32>, i32>();
        let edge = SimpleEdge { start: 1, end: 2 };
        assert_eq!(metric.compute_weight(&edge), 1.0);
    }

    #[test]
    fn test_unit_metric_for_different_edge_types() {
        let metric = unit_metric::<SimpleEdge<&str>, &str>();
        let edge = SimpleEdge {
            start: "a",
            end: "b",
        };
        assert_eq!(metric.compute_weight(&edge), 1.0);
    }

    #[test]
    fn test_unit_metric_multiple_edges() {
        let metric = unit_metric::<SimpleEdge<f64>, f64>();
        let edge1 = SimpleEdge { start: 1.0, end: 2.0 };
        let edge2 = SimpleEdge { start: 3.0, end: 4.0 };
        assert_eq!(metric.compute_weight(&edge1), 1.0);
        assert_eq!(metric.compute_weight(&edge2), 1.0);
    }

    #[test]
    fn test_natural_metric_returns_weight() {
        let metric = natural_metric::<SimpleWeightedEdge<i32>, i32>();
        let edge = SimpleWeightedEdge {
            start: 1,
            end: 2,
            weight: 3.14,
        };
        assert_eq!(metric.compute_weight(&edge), 3.14);
    }

    #[test]
    fn test_natural_metric_zero_weight() {
        let metric = natural_metric::<SimpleWeightedEdge<&str>, &str>();
        let edge = SimpleWeightedEdge {
            start: "x",
            end: "y",
            weight: 0.0,
        };
        assert_eq!(metric.compute_weight(&edge), 0.0);
    }

    #[test]
    fn test_natural_metric_negative_weight() {
        let metric = natural_metric::<SimpleWeightedEdge<i32>, i32>();
        let edge = SimpleWeightedEdge {
            start: 1,
            end: 2,
            weight: -5.5,
        };
        assert_eq!(metric.compute_weight(&edge), -5.5);
    }

    #[test]
    fn test_natural_metric_large_weight() {
        let metric = natural_metric::<SimpleWeightedEdge<i32>, i32>();
        let edge = SimpleWeightedEdge {
            start: 1,
            end: 2,
            weight: f64::MAX,
        };
        assert_eq!(metric.compute_weight(&edge), f64::MAX);
    }

    #[test]
    fn test_unit_metric_trait_object() {
        let metric: Box<dyn GEdgeWeightMetric<SimpleEdge<i32>, i32>> = Box::new(UnitMetric);
        let edge = SimpleEdge { start: 1, end: 2 };
        assert_eq!(metric.compute_weight(&edge), 1.0);
    }

    #[test]
    fn test_natural_metric_trait_object() {
        let metric: Box<dyn GEdgeWeightMetric<SimpleWeightedEdge<i32>, i32>> =
            Box::new(NaturalMetric);
        let edge = SimpleWeightedEdge {
            start: 1,
            end: 2,
            weight: 2.5,
        };
        assert_eq!(metric.compute_weight(&edge), 2.5);
    }
}
