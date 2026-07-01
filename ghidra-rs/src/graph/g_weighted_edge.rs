use super::g_edge::GEdge;

/// An edge having a natural weight.
///
/// This trait extends `GEdge` to associate a weight (cost) with an edge.
pub trait GWeightedEdge<V>: GEdge<V> {
    /// Returns the natural weight of the edge.
    fn get_weight(&self) -> f64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WeightedEdge<V> {
        start: V,
        end: V,
        weight: f64,
    }

    impl<V> GEdge<V> for WeightedEdge<V> {
        fn get_start(&self) -> &V {
            &self.start
        }

        fn get_end(&self) -> &V {
            &self.end
        }
    }

    impl<V> GWeightedEdge<V> for WeightedEdge<V> {
        fn get_weight(&self) -> f64 {
            self.weight
        }
    }

    #[test]
    fn test_get_weight() {
        let edge = WeightedEdge {
            start: 1u32,
            end: 2u32,
            weight: 3.14,
        };
        assert_eq!(edge.get_weight(), 3.14);
    }

    #[test]
    fn test_zero_weight() {
        let edge = WeightedEdge {
            start: "a",
            end: "b",
            weight: 0.0,
        };
        assert_eq!(edge.get_weight(), 0.0);
    }

    #[test]
    fn test_negative_weight() {
        let edge = WeightedEdge {
            start: 1u32,
            end: 2u32,
            weight: -5.5,
        };
        assert_eq!(edge.get_weight(), -5.5);
    }

    #[test]
    fn test_large_weight() {
        let edge = WeightedEdge {
            start: 1u32,
            end: 2u32,
            weight: f64::MAX,
        };
        assert_eq!(edge.get_weight(), f64::MAX);
    }

    #[test]
    fn test_weighted_edge_is_also_edge() {
        let edge = WeightedEdge {
            start: 1u32,
            end: 2u32,
            weight: 1.5,
        };
        assert_eq!(edge.get_start(), &1u32);
        assert_eq!(edge.get_end(), &2u32);
        assert_eq!(edge.get_weight(), 1.5);
    }

    #[test]
    fn test_weighted_edge_with_string_vertices() {
        let edge = WeightedEdge {
            start: "source",
            end: "dest",
            weight: 2.71,
        };
        assert_eq!(edge.get_start(), &"source");
        assert_eq!(edge.get_end(), &"dest");
        assert_eq!(edge.get_weight(), 2.71);
    }
}
