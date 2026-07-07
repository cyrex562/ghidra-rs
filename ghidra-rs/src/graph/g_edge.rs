/// An edge in a (usually directed) graph.
///
/// In the edge `x -> y`, `x` is the start (tail) and `y` is the end (head).
pub trait GEdge<V> {
    /// Returns the start (tail) of the edge.
    ///
    /// In the edge `x -> y`, `x` is the start.
    fn get_start(&self) -> &V;

    /// Returns the end (head) of the edge.
    ///
    /// In the edge `x -> y`, `y` is the end.
    fn get_end(&self) -> &V;
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

    #[test]
    fn test_get_start() {
        let edge = SimpleEdge { start: 1u32, end: 2u32 };
        assert_eq!(edge.get_start(), &1u32);
    }

    #[test]
    fn test_get_end() {
        let edge = SimpleEdge { start: 1u32, end: 2u32 };
        assert_eq!(edge.get_end(), &2u32);
    }

    #[test]
    fn test_start_is_not_end() {
        let edge = SimpleEdge { start: "x", end: "y" };
        assert_ne!(edge.get_start(), edge.get_end());
    }

    #[test]
    fn test_string_vertices() {
        let edge = SimpleEdge { start: "a", end: "b" };
        assert_eq!(edge.get_start(), &"a");
        assert_eq!(edge.get_end(), &"b");
    }
}
