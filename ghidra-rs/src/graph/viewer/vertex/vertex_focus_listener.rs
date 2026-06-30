/// A listener called when a vertex is focused.
pub trait VertexFocusListener<V> {
    /// Called when the given vertex receives focus.
    fn vertex_focused(&mut self, vertex: &V);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFocusListener<V> {
        last_focused: Option<V>,
    }

    impl<V: Clone> VertexFocusListener<V> for MockFocusListener<V> {
        fn vertex_focused(&mut self, vertex: &V) {
            self.last_focused = Some(vertex.clone());
        }
    }

    #[test]
    fn test_vertex_focused_called() {
        let mut l = MockFocusListener { last_focused: None::<i32> };
        l.vertex_focused(&42);
        assert_eq!(l.last_focused, Some(42));
    }

    #[test]
    fn test_vertex_focused_updates() {
        let mut l = MockFocusListener { last_focused: None::<i32> };
        l.vertex_focused(&1);
        l.vertex_focused(&2);
        assert_eq!(l.last_focused, Some(2));
    }

    #[test]
    fn test_trait_object() {
        let mut l: Box<dyn VertexFocusListener<i32>> =
            Box::new(MockFocusListener { last_focused: None });
        l.vertex_focused(&99);
    }

    #[test]
    fn test_string_vertex() {
        let mut l = MockFocusListener { last_focused: None::<String> };
        l.vertex_focused(&"node_a".to_string());
        assert_eq!(l.last_focused.as_deref(), Some("node_a"));
    }
}
