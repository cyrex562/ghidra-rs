/// A listener to get notified of graph changes.
pub trait VisualGraphChangeListener<V, E> {
    /// Called when the given vertices have been added to the graph.
    fn vertices_added(&mut self, vertices: &[V]);

    /// Called when the given vertices have been removed from the graph.
    fn vertices_removed(&mut self, vertices: &[V]);

    /// Called when the given edges have been added to the graph.
    fn edges_added(&mut self, edges: &[E]);

    /// Called when the given edges have been removed from the graph.
    fn edges_removed(&mut self, edges: &[E]);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        vertices_added: Vec<i32>,
        vertices_removed: Vec<i32>,
        edges_added: Vec<(i32, i32)>,
        edges_removed: Vec<(i32, i32)>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                vertices_added: Vec::new(),
                vertices_removed: Vec::new(),
                edges_added: Vec::new(),
                edges_removed: Vec::new(),
            }
        }
    }

    impl VisualGraphChangeListener<i32, (i32, i32)> for RecordingListener {
        fn vertices_added(&mut self, vertices: &[i32]) {
            self.vertices_added.extend_from_slice(vertices);
        }

        fn vertices_removed(&mut self, vertices: &[i32]) {
            self.vertices_removed.extend_from_slice(vertices);
        }

        fn edges_added(&mut self, edges: &[(i32, i32)]) {
            self.edges_added.extend_from_slice(edges);
        }

        fn edges_removed(&mut self, edges: &[(i32, i32)]) {
            self.edges_removed.extend_from_slice(edges);
        }
    }

    #[test]
    fn test_vertices_added() {
        let mut listener = RecordingListener::new();
        listener.vertices_added(&[1, 2, 3]);
        assert_eq!(listener.vertices_added, vec![1, 2, 3]);
    }

    #[test]
    fn test_vertices_removed() {
        let mut listener = RecordingListener::new();
        listener.vertices_removed(&[4, 5]);
        assert_eq!(listener.vertices_removed, vec![4, 5]);
    }

    #[test]
    fn test_edges_added() {
        let mut listener = RecordingListener::new();
        listener.edges_added(&[(1, 2), (3, 4)]);
        assert_eq!(listener.edges_added, vec![(1, 2), (3, 4)]);
    }

    #[test]
    fn test_edges_removed() {
        let mut listener = RecordingListener::new();
        listener.edges_removed(&[(5, 6)]);
        assert_eq!(listener.edges_removed, vec![(5, 6)]);
    }

    #[test]
    fn test_empty_slices_are_valid() {
        let mut listener = RecordingListener::new();
        listener.vertices_added(&[]);
        listener.vertices_removed(&[]);
        listener.edges_added(&[]);
        listener.edges_removed(&[]);
        assert!(listener.vertices_added.is_empty());
        assert!(listener.vertices_removed.is_empty());
        assert!(listener.edges_added.is_empty());
        assert!(listener.edges_removed.is_empty());
    }

    #[test]
    fn test_multiple_calls_accumulate() {
        let mut listener = RecordingListener::new();
        listener.vertices_added(&[1]);
        listener.vertices_added(&[2, 3]);
        assert_eq!(listener.vertices_added, vec![1, 2, 3]);
    }
}
