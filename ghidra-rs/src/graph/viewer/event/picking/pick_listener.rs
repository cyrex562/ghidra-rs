use std::collections::HashSet;
use std::hash::Hash;

/// Indicates where a pick event originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    /// Originated from outside of the graph API (e.g., an external location change).
    External,
    /// Originated from the graph API (e.g., a user click, a graph grouping).
    Internal,
}

/// Listener notified when graph vertices are picked (selected).
pub trait PickListener<V: Eq + Hash> {
    /// Called when the set of picked vertices changes.
    fn vertices_picked(&mut self, vertices: &HashSet<V>, source: EventSource);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPickListener {
        last_count: usize,
        last_source: Option<EventSource>,
    }

    impl PickListener<i32> for MockPickListener {
        fn vertices_picked(&mut self, vertices: &HashSet<i32>, source: EventSource) {
            self.last_count = vertices.len();
            self.last_source = Some(source);
        }
    }

    #[test]
    fn test_external_pick() {
        let mut l = MockPickListener { last_count: 0, last_source: None };
        let verts: HashSet<i32> = [1, 2, 3].iter().copied().collect();
        l.vertices_picked(&verts, EventSource::External);
        assert_eq!(l.last_count, 3);
        assert_eq!(l.last_source, Some(EventSource::External));
    }

    #[test]
    fn test_internal_pick() {
        let mut l = MockPickListener { last_count: 0, last_source: None };
        let verts: HashSet<i32> = [42].iter().copied().collect();
        l.vertices_picked(&verts, EventSource::Internal);
        assert_eq!(l.last_count, 1);
        assert_eq!(l.last_source, Some(EventSource::Internal));
    }

    #[test]
    fn test_empty_pick() {
        let mut l = MockPickListener { last_count: 1, last_source: None };
        let verts: HashSet<i32> = HashSet::new();
        l.vertices_picked(&verts, EventSource::Internal);
        assert_eq!(l.last_count, 0);
    }

    #[test]
    fn test_trait_object() {
        let mut l: Box<dyn PickListener<i32>> =
            Box::new(MockPickListener { last_count: 0, last_source: None });
        let verts: HashSet<i32> = [7, 8].iter().copied().collect();
        l.vertices_picked(&verts, EventSource::External);
    }

    #[test]
    fn test_event_source_equality() {
        assert_eq!(EventSource::External, EventSource::External);
        assert_ne!(EventSource::External, EventSource::Internal);
    }
}
