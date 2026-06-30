use std::marker::PhantomData;

/// Status of a vertex as it is processed by a graph algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Waiting,
    Scheduled,
    Exploring,
    Blocked,
    InPath,
}

/// An interface and state values used to follow the state of vertices as they
/// are processed by algorithms.
///
/// This is the default no-op implementation. The `total_status_changes` field
/// is `pub` to mirror Java's `protected` visibility, allowing callers that
/// wrap this struct to maintain the counter themselves.
pub struct GraphAlgorithmStatusListener<V> {
    pub total_status_changes: u32,
    _phantom: PhantomData<V>,
}

impl<V> GraphAlgorithmStatusListener<V> {
    pub fn new() -> Self {
        GraphAlgorithmStatusListener {
            total_status_changes: 0,
            _phantom: PhantomData,
        }
    }

    /// Called when the status of vertex `v` changes to `s`.
    ///
    /// The default implementation is a no-op.
    pub fn status_changed(&mut self, _v: &V, _s: Status) {}

    /// Called when the algorithm has finished processing.
    ///
    /// The default implementation is a no-op.
    pub fn finished(&mut self) {}

    /// Returns the total number of status changes recorded.
    pub fn get_total_status_changes(&self) -> u32 {
        self.total_status_changes
    }
}

impl<V> Default for GraphAlgorithmStatusListener<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_zero_changes() {
        let listener: GraphAlgorithmStatusListener<i32> = GraphAlgorithmStatusListener::new();
        assert_eq!(listener.get_total_status_changes(), 0);
    }

    #[test]
    fn test_default_has_zero_changes() {
        let listener: GraphAlgorithmStatusListener<i32> = GraphAlgorithmStatusListener::default();
        assert_eq!(listener.get_total_status_changes(), 0);
    }

    #[test]
    fn test_status_changed_is_noop() {
        let mut listener = GraphAlgorithmStatusListener::new();
        listener.status_changed(&42i32, Status::Waiting);
        listener.status_changed(&42i32, Status::Scheduled);
        listener.status_changed(&42i32, Status::Exploring);
        listener.status_changed(&42i32, Status::Blocked);
        listener.status_changed(&42i32, Status::InPath);
        assert_eq!(listener.get_total_status_changes(), 0);
    }

    #[test]
    fn test_finished_is_noop() {
        let mut listener: GraphAlgorithmStatusListener<&str> = GraphAlgorithmStatusListener::new();
        listener.finished();
        assert_eq!(listener.get_total_status_changes(), 0);
    }

    #[test]
    fn test_total_status_changes_is_mutable() {
        let mut listener: GraphAlgorithmStatusListener<i32> = GraphAlgorithmStatusListener::new();
        listener.total_status_changes = 7;
        assert_eq!(listener.get_total_status_changes(), 7);
    }

    #[test]
    fn test_status_variants_are_distinct() {
        assert_ne!(Status::Waiting, Status::Scheduled);
        assert_ne!(Status::Scheduled, Status::Exploring);
        assert_ne!(Status::Exploring, Status::Blocked);
        assert_ne!(Status::Blocked, Status::InPath);
    }

    #[test]
    fn test_status_copy() {
        let s = Status::Exploring;
        let t = s;
        assert_eq!(s, t);
    }
}
