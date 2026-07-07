/// Describes a change in a tree model.
///
/// Corresponds to `javax.swing.event.TreeModelEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeModelEvent {
    /// Index path from the root to the changed node's parent.
    pub path: Vec<usize>,
    /// Indices of the children affected by the change.
    pub child_indices: Vec<usize>,
}

impl TreeModelEvent {
    pub fn new(path: Vec<usize>, child_indices: Vec<usize>) -> Self {
        Self { path, child_indices }
    }
}
