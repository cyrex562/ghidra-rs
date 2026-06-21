use super::TreeModelEvent;

/// Listener for changes to a tree model.
///
/// Corresponds to `javax.swing.event.TreeModelListener`.
pub trait TreeModelListener {
    fn tree_nodes_changed(&mut self, e: &TreeModelEvent);
    fn tree_nodes_inserted(&mut self, e: &TreeModelEvent);
    fn tree_nodes_removed(&mut self, e: &TreeModelEvent);
    fn tree_structure_changed(&mut self, e: &TreeModelEvent);
}
