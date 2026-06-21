use super::{TreeModelEvent, TreeModelListener};

/// A [`TreeModelListener`] that routes all four change callbacks to a single
/// [`tree_changed`](AnyChangeTreeModelListener::tree_changed) method.
///
/// Corresponds to `docking.widgets.tree.AnyChangeTreeModelListener`.
pub trait AnyChangeTreeModelListener {
    fn tree_changed(&mut self, e: &TreeModelEvent);
}

impl<T: AnyChangeTreeModelListener> TreeModelListener for T {
    fn tree_nodes_changed(&mut self, e: &TreeModelEvent) {
        self.tree_changed(e);
    }

    fn tree_nodes_inserted(&mut self, e: &TreeModelEvent) {
        self.tree_changed(e);
    }

    fn tree_nodes_removed(&mut self, e: &TreeModelEvent) {
        self.tree_changed(e);
    }

    fn tree_structure_changed(&mut self, e: &TreeModelEvent) {
        self.tree_changed(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CallTracker {
        calls: Vec<Vec<usize>>,
    }

    impl AnyChangeTreeModelListener for CallTracker {
        fn tree_changed(&mut self, e: &TreeModelEvent) {
            self.calls.push(e.path.clone());
        }
    }

    fn event(path: Vec<usize>) -> TreeModelEvent {
        TreeModelEvent::new(path, vec![])
    }

    #[test]
    fn nodes_changed_dispatches_to_tree_changed() {
        let mut t = CallTracker { calls: vec![] };
        t.tree_nodes_changed(&event(vec![0]));
        assert_eq!(t.calls, vec![vec![0]]);
    }

    #[test]
    fn nodes_inserted_dispatches_to_tree_changed() {
        let mut t = CallTracker { calls: vec![] };
        t.tree_nodes_inserted(&event(vec![1, 2]));
        assert_eq!(t.calls, vec![vec![1, 2]]);
    }

    #[test]
    fn nodes_removed_dispatches_to_tree_changed() {
        let mut t = CallTracker { calls: vec![] };
        t.tree_nodes_removed(&event(vec![3]));
        assert_eq!(t.calls, vec![vec![3]]);
    }

    #[test]
    fn structure_changed_dispatches_to_tree_changed() {
        let mut t = CallTracker { calls: vec![] };
        t.tree_structure_changed(&event(vec![]));
        assert_eq!(t.calls, vec![Vec::<usize>::new()]);
    }

    #[test]
    fn all_four_callbacks_accumulate_in_order() {
        let mut t = CallTracker { calls: vec![] };
        t.tree_nodes_changed(&event(vec![0]));
        t.tree_nodes_inserted(&event(vec![1]));
        t.tree_nodes_removed(&event(vec![2]));
        t.tree_structure_changed(&event(vec![3]));
        assert_eq!(t.calls, vec![vec![0], vec![1], vec![2], vec![3]]);
    }
}
