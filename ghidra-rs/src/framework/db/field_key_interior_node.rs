use std::io;

use super::field::Field;
use super::interior_node::InteriorNode;
use crate::framework::seam_stubs::FieldKeyNode;

/// Common interface for `FieldKeyNode` implementations which are also an `InteriorNode`.
///
/// Mirrors `db.FieldKeyInteriorNode`, which extends both `InteriorNode` and `FieldKeyNode`.
/// `FieldKeyNode` is not yet ported, so it is represented here by a minimal placeholder trait in
/// [`seam_stubs`](crate::framework::seam_stubs) (see `STUBS.tsv`).
pub trait FieldKeyInteriorNode: InteriorNode + FieldKeyNode {
    /// Callback method for when a child node's leftmost key changes.
    ///
    /// - `old_key`: previous leftmost key.
    /// - `new_key`: new leftmost key.
    /// - `child_node`: child node containing `old_key` (`None` if not a `VarKeyNode`).
    fn key_changed(
        &mut self,
        old_key: &Field,
        new_key: &Field,
        child_node: Option<&dyn FieldKeyNode>,
    ) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::nodes::BTreeNode;

    struct MockFieldKeyInteriorNode {
        buffer_id: i32,
        key_count: i32,
        last_change: Option<(Field, Field)>,
    }

    impl MockFieldKeyInteriorNode {
        fn last_change(&self) -> Option<&(Field, Field)> {
            self.last_change.as_ref()
        }
    }

    impl BTreeNode for MockFieldKeyInteriorNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            self.key_count
        }

        fn set_key_count(&mut self, count: i32) {
            self.key_count = count;
        }
    }

    impl InteriorNode for MockFieldKeyInteriorNode {}
    impl FieldKeyNode for MockFieldKeyInteriorNode {}

    impl FieldKeyInteriorNode for MockFieldKeyInteriorNode {
        fn key_changed(
            &mut self,
            old_key: &Field,
            new_key: &Field,
            _child_node: Option<&dyn FieldKeyNode>,
        ) -> io::Result<()> {
            self.last_change = Some((old_key.clone(), new_key.clone()));
            Ok(())
        }
    }

    #[test]
    fn test_field_key_interior_node_is_object_safe() {
        let mut node = MockFieldKeyInteriorNode { buffer_id: 1, key_count: 0, last_change: None };
        let old_key = Field::Long(Some(1));
        let new_key = Field::Long(Some(2));
        node.key_changed(&old_key, &new_key, None).unwrap();
        assert_eq!(node.last_change(), Some(&(old_key.clone(), new_key.clone())));

        let boxed: Box<dyn FieldKeyInteriorNode> = Box::new(node);
        assert_eq!(boxed.get_buffer_id(), 1);
    }
}
