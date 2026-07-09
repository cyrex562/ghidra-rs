use std::io;

use super::field::Field;
use super::field_key_node::FieldKeyNode;
use super::interior_node::InteriorNode;

/// Common interface for `FieldKeyNode` implementations which are also an `InteriorNode`.
///
/// Mirrors `db.FieldKeyInteriorNode`, which extends both `InteriorNode` and `FieldKeyNode`.
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

    impl FieldKeyNode for MockFieldKeyInteriorNode {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }

        fn get_leaf_node(
            &self,
            _key: &Field,
        ) -> io::Result<Box<dyn crate::framework::seam_stubs::FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_leftmost_leaf_node(
            &self,
        ) -> io::Result<Box<dyn crate::framework::seam_stubs::FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_rightmost_leaf_node(
            &self,
        ) -> io::Result<Box<dyn crate::framework::seam_stubs::FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn compare_key_field(&self, _k: &Field, _key_index: i32) -> i32 {
            0
        }
    }

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
