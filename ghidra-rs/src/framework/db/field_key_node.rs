use std::io;

use super::field::Field;
use super::field_key_interior_node::FieldKeyInteriorNode;
use super::field_key_record_node::FieldKeyRecordNode;
use super::nodes::BTreeNode;

/// Common interface for `BTreeNode` implementations which utilize a `Field` key.
///
/// Mirrors `db.FieldKeyNode`, which extends `BTreeNode`.
pub trait FieldKeyNode: BTreeNode {
    /// Get the parent node, or `None` if this is the root.
    fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>>;

    /// Get the leaf node which contains the specified key.
    fn get_leaf_node(&self, key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>>;

    /// Get the left-most leaf node within the tree.
    fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>>;

    /// Get the right-most leaf node within the tree.
    fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>>;

    /// Performs a fast in-place key comparison of the specified key value with a key stored
    /// within this node at the specified `key_index`.
    ///
    /// Returns zero if equal, -1 if `k` has a value less than the stored key, or +1 if `k` has a
    /// value greater than the stored key located at `key_index`.
    fn compare_key_field(&self, k: &Field, key_index: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFieldKeyNode {
        buffer_id: i32,
        key_count: i32,
        keys: Vec<i64>,
    }

    impl BTreeNode for MockFieldKeyNode {
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

    impl FieldKeyNode for MockFieldKeyNode {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }

        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            match self.keys[key_index as usize].cmp(&k.get_long_value()) {
                std::cmp::Ordering::Less => 1,
                std::cmp::Ordering::Greater => -1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    #[test]
    fn test_field_key_node_is_object_safe() {
        let node = MockFieldKeyNode { buffer_id: 1, key_count: 2, keys: vec![10, 20] };

        let boxed: Box<dyn FieldKeyNode> = Box::new(node);
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 2);
        assert!(boxed.get_parent().is_none());
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(10)), 0), 0);
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(5)), 0), -1);
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(20)), 0), 1);
        assert!(boxed.get_leaf_node(&Field::Long(Some(10))).is_err());
    }
}
